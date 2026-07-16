"""Targeted escalation for the registry monitor.

The registry sweep scans every skill with the rule engine + threat intel (fast,
free, 100% recall on the benchmark). That first pass is confident at the two
ends — obviously clean and obviously malicious — but there is an **ambiguous
middle** where a sneaky skill can hide: it scores just under the line, or looks
clean to the rules while the ML model finds it anomalous.

Spending a deeper (paid/slow) analysis on *every* flagged skill is wasteful —
most of that spend lands on skills already decided. This module picks only the
skills where a second opinion can actually change the verdict, and runs a
pluggable **backend** on them:

* ``none``      — no second opinion (the policy still marks candidates).
* ``hf``        — a free, local Hugging Face classifier (CPU, no API cost).
* ``anthropic`` — the full LLM analyzer (highest quality, paid).
* ``tiered``    — ``hf`` triage first, escalating to ``anthropic`` *only* the
                  skills the free tier still finds suspicious. Money is spent
                  on the residual, not the whole band.

The policy is a pure function of the first-pass record, so it is cheap and
fully testable; the backends share one small async ``assess`` interface.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, Field

from malwar.monitor.models import SkillRecord

logger = logging.getLogger("malwar.monitor.escalation")

# Rule risk at/above which a skill is already a confident detection — a deeper
# look would not change the verdict, so we don't spend on it. (Mirrors the
# MALICIOUS threshold in ScanResult.verdict.)
_MALICIOUS_RISK = 75

# Rules that, on a single line match, are known to over-flag legitimate content:
#   * MALWAR-CMD-001 fires on any ``curl … | sh`` — the documented install path
#     for a large share of legitimate dev tools (installer-host allowlisting in
#     the rule handles the dedicated-domain cases; multi-tenant hosts remain).
#   * MALWAR-ENV-001's broad pattern matches ordinary prose ("…the key you need
#     to set", "…by running env").
# A MALICIOUS verdict resting on a *single* one of these rules is fragile: it
# has never been corroborated by a second rule or a semantic pass. Such verdicts
# are re-checked (escalated) and, if not authoritatively confirmed, downgraded
# to SUSPICIOUS rather than published as a confident conviction.
HIGH_FP_RULES: frozenset[str] = frozenset({"MALWAR-CMD-001", "MALWAR-ENV-001"})


def is_fragile_malicious(record: SkillRecord) -> bool:
    """True when a MALICIOUS verdict rests on a single high-false-positive rule.

    These are the verdicts most likely to be wrong: one line, one high-FP rule,
    auto-scored CRITICAL, no corroboration. They warrant verification before we
    stand behind the MALICIOUS label.
    """
    if record.verdict != "MALICIOUS":
        return False
    rules = record.finding_rule_ids
    return len(rules) == 1 and rules[0] in HIGH_FP_RULES


@dataclass(frozen=True)
class EscalationPolicy:
    """Decides which first-pass records deserve a deeper second opinion.

    A skill qualifies when it sits in the ambiguous middle — either the rule
    engine flagged *something* short of a confident verdict, or the rules were
    quiet but the ML model finds the skill anomalous ("looks clean but off").
    Confident-clean and confident-malicious skills are skipped: a second opinion
    can't change their verdict, so spending on them is waste.
    """

    # Rule risk at/above which the rules already saw enough to warrant a look.
    # Default 8 is below the CAUTION threshold (15) so we also catch
    # "just-under-the-line" skills a sneaky author tuned to stay clean.
    min_rule_risk: int = 8
    # Rule risk at/above which the skill is already a confident detection.
    malicious_risk: int = _MALICIOUS_RISK
    # ML anomaly probability at/above which a rule-clean skill is still worth a
    # look (the "sneaky clean" path). Disabled by default (None): the current
    # RiskScorer saturates near 1.0 for *both* benign and malicious skills, so
    # it can't yet discriminate — turning it on would escalate everything. Once
    # the model is recalibrated to separate the classes, set e.g. 0.6.
    ml_threshold: float | None = None
    # Cap on how many skills to escalate per run (most-suspicious first). None
    # means no cap. Bounds the per-run cost of a paid backend.
    budget: int | None = None

    def qualifies(self, record: SkillRecord) -> bool:
        """True if this first-pass record sits in the ambiguous band."""
        if record.error is not None or record.verdict == "UNKNOWN":
            return False  # not scanned yet / failed — nothing to second-guess
        # A MALICIOUS verdict built on a single high-FP rule is *not* confident —
        # verify it before publishing the conviction (see is_fragile_malicious).
        if is_fragile_malicious(record):
            return True
        if record.risk_score >= self.malicious_risk:
            return False  # already a confident (corroborated) detection
        if record.risk_score >= self.min_rule_risk:
            return True  # rules saw something short of a verdict
        # Rules were quiet — escalate only if the ML model is suspicious.
        return (
            self.ml_threshold is not None
            and record.ml_risk_score is not None
            and record.ml_risk_score >= self.ml_threshold
        )

    def suspicion(self, record: SkillRecord) -> float:
        """A 0-1 rank for ordering candidates most-suspicious first."""
        rule = record.risk_score / 100.0
        ml = record.ml_risk_score or 0.0
        return max(rule, ml)


def select_candidates(
    records: Mapping[str, SkillRecord],
    policy: EscalationPolicy,
) -> list[str]:
    """Return the slugs to escalate, most-suspicious first, capped by budget."""
    candidates = [slug for slug, rec in records.items() if policy.qualifies(rec)]
    candidates.sort(key=lambda slug: records[slug].risk_score, reverse=False)  # stable base
    candidates.sort(key=lambda slug: policy.suspicion(records[slug]), reverse=True)
    if policy.budget is not None:
        candidates = candidates[: policy.budget]
    return candidates


class EscalationResult(BaseModel):
    """The outcome of a backend's deeper look at one skill."""

    backend: str
    flagged: bool = False
    verdict: str = ""
    score: float | None = Field(default=None, description="Backend confidence [0,1]")
    # True when this came from a full re-scan (rules + LLM + suppression), whose
    # verdict is authoritative and should replace the first-pass verdict. False
    # for a narrow classifier whose flag is only a triage signal.
    authoritative: bool = False
    detail: str = ""


class EscalationBackend(Protocol):
    """A deeper second-opinion analyzer for an ambiguous skill."""

    name: str

    async def assess(self, content: str, *, file_name: str) -> EscalationResult: ...


class NoneBackend:
    """No second opinion — the policy still selects candidates for reporting."""

    name = "none"

    async def assess(self, content: str, *, file_name: str) -> EscalationResult:
        return EscalationResult(backend=self.name, flagged=False, verdict="")


class AnthropicBackend:
    """Full LLM analyzer (paid) — reruns the pipeline with the LLM layer on."""

    name = "anthropic"

    async def assess(self, content: str, *, file_name: str) -> EscalationResult:
        from malwar.sdk import scan

        # LLM semantic analysis + rules + threat intel. Live URL crawling is
        # left off: it adds latency and external-fetch flakiness at escalation
        # scale, and the deep dive's value here is the LLM's read of intent.
        result = await scan(content, file_name=file_name, use_llm=True, use_urls=False)
        return EscalationResult(
            backend=self.name,
            flagged=result.verdict != "CLEAN",
            verdict=result.verdict,
            score=result.risk_score / 100.0,
            authoritative=True,  # full pipeline verdict (incl. LLM suppression)
            detail=f"risk={result.risk_score}",
        )


# Default Hugging Face model for the free tier. A small prompt-injection /
# jailbreak classifier that runs on CPU. Overridable; pin a verified model id
# once confirmed against the Hub.
DEFAULT_HF_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"

# Truncate content before classification — these models have a 512-token window,
# and the malicious intent is virtually always in the instructions up top.
_HF_MAX_CHARS = 4000


class HfClassifierBackend:
    """Free, local Hugging Face text-classifier tier (no API cost).

    Loads a small sequence-classification model via ``transformers`` and scores
    the content as malicious/benign. The model is loaded lazily and cached; if
    ``transformers`` (or the model) is unavailable, ``assess`` degrades to an
    ``unavailable`` result rather than raising, so it can never break a sweep.

    A ``classifier`` callable may be injected (tests, or a custom scorer): it
    takes the text and returns ``(label, score)`` with ``score`` in [0, 1].
    """

    name = "hf"

    def __init__(
        self,
        model: str = DEFAULT_HF_MODEL,
        *,
        threshold: float = 0.5,
        malicious_labels: tuple[str, ...] = ("INJECTION", "MALICIOUS", "JAILBREAK", "LABEL_1"),
        classifier: object | None = None,
    ) -> None:
        self.model = model
        self.threshold = threshold
        self._malicious_labels = {label.upper() for label in malicious_labels}
        self._classifier = classifier  # injected or lazily built pipeline
        self._load_failed = False

    def _get_classifier(self) -> object | None:
        if self._classifier is not None:
            return self._classifier
        if self._load_failed:
            return None
        try:  # pragma: no cover - exercised only when transformers is installed
            from transformers import pipeline as hf_pipeline

            self._classifier = hf_pipeline(
                "text-classification", model=self.model, truncation=True
            )
            return self._classifier
        except Exception as exc:
            self._load_failed = True
            logger.warning(
                "HF classifier unavailable (%s); install the 'hf' extra "
                "(pip install malwar[hf]) to enable the free escalation tier.",
                exc,
            )
            return None

    async def assess(self, content: str, *, file_name: str) -> EscalationResult:
        clf = self._get_classifier()
        if clf is None:
            return EscalationResult(
                backend=self.name, flagged=False, verdict="", detail="unavailable"
            )

        try:
            out = clf(content[:_HF_MAX_CHARS])  # type: ignore[operator]
        except Exception as exc:
            logger.warning("HF classification failed for %s: %s", file_name, exc)
            return EscalationResult(
                backend=self.name, flagged=False, verdict="", detail=f"error: {exc}"
            )

        label, score = _parse_classifier_output(out)
        malicious = label.upper() in self._malicious_labels
        flagged = malicious and score >= self.threshold
        return EscalationResult(
            backend=self.name,
            flagged=flagged,
            verdict="SUSPICIOUS" if flagged else "CLEAN",
            score=score if malicious else (1.0 - score),
            detail=f"{label}={score:.2f}",
        )


def _parse_classifier_output(out: object) -> tuple[str, float]:
    """Normalize a transformers text-classification result to (label, score).

    Accepts ``[{"label": ..., "score": ...}]`` (the common shape), a bare dict,
    or a list of per-label scores (picks the argmax).
    """
    item: object = out
    if isinstance(out, list) and out:
        # Could be [{label,score}] or [[{label,score}, ...]] (return_all_scores).
        first = out[0]
        if isinstance(first, list) and first:
            item = max(first, key=lambda d: d.get("score", 0.0))
        else:
            item = first
    if isinstance(item, dict):
        return str(item.get("label", "")), float(item.get("score", 0.0))
    return "", 0.0


class TieredBackend:
    """Run a cheap backend first, escalating to an expensive one only on a hit.

    This is the money-saver: the free ``hf`` tier triages the ambiguous band,
    and the paid ``anthropic`` tier is invoked *only* for skills the free tier
    still flags — so paid spend tracks the residual, not the whole band.
    """

    name = "tiered"

    def __init__(self, cheap: EscalationBackend, expensive: EscalationBackend) -> None:
        self.cheap = cheap
        self.expensive = expensive

    async def assess(self, content: str, *, file_name: str) -> EscalationResult:
        first = await self.cheap.assess(content, file_name=file_name)
        if not first.flagged:
            return first
        second = await self.expensive.assess(content, file_name=file_name)
        second.detail = f"{self.cheap.name}->{self.expensive.name}; {second.detail}".strip()
        return second


def make_backend(
    name: str,
    *,
    hf_model: str = DEFAULT_HF_MODEL,
) -> EscalationBackend:
    """Build an escalation backend by name.

    ``none`` | ``hf`` | ``anthropic`` | ``tiered`` (hf -> anthropic).
    """
    key = (name or "none").strip().lower()
    if key in ("none", "off", ""):
        return NoneBackend()
    if key == "hf":
        return HfClassifierBackend(model=hf_model)
    if key == "anthropic":
        return AnthropicBackend()
    if key == "tiered":
        return TieredBackend(HfClassifierBackend(model=hf_model), AnthropicBackend())
    raise ValueError(
        f"unknown escalation backend {name!r} (expected none|hf|anthropic|tiered)"
    )
