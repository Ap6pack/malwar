# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Diff scanning engine — compare two versions of a skill and flag changes."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from malwar.models.finding import Finding
from malwar.models.scan import ScanResult


def _finding_key(finding: Finding) -> str:
    """Produce a stable identity key for a finding.

    Findings are matched across scans by ``rule_id`` combined with a
    normalised hash of the evidence list.  This avoids comparing by
    the per-scan unique ``id`` field.
    """
    evidence_normalized = "|".join(sorted(e.strip() for e in finding.evidence))
    evidence_hash = hashlib.sha256(evidence_normalized.encode()).hexdigest()[:16]
    return f"{finding.rule_id}:{evidence_hash}"


@dataclass
class DiffResult:
    """Result of comparing two scans of different skill versions."""

    old_scan: ScanResult
    new_scan: ScanResult
    new_findings: list[Finding] = field(default_factory=list)
    removed_findings: list[Finding] = field(default_factory=list)
    unchanged_findings: list[Finding] = field(default_factory=list)
    verdict_changed: bool = False
    old_verdict: str = ""
    new_verdict: str = ""
    risk_delta: int = 0


def diff_findings(
    old_findings: list[Finding],
    new_findings: list[Finding],
) -> tuple[list[Finding], list[Finding], list[Finding]]:
    """Classify findings between two scans as new, removed, or unchanged.

    Parameters
    ----------
    old_findings:
        Findings from the *old* (baseline) scan.
    new_findings:
        Findings from the *new* (updated) scan.

    Returns
    -------
    tuple[list[Finding], list[Finding], list[Finding]]
        ``(new, removed, unchanged)`` — findings only in the new scan,
        findings only in the old scan, and findings present in both.
    """
    old_keys = {_finding_key(f): f for f in old_findings}
    new_keys = {_finding_key(f): f for f in new_findings}

    old_key_set = set(old_keys.keys())
    new_key_set = set(new_keys.keys())

    introduced = [new_keys[k] for k in sorted(new_key_set - old_key_set)]
    removed = [old_keys[k] for k in sorted(old_key_set - new_key_set)]
    unchanged = [new_keys[k] for k in sorted(old_key_set & new_key_set)]

    return introduced, removed, unchanged


async def diff_scan(
    old_content: str,
    new_content: str,
    *,
    file_name: str = "SKILL.md",
    use_llm: bool = True,
    use_urls: bool = True,
    layers: list[str] | None = None,
) -> DiffResult:
    """Scan two versions of a skill and return the difference.

    Both versions are scanned independently using the same pipeline
    configuration, then findings are compared to identify what changed.

    Parameters
    ----------
    old_content:
        Raw text of the *old* (baseline) SKILL.md version.
    new_content:
        Raw text of the *new* (updated) SKILL.md version.
    file_name:
        Label used as the ``target`` in both scan results.
    use_llm:
        Set ``False`` to skip the LLM analysis layer.
    use_urls:
        Set ``False`` to skip URL crawling.
    layers:
        Explicit list of layer names to execute.

    Returns
    -------
    DiffResult
        Comparison result with new/removed/unchanged findings and
        verdict change information.
    """
    scan_kwargs: dict = {
        "file_name": file_name,
        "use_llm": use_llm,
        "use_urls": use_urls,
        "layers": layers,
    }

    from malwar.sdk import scan as sdk_scan

    old_scan = await sdk_scan(old_content, **scan_kwargs)
    new_scan = await sdk_scan(new_content, **scan_kwargs)

    new_f, removed_f, unchanged_f = diff_findings(
        old_scan.findings, new_scan.findings
    )

    return DiffResult(
        old_scan=old_scan,
        new_scan=new_scan,
        new_findings=new_f,
        removed_findings=removed_f,
        unchanged_findings=unchanged_f,
        verdict_changed=old_scan.verdict != new_scan.verdict,
        old_verdict=old_scan.verdict,
        new_verdict=new_scan.verdict,
        risk_delta=new_scan.risk_score - old_scan.risk_score,
    )
