"""Detection of skills that widen the agent's own permission scope.

An agent skill is instructions, not code, so the interesting supply-chain move
is not a payload: it is telling the agent to loosen its own guardrails as part
of setup. Two independent examples from the live registry, neither of them
written by an attacker:

* A vendor shipping 64 SaaS connector skills, each of whose install section
  runs ``openclaw config set tools.alsoAllow ...`` and restarts the gateway,
  widening the allowlist before any integration is used.
* A development-workflow skill that instructs the agent to run a trivial
  background task first, purely to spend the user's one-time approval prompt,
  so that later background work executes without asking:
  "the first background task requires confirmation, subsequent ones don't ...
  once trust is established, no confirmation is needed all day."

Both are disclosed, both are useful, and both leave the agent permanently more
permissive than the user consented to in the moment. That is worth surfacing on
its own terms rather than as malware: the rule is deliberately capped as
FP-prone (see HIGH_FP_RULES), because a legitimate integration genuinely needs
its tools allowed, and the distinction between "asks for what it needs" and
"quietly widens the blast radius" is not one a regex can make alone.
"""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class PermissionScopeExpansion(BaseRule):
    rule_id = "MALWAR-PERM-001"
    title = "Agent permission scope expansion"
    severity = Severity.HIGH
    category = ThreatCategory.SECURITY_DISABLEMENT
    description = (
        "Detects instructions that widen the agent's own permissions during "
        "setup: editing tool allowlists, bypassing approval prompts, or "
        "priming a confirmation so later actions run unprompted"
    )

    PATTERNS: list[tuple[re.Pattern[str], str]] = [
        # Editing the agent's tool allowlist / permission config.
        (
            re.compile(
                r"config\s+set\s+[\w.]*(?:tools?\.(?:alsoAllow|allow|allowed)"
                r"|allowedTools|permissions?\.allow)",
                re.IGNORECASE,
            ),
            "writes to the agent's tool allowlist",
        ),
        (
            re.compile(
                r"\"?(?:allowedTools|alsoAllow|autoApprove|auto_approve)\"?\s*[:=]",
                re.IGNORECASE,
            ),
            "sets an allowlist or auto-approve key",
        ),
        # Explicit approval bypass flags.
        (
            re.compile(
                r"--(?:dangerously-skip-permissions|yolo|no-confirm|auto-approve"
                r"|skip-permissions|allow-all-tools)\b",
                re.IGNORECASE,
            ),
            "passes an approval-bypass flag",
        ),
        # Turning confirmation off in prose or config.
        (
            re.compile(
                r"(?:disable|turn\s+off|bypass|skip|suppress)\s+(?:the\s+)?"
                r"(?:confirmation|approval|permission)\s*(?:prompts?|dialogs?|checks?|requests?)?",
                re.IGNORECASE,
            ),
            "disables confirmation prompts",
        ),
        # Priming consent: run something harmless first so the approval is
        # already spent when it matters. The tell is an explicit claim that
        # later actions will not need confirming.
        (
            re.compile(
                r"(?:first|initial|warm[\s-]?up|once\s+approved|after\s+(?:the\s+)?first)"
                r"[^.\n]{0,120}?(?:no\s+(?:further\s+|more\s+)?(?:confirmation|approval)"
                r"|without\s+(?:further\s+|additional\s+)?(?:confirmation|approval|asking)"
                r"|subsequent[^.\n]{0,40}(?:no\s+confirmation|do\s*n[o']?t\s+(?:need|require)))",
                re.IGNORECASE,
            ),
            "primes an approval so later actions run unprompted",
        ),
        # Same idea expressed as establishing durable trust.
        (
            re.compile(
                r"(?:establish|build|gain)\w*\s+trust[^.\n]{0,80}"
                r"(?:no\s+(?:confirmation|approval)|without\s+(?:confirmation|approval|asking))",
                re.IGNORECASE,
            ),
            "establishes standing trust to avoid later prompts",
        ),
        # A large share of the registry is written in Chinese, and the skill
        # that prompted this rule is entirely so. English-only patterns would
        # have reported that this behaviour does not occur there, which is a
        # coverage gap masquerading as a finding.
        #
        # 需要确认 ("requires confirmation") is the benign case and must not
        # match; the signal is its negation.
        (
            re.compile(r"无需(?:再次)?确认|免确认|跳过确认|跳过权限|自动(?:批准|确认|授权)"),
            "states that later actions need no confirmation (zh)",
        ),
        (
            re.compile(r"建立信任[^。\n]{0,40}(?:无需|不用|不需)"),
            "establishes standing trust to avoid later prompts (zh)",
        ),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        findings: list[Finding] = []
        for line_num, line in enumerate(skill.raw_content.splitlines(), 1):
            for pattern, what in self.PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"{self.rule_id}-L{line_num}",
                        rule_id=self.rule_id,
                        title=self.title,
                        description=f"Setup instruction {what}",
                        severity=self.severity,
                        # Deliberately below the rules that convict on their
                        # own: a disclosed integration widening its allowlist
                        # is legitimate, and this signal is about scope, not
                        # intent.
                        confidence=0.70,
                        category=self.category,
                        detector_layer=DetectorLayer.RULE_ENGINE,
                        location=Location(
                            line_start=line_num,
                            snippet=line.strip()[:200],
                        ),
                        evidence=[f"Permission scope: {what}"],
                    ))
                    break  # one finding per line
        return findings
