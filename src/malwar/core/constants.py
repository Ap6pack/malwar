"""Enumerations, severity weights, and threshold constants."""

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class DetectorLayer(StrEnum):
    RULE_ENGINE = "rule_engine"
    URL_CRAWLER = "url_crawler"
    LLM_ANALYZER = "llm_analyzer"
    THREAT_INTEL = "threat_intel"


class ThreatCategory(StrEnum):
    OBFUSCATED_COMMAND = "obfuscated_command"
    SOCIAL_ENGINEERING = "social_engineering"
    PROMPT_INJECTION = "prompt_injection"
    KNOWN_MALWARE = "known_malware"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    SUSPICIOUS_COMMAND = "suspicious_command"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_URL = "malicious_url"
    SUSPICIOUS_DEPENDENCY = "suspicious_dependency"
    TYPOSQUATTING = "typosquatting"
    SECURITY_DISABLEMENT = "security_disablement"
    FINANCIAL_FRAUD = "financial_fraud"
    DETECTION_EVASION = "detection_evasion"


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 0,
}

RISK_THRESHOLD_CRITICAL = 100
RISK_THRESHOLD_HIGH = 75
RISK_THRESHOLD_MEDIUM = 40
RISK_THRESHOLD_LOW = 15

# Rules empirically shown to over-flag legitimate content when they are the
# *only* thing that fired. Each was confirmed by running the rule against real
# benign inputs, e.g.:
#   * CMD-001    the official `curl ... | sh` installers (rustup, Docker, ...)
#   * ENV-001    ordinary prose ("the key you need to set", "run env")
#   * PERSIST-002 self-referential SKILL.md/CLAUDE.md ops, including reads
#   * MULTI-001  "applies the patch without showing the full diff"
#   * CMD-002    `npx -y <pkg>`, the standard way to run MCP servers
#   * CRED-002   onboarding prose ("enter your API key", "paste your token")
#   * EXFIL-001  skill tooling reading ~/.claude/ or .cursor/
#   * EXFIL-003  `curl -X POST -d "$(cat file)"`, a normal API upload
#   * PI-001     security/detection skills that quote injection phrases
#   * HIJACK-001 roleplay/persona skills ("you are now...", "your new role is")
#   * PERSIST-001 a plain `(crontab -l; echo ...) | crontab -` daily job, and
#                 `systemctl enable`, which are how you install *any* scheduled
#                 task or service. Previously excluded here on the reasoning
#                 that cron/systemd are tight signals; a benign daily-report
#                 skill scores 87 on it alone, i.e. MALICIOUS with no
#                 corroboration, and it is the single largest source of
#                 uncorroborated convictions in the registry (482 of 2,076).
#
# These rules keep full weight when corroborated by a second, independent rule.
# It is the *uncorroborated single hit* that is unreliable, so a lone match is
# capped below the MALICIOUS line (see FRAGILE_MAX_RISK) instead of convicting
# on one regex. Tighter rules stay confident on a single hit: EXFIL-002 (crypto
# wallets), FRAUD-002 (front-running), CRED-001 (real credential formats),
# SUPPLY-001 (known-malicious package names).
HIGH_FP_RULES: frozenset[str] = frozenset({
    "MALWAR-PERSIST-001",
    "MALWAR-CMD-001",
    "MALWAR-CMD-002",
    "MALWAR-ENV-001",
    "MALWAR-PERSIST-002",
    "MALWAR-MULTI-001",
    "MALWAR-CRED-002",
    "MALWAR-EXFIL-001",
    "MALWAR-EXFIL-003",
    "MALWAR-PI-001",
    "MALWAR-HIJACK-001",
})

# Risk ceiling applied to an uncorroborated single high-FP-rule detection.
# Sits in the SUSPICIOUS band, just under RISK_THRESHOLD_HIGH, so the skill is
# still surfaced as a concern but is never published as a confident conviction.
FRAGILE_MAX_RISK = 74


# Rules that observe the same underlying behaviour. Two rules from one family
# firing is that behaviour detected twice, not two independent opinions about
# it: a skill that both appends to ~/.bashrc and enables a systemd unit is
# doing one thing (installing itself to run later), and counting it as
# corroboration converts a single fragile signal into a confident conviction.
# 76 skills currently sit at MALICIOUS on PERSIST-001 + PERSIST-002 alone.
RULE_FAMILIES: dict[str, str] = {
    "MALWAR-PERSIST-001": "persistence",
    "MALWAR-PERSIST-002": "persistence",
    "MALWAR-CMD-001": "command-execution",
    "MALWAR-CMD-002": "command-execution",
    "MALWAR-EXFIL-001": "exfiltration",
    "MALWAR-EXFIL-002": "exfiltration",
    "MALWAR-EXFIL-003": "exfiltration",
    "MALWAR-CRED-001": "credential-access",
    "MALWAR-CRED-002": "credential-access",
    "MALWAR-FRAUD-001": "fraud",
    "MALWAR-FRAUD-002": "fraud",
    "MALWAR-PI-001": "prompt-injection",
    "MALWAR-PI-002": "prompt-injection",
    "MALWAR-PI-003": "prompt-injection",
    "MALWAR-OBF-001": "obfuscation",
    "MALWAR-OBF-003": "obfuscation",
    "MALWAR-OBF-004": "obfuscation",
}


def is_fragile_rule_set(rule_ids: set[str]) -> bool:
    """True when a detection has no independent corroboration behind it.

    ``rule_ids`` is the set of *distinct* rules that fired (repeat hits from
    the same rule do not corroborate each other -- three `npx -y` lines are
    still just "this doc installs npm packages").

    Fragile in two cases:

    * A lone high-false-positive rule. One regex is not a conviction.
    * Several high-false-positive rules that all belong to one family.
      Corroboration is supposed to mean independent signals agreeing; rules
      from the same family are the same signal counted more than once, which
      is how a benign crontab entry reaches a confident verdict.

    The second case requires *every* rule in the set to be FP-prone. A family
    of tight rules agreeing is still conclusive: a base64 blob piped to bash
    trips two obfuscation rules and is one behaviour seen twice, but that
    behaviour has essentially no benign use in a skill file, so downgrading it
    would trade a false positive for a false negative.

    Rules outside :data:`RULE_FAMILIES` are treated as their own family, so
    anything unlisted still corroborates normally.
    """
    if not rule_ids:
        return False
    if len(rule_ids) == 1:
        return next(iter(rule_ids)) in HIGH_FP_RULES
    if not rule_ids <= HIGH_FP_RULES:
        return False
    families = {RULE_FAMILIES.get(rid, rid) for rid in rule_ids}
    return len(families) == 1
