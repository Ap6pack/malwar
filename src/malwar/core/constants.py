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
#
# These rules keep full weight when corroborated by a second, independent rule.
# It is the *uncorroborated single hit* that is unreliable, so a lone match is
# capped below the MALICIOUS line (see FRAGILE_MAX_RISK) instead of convicting
# on one regex. Tighter rules are deliberately absent and stay confident on a
# single hit: PERSIST-001 (cron/systemd), EXFIL-002 (crypto wallets),
# FRAUD-002 (front-running), CRED-001 (real credential formats),
# SUPPLY-001 (known-malicious package names).
HIGH_FP_RULES: frozenset[str] = frozenset({
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


def is_fragile_rule_set(rule_ids: set[str]) -> bool:
    """True when a detection rests on a single high-false-positive rule.

    ``rule_ids`` is the set of *distinct* rules that fired (repeat hits from
    the same rule do not corroborate each other -- three `npx -y` lines are
    still just "this doc installs npm packages"). Two different rules firing
    is corroboration and is not fragile.
    """
    return len(rule_ids) == 1 and next(iter(rule_ids)) in HIGH_FP_RULES
