# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
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
