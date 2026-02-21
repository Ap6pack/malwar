# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Feature extraction from SkillContent for ML-based risk scoring."""

from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urlparse

from malwar.models.skill import SkillContent

# Patterns for detecting suspicious constructs
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}")
_COMMAND_PATTERNS = re.compile(
    r"\b(?:curl|wget|bash|sh|eval|exec|base64|chmod\s+\+x|sudo|"
    r"crontab|systemctl|launchctl|nc\b|ncat|python[23]?\s+-c|"
    r"perl\s+-e|ruby\s+-e|rm\s+-rf|dd\s+if=|mkfifo|/dev/tcp)\b",
    re.IGNORECASE,
)
_ENV_VAR_RE = re.compile(
    r"\$(?:(?:AWS_|OPENAI_|ANTHROPIC_|GITHUB_|STRIPE_|POLYMARKET_)"
    r"[A-Z_]+|[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*)",
)
_PIPE_BASH_RE = re.compile(r"\|\s*(?:bash|sh)\b")
_PROMPT_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?(?:previous\s+)?instructions|"
    r"developer\s+mode|unrestricted\s+mode|"
    r"you\s+are\s+now|forget\s+(?:all\s+)?your|"
    r"disregard\s+your|switch\s+to\s+admin|"
    r"safety\s+(?:checks?\s+)?(?:are\s+)?(?:lifted|disabled)|"
    r"<system>|</system>)",
    re.IGNORECASE,
)
_HIDDEN_TEXT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_EXFIL_RE = re.compile(
    r"(?:curl\s+-[Xd].*?POST|curl.*?-d\s+@-|"
    r"env\s*\|.*?curl|cat\s+.*?\|\s*(?:curl|base64)|"
    r"\bexfil|\bdata.*?collect)",
    re.IGNORECASE,
)

# Well-known legitimate domains
_TRUSTED_DOMAINS = frozenset({
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "pypi.org",
    "npmjs.com",
    "www.npmjs.com",
    "docs.python.org",
    "developer.mozilla.org",
    "stackoverflow.com",
    "api.search.brave.com",
    "prettier.io",
    "numpy.org",
    "realpython.com",
    "peps.python.org",
})

# Feature names in fixed order (for model compatibility)
FEATURE_NAMES: list[str] = [
    "line_count",
    "file_size_bytes",
    "code_block_count",
    "code_block_ratio",
    "url_count",
    "external_url_ratio",
    "unique_domain_count",
    "untrusted_domain_ratio",
    "encoded_content_ratio",
    "command_pattern_density",
    "env_var_reference_count",
    "pipe_to_bash_count",
    "prompt_injection_score",
    "content_entropy",
    "section_count",
    "metadata_completeness",
    "hidden_content_ratio",
    "exfiltration_pattern_count",
    "avg_code_block_length",
    "hex_escape_density",
]


def _shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of the given text in bits per character."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _extract_domains(urls: list[str]) -> list[str]:
    """Extract unique domain names from a list of URLs."""
    domains: list[str] = []
    seen: set[str] = set()
    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            domain = domain.lower()
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
        except Exception:
            pass
    return domains


class FeatureExtractor:
    """Extracts numerical feature vectors from SkillContent objects."""

    @staticmethod
    def feature_names() -> list[str]:
        """Return the ordered list of feature names."""
        return list(FEATURE_NAMES)

    def extract(self, skill: SkillContent) -> list[float]:
        """Compute a feature vector from a SkillContent object.

        Returns a list of floats in the same order as ``FEATURE_NAMES``.
        """
        raw = skill.raw_content
        body = skill.body_markdown
        lines = raw.split("\n")
        line_count = len(lines)

        # Code block features
        code_block_count = len(skill.code_blocks)
        total_code_chars = sum(len(cb.content) for cb in skill.code_blocks)
        code_block_ratio = total_code_chars / max(len(raw), 1)
        avg_code_block_length = (
            total_code_chars / code_block_count if code_block_count > 0 else 0.0
        )

        # URL features
        url_count = len(skill.urls)
        domains = _extract_domains(skill.urls)
        unique_domain_count = len(domains)
        external_url_ratio = url_count / max(line_count, 1)
        untrusted_count = sum(
            1 for d in domains if d not in _TRUSTED_DOMAINS
        )
        untrusted_domain_ratio = (
            untrusted_count / max(unique_domain_count, 1)
        )

        # Encoded content detection
        base64_matches = _BASE64_RE.findall(raw)
        encoded_chars = sum(len(m) for m in base64_matches)
        encoded_content_ratio = encoded_chars / max(len(raw), 1)

        # Command pattern density
        command_matches = _COMMAND_PATTERNS.findall(raw)
        command_pattern_density = len(command_matches) / max(line_count, 1)

        # Environment variable references
        env_var_reference_count = len(_ENV_VAR_RE.findall(raw))

        # Pipe-to-bash patterns
        pipe_to_bash_count = len(_PIPE_BASH_RE.findall(raw))

        # Prompt injection indicators
        injection_matches = _PROMPT_INJECTION_RE.findall(raw)
        prompt_injection_score = min(len(injection_matches) / 3.0, 1.0)

        # Shannon entropy of the full content
        content_entropy = _shannon_entropy(raw)

        # Section count
        section_count = len(skill.sections)

        # Metadata completeness (0.0 to 1.0)
        meta = skill.metadata
        meta_fields = [
            meta.name,
            meta.description,
            meta.version,
            meta.author,
        ]
        optional_fields = [
            meta.author_url,
            meta.source_url,
            bool(meta.tags),
            bool(meta.tools),
        ]
        required_present = sum(1 for f in meta_fields if f)
        optional_present = sum(1 for f in optional_fields if f)
        metadata_completeness = (
            required_present * 0.15 + optional_present * 0.1
        )
        metadata_completeness = min(metadata_completeness, 1.0)

        # Hidden content (HTML comments)
        hidden_matches = _HIDDEN_TEXT_RE.findall(raw)
        hidden_chars = sum(len(m) for m in hidden_matches)
        hidden_content_ratio = hidden_chars / max(len(raw), 1)

        # Exfiltration patterns
        exfiltration_pattern_count = len(_EXFIL_RE.findall(raw))

        # Hex escape density
        hex_escapes = _HEX_ESCAPE_RE.findall(body)
        hex_escape_density = len(hex_escapes) / max(len(body), 1)

        return [
            float(line_count),
            float(skill.file_size_bytes),
            float(code_block_count),
            code_block_ratio,
            float(url_count),
            external_url_ratio,
            float(unique_domain_count),
            untrusted_domain_ratio,
            encoded_content_ratio,
            command_pattern_density,
            float(env_var_reference_count),
            float(pipe_to_bash_count),
            prompt_injection_score,
            content_entropy,
            float(section_count),
            metadata_completeness,
            hidden_content_ratio,
            float(exfiltration_pattern_count),
            avg_code_block_length,
            hex_escape_density,
        ]

    def extract_dict(self, skill: SkillContent) -> dict[str, float]:
        """Extract features as a named dictionary."""
        values = self.extract(skill)
        return dict(zip(FEATURE_NAMES, values, strict=True))
