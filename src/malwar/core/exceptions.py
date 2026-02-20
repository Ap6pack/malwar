# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Custom exception hierarchy for malwar."""


class MalwarError(Exception):
    """Base exception for all malwar errors."""


class ConfigurationError(MalwarError):
    """Invalid or missing configuration."""


class ParseError(MalwarError):
    """Failed to parse a SKILL.md file."""


class ScanError(MalwarError):
    """Error during scan execution."""


class DetectorError(MalwarError):
    """Error within a detection layer."""


class StorageError(MalwarError):
    """Database or storage operation failed."""


class FetchError(MalwarError):
    """Failed to fetch a URL."""


class LLMError(MalwarError):
    """Error communicating with the LLM API."""


class AuthenticationError(MalwarError):
    """API authentication failure."""
