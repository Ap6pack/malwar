# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Structured logging with sensitive data redaction."""

import logging
import json
import re
import sys
from typing import Any


REDACT_PATTERNS = [
    re.compile(r"(sk-ant-[a-zA-Z0-9\-]{10})[a-zA-Z0-9\-]*"),
    re.compile(r"(sk-[a-zA-Z0-9]{10})[a-zA-Z0-9]*"),
    re.compile(r"(AKIA[A-Z0-9]{4})[A-Z0-9]{12}"),
    re.compile(r"(ghp_[A-Za-z0-9]{4})[A-Za-z0-9_]{32,}"),
    re.compile(r"(Bearer\s+[a-zA-Z0-9\-._~+/]{10})[a-zA-Z0-9\-._~+/]*"),
]


def redact_sensitive(text: str) -> str:
    for pattern in REDACT_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_sensitive(record.getMessage()),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = redact_sensitive(str(record.exc_info[1]))
        return json.dumps(log_entry)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        return redact_sensitive(msg)


def setup_logging(level: str = "INFO", fmt: str = "json") -> None:
    root = logging.getLogger("malwar")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            TextFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
    root.addHandler(handler)
