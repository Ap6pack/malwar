# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Centralized audit logger that writes to both structured JSON files and SQLite."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from malwar.audit.events import AuditEvent, AuditEventType

_logger = logging.getLogger("malwar.audit")

# Module-level singleton
_audit_logger: AuditLogger | None = None


class AuditLogger:
    """Records security-relevant events to structured JSON log files and SQLite.

    The logger provides fire-and-forget semantics: failures to persist an
    event are logged but never propagate to the caller.
    """

    def __init__(
        self,
        *,
        log_dir: Path | None = None,
    ) -> None:
        self._log_dir = log_dir
        if self._log_dir is not None:
            self._log_dir.mkdir(parents=True, exist_ok=True)

    async def log(self, event: AuditEvent) -> AuditEvent:
        """Persist an audit event to both the JSON log file and the database.

        Returns the event (with its generated event_id) for convenience.
        """
        # 1. Write to structured JSON log file
        self._write_json_log(event)

        # 2. Persist to SQLite
        await self._persist_to_db(event)

        _logger.info(
            "audit event=%s type=%s actor=%s resource=%s/%s",
            event.event_id,
            event.event_type,
            event.actor,
            event.resource_type,
            event.resource_id,
        )
        return event

    def _write_json_log(self, event: AuditEvent) -> None:
        """Append a single JSON line to the daily audit log file."""
        if self._log_dir is None:
            return
        try:
            today = datetime.now(UTC).strftime("%Y-%m-%d")
            log_file = self._log_dir / f"audit-{today}.jsonl"
            line = json.dumps(event.model_dump(mode="json"), default=str)
            with log_file.open("a") as fh:
                fh.write(line + "\n")
        except Exception:
            _logger.exception("Failed to write JSON audit log")

    async def _persist_to_db(self, event: AuditEvent) -> None:
        """Insert the event into the audit_log table via AuditStore."""
        try:
            from malwar.audit.store import AuditStore
            from malwar.storage.database import get_db

            db = await get_db()
            store = AuditStore(db)
            await store.insert(event)
        except Exception:
            _logger.exception("Failed to persist audit event to database")

    # -----------------------------------------------------------------
    # Convenience methods for common event types
    # -----------------------------------------------------------------

    async def log_scan_started(
        self,
        scan_id: str,
        target: str,
        *,
        actor: str = "cli",
        ip_address: str = "",
        layers: list[str] | None = None,
    ) -> AuditEvent:
        """Log that a scan has been initiated."""
        return await self.log(
            AuditEvent(
                event_type=AuditEventType.SCAN_STARTED,
                actor=actor,
                resource_type="scan",
                resource_id=scan_id,
                action=f"Scan started on {target}",
                details={"target": target, "layers": layers or []},
                ip_address=ip_address,
            )
        )

    async def log_scan_completed(
        self,
        scan_id: str,
        verdict: str,
        risk_score: int,
        finding_count: int,
        *,
        actor: str = "cli",
        ip_address: str = "",
        duration_ms: int | None = None,
    ) -> AuditEvent:
        """Log that a scan has completed."""
        return await self.log(
            AuditEvent(
                event_type=AuditEventType.SCAN_COMPLETED,
                actor=actor,
                resource_type="scan",
                resource_id=scan_id,
                action=f"Scan completed: verdict={verdict}",
                details={
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "finding_count": finding_count,
                    "duration_ms": duration_ms,
                },
                ip_address=ip_address,
            )
        )

    async def log_finding(
        self,
        scan_id: str,
        rule_id: str,
        severity: str,
        *,
        actor: str = "cli",
        ip_address: str = "",
        title: str = "",
    ) -> AuditEvent:
        """Log a detected finding."""
        return await self.log(
            AuditEvent(
                event_type=AuditEventType.FINDING_DETECTED,
                actor=actor,
                resource_type="finding",
                resource_id=f"{scan_id}/{rule_id}",
                action=f"Finding detected: {rule_id} ({severity})",
                details={
                    "scan_id": scan_id,
                    "rule_id": rule_id,
                    "severity": severity,
                    "title": title,
                },
                ip_address=ip_address,
            )
        )

    async def log_api_key_used(
        self,
        api_key: str,
        endpoint: str,
        method: str,
        *,
        ip_address: str = "",
        status_code: int = 0,
    ) -> AuditEvent:
        """Log API key usage (key is hashed for security)."""
        return await self.log(
            AuditEvent(
                event_type=AuditEventType.API_KEY_USED,
                actor=hash_api_key(api_key),
                resource_type="api_endpoint",
                resource_id=endpoint,
                action=f"{method} {endpoint}",
                details={"method": method, "status_code": status_code},
                ip_address=ip_address,
            )
        )

    async def log_signature_change(
        self,
        event_type: AuditEventType,
        sig_id: str,
        *,
        actor: str = "cli",
        ip_address: str = "",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a signature create/update/delete event."""
        action_map = {
            AuditEventType.SIGNATURE_CREATED: "Signature created",
            AuditEventType.SIGNATURE_UPDATED: "Signature updated",
            AuditEventType.SIGNATURE_DELETED: "Signature deleted",
        }
        return await self.log(
            AuditEvent(
                event_type=event_type,
                actor=actor,
                resource_type="signature",
                resource_id=sig_id,
                action=f"{action_map.get(event_type, 'Signature changed')}: {sig_id}",
                details=details or {},
                ip_address=ip_address,
            )
        )

    async def log_config_change(
        self,
        setting_name: str,
        *,
        actor: str = "cli",
        ip_address: str = "",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Log a configuration change."""
        return await self.log(
            AuditEvent(
                event_type=AuditEventType.CONFIG_CHANGED,
                actor=actor,
                resource_type="config",
                resource_id=setting_name,
                action=f"Configuration changed: {setting_name}",
                details=details or {},
                ip_address=ip_address,
            )
        )

    async def log_api_request(
        self,
        method: str,
        path: str,
        status_code: int,
        *,
        actor: str = "anonymous",
        ip_address: str = "",
        duration_ms: float = 0,
    ) -> AuditEvent:
        """Log an API request."""
        return await self.log(
            AuditEvent(
                event_type=AuditEventType.API_REQUEST,
                actor=actor,
                resource_type="api_endpoint",
                resource_id=path,
                action=f"{method} {path} -> {status_code}",
                details={
                    "method": method,
                    "path": path,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                },
                ip_address=ip_address,
            )
        )


def hash_api_key(api_key: str) -> str:
    """Return a SHA-256 prefix hash of an API key for safe logging."""
    if not api_key or api_key in ("anonymous", "cli"):
        return api_key or "anonymous"
    return f"sha256:{hashlib.sha256(api_key.encode()).hexdigest()[:16]}"


def get_audit_logger() -> AuditLogger:
    """Return the module-level AuditLogger singleton."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def set_audit_logger(logger: AuditLogger) -> None:
    """Replace the module-level AuditLogger singleton (useful for testing)."""
    global _audit_logger
    _audit_logger = logger
