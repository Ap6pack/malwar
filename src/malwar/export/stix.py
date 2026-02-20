# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""STIX 2.1 bundle generation from Malwar threat intelligence data.

Generates valid STIX 2.1 JSON directly without requiring the ``stix2``
Python library.  The output conforms to the OASIS STIX 2.1 specification
(https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# IOC type -> STIX 2.1 cyber-observable pattern mapping
# ---------------------------------------------------------------------------

IOC_PATTERN_MAP: dict[str, str] = {
    "ip": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "sha256": "[file:hashes.'SHA-256' = '{value}']",
    "hash": "[file:hashes.'SHA-256' = '{value}']",
    "email": "[email-addr:value = '{value}']",
    "regex": "[artifact:payload_bin = '{value}']",
}

# Severity -> STIX TLP marking (informational mapping)
_SEVERITY_TLP: dict[str, str] = {
    "critical": "TLP:RED",
    "high": "TLP:AMBER",
    "medium": "TLP:AMBER",
    "low": "TLP:GREEN",
    "info": "TLP:WHITE",
}

# Malwar identity — the tool itself as STIX Identity
_MALWAR_IDENTITY_ID = "identity--malwar-analysis-tool-00001"


def _deterministic_id(stix_type: str, seed: str) -> str:
    """Generate a deterministic STIX ID from a type and seed string.

    Uses UUID-5 with the STIX namespace to produce reproducible IDs
    so the same input data always yields the same STIX bundle.
    """
    namespace = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    return f"{stix_type}--{uuid.uuid5(namespace, seed)}"


def _now_iso() -> str:
    """Return the current UTC time in ISO-8601 format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _ensure_iso(value: str | datetime | None) -> str:
    """Normalise a timestamp to ISO-8601 string."""
    if value is None:
        return _now_iso()
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # Already a string — ensure it ends with Z
    if "T" in value:
        return value
    return f"{value}T00:00:00.000Z"


# ---- Malwar Identity object ------------------------------------------------

def malwar_identity() -> dict[str, Any]:
    """Return the STIX Identity object representing Malwar itself."""
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _MALWAR_IDENTITY_ID,
        "created": "2026-01-01T00:00:00.000Z",
        "modified": "2026-01-01T00:00:00.000Z",
        "name": "Malwar Detection Engine",
        "description": (
            "Automated malware detection engine for agentic skills "
            "(SKILL.md). Produces threat intelligence from scan results, "
            "campaign tracking, and signature databases."
        ),
        "identity_class": "system",
    }


# ---- Campaign conversion ---------------------------------------------------

def campaign_to_stix(campaign: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a Malwar campaign dict to STIX ThreatActor + Campaign objects.

    Returns a list containing one ``threat-actor`` and one ``campaign``
    SDO, plus a ``relationship`` linking them.
    """
    cid = campaign["id"]
    name = campaign["name"]
    first_seen = _ensure_iso(campaign.get("first_seen"))
    last_seen = _ensure_iso(campaign.get("last_seen"))
    description = campaign.get("description", "")
    attributed_to = campaign.get("attributed_to")
    now = _now_iso()

    # Parse IOCs if stored as JSON string
    iocs_raw = campaign.get("iocs", [])
    if isinstance(iocs_raw, str):
        try:
            iocs_raw = json.loads(iocs_raw)
        except (json.JSONDecodeError, TypeError):
            iocs_raw = []

    threat_actor_id = _deterministic_id("threat-actor", cid)
    campaign_stix_id = _deterministic_id("campaign", cid)

    threat_actor: dict[str, Any] = {
        "type": "threat-actor",
        "spec_version": "2.1",
        "id": threat_actor_id,
        "created": first_seen,
        "modified": now,
        "name": attributed_to or name,
        "description": f"Threat actor behind the {name} campaign.",
        "threat_actor_types": ["unknown"],
        "first_seen": first_seen,
        "last_seen": last_seen,
    }

    campaign_obj: dict[str, Any] = {
        "type": "campaign",
        "spec_version": "2.1",
        "id": campaign_stix_id,
        "created": first_seen,
        "modified": now,
        "name": name,
        "description": description or f"Malwar tracked campaign: {name}",
        "first_seen": first_seen,
        "last_seen": last_seen,
    }

    relationship: dict[str, Any] = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _deterministic_id("relationship", f"{threat_actor_id}-{campaign_stix_id}"),
        "created": now,
        "modified": now,
        "relationship_type": "attributed-to",
        "source_ref": campaign_stix_id,
        "target_ref": threat_actor_id,
    }

    return [threat_actor, campaign_obj, relationship]


# ---- Signature conversion ---------------------------------------------------

def _build_stix_pattern(ioc_type: str | None, pattern_value: str) -> str:
    """Build a STIX 2.1 indicator pattern from Malwar IOC type + value."""
    if ioc_type and ioc_type in IOC_PATTERN_MAP:
        return IOC_PATTERN_MAP[ioc_type].format(value=pattern_value)
    # Fallback: wrap as artifact pattern
    return f"[artifact:payload_bin = '{pattern_value}']"


def signature_to_stix_indicator(
    signature: dict[str, Any],
    campaign_stix_id: str | None = None,
) -> list[dict[str, Any]]:
    """Convert a Malwar signature dict to a STIX Indicator + optional Relationship.

    Parameters
    ----------
    signature:
        Row dict from the signatures table.
    campaign_stix_id:
        If the signature is linked to a campaign, the STIX ID of the
        campaign object so a ``relationship`` can be emitted.

    Returns
    -------
    list:
        One ``indicator`` SDO and optionally one ``relationship`` SRO.
    """
    sig_id = signature["id"]
    pattern_value = signature["pattern_value"]
    ioc_type = signature.get("ioc_type")
    severity = signature.get("severity", "medium")
    confidence = signature.get("confidence")
    name = signature.get("name", sig_id)
    description = signature.get("description", "")
    now = _now_iso()

    indicator_id = _deterministic_id("indicator", sig_id)

    pattern = _build_stix_pattern(ioc_type, pattern_value)

    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": name,
        "description": description or f"Malwar signature: {name}",
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": now,
        "labels": [f"severity:{severity}"],
    }

    if confidence is not None:
        # STIX confidence is 0-100
        indicator["confidence"] = (
            int(float(confidence) * 100)
            if float(confidence) <= 1
            else int(float(confidence))
        )

    objects: list[dict[str, Any]] = [indicator]

    if campaign_stix_id:
        rel_id = _deterministic_id(
            "relationship", f"{indicator_id}-{campaign_stix_id}"
        )
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": now,
            "modified": now,
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": campaign_stix_id,
        })

    return objects


# ---- Scan result conversion -------------------------------------------------

def scan_to_stix_malware_analysis(scan: dict[str, Any]) -> dict[str, Any]:
    """Convert a Malwar scan result dict to a STIX MalwareAnalysis SDO."""
    scan_id = scan.get("id", scan.get("scan_id", str(uuid.uuid4())))
    now = _now_iso()

    analysis_id = _deterministic_id("malware-analysis", scan_id)

    result_map: dict[str, str] = {
        "MALICIOUS": "malicious",
        "SUSPICIOUS": "suspicious",
        "CAUTION": "suspicious",
        "CLEAN": "benign",
    }
    verdict = scan.get("verdict", "CLEAN")
    analysis_result = result_map.get(verdict, "unknown")

    return {
        "type": "malware-analysis",
        "spec_version": "2.1",
        "id": analysis_id,
        "created": now,
        "modified": now,
        "product": "Malwar Detection Engine",
        "result": analysis_result,
        "analysis_started": _ensure_iso(scan.get("started_at")),
        "analysis_ended": _ensure_iso(scan.get("completed_at")),
        "submitted": _ensure_iso(scan.get("started_at")),
    }


# ---- Full bundle builder ----------------------------------------------------

def build_stix_bundle(
    campaigns: list[dict[str, Any]] | None = None,
    signatures: list[dict[str, Any]] | None = None,
    scans: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a complete STIX 2.1 Bundle from Malwar data.

    Parameters
    ----------
    campaigns:
        List of campaign row dicts.
    signatures:
        List of signature row dicts.
    scans:
        List of scan row dicts.

    Returns
    -------
    dict:
        A valid STIX 2.1 Bundle (``type: "bundle"``).
    """
    objects: list[dict[str, Any]] = []

    # Always include the Malwar identity
    objects.append(malwar_identity())

    # Build a lookup of campaign_id -> STIX campaign ID
    campaign_stix_ids: dict[str, str] = {}

    for campaign in campaigns or []:
        stix_objects = campaign_to_stix(campaign)
        objects.extend(stix_objects)
        # The campaign SDO is the second object returned
        campaign_stix_ids[campaign["id"]] = stix_objects[1]["id"]

    for signature in signatures or []:
        campaign_id = signature.get("campaign_id")
        campaign_stix_id = campaign_stix_ids.get(campaign_id) if campaign_id else None
        stix_objects = signature_to_stix_indicator(signature, campaign_stix_id)
        objects.extend(stix_objects)

    for scan in scans or []:
        objects.append(scan_to_stix_malware_analysis(scan))

    # Deterministic bundle ID based on content hash
    content_hash = hashlib.sha256(
        json.dumps(objects, sort_keys=True).encode()
    ).hexdigest()[:32]
    bundle_id = f"bundle--{uuid.UUID(content_hash[:32])}"

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
