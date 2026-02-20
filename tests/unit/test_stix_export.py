# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for STIX 2.1 bundle generation and TAXII response formatting."""

from __future__ import annotations

import json

from malwar.export.stix import (
    IOC_PATTERN_MAP,
    build_stix_bundle,
    campaign_to_stix,
    malwar_identity,
    scan_to_stix_malware_analysis,
    signature_to_stix_indicator,
)
from malwar.export.taxii import (
    format_taxii_collections,
    format_taxii_discovery,
    format_taxii_objects,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CAMPAIGN = {
    "id": "campaign-test-001",
    "name": "TestCampaign",
    "description": "A test malware campaign.",
    "first_seen": "2025-06-01T00:00:00.000Z",
    "last_seen": "2025-12-15T00:00:00.000Z",
    "attributed_to": "APT-Test",
    "iocs": json.dumps(["198.51.100.42", "evil.example.com"]),
    "status": "active",
    "total_skills_affected": 5,
}

SAMPLE_SIGNATURE_IP = {
    "id": "sig-test-ip-001",
    "name": "Known C2 IP",
    "description": "IP address of known C2 server.",
    "severity": "high",
    "category": "known_malware",
    "pattern_type": "ioc",
    "pattern_value": "198.51.100.42",
    "ioc_type": "ip",
    "campaign_id": "campaign-test-001",
    "source": "test",
    "enabled": 1,
}

SAMPLE_SIGNATURE_DOMAIN = {
    "id": "sig-test-domain-001",
    "name": "Malicious Domain",
    "description": "Known phishing domain.",
    "severity": "medium",
    "category": "malicious_url",
    "pattern_type": "ioc",
    "pattern_value": "evil.example.com",
    "ioc_type": "domain",
    "campaign_id": None,
    "source": "test",
    "enabled": 1,
}

SAMPLE_SIGNATURE_URL = {
    "id": "sig-test-url-001",
    "name": "Malicious URL",
    "description": "Known payload delivery URL.",
    "severity": "critical",
    "category": "malicious_url",
    "pattern_type": "ioc",
    "pattern_value": "https://evil.example.com/payload.exe",
    "ioc_type": "url",
    "campaign_id": None,
    "source": "test",
    "enabled": 1,
}

SAMPLE_SIGNATURE_SHA256 = {
    "id": "sig-test-sha256-001",
    "name": "Malicious Hash",
    "description": "SHA-256 of known malware.",
    "severity": "critical",
    "category": "known_malware",
    "pattern_type": "ioc",
    "pattern_value": "a" * 64,
    "ioc_type": "sha256",
    "campaign_id": None,
    "source": "test",
    "enabled": 1,
}

SAMPLE_SIGNATURE_REGEX = {
    "id": "sig-test-regex-001",
    "name": "Obfuscated Curl",
    "description": "Regex for obfuscated curl usage.",
    "severity": "medium",
    "category": "obfuscated_command",
    "pattern_type": "regex",
    "pattern_value": r"curl.*evil\.com",
    "ioc_type": "regex",
    "campaign_id": None,
    "source": "test",
    "enabled": 1,
}

SAMPLE_SCAN = {
    "id": "scan-test-001",
    "target": "/tmp/test-skill.md",
    "status": "completed",
    "risk_score": 85,
    "overall_severity": "critical",
    "verdict": "MALICIOUS",
    "started_at": "2025-12-01T10:00:00.000Z",
    "completed_at": "2025-12-01T10:00:05.000Z",
    "duration_ms": 5000,
}


# ===========================================================================
# STIX Bundle structure tests
# ===========================================================================


class TestStixBundleStructure:
    """Verify the overall STIX 2.1 bundle is well-formed."""

    def test_bundle_has_required_fields(self) -> None:
        bundle = build_stix_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert "objects" in bundle
        assert isinstance(bundle["objects"], list)

    def test_bundle_is_json_serializable(self) -> None:
        bundle = build_stix_bundle(
            campaigns=[SAMPLE_CAMPAIGN],
            signatures=[SAMPLE_SIGNATURE_IP],
            scans=[SAMPLE_SCAN],
        )
        text = json.dumps(bundle)
        parsed = json.loads(text)
        assert parsed["type"] == "bundle"

    def test_bundle_always_includes_identity(self) -> None:
        bundle = build_stix_bundle()
        types = [obj["type"] for obj in bundle["objects"]]
        assert "identity" in types

    def test_bundle_id_is_deterministic(self) -> None:
        """Same input produces the same bundle ID."""
        b1 = build_stix_bundle(campaigns=[SAMPLE_CAMPAIGN])
        b2 = build_stix_bundle(campaigns=[SAMPLE_CAMPAIGN])
        assert b1["id"] == b2["id"]

    def test_all_objects_have_spec_version(self) -> None:
        bundle = build_stix_bundle(
            campaigns=[SAMPLE_CAMPAIGN],
            signatures=[SAMPLE_SIGNATURE_IP],
            scans=[SAMPLE_SCAN],
        )
        for obj in bundle["objects"]:
            assert obj.get("spec_version") == "2.1", (
                f"Object {obj['id']} missing spec_version"
            )


# ===========================================================================
# Campaign -> ThreatActor + Campaign
# ===========================================================================


class TestCampaignConversion:
    """Test campaign -> STIX ThreatActor + Campaign conversion."""

    def test_returns_three_objects(self) -> None:
        result = campaign_to_stix(SAMPLE_CAMPAIGN)
        assert len(result) == 3

    def test_threat_actor_object(self) -> None:
        result = campaign_to_stix(SAMPLE_CAMPAIGN)
        threat_actor = result[0]
        assert threat_actor["type"] == "threat-actor"
        assert threat_actor["spec_version"] == "2.1"
        assert threat_actor["name"] == "APT-Test"
        assert threat_actor["id"].startswith("threat-actor--")

    def test_campaign_object(self) -> None:
        result = campaign_to_stix(SAMPLE_CAMPAIGN)
        campaign_obj = result[1]
        assert campaign_obj["type"] == "campaign"
        assert campaign_obj["spec_version"] == "2.1"
        assert campaign_obj["name"] == "TestCampaign"
        assert campaign_obj["id"].startswith("campaign--")
        assert campaign_obj["first_seen"] == "2025-06-01T00:00:00.000Z"
        assert campaign_obj["last_seen"] == "2025-12-15T00:00:00.000Z"

    def test_relationship_object(self) -> None:
        result = campaign_to_stix(SAMPLE_CAMPAIGN)
        rel = result[2]
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "attributed-to"
        assert rel["source_ref"] == result[1]["id"]  # campaign
        assert rel["target_ref"] == result[0]["id"]  # threat actor

    def test_campaign_without_attributed_to(self) -> None:
        campaign = {**SAMPLE_CAMPAIGN, "attributed_to": None}
        result = campaign_to_stix(campaign)
        # threat actor name falls back to campaign name
        assert result[0]["name"] == "TestCampaign"

    def test_campaign_with_iocs_as_json_string(self) -> None:
        """IOCs stored as JSON string should be parsed without error."""
        campaign = {**SAMPLE_CAMPAIGN, "iocs": '["1.2.3.4"]'}
        result = campaign_to_stix(campaign)
        assert len(result) == 3

    def test_campaign_deterministic_ids(self) -> None:
        r1 = campaign_to_stix(SAMPLE_CAMPAIGN)
        r2 = campaign_to_stix(SAMPLE_CAMPAIGN)
        assert r1[0]["id"] == r2[0]["id"]
        assert r1[1]["id"] == r2[1]["id"]


# ===========================================================================
# Signature -> Indicator
# ===========================================================================


class TestSignatureConversion:
    """Test signature -> STIX Indicator conversion with proper patterns."""

    def test_ip_indicator(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_IP)
        indicator = result[0]
        assert indicator["type"] == "indicator"
        assert indicator["pattern"] == "[ipv4-addr:value = '198.51.100.42']"
        assert indicator["pattern_type"] == "stix"

    def test_domain_indicator(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_DOMAIN)
        indicator = result[0]
        assert indicator["pattern"] == "[domain-name:value = 'evil.example.com']"

    def test_url_indicator(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_URL)
        indicator = result[0]
        assert indicator["pattern"] == "[url:value = 'https://evil.example.com/payload.exe']"

    def test_sha256_indicator(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_SHA256)
        indicator = result[0]
        expected = f"[file:hashes.'SHA-256' = '{'a' * 64}']"
        assert indicator["pattern"] == expected

    def test_regex_indicator(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_REGEX)
        indicator = result[0]
        assert "artifact:payload_bin" in indicator["pattern"]

    def test_indicator_has_required_fields(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_IP)
        indicator = result[0]
        assert indicator["spec_version"] == "2.1"
        assert indicator["id"].startswith("indicator--")
        assert "name" in indicator
        assert "valid_from" in indicator
        assert "indicator_types" in indicator

    def test_indicator_with_campaign_relationship(self) -> None:
        campaign_stix_id = "campaign--test-123"
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_IP, campaign_stix_id)
        assert len(result) == 2
        rel = result[1]
        assert rel["type"] == "relationship"
        assert rel["relationship_type"] == "indicates"
        assert rel["source_ref"] == result[0]["id"]
        assert rel["target_ref"] == campaign_stix_id

    def test_indicator_without_campaign(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_DOMAIN)
        assert len(result) == 1  # no relationship

    def test_indicator_severity_label(self) -> None:
        result = signature_to_stix_indicator(SAMPLE_SIGNATURE_IP)
        indicator = result[0]
        assert "severity:high" in indicator["labels"]

    def test_indicator_with_confidence(self) -> None:
        sig = {**SAMPLE_SIGNATURE_IP, "confidence": 0.95}
        result = signature_to_stix_indicator(sig)
        assert result[0]["confidence"] == 95

    def test_indicator_unknown_ioc_type_falls_back(self) -> None:
        sig = {**SAMPLE_SIGNATURE_IP, "ioc_type": "unknown_type"}
        result = signature_to_stix_indicator(sig)
        assert "artifact:payload_bin" in result[0]["pattern"]


# ===========================================================================
# IOC type mapping
# ===========================================================================


class TestIocTypeMapping:
    """Verify the IOC type -> STIX pattern mapping table is correct."""

    def test_ip_mapping(self) -> None:
        assert "ip" in IOC_PATTERN_MAP
        assert "ipv4-addr" in IOC_PATTERN_MAP["ip"]

    def test_domain_mapping(self) -> None:
        assert "domain" in IOC_PATTERN_MAP
        assert "domain-name" in IOC_PATTERN_MAP["domain"]

    def test_url_mapping(self) -> None:
        assert "url" in IOC_PATTERN_MAP
        assert "url:value" in IOC_PATTERN_MAP["url"]

    def test_sha256_mapping(self) -> None:
        assert "sha256" in IOC_PATTERN_MAP
        assert "SHA-256" in IOC_PATTERN_MAP["sha256"]

    def test_regex_mapping(self) -> None:
        assert "regex" in IOC_PATTERN_MAP


# ===========================================================================
# Scan -> MalwareAnalysis
# ===========================================================================


class TestScanConversion:
    """Test scan result -> STIX MalwareAnalysis conversion."""

    def test_malware_analysis_structure(self) -> None:
        result = scan_to_stix_malware_analysis(SAMPLE_SCAN)
        assert result["type"] == "malware-analysis"
        assert result["spec_version"] == "2.1"
        assert result["id"].startswith("malware-analysis--")
        assert result["product"] == "Malwar Detection Engine"

    def test_malicious_verdict_maps_correctly(self) -> None:
        result = scan_to_stix_malware_analysis(SAMPLE_SCAN)
        assert result["result"] == "malicious"

    def test_clean_verdict_maps_correctly(self) -> None:
        scan = {**SAMPLE_SCAN, "verdict": "CLEAN"}
        result = scan_to_stix_malware_analysis(scan)
        assert result["result"] == "benign"

    def test_suspicious_verdict_maps_correctly(self) -> None:
        scan = {**SAMPLE_SCAN, "verdict": "SUSPICIOUS"}
        result = scan_to_stix_malware_analysis(scan)
        assert result["result"] == "suspicious"

    def test_caution_verdict_maps_to_suspicious(self) -> None:
        scan = {**SAMPLE_SCAN, "verdict": "CAUTION"}
        result = scan_to_stix_malware_analysis(scan)
        assert result["result"] == "suspicious"


# ===========================================================================
# Identity
# ===========================================================================


class TestMalwarIdentity:
    """Test the Malwar identity STIX object."""

    def test_identity_structure(self) -> None:
        identity = malwar_identity()
        assert identity["type"] == "identity"
        assert identity["spec_version"] == "2.1"
        assert identity["identity_class"] == "system"
        assert "Malwar" in identity["name"]


# ===========================================================================
# Full bundle integration
# ===========================================================================


class TestFullBundle:
    """Test building a complete bundle with all data types."""

    def test_bundle_with_all_data(self) -> None:
        bundle = build_stix_bundle(
            campaigns=[SAMPLE_CAMPAIGN],
            signatures=[SAMPLE_SIGNATURE_IP, SAMPLE_SIGNATURE_DOMAIN],
            scans=[SAMPLE_SCAN],
        )
        types = [obj["type"] for obj in bundle["objects"]]
        assert "identity" in types
        assert "threat-actor" in types
        assert "campaign" in types
        assert "indicator" in types
        assert "malware-analysis" in types
        assert "relationship" in types

    def test_campaign_indicator_relationship_wired(self) -> None:
        """Signature linked to campaign should produce an 'indicates' relationship."""
        bundle = build_stix_bundle(
            campaigns=[SAMPLE_CAMPAIGN],
            signatures=[SAMPLE_SIGNATURE_IP],
        )
        rels = [
            obj for obj in bundle["objects"]
            if obj["type"] == "relationship" and obj["relationship_type"] == "indicates"
        ]
        assert len(rels) == 1
        # The indicator should point to the campaign
        indicator_ids = [
            obj["id"] for obj in bundle["objects"] if obj["type"] == "indicator"
        ]
        campaign_ids = [
            obj["id"] for obj in bundle["objects"] if obj["type"] == "campaign"
        ]
        assert rels[0]["source_ref"] in indicator_ids
        assert rels[0]["target_ref"] in campaign_ids


# ===========================================================================
# Empty data handling
# ===========================================================================


class TestEmptyData:
    """Verify graceful handling of empty / None data."""

    def test_empty_bundle(self) -> None:
        bundle = build_stix_bundle()
        assert bundle["type"] == "bundle"
        # Should contain at least the identity
        assert len(bundle["objects"]) == 1
        assert bundle["objects"][0]["type"] == "identity"

    def test_none_campaigns(self) -> None:
        bundle = build_stix_bundle(campaigns=None)
        assert bundle["type"] == "bundle"

    def test_none_signatures(self) -> None:
        bundle = build_stix_bundle(signatures=None)
        assert bundle["type"] == "bundle"

    def test_none_scans(self) -> None:
        bundle = build_stix_bundle(scans=None)
        assert bundle["type"] == "bundle"

    def test_empty_lists(self) -> None:
        bundle = build_stix_bundle(campaigns=[], signatures=[], scans=[])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1  # just identity


# ===========================================================================
# TAXII response formatting
# ===========================================================================


class TestTaxiiDiscovery:
    """Test TAXII discovery response formatting."""

    def test_discovery_structure(self) -> None:
        result = format_taxii_discovery()
        assert "title" in result
        assert "api_roots" in result
        assert isinstance(result["api_roots"], list)
        assert len(result["api_roots"]) >= 1

    def test_discovery_default_values(self) -> None:
        result = format_taxii_discovery()
        assert result["default"] == "/api/v1/export/taxii"

    def test_discovery_custom_values(self) -> None:
        result = format_taxii_discovery(
            title="Custom",
            api_root_url="/custom/taxii",
        )
        assert result["title"] == "Custom"
        assert result["default"] == "/custom/taxii"


class TestTaxiiCollections:
    """Test TAXII collections response formatting."""

    def test_collections_structure(self) -> None:
        result = format_taxii_collections()
        assert "collections" in result
        assert isinstance(result["collections"], list)
        assert len(result["collections"]) >= 1

    def test_collection_has_required_fields(self) -> None:
        result = format_taxii_collections()
        coll = result["collections"][0]
        assert "id" in coll
        assert "title" in coll
        assert coll["can_read"] is True
        assert coll["can_write"] is False

    def test_collection_default_id(self) -> None:
        result = format_taxii_collections()
        assert result["collections"][0]["id"] == "malwar-threat-intel-001"


class TestTaxiiObjects:
    """Test TAXII objects envelope formatting."""

    def test_envelope_structure(self) -> None:
        bundle = build_stix_bundle()
        result = format_taxii_objects(bundle)
        assert "more" in result
        assert "objects" in result
        assert isinstance(result["objects"], list)

    def test_envelope_contains_stix_objects(self) -> None:
        bundle = build_stix_bundle(campaigns=[SAMPLE_CAMPAIGN])
        result = format_taxii_objects(bundle)
        types = [obj["type"] for obj in result["objects"]]
        assert "identity" in types
        assert "threat-actor" in types

    def test_envelope_more_false_by_default(self) -> None:
        bundle = build_stix_bundle()
        result = format_taxii_objects(bundle)
        assert result["more"] is False

    def test_envelope_with_pagination(self) -> None:
        bundle = build_stix_bundle()
        result = format_taxii_objects(bundle, more=True, next_id="abc123")
        assert result["more"] is True
        assert result["next"] == "abc123"

    def test_empty_bundle_envelope(self) -> None:
        bundle = {"type": "bundle", "id": "bundle--test", "objects": []}
        result = format_taxii_objects(bundle)
        assert result["objects"] == []
        assert result["more"] is False
