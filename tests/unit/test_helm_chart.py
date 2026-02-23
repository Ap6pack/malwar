# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for validating the Helm chart structure and YAML correctness."""

from __future__ import annotations

from pathlib import Path

import yaml

HELM_DIR = Path(__file__).resolve().parent.parent.parent / "deploy" / "helm" / "malwar"
TEMPLATES_DIR = HELM_DIR / "templates"


# ---------------------------------------------------------------------------
# Chart.yaml
# ---------------------------------------------------------------------------


class TestChartYaml:
    """Validate Chart.yaml metadata."""

    def setup_method(self) -> None:
        self.chart = yaml.safe_load((HELM_DIR / "Chart.yaml").read_text())

    def test_chart_file_exists(self) -> None:
        assert (HELM_DIR / "Chart.yaml").is_file()

    def test_chart_api_version(self) -> None:
        assert self.chart["apiVersion"] == "v2"

    def test_chart_name(self) -> None:
        assert self.chart["name"] == "malwar"

    def test_chart_version(self) -> None:
        assert self.chart["version"] == "0.3.0"

    def test_chart_app_version(self) -> None:
        assert self.chart["appVersion"] == "0.3.0"

    def test_chart_type(self) -> None:
        assert self.chart["type"] == "application"

    def test_chart_description(self) -> None:
        assert "malwar" in self.chart["description"].lower()


# ---------------------------------------------------------------------------
# values.yaml
# ---------------------------------------------------------------------------


class TestValuesYaml:
    """Validate values.yaml has all required keys with sensible defaults."""

    def setup_method(self) -> None:
        self.values = yaml.safe_load((HELM_DIR / "values.yaml").read_text())

    def test_values_file_exists(self) -> None:
        assert (HELM_DIR / "values.yaml").is_file()

    def test_replica_count(self) -> None:
        assert self.values["replicaCount"] == 1

    def test_image_repository(self) -> None:
        assert self.values["image"]["repository"] == "ghcr.io/ap6pack/malwar"

    def test_image_tag(self) -> None:
        assert self.values["image"]["tag"] == "latest"

    def test_image_pull_policy(self) -> None:
        assert self.values["image"]["pullPolicy"] == "IfNotPresent"

    def test_service_type(self) -> None:
        assert self.values["service"]["type"] == "ClusterIP"

    def test_service_port(self) -> None:
        assert self.values["service"]["port"] == 8000

    def test_ingress_disabled(self) -> None:
        assert self.values["ingress"]["enabled"] is False

    def test_resources_requests(self) -> None:
        requests = self.values["resources"]["requests"]
        assert requests["cpu"] == "100m"
        assert requests["memory"] == "256Mi"

    def test_resources_limits(self) -> None:
        limits = self.values["resources"]["limits"]
        assert limits["cpu"] == "500m"
        assert limits["memory"] == "512Mi"

    def test_persistence_enabled(self) -> None:
        assert self.values["persistence"]["enabled"] is True

    def test_persistence_size(self) -> None:
        assert self.values["persistence"]["size"] == "1Gi"

    def test_persistence_storage_class(self) -> None:
        assert self.values["persistence"]["storageClass"] == ""

    def test_autoscaling_disabled(self) -> None:
        assert self.values["autoscaling"]["enabled"] is False

    def test_autoscaling_replicas(self) -> None:
        assert self.values["autoscaling"]["minReplicas"] == 1
        assert self.values["autoscaling"]["maxReplicas"] == 5

    def test_malwar_api_keys(self) -> None:
        assert self.values["malwar"]["apiKeys"] == []

    def test_malwar_log_level(self) -> None:
        assert self.values["malwar"]["logLevel"] == "INFO"

    def test_malwar_auto_migrate(self) -> None:
        assert self.values["malwar"]["autoMigrate"] is True

    def test_malwar_anthropic_api_key(self) -> None:
        assert self.values["malwar"]["anthropicApiKey"] == ""

    def test_malwar_webhook_urls(self) -> None:
        assert self.values["malwar"]["webhookUrls"] == []

    def test_malwar_webhook_secret(self) -> None:
        assert self.values["malwar"]["webhookSecret"] == ""

    def test_security_context_non_root(self) -> None:
        sc = self.values["securityContext"]
        assert sc["runAsNonRoot"] is True
        assert sc["runAsUser"] == 1000
        assert sc["readOnlyRootFilesystem"] is True
        assert sc["allowPrivilegeEscalation"] is False


# ---------------------------------------------------------------------------
# Template files existence and YAML validity
# ---------------------------------------------------------------------------


EXPECTED_TEMPLATES = [
    "deployment.yaml",
    "service.yaml",
    "ingress.yaml",
    "configmap.yaml",
    "secret.yaml",
    "hpa.yaml",
    "pvc.yaml",
    "serviceaccount.yaml",
    "NOTES.txt",
]


class TestTemplateFiles:
    """Validate that all expected template files exist."""

    def test_templates_directory_exists(self) -> None:
        assert TEMPLATES_DIR.is_dir()

    def test_helpers_tpl_exists(self) -> None:
        assert (TEMPLATES_DIR / "_helpers.tpl").is_file()

    def test_all_templates_exist(self) -> None:
        for template in EXPECTED_TEMPLATES:
            path = TEMPLATES_DIR / template
            assert path.is_file(), f"Missing template: {template}"

    def test_test_connection_exists(self) -> None:
        assert (TEMPLATES_DIR / "tests" / "test-connection.yaml").is_file()

    def test_helmignore_exists(self) -> None:
        assert (HELM_DIR / ".helmignore").is_file()


class TestTemplateYamlValidity:
    """Validate that YAML template files are syntactically plausible.

    Since templates contain Go template directives ({{ ... }}), they are not
    valid YAML on their own. We check that the raw content contains expected
    Kubernetes resource markers.
    """

    def test_deployment_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "kind: Deployment" in content

    def test_deployment_has_health_probes(self) -> None:
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "/api/v1/health" in content
        assert "/api/v1/ready" in content
        assert "livenessProbe" in content
        assert "readinessProbe" in content

    def test_deployment_has_security_context(self) -> None:
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "securityContext" in content

    def test_deployment_mounts_pvc(self) -> None:
        content = (TEMPLATES_DIR / "deployment.yaml").read_text()
        assert "volumeMounts" in content
        assert "/data" in content

    def test_service_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "service.yaml").read_text()
        assert "kind: Service" in content

    def test_ingress_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "ingress.yaml").read_text()
        assert "kind: Ingress" in content

    def test_configmap_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "configmap.yaml").read_text()
        assert "kind: ConfigMap" in content
        assert "MALWAR_LOG_LEVEL" in content
        assert "MALWAR_AUTO_MIGRATE" in content

    def test_secret_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "secret.yaml").read_text()
        assert "kind: Secret" in content
        assert "MALWAR_API_KEYS" in content
        assert "MALWAR_ANTHROPIC_API_KEY" in content

    def test_hpa_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "hpa.yaml").read_text()
        assert "kind: HorizontalPodAutoscaler" in content

    def test_pvc_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "pvc.yaml").read_text()
        assert "kind: PersistentVolumeClaim" in content

    def test_serviceaccount_has_kind(self) -> None:
        content = (TEMPLATES_DIR / "serviceaccount.yaml").read_text()
        assert "kind: ServiceAccount" in content


# ---------------------------------------------------------------------------
# Non-template YAML files parse correctly
# ---------------------------------------------------------------------------


class TestYamlParsing:
    """Ensure non-template YAML files parse without errors."""

    def test_chart_yaml_parses(self) -> None:
        data = yaml.safe_load((HELM_DIR / "Chart.yaml").read_text())
        assert isinstance(data, dict)

    def test_values_yaml_parses(self) -> None:
        data = yaml.safe_load((HELM_DIR / "values.yaml").read_text())
        assert isinstance(data, dict)

    def test_configmap_contains_expected_keys(self) -> None:
        content = (TEMPLATES_DIR / "configmap.yaml").read_text()
        assert "MALWAR_DB_PATH" in content

    def test_notes_txt_not_empty(self) -> None:
        content = (TEMPLATES_DIR / "NOTES.txt").read_text()
        assert len(content) > 0
        assert "port-forward" in content
