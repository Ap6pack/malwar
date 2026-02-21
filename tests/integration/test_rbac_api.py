# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Integration tests for RBAC API endpoints and permission enforcement."""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from malwar.api.app import create_app
from malwar.api.keys import APIKeyManager
from malwar.api.rbac import Role
from malwar.storage.database import close_db, init_db

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "skills"
BENIGN_DIR = FIXTURES_DIR / "benign"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Create a FastAPI app with a temporary database (no env keys)."""
    db_path = tmp_path / "test_rbac.db"
    monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
    # Ensure no env-var keys are set so RBAC DB keys are the sole authority
    monkeypatch.delenv("MALWAR_API_KEYS", raising=False)
    monkeypatch.delenv("MALWAR_API_KEY", raising=False)
    return create_app()


@pytest.fixture
async def db(tmp_path):
    """Initialize and yield a DB connection, then clean up."""
    db_path = tmp_path / "test_rbac.db"
    conn = await init_db(db_path)
    yield conn
    await close_db()


@pytest.fixture
async def admin_key(db) -> str:
    """Create an admin API key and return the raw key string."""
    km = APIKeyManager(db)
    _record, raw_key = await km.create_key("test-admin", Role.ADMIN)
    return raw_key


@pytest.fixture
async def scanner_key(db) -> str:
    """Create a scanner API key and return the raw key string."""
    km = APIKeyManager(db)
    _record, raw_key = await km.create_key("test-scanner", Role.SCANNER)
    return raw_key


@pytest.fixture
async def readonly_key(db) -> str:
    """Create a readonly API key and return the raw key string."""
    km = APIKeyManager(db)
    _record, raw_key = await km.create_key("test-readonly", Role.READONLY)
    return raw_key


@pytest.fixture
async def analyst_key(db) -> str:
    """Create an analyst API key and return the raw key string."""
    km = APIKeyManager(db)
    _record, raw_key = await km.create_key("test-analyst", Role.ANALYST)
    return raw_key


@pytest.fixture
async def client(app, db):
    """Provide an async HTTP client bound to the test app."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Key management endpoints (admin-only)
# ---------------------------------------------------------------------------


class TestKeyManagement:
    """Test POST/GET/DELETE/PUT /api/v1/keys endpoints."""

    async def test_create_key_as_admin(self, client, admin_key) -> None:
        resp = await client.post(
            "/api/v1/keys",
            json={"name": "new-key", "role": "scanner"},
            headers={"X-API-Key": admin_key},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "new-key"
        assert data["role"] == "scanner"
        assert "raw_key" in data
        assert data["raw_key"].startswith("mlw_")

    async def test_create_key_as_scanner_forbidden(self, client, scanner_key) -> None:
        resp = await client.post(
            "/api/v1/keys",
            json={"name": "sneaky", "role": "admin"},
            headers={"X-API-Key": scanner_key},
        )
        assert resp.status_code == 403

    async def test_list_keys_as_admin(self, client, admin_key) -> None:
        resp = await client.get(
            "/api/v1/keys",
            headers={"X-API-Key": admin_key},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        # At least the admin key should be listed
        assert len(data["keys"]) >= 1

    async def test_list_keys_as_scanner_forbidden(self, client, scanner_key) -> None:
        resp = await client.get(
            "/api/v1/keys",
            headers={"X-API-Key": scanner_key},
        )
        assert resp.status_code == 403

    async def test_revoke_key(self, client, admin_key, db) -> None:
        # Create a key to revoke
        km = APIKeyManager(db)
        record, _raw = await km.create_key("to-revoke", Role.SCANNER)

        resp = await client.delete(
            f"/api/v1/keys/{record['id']}",
            headers={"X-API-Key": admin_key},
        )
        assert resp.status_code == 204

    async def test_revoke_nonexistent_key(self, client, admin_key) -> None:
        resp = await client.delete(
            "/api/v1/keys/no-such-key",
            headers={"X-API-Key": admin_key},
        )
        assert resp.status_code == 404

    async def test_update_role(self, client, admin_key, db) -> None:
        km = APIKeyManager(db)
        record, _raw = await km.create_key("role-change", Role.SCANNER)

        resp = await client.put(
            f"/api/v1/keys/{record['id']}/role",
            json={"role": "analyst"},
            headers={"X-API-Key": admin_key},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "analyst"


# ---------------------------------------------------------------------------
# Permission enforcement on scan endpoints
# ---------------------------------------------------------------------------


class TestScanPermissions:
    """Verify RBAC enforcement on scan endpoints."""

    async def test_scanner_can_create_scan(self, client, scanner_key) -> None:
        content = (BENIGN_DIR / "hello_world.md").read_text()
        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine"],
                "use_llm": False,
            },
            headers={"X-API-Key": scanner_key},
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "CLEAN"

    async def test_readonly_cannot_create_scan(self, client, readonly_key) -> None:
        content = (BENIGN_DIR / "hello_world.md").read_text()
        resp = await client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "file_name": "hello_world.md",
                "layers": ["rule_engine"],
                "use_llm": False,
            },
            headers={"X-API-Key": readonly_key},
        )
        assert resp.status_code == 403

    async def test_readonly_can_read_scans(self, client, readonly_key) -> None:
        resp = await client.get(
            "/api/v1/scans",
            headers={"X-API-Key": readonly_key},
        )
        assert resp.status_code == 200

    async def test_scanner_can_read_scans(self, client, scanner_key) -> None:
        resp = await client.get(
            "/api/v1/scans",
            headers={"X-API-Key": scanner_key},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Permission enforcement on signature endpoints
# ---------------------------------------------------------------------------


class TestSignaturePermissions:
    """Verify RBAC enforcement on signature endpoints."""

    async def test_analyst_can_list_signatures(self, client, analyst_key) -> None:
        resp = await client.get(
            "/api/v1/signatures",
            headers={"X-API-Key": analyst_key},
        )
        assert resp.status_code == 200

    async def test_scanner_cannot_list_signatures(self, client, scanner_key) -> None:
        resp = await client.get(
            "/api/v1/signatures",
            headers={"X-API-Key": scanner_key},
        )
        assert resp.status_code == 403

    async def test_admin_can_create_signature(self, client, admin_key) -> None:
        resp = await client.post(
            "/api/v1/signatures",
            json={
                "name": "test-sig",
                "description": "Test signature",
                "severity": "medium",
                "category": "known_malware",
                "pattern_type": "exact",
                "pattern_value": "evil.example.com",
            },
            headers={"X-API-Key": admin_key},
        )
        assert resp.status_code == 201

    async def test_readonly_cannot_create_signature(self, client, readonly_key) -> None:
        resp = await client.post(
            "/api/v1/signatures",
            json={
                "name": "sneaky-sig",
                "description": "Should fail",
                "severity": "low",
                "category": "known_malware",
                "pattern_type": "exact",
                "pattern_value": "sneaky.example.com",
            },
            headers={"X-API-Key": readonly_key},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Permission enforcement on report endpoints
# ---------------------------------------------------------------------------


class TestReportPermissions:
    """Verify RBAC enforcement on report endpoints."""

    async def test_scanner_can_read_reports(self, client, scanner_key) -> None:
        resp = await client.get(
            "/api/v1/reports",
            headers={"X-API-Key": scanner_key},
        )
        assert resp.status_code == 200

    async def test_readonly_can_read_reports(self, client, readonly_key) -> None:
        resp = await client.get(
            "/api/v1/reports",
            headers={"X-API-Key": readonly_key},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Backward compatibility: no keys = open admin access
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    """Verify backward-compatible behavior when no keys are configured."""

    @pytest.fixture
    def open_app(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test_open.db"
        monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
        monkeypatch.delenv("MALWAR_API_KEYS", raising=False)
        monkeypatch.delenv("MALWAR_API_KEY", raising=False)
        return create_app()

    @pytest.fixture
    async def open_client(self, open_app, tmp_path):
        db_path = tmp_path / "test_open.db"
        await init_db(db_path)
        try:
            async with AsyncClient(
                transport=ASGITransport(app=open_app), base_url="http://test"
            ) as ac:
                yield ac
        finally:
            await close_db()

    async def test_no_keys_allows_scan(self, open_client) -> None:
        content = (BENIGN_DIR / "hello_world.md").read_text()
        resp = await open_client.post(
            "/api/v1/scan",
            json={
                "content": content,
                "layers": ["rule_engine"],
                "use_llm": False,
            },
        )
        assert resp.status_code == 200

    async def test_no_keys_allows_scans_list(self, open_client) -> None:
        resp = await open_client.get("/api/v1/scans")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Backward compatibility: env-var keys = admin
# ---------------------------------------------------------------------------


class TestEnvVarKeyCompat:
    """Verify MALWAR_API_KEYS env-var keys are treated as admin."""

    @pytest.fixture
    def env_app(self, tmp_path, monkeypatch):
        db_path = tmp_path / "test_env.db"
        monkeypatch.setenv("MALWAR_DB_PATH", str(db_path))
        monkeypatch.setenv("MALWAR_API_KEYS", '["env-key-123"]')
        return create_app()

    @pytest.fixture
    async def env_client(self, env_app, tmp_path):
        db_path = tmp_path / "test_env.db"
        await init_db(db_path)
        try:
            async with AsyncClient(
                transport=ASGITransport(app=env_app), base_url="http://test"
            ) as ac:
                yield ac
        finally:
            await close_db()

    async def test_env_key_has_admin_access(self, env_client) -> None:
        resp = await env_client.get(
            "/api/v1/scans",
            headers={"X-API-Key": "env-key-123"},
        )
        assert resp.status_code == 200

    async def test_env_key_missing_returns_401(self, env_client) -> None:
        resp = await env_client.get("/api/v1/scans")
        assert resp.status_code == 401

    async def test_env_key_wrong_returns_403(self, env_client) -> None:
        resp = await env_client.get(
            "/api/v1/scans",
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Revoked key cannot authenticate
# ---------------------------------------------------------------------------


class TestRevokedKey:
    """Verify a revoked key is rejected."""

    async def test_revoked_key_rejected(self, client, db) -> None:
        km = APIKeyManager(db)
        record, raw_key = await km.create_key("temp", Role.SCANNER)
        # Revoke it
        await km.revoke_key(record["id"])
        # Try to use it
        resp = await client.get(
            "/api/v1/scans",
            headers={"X-API-Key": raw_key},
        )
        assert resp.status_code == 403
