# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Unit tests for the RBAC module (roles, permissions, mapping, hashing)."""

from __future__ import annotations

import pytest

from malwar.api.rbac import (
    ROLE_PERMISSIONS,
    AuthenticatedKey,
    Permission,
    Role,
    generate_raw_key,
    hash_api_key,
    role_has_permission,
)

# ---------------------------------------------------------------------------
# Role enumeration
# ---------------------------------------------------------------------------


class TestRoleEnum:
    """Verify all expected roles exist."""

    def test_admin_exists(self) -> None:
        assert Role.ADMIN == "admin"

    def test_analyst_exists(self) -> None:
        assert Role.ANALYST == "analyst"

    def test_scanner_exists(self) -> None:
        assert Role.SCANNER == "scanner"

    def test_readonly_exists(self) -> None:
        assert Role.READONLY == "readonly"

    def test_role_count(self) -> None:
        assert len(Role) == 4


# ---------------------------------------------------------------------------
# Permission enumeration
# ---------------------------------------------------------------------------


class TestPermissionEnum:
    """Verify all expected permissions exist."""

    def test_all_permissions_present(self) -> None:
        expected = {
            "scan:create",
            "scan:read",
            "signature:manage",
            "campaign:manage",
            "audit:read",
            "config:manage",
            "api_key:manage",
        }
        actual = {p.value for p in Permission}
        assert actual == expected

    def test_permission_count(self) -> None:
        assert len(Permission) == 7


# ---------------------------------------------------------------------------
# Role-to-permission mapping
# ---------------------------------------------------------------------------


class TestRolePermissions:
    """Verify the role-to-permission mapping."""

    def test_admin_has_all_permissions(self) -> None:
        admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
        for perm in Permission:
            assert perm in admin_perms, f"ADMIN should have {perm}"

    def test_analyst_permissions(self) -> None:
        analyst_perms = ROLE_PERMISSIONS[Role.ANALYST]
        assert Permission.SCAN_CREATE in analyst_perms
        assert Permission.SCAN_READ in analyst_perms
        assert Permission.SIGNATURE_MANAGE in analyst_perms
        assert Permission.CAMPAIGN_MANAGE in analyst_perms
        assert Permission.AUDIT_READ in analyst_perms
        # Analyst should NOT have these:
        assert Permission.CONFIG_MANAGE not in analyst_perms
        assert Permission.API_KEY_MANAGE not in analyst_perms

    def test_scanner_permissions(self) -> None:
        scanner_perms = ROLE_PERMISSIONS[Role.SCANNER]
        assert Permission.SCAN_CREATE in scanner_perms
        assert Permission.SCAN_READ in scanner_perms
        # Scanner should NOT have these:
        assert Permission.SIGNATURE_MANAGE not in scanner_perms
        assert Permission.CAMPAIGN_MANAGE not in scanner_perms
        assert Permission.API_KEY_MANAGE not in scanner_perms

    def test_readonly_permissions(self) -> None:
        readonly_perms = ROLE_PERMISSIONS[Role.READONLY]
        assert Permission.SCAN_READ in readonly_perms
        assert Permission.AUDIT_READ in readonly_perms
        # READONLY should NOT have these:
        assert Permission.SCAN_CREATE not in readonly_perms
        assert Permission.SIGNATURE_MANAGE not in readonly_perms
        assert Permission.API_KEY_MANAGE not in readonly_perms


# ---------------------------------------------------------------------------
# role_has_permission()
# ---------------------------------------------------------------------------


class TestRoleHasPermission:
    """Test the role_has_permission helper."""

    def test_admin_has_api_key_manage(self) -> None:
        assert role_has_permission(Role.ADMIN, Permission.API_KEY_MANAGE)

    def test_scanner_has_scan_create(self) -> None:
        assert role_has_permission(Role.SCANNER, Permission.SCAN_CREATE)

    def test_readonly_lacks_scan_create(self) -> None:
        assert not role_has_permission(Role.READONLY, Permission.SCAN_CREATE)

    def test_scanner_lacks_config_manage(self) -> None:
        assert not role_has_permission(Role.SCANNER, Permission.CONFIG_MANAGE)


# ---------------------------------------------------------------------------
# AuthenticatedKey
# ---------------------------------------------------------------------------


class TestAuthenticatedKey:
    """Test the AuthenticatedKey wrapper."""

    def test_has_permission_true(self) -> None:
        key = AuthenticatedKey(key_id="k1", name="test", role=Role.ADMIN)
        assert key.has_permission(Permission.API_KEY_MANAGE)

    def test_has_permission_false(self) -> None:
        key = AuthenticatedKey(key_id="k1", name="test", role=Role.READONLY)
        assert not key.has_permission(Permission.SCAN_CREATE)

    def test_attributes(self) -> None:
        key = AuthenticatedKey(key_id="k1", name="my-key", role=Role.ANALYST)
        assert key.key_id == "k1"
        assert key.name == "my-key"
        assert key.role == Role.ANALYST


# ---------------------------------------------------------------------------
# Hashing and key generation
# ---------------------------------------------------------------------------


class TestHashing:
    """Test hash_api_key and generate_raw_key utilities."""

    def test_hash_deterministic(self) -> None:
        h1 = hash_api_key("test-key")
        h2 = hash_api_key("test-key")
        assert h1 == h2

    def test_hash_differs_for_different_keys(self) -> None:
        h1 = hash_api_key("key-a")
        h2 = hash_api_key("key-b")
        assert h1 != h2

    def test_hash_is_hex_string(self) -> None:
        h = hash_api_key("sample")
        assert len(h) == 64  # SHA-256 hex = 64 chars
        int(h, 16)  # should not raise

    def test_generate_raw_key_unique(self) -> None:
        keys = {generate_raw_key() for _ in range(50)}
        assert len(keys) == 50, "Generated keys should be unique"

    def test_generate_raw_key_prefix(self) -> None:
        key = generate_raw_key()
        assert key.startswith("mlw_")

    def test_generate_raw_key_length(self) -> None:
        key = generate_raw_key()
        # "mlw_" + 48 hex chars = 52 chars
        assert len(key) == 52


# ---------------------------------------------------------------------------
# APIKeyManager (unit tests with in-memory DB)
# ---------------------------------------------------------------------------


class TestAPIKeyManager:
    """Test APIKeyManager operations against an in-memory SQLite DB."""

    @pytest.fixture
    async def db(self):
        import aiosqlite

        conn = await aiosqlite.connect(":memory:")
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA foreign_keys=ON")
        # Create the api_keys table directly
        await conn.execute("""
            CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'scanner',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_used TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        """)
        await conn.commit()
        yield conn
        await conn.close()

    @pytest.fixture
    def manager(self, db):
        from malwar.api.keys import APIKeyManager

        return APIKeyManager(db)

    async def test_create_key(self, manager) -> None:
        record, raw_key = await manager.create_key("test-key", Role.SCANNER)
        assert record["name"] == "test-key"
        assert record["role"] == "scanner"
        assert record["is_active"] is True
        assert raw_key.startswith("mlw_")

    async def test_verify_key(self, manager) -> None:
        _record, raw_key = await manager.create_key("v-key", Role.ANALYST)
        result = await manager.verify_key(raw_key)
        assert result is not None
        assert result["name"] == "v-key"
        assert result["role"] == "analyst"

    async def test_verify_wrong_key(self, manager) -> None:
        await manager.create_key("v-key", Role.ANALYST)
        result = await manager.verify_key("mlw_nonexistent")
        assert result is None

    async def test_list_keys(self, manager) -> None:
        await manager.create_key("k1", Role.ADMIN)
        await manager.create_key("k2", Role.SCANNER)
        keys = await manager.list_keys()
        assert len(keys) == 2
        names = {k["name"] for k in keys}
        assert names == {"k1", "k2"}

    async def test_revoke_key(self, manager) -> None:
        record, raw_key = await manager.create_key("rev", Role.SCANNER)
        revoked = await manager.revoke_key(record["id"])
        assert revoked is True
        # Verify key no longer works
        result = await manager.verify_key(raw_key)
        assert result is None

    async def test_revoke_nonexistent(self, manager) -> None:
        revoked = await manager.revoke_key("no-such-key")
        assert revoked is False

    async def test_update_role(self, manager) -> None:
        record, _raw_key = await manager.create_key("ur", Role.SCANNER)
        updated = await manager.update_role(record["id"], Role.ADMIN)
        assert updated is True
        refreshed = await manager.get_key(record["id"])
        assert refreshed is not None
        assert refreshed["role"] == "admin"

    async def test_update_role_nonexistent(self, manager) -> None:
        updated = await manager.update_role("no-such-key", Role.ADMIN)
        assert updated is False

    async def test_has_any_keys_empty(self, manager) -> None:
        result = await manager.has_any_keys()
        assert result is False

    async def test_has_any_keys_after_create(self, manager) -> None:
        await manager.create_key("first", Role.SCANNER)
        result = await manager.has_any_keys()
        assert result is True

    async def test_touch_last_used(self, manager) -> None:
        record, _raw_key = await manager.create_key("touch", Role.SCANNER)
        assert record["last_used"] is None
        await manager.touch_last_used(record["id"])
        refreshed = await manager.get_key(record["id"])
        assert refreshed is not None
        assert refreshed["last_used"] is not None
