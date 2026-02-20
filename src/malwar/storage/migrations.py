# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Versioned database migration system for the malwar database.

Replaces the previous create-or-ignore approach with a proper migration
registry that tracks applied versions in a ``schema_migrations`` table.
Each migration is idempotent and runs inside a transaction.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Migration registry infrastructure
# ---------------------------------------------------------------------------

MigrationFunc = Callable[[aiosqlite.Connection], Coroutine[Any, Any, None]]


@dataclass(frozen=True, slots=True)
class Migration:
    """A single database migration."""

    version: int
    name: str
    func: MigrationFunc


# Ordered list of all migrations.  New migrations are appended here.
_MIGRATIONS: list[Migration] = []


def _register(version: int, name: str) -> Callable[[MigrationFunc], MigrationFunc]:
    """Decorator that registers a migration function."""

    def decorator(fn: MigrationFunc) -> MigrationFunc:
        _MIGRATIONS.append(Migration(version=version, name=name, func=fn))
        return fn

    return decorator


# ---------------------------------------------------------------------------
# Schema-migrations bookkeeping table
# ---------------------------------------------------------------------------

_CREATE_SCHEMA_MIGRATIONS = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


async def _ensure_migrations_table(db: aiosqlite.Connection) -> None:
    """Create the ``schema_migrations`` table if it does not exist."""
    await db.execute(_CREATE_SCHEMA_MIGRATIONS)
    await db.commit()


async def get_current_version(db: aiosqlite.Connection) -> int:
    """Return the highest applied migration version, or 0 if none."""
    await _ensure_migrations_table(db)
    cursor = await db.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
    )
    row = await cursor.fetchone()
    return int(row[0]) if row else 0


async def get_pending_migrations(db: aiosqlite.Connection) -> list[Migration]:
    """Return migrations that have not yet been applied."""
    current = await get_current_version(db)
    return [m for m in _MIGRATIONS if m.version > current]


async def run_migrations(db: aiosqlite.Connection) -> list[Migration]:
    """Run all pending migrations in order and return those applied.

    Each migration runs in its own transaction.  The migration version is
    recorded in ``schema_migrations`` after successful execution.
    """
    await _ensure_migrations_table(db)

    current = await get_current_version(db)
    applied: list[Migration] = []

    for migration in _MIGRATIONS:
        if migration.version <= current:
            continue

        logger.info(
            "Applying migration %03d: %s", migration.version, migration.name
        )

        # Execute the migration function (each is responsible for its own SQL)
        await migration.func(db)

        # Record the migration version
        await db.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (?, ?)",
            (migration.version, migration.name),
        )
        await db.commit()

        applied.append(migration)
        logger.info("Migration %03d applied successfully.", migration.version)

    return applied


# =========================================================================
# Migration 001 -- Initial schema (campaigns, scans, findings, etc.)
# =========================================================================

_CREATE_CAMPAIGNS = """
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    attributed_to TEXT,
    iocs TEXT DEFAULT '[]',
    total_skills_affected INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    skill_name TEXT,
    skill_author TEXT,
    skill_sha256 TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    risk_score INTEGER DEFAULT 0,
    overall_severity TEXT DEFAULT 'info',
    verdict TEXT DEFAULT 'CLEAN',
    layers_executed TEXT DEFAULT '[]',
    errors TEXT DEFAULT '[]',
    started_at TEXT NOT NULL,
    completed_at TEXT,
    duration_ms INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    category TEXT NOT NULL,
    detector_layer TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    snippet TEXT,
    evidence TEXT DEFAULT '[]',
    ioc_values TEXT DEFAULT '[]',
    remediation TEXT DEFAULT '',
    detected_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_SIGNATURES = """
CREATE TABLE IF NOT EXISTS signatures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    pattern_type TEXT NOT NULL,
    pattern_value TEXT NOT NULL,
    ioc_type TEXT,
    campaign_id TEXT REFERENCES campaigns(id),
    source TEXT NOT NULL DEFAULT 'manual',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_PUBLISHERS = """
CREATE TABLE IF NOT EXISTS publishers (
    id TEXT PRIMARY KEY,
    display_name TEXT,
    first_seen TEXT,
    last_seen TEXT,
    total_skills INTEGER DEFAULT 0,
    malicious_skills INTEGER DEFAULT 0,
    reputation_score REAL DEFAULT 0.5,
    is_known_threat_actor INTEGER DEFAULT 0,
    campaigns TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_CREATE_URL_ANALYSIS = """
CREATE TABLE IF NOT EXISTS url_analysis (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    final_url TEXT,
    status_code INTEGER,
    content_type TEXT,
    redirect_chain TEXT DEFAULT '[]',
    is_malicious INTEGER DEFAULT 0,
    risk_indicators TEXT DEFAULT '[]',
    domain_reputation REAL,
    fetched_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_INDEXES_001 = [
    "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);",
    "CREATE INDEX IF NOT EXISTS idx_scans_skill_sha256 ON scans(skill_sha256);",
    "CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);",
    "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
    "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);",
]

_SEED_CAMPAIGNS = [
    """
    INSERT OR IGNORE INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
    VALUES (
        'campaign-clawhavoc-001',
        'ClawHavoc',
        'Mass poisoning campaign delivering AMOS infostealer via trojanized archives. Attackers published trojanized skills on ClawHub that appear to be legitimate developer tools but contain hidden instructions to download and execute AMOS infostealer payloads. The campaign uses password-protected archives hosted on paste sites and direct IP-based C2 servers to evade detection.',
        '2026-01-15',
        '2026-02-10',
        'zaycv / Ddoy233 / hightower6eu',
        '["91.92.242.30", "glot.io/snippets/hfd3x9ueu5", "Ddoy233/openclawcli", "download.setup-service.com", "clawdhub1", "Aslaep123", "moonshine-100rze", "hightower6eu"]',
        824,
        'active'
    );
    """,
    """
    INSERT OR IGNORE INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
    VALUES (
        'campaign-snyktoxic-001',
        'SnykToxic',
        'Data exfiltration campaign discovered through Snyk ToxicSkills research. Malicious MCP skills published on ClawHub exfiltrate host information, environment variables, and credentials via Vercel deployments and Google Apps Script webhooks. Skills use ASCII smuggling and prompt injection to hide exfiltration commands within seemingly legitimate developer tools. 91%% of samples combine prompt injection with traditional malware techniques to bypass both AI safety mechanisms and conventional security tooling.',
        '2026-01-20',
        '2026-02-15',
        'aztr0nutzs / denboss99',
        '["aztr0nutzs/NET_NiNjA.v1.2", "rentry.co/openclaw-core", "denboss99/openclaw-core", "script.google.com/macros/s/exfil", "pastebin.com", "aztr0nutzs"]',
        76,
        'active'
    );
    """,
    """
    INSERT OR IGNORE INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
    VALUES (
        'campaign-shadowpkg-001',
        'ShadowPkg',
        'Supply chain campaign distributing trojanized npm and pip packages through the prerequisites sections of agent skills. Malicious skills instruct users or agents to install typosquatted packages (e.g., crossenv, colourfool, python3-dateutil) or pull from attacker-controlled registries. Packages contain post-install hooks that harvest environment variables, SSH keys, and cloud credentials. The campaign exploits the trust users place in skill-recommended dependencies.',
        '2026-01-28',
        '2026-02-18',
        'ScaffoldPro',
        '["crossenv", "colourfool", "python3-dateutil", "babelcli", "lodash-utils", "evil-registry.example.com", "evil-mirror.example.com", "ScaffoldPro"]',
        42,
        'active'
    );
    """,
]

_SEED_SIGNATURES = [
    # -- ClawHavoc signatures --
    (
        "sig-clawhavoc-c2-ip",
        "ClawHavoc C2 IP",
        "Command-and-control IP address used by ClawHavoc campaign",
        "critical",
        "known_malware",
        "exact",
        "91.92.242.30",
        "ip",
        "campaign-clawhavoc-001",
        "clawhavoc",
    ),
    (
        "sig-clawhavoc-glot",
        "ClawHavoc Glot Snippet",
        "Glot.io snippet used for payload staging by ClawHavoc",
        "critical",
        "known_malware",
        "exact",
        "glot.io/snippets/hfd3x9ueu5",
        "url",
        "campaign-clawhavoc-001",
        "clawhavoc",
    ),
    (
        "sig-clawhavoc-github",
        "ClawHavoc GitHub Repo",
        "GitHub repository distributing trojanized OpenClaw CLI",
        "critical",
        "known_malware",
        "exact",
        "Ddoy233/openclawcli",
        "url",
        "campaign-clawhavoc-001",
        "clawhavoc",
    ),
    (
        "sig-clawhavoc-domain",
        "ClawHavoc Malicious Domain",
        "Domain used for payload delivery by ClawHavoc campaign",
        "critical",
        "known_malware",
        "exact",
        "download.setup-service.com",
        "domain",
        "campaign-clawhavoc-001",
        "clawhavoc",
    ),
    # -- SnykToxic signatures --
    (
        "sig-snyktoxic-github-repo",
        "SnykToxic GitHub Repo",
        "GitHub repository hosting ready-to-deploy malicious MCP skills discovered in Snyk ToxicSkills research",
        "critical",
        "known_malware",
        "exact",
        "aztr0nutzs/NET_NiNjA.v1.2",
        "url",
        "campaign-snyktoxic-001",
        "snyk-toxicskills",
    ),
    (
        "sig-snyktoxic-rentry-stager",
        "SnykToxic Rentry Stager",
        "Rentry.co pastebin page used as a payload stager for fake openclaw-core distribution",
        "critical",
        "known_malware",
        "exact",
        "rentry.co/openclaw-core",
        "url",
        "campaign-snyktoxic-001",
        "snyk-toxicskills",
    ),
    (
        "sig-snyktoxic-gas-exfil",
        "SnykToxic Google Apps Script Exfil",
        "Google Apps Script macro endpoint used to exfiltrate credentials and environment variables from compromised hosts",
        "critical",
        "data_exfiltration",
        "regex",
        "script\\.google\\.com/macros/s/[A-Za-z0-9_-]+/exec",
        "url",
        "campaign-snyktoxic-001",
        "snyk-toxicskills",
    ),
    (
        "sig-snyktoxic-github-releases",
        "SnykToxic Fake OpenClaw Core",
        "GitHub releases page distributing password-protected payload archives disguised as openclaw-core",
        "critical",
        "known_malware",
        "exact",
        "denboss99/openclaw-core",
        "url",
        "campaign-snyktoxic-001",
        "snyk-toxicskills",
    ),
    # -- ShadowPkg signatures --
    (
        "sig-shadowpkg-crossenv",
        "ShadowPkg Typosquat crossenv",
        "Typosquatted npm package 'crossenv' mimicking the legitimate 'cross-env'; contains post-install credential harvesting hook",
        "high",
        "known_malware",
        "exact",
        "crossenv",
        "hash",
        "campaign-shadowpkg-001",
        "shadowpkg",
    ),
    (
        "sig-shadowpkg-colourfool",
        "ShadowPkg Typosquat colourfool",
        "Typosquatted pip package 'colourfool' mimicking the legitimate 'colorful'; exfiltrates environment variables on import",
        "high",
        "known_malware",
        "exact",
        "colourfool",
        "hash",
        "campaign-shadowpkg-001",
        "shadowpkg",
    ),
    (
        "sig-shadowpkg-evil-registry",
        "ShadowPkg Malicious Registry",
        "Attacker-controlled pip registry used to distribute trojanized packages via --index-url directives in skill prerequisites",
        "critical",
        "known_malware",
        "exact",
        "evil-registry.example.com",
        "domain",
        "campaign-shadowpkg-001",
        "shadowpkg",
    ),
    (
        "sig-shadowpkg-evil-mirror",
        "ShadowPkg Malicious Mirror",
        "Attacker-controlled pip mirror used to distribute trojanized packages via --trusted-host directives in skill prerequisites",
        "critical",
        "known_malware",
        "exact",
        "evil-mirror.example.com",
        "domain",
        "campaign-shadowpkg-001",
        "shadowpkg",
    ),
]

_SEED_SIGNATURE_SQL = """
INSERT OR IGNORE INTO signatures
    (id, name, description, severity, category, pattern_type, pattern_value, ioc_type, campaign_id, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_SEED_PUBLISHERS = [
    # ClawHavoc operators
    "zaycv",
    "Ddoy233",
    "hightower6eu",
    "clawdhub1",
    "Aslaep123",
    "moonshine-100rze",
    # SnykToxic operators
    "aztr0nutzs",
    "denboss99",
    # ShadowPkg operators
    "ScaffoldPro",
]

_SEED_PUBLISHER_SQL = """
INSERT OR IGNORE INTO publishers (id, is_known_threat_actor, reputation_score)
VALUES (?, 1, 0.0);
"""


@_register(1, "initial_schema")
async def _migration_001_initial_schema(db: aiosqlite.Connection) -> None:
    """Create the initial set of tables, indexes, and seed data."""
    # Create tables -- campaigns first (referenced by signatures FK)
    await db.execute(_CREATE_CAMPAIGNS)
    await db.execute(_CREATE_SCANS)
    await db.execute(_CREATE_FINDINGS)
    await db.execute(_CREATE_SIGNATURES)
    await db.execute(_CREATE_PUBLISHERS)
    await db.execute(_CREATE_URL_ANALYSIS)

    # Create indexes
    for idx_sql in _INDEXES_001:
        await db.execute(idx_sql)

    # Seed data
    await seed_data(db)


# =========================================================================
# Migration 002 -- api_usage table (issue #9)
# =========================================================================

_CREATE_API_USAGE = """
CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key TEXT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_INDEX_API_USAGE_KEY = (
    "CREATE INDEX IF NOT EXISTS idx_api_usage_key ON api_usage(api_key);"
)
_INDEX_API_USAGE_TIMESTAMP = (
    "CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);"
)


@_register(2, "api_usage_table")
async def _migration_002_api_usage(db: aiosqlite.Connection) -> None:
    """Create the api_usage table for tracking API request metrics."""
    await db.execute(_CREATE_API_USAGE)
    await db.execute(_INDEX_API_USAGE_KEY)
    await db.execute(_INDEX_API_USAGE_TIMESTAMP)


# ---------------------------------------------------------------------------
# Public helper -- seed_data (kept for standalone use by CLI db-seed command)
# ---------------------------------------------------------------------------


async def seed_data(db: aiosqlite.Connection) -> None:
    """Insert seed data (campaigns, signatures, publishers).

    Uses INSERT OR IGNORE so it is safe to run repeatedly.
    """
    for campaign_sql in _SEED_CAMPAIGNS:
        await db.execute(campaign_sql)

    for sig in _SEED_SIGNATURES:
        await db.execute(_SEED_SIGNATURE_SQL, sig)

    for publisher_id in _SEED_PUBLISHERS:
        await db.execute(_SEED_PUBLISHER_SQL, (publisher_id,))
