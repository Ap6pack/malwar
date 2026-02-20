# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""Schema creation with seed data for the malwar database."""

from __future__ import annotations

import aiosqlite

# ---------------------------------------------------------------------------
# Table definitions
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Indexes
# ---------------------------------------------------------------------------

_INDEXES = [
    # scans indexes
    "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);",
    "CREATE INDEX IF NOT EXISTS idx_scans_skill_sha256 ON scans(skill_sha256);",
    "CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);",
    "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);",
    # findings indexes
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
    "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);",
]

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

_SEED_CAMPAIGN = """
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
"""

_SEED_SIGNATURES = [
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
]

_SEED_SIGNATURE_SQL = """
INSERT OR IGNORE INTO signatures
    (id, name, description, severity, category, pattern_type, pattern_value, ioc_type, campaign_id, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_SEED_PUBLISHERS = [
    "zaycv",
    "Ddoy233",
    "hightower6eu",
    "clawdhub1",
    "Aslaep123",
    "moonshine-100rze",
]

_SEED_PUBLISHER_SQL = """
INSERT OR IGNORE INTO publishers (id, is_known_threat_actor, reputation_score)
VALUES (?, 1, 0.0);
"""


async def run_migrations(db: aiosqlite.Connection) -> None:
    """Create all tables, indexes, and seed initial data.

    Uses IF NOT EXISTS / INSERT OR IGNORE so it is safe to run repeatedly.
    """
    # Create tables -- campaigns first (referenced by signatures FK)
    await db.execute(_CREATE_CAMPAIGNS)
    await db.execute(_CREATE_SCANS)
    await db.execute(_CREATE_FINDINGS)
    await db.execute(_CREATE_SIGNATURES)
    await db.execute(_CREATE_PUBLISHERS)
    await db.execute(_CREATE_URL_ANALYSIS)

    # Create indexes
    for idx_sql in _INDEXES:
        await db.execute(idx_sql)

    # Seed data
    await seed_data(db)

    await db.commit()


async def seed_data(db: aiosqlite.Connection) -> None:
    """Insert seed data (campaigns, signatures, publishers).

    Uses INSERT OR IGNORE so it is safe to run repeatedly.
    """
    await db.execute(_SEED_CAMPAIGN)

    for sig in _SEED_SIGNATURES:
        await db.execute(_SEED_SIGNATURE_SQL, sig)

    for publisher_id in _SEED_PUBLISHERS:
        await db.execute(_SEED_PUBLISHER_SQL, (publisher_id,))
