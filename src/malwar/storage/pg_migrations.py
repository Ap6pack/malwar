# Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
"""PostgreSQL-specific schema migrations.

Mirrors the SQLite migration history in ``migrations.py`` but uses
PostgreSQL-native types: ``VARCHAR`` instead of ``TEXT`` for bounded
columns, ``BIGINT`` for large integers, ``TIMESTAMP`` for datetime
columns, and ``BOOLEAN`` for flags.
"""

from __future__ import annotations

import logging

from malwar.storage.postgres import PostgresDatabase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Migration bookkeeping
# ---------------------------------------------------------------------------

_CREATE_SCHEMA_MIGRATIONS = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""


async def _ensure_migrations_table(db: PostgresDatabase) -> None:
    await db.execute(_CREATE_SCHEMA_MIGRATIONS)


async def get_current_version(db: PostgresDatabase) -> int:
    await _ensure_migrations_table(db)
    row = await db.fetch_one(
        "SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations"
    )
    return int(row["v"]) if row else 0


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

_PG_MIGRATIONS: list[tuple[int, str, str | list[str]]] = []


def _register_pg(version: int, name: str, sql: str | list[str]) -> None:
    _PG_MIGRATIONS.append((version, name, sql))


# ---------------------------------------------------------------------------
# Migration 001 -- Initial schema
# ---------------------------------------------------------------------------

_PG_CREATE_CAMPAIGNS = """
CREATE TABLE IF NOT EXISTS campaigns (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    first_seen VARCHAR(32) NOT NULL,
    last_seen VARCHAR(32) NOT NULL,
    attributed_to VARCHAR(512),
    iocs TEXT DEFAULT '[]',
    total_skills_affected BIGINT DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_CREATE_SCANS = """
CREATE TABLE IF NOT EXISTS scans (
    id VARCHAR(255) PRIMARY KEY,
    target TEXT NOT NULL,
    skill_name VARCHAR(255),
    skill_author VARCHAR(255),
    skill_sha256 VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    risk_score BIGINT DEFAULT 0,
    overall_severity VARCHAR(32) DEFAULT 'info',
    verdict VARCHAR(32) DEFAULT 'CLEAN',
    layers_executed TEXT DEFAULT '[]',
    errors TEXT DEFAULT '[]',
    started_at VARCHAR(64) NOT NULL,
    completed_at VARCHAR(64),
    duration_ms BIGINT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_CREATE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(255) PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id VARCHAR(255) NOT NULL,
    title VARCHAR(512) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    category VARCHAR(64) NOT NULL,
    detector_layer VARCHAR(64) NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    snippet TEXT,
    evidence TEXT DEFAULT '[]',
    ioc_values TEXT DEFAULT '[]',
    remediation TEXT DEFAULT '',
    detected_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_CREATE_SIGNATURES = """
CREATE TABLE IF NOT EXISTS signatures (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(32) NOT NULL,
    category VARCHAR(64) NOT NULL,
    pattern_type VARCHAR(32) NOT NULL,
    pattern_value TEXT NOT NULL,
    ioc_type VARCHAR(32),
    campaign_id VARCHAR(255) REFERENCES campaigns(id),
    source VARCHAR(64) NOT NULL DEFAULT 'manual',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_CREATE_PUBLISHERS = """
CREATE TABLE IF NOT EXISTS publishers (
    id VARCHAR(255) PRIMARY KEY,
    display_name VARCHAR(255),
    first_seen VARCHAR(32),
    last_seen VARCHAR(32),
    total_skills BIGINT DEFAULT 0,
    malicious_skills BIGINT DEFAULT 0,
    reputation_score DOUBLE PRECISION DEFAULT 0.5,
    is_known_threat_actor BOOLEAN DEFAULT FALSE,
    campaigns TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_CREATE_URL_ANALYSIS = """
CREATE TABLE IF NOT EXISTS url_analysis (
    id VARCHAR(255) PRIMARY KEY,
    scan_id VARCHAR(255) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    final_url TEXT,
    status_code INTEGER,
    content_type VARCHAR(128),
    redirect_chain TEXT DEFAULT '[]',
    is_malicious BOOLEAN DEFAULT FALSE,
    risk_indicators TEXT DEFAULT '[]',
    domain_reputation DOUBLE PRECISION,
    fetched_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_INDEXES_001 = [
    "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);",
    "CREATE INDEX IF NOT EXISTS idx_scans_skill_sha256 ON scans(skill_sha256);",
    "CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);",
    "CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);",
    "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id);",
    "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
    "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);",
]

_PG_SEED_CAMPAIGNS = [
    """
    INSERT INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
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
    )
    ON CONFLICT (id) DO NOTHING;
    """,
    """
    INSERT INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
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
    )
    ON CONFLICT (id) DO NOTHING;
    """,
    """
    INSERT INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
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
    )
    ON CONFLICT (id) DO NOTHING;
    """,
]

_PG_SEED_SIGNATURES = [
    ("sig-clawhavoc-c2-ip", "ClawHavoc C2 IP", "Command-and-control IP address used by ClawHavoc campaign", "critical", "known_malware", "exact", "91.92.242.30", "ip", "campaign-clawhavoc-001", "clawhavoc"),
    ("sig-clawhavoc-glot", "ClawHavoc Glot Snippet", "Glot.io snippet used for payload staging by ClawHavoc", "critical", "known_malware", "exact", "glot.io/snippets/hfd3x9ueu5", "url", "campaign-clawhavoc-001", "clawhavoc"),
    ("sig-clawhavoc-github", "ClawHavoc GitHub Repo", "GitHub repository distributing trojanized OpenClaw CLI", "critical", "known_malware", "exact", "Ddoy233/openclawcli", "url", "campaign-clawhavoc-001", "clawhavoc"),
    ("sig-clawhavoc-domain", "ClawHavoc Malicious Domain", "Domain used for payload delivery by ClawHavoc campaign", "critical", "known_malware", "exact", "download.setup-service.com", "domain", "campaign-clawhavoc-001", "clawhavoc"),
    ("sig-snyktoxic-github-repo", "SnykToxic GitHub Repo", "GitHub repository hosting ready-to-deploy malicious MCP skills discovered in Snyk ToxicSkills research", "critical", "known_malware", "exact", "aztr0nutzs/NET_NiNjA.v1.2", "url", "campaign-snyktoxic-001", "snyk-toxicskills"),
    ("sig-snyktoxic-rentry-stager", "SnykToxic Rentry Stager", "Rentry.co pastebin page used as a payload stager for fake openclaw-core distribution", "critical", "known_malware", "exact", "rentry.co/openclaw-core", "url", "campaign-snyktoxic-001", "snyk-toxicskills"),
    ("sig-snyktoxic-gas-exfil", "SnykToxic Google Apps Script Exfil", "Google Apps Script macro endpoint used to exfiltrate credentials and environment variables from compromised hosts", "critical", "data_exfiltration", "regex", r"script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec", "url", "campaign-snyktoxic-001", "snyk-toxicskills"),
    ("sig-snyktoxic-github-releases", "SnykToxic Fake OpenClaw Core", "GitHub releases page distributing password-protected payload archives disguised as openclaw-core", "critical", "known_malware", "exact", "denboss99/openclaw-core", "url", "campaign-snyktoxic-001", "snyk-toxicskills"),
    ("sig-shadowpkg-crossenv", "ShadowPkg Typosquat crossenv", "Typosquatted npm package 'crossenv' mimicking the legitimate 'cross-env'; contains post-install credential harvesting hook", "high", "known_malware", "exact", "crossenv", "hash", "campaign-shadowpkg-001", "shadowpkg"),
    ("sig-shadowpkg-colourfool", "ShadowPkg Typosquat colourfool", "Typosquatted pip package 'colourfool' mimicking the legitimate 'colorful'; exfiltrates environment variables on import", "high", "known_malware", "exact", "colourfool", "hash", "campaign-shadowpkg-001", "shadowpkg"),
    ("sig-shadowpkg-evil-registry", "ShadowPkg Malicious Registry", "Attacker-controlled pip registry used to distribute trojanized packages via --index-url directives in skill prerequisites", "critical", "known_malware", "exact", "evil-registry.example.com", "domain", "campaign-shadowpkg-001", "shadowpkg"),
    ("sig-shadowpkg-evil-mirror", "ShadowPkg Malicious Mirror", "Attacker-controlled pip mirror used to distribute trojanized packages via --trusted-host directives in skill prerequisites", "critical", "known_malware", "exact", "evil-mirror.example.com", "domain", "campaign-shadowpkg-001", "shadowpkg"),
]

_PG_SEED_SIGNATURE_SQL = """
INSERT INTO signatures
    (id, name, description, severity, category, pattern_type, pattern_value, ioc_type, campaign_id, source)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (id) DO NOTHING;
"""

_PG_SEED_PUBLISHERS = [
    "zaycv", "Ddoy233", "hightower6eu", "clawdhub1", "Aslaep123",
    "moonshine-100rze", "aztr0nutzs", "denboss99", "ScaffoldPro",
]

_PG_SEED_PUBLISHER_SQL = """
INSERT INTO publishers (id, is_known_threat_actor, reputation_score)
VALUES ($1, TRUE, 0.0)
ON CONFLICT (id) DO NOTHING;
"""


# ---------------------------------------------------------------------------
# Migration 001 -- initial schema
# ---------------------------------------------------------------------------

_MIGRATION_001_SQL = [
    _PG_CREATE_CAMPAIGNS,
    _PG_CREATE_SCANS,
    _PG_CREATE_FINDINGS,
    _PG_CREATE_SIGNATURES,
    _PG_CREATE_PUBLISHERS,
    _PG_CREATE_URL_ANALYSIS,
    *_PG_INDEXES_001,
]

_register_pg(1, "initial_schema", _MIGRATION_001_SQL)


# ---------------------------------------------------------------------------
# Migration 002 -- api_usage table
# ---------------------------------------------------------------------------

_PG_CREATE_API_USAGE = """
CREATE TABLE IF NOT EXISTS api_usage (
    id BIGSERIAL PRIMARY KEY,
    api_key VARCHAR(255),
    endpoint VARCHAR(512) NOT NULL,
    method VARCHAR(16) NOT NULL,
    status_code INTEGER,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_register_pg(
    2,
    "api_usage_table",
    [
        _PG_CREATE_API_USAGE,
        "CREATE INDEX IF NOT EXISTS idx_api_usage_key ON api_usage(api_key);",
        "CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);",
    ],
)


# ---------------------------------------------------------------------------
# Migration 003 -- audit_log table
# ---------------------------------------------------------------------------

_PG_CREATE_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS audit_log (
    event_id VARCHAR(255) PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL DEFAULT 'cli',
    resource_type VARCHAR(64) NOT NULL DEFAULT '',
    resource_id VARCHAR(255) NOT NULL DEFAULT '',
    action VARCHAR(64) NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    ip_address VARCHAR(45) NOT NULL DEFAULT ''
);
"""

_register_pg(
    3,
    "audit_log_table",
    [
        _PG_CREATE_AUDIT_LOG,
        "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor);",
        "CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);",
    ],
)


# ---------------------------------------------------------------------------
# Migration 004 -- api_keys table
# ---------------------------------------------------------------------------

_PG_CREATE_API_KEYS = """
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(255) PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'scanner',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_used TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
"""

_register_pg(
    4,
    "api_keys_table",
    [
        _PG_CREATE_API_KEYS,
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);",
        "CREATE INDEX IF NOT EXISTS idx_api_keys_role ON api_keys(role);",
    ],
)


# ---------------------------------------------------------------------------
# Migration 005 -- scheduled_jobs + job_runs
# ---------------------------------------------------------------------------

_PG_CREATE_SCHEDULED_JOBS = """
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    target_path TEXT NOT NULL,
    schedule VARCHAR(128) NOT NULL,
    layers VARCHAR(512) NOT NULL DEFAULT 'rule_engine,url_crawler,llm_analyzer,threat_intel',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run TIMESTAMP,
    next_run TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
"""

_PG_CREATE_JOB_RUNS = """
CREATE TABLE IF NOT EXISTS job_runs (
    id VARCHAR(255) PRIMARY KEY,
    job_id VARCHAR(255) NOT NULL REFERENCES scheduled_jobs(id) ON DELETE CASCADE,
    scan_id VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    verdict VARCHAR(32),
    risk_score BIGINT,
    error TEXT,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP
);
"""

_register_pg(
    5,
    "scheduled_scanning_tables",
    [
        _PG_CREATE_SCHEDULED_JOBS,
        _PG_CREATE_JOB_RUNS,
        "CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_enabled ON scheduled_jobs(enabled);",
        "CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_next_run ON scheduled_jobs(next_run);",
        "CREATE INDEX IF NOT EXISTS idx_job_runs_job_id ON job_runs(job_id);",
        "CREATE INDEX IF NOT EXISTS idx_job_runs_started_at ON job_runs(started_at);",
    ],
)


# ---------------------------------------------------------------------------
# Migration runner
# ---------------------------------------------------------------------------


async def run_pg_migrations(db: PostgresDatabase) -> list[tuple[int, str]]:
    """Run all pending PostgreSQL migrations.

    Returns:
        List of ``(version, name)`` tuples for applied migrations.
    """
    await _ensure_migrations_table(db)
    current = await get_current_version(db)
    applied: list[tuple[int, str]] = []

    for version, name, sql_list in _PG_MIGRATIONS:
        if version <= current:
            continue

        logger.info("Applying PG migration %03d: %s", version, name)

        statements = sql_list if isinstance(sql_list, list) else [sql_list]
        for stmt in statements:
            await db.execute(stmt)

        await db.execute(
            "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)"
            " ON CONFLICT (version) DO NOTHING",
            (version, name),
        )

        applied.append((version, name))
        logger.info("PG migration %03d applied successfully.", version)

    # Seed data (idempotent via ON CONFLICT)
    if current < 1:
        await _seed_data(db)

    return applied


async def _seed_data(db: PostgresDatabase) -> None:
    """Insert seed campaigns, signatures, and publishers."""
    for campaign_sql in _PG_SEED_CAMPAIGNS:
        await db.execute(campaign_sql)

    for sig in _PG_SEED_SIGNATURES:
        await db.execute(_PG_SEED_SIGNATURE_SQL, sig)

    for publisher_id in _PG_SEED_PUBLISHERS:
        await db.execute(_PG_SEED_PUBLISHER_SQL, (publisher_id,))
