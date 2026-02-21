# Audit Logging

malwar includes a compliance-grade audit logging system that records all security-relevant events to both structured JSON log files and the SQLite database.

## Overview

The audit system tracks:

- **Scan lifecycle** -- scan started, scan completed, findings detected
- **API key usage** -- which key was used, when, and for what endpoint
- **Configuration changes** -- any modifications to settings
- **Signature management** -- creation, updates, and deletion of threat signatures
- **API requests** -- all API requests (excluding health checks)

All API keys are hashed (SHA-256 prefix) before being stored in audit logs to prevent credential exposure.

## Architecture

```
AuditLogger (singleton)
  |
  +-- writes JSON lines --> logs/audit-YYYY-MM-DD.jsonl
  |
  +-- persists via AuditStore --> SQLite audit_log table
```

### Components

| Module | Description |
|--------|-------------|
| `malwar.audit.events` | `AuditEvent` Pydantic model and `AuditEventType` enum |
| `malwar.audit.logger` | `AuditLogger` class with convenience methods for each event type |
| `malwar.audit.store` | `AuditStore` repository for SQLite persistence and querying |
| `malwar.audit.middleware` | FastAPI middleware that auto-logs every API request |

## AuditEvent Schema

| Field | Type | Description |
|-------|------|-------------|
| `event_id` | UUID (hex) | Unique event identifier |
| `timestamp` | ISO 8601 datetime | When the event occurred |
| `event_type` | AuditEventType enum | Category of event |
| `actor` | string | API key hash (`sha256:...`) or `cli` |
| `resource_type` | string | Type of resource (scan, signature, config, etc.) |
| `resource_id` | string | Identifier of the affected resource |
| `action` | string | Human-readable action description |
| `details` | JSON object | Structured event-specific data |
| `ip_address` | string | Client IP address (API requests only) |

## Event Types

| Type | Triggered By |
|------|-------------|
| `scan_started` | Scan initiation via API or CLI |
| `scan_completed` | Scan completion with verdict |
| `finding_detected` | Each individual finding during a scan |
| `api_key_used` | Authenticated API request |
| `config_changed` | Configuration modification |
| `signature_created` | New signature added |
| `signature_updated` | Existing signature modified |
| `signature_deleted` | Signature removed |
| `api_request` | Any API request (via middleware) |

## API Endpoints

### List Audit Events

```
GET /api/v1/audit
```

Query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Filter by event type |
| `actor` | string | Filter by actor |
| `start_date` | ISO date | Start of date range (inclusive) |
| `end_date` | ISO date | End of date range (inclusive) |
| `limit` | integer | Max events to return (default 100) |
| `offset` | integer | Pagination offset (default 0) |

Example:

```bash
curl "http://localhost:8000/api/v1/audit?event_type=scan_completed&limit=10"
```

### Get Single Audit Event

```
GET /api/v1/audit/{event_id}
```

Returns a single audit event by its ID.

## CLI Commands

### List Audit Events

```bash
malwar audit list [OPTIONS]
```

Options:

| Flag | Description |
|------|-------------|
| `--type, -t` | Filter by event type |
| `--actor, -a` | Filter by actor |
| `--start` | Start date (ISO format) |
| `--end` | End date (ISO format) |
| `--limit, -n` | Maximum events to show (default 50) |

Example:

```bash
# Show all scan events
malwar audit list --type scan_completed

# Show events from a specific date range
malwar audit list --start 2026-02-01 --end 2026-02-20

# Show last 10 events
malwar audit list -n 10
```

## JSON Log Files

When `log_dir` is configured, the audit logger writes one JSON Lines file per day:

```
logs/audit-2026-02-20.jsonl
```

Each line is a complete JSON object representing one audit event. These files can be ingested by external log aggregation systems (ELK, Splunk, etc.).

## Database Schema

The `audit_log` table is created by migration 003:

```sql
CREATE TABLE audit_log (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'cli',
    resource_type TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    ip_address TEXT NOT NULL DEFAULT ''
);
```

Indexed on: `timestamp`, `event_type`, `actor`, and `(resource_type, resource_id)`.

## Security Considerations

- API keys are **never stored in plain text** in audit logs. They are hashed using SHA-256 with a 16-character prefix.
- The audit middleware gracefully degrades -- if the database is unavailable, API requests still succeed; only audit logging is silently skipped.
- Audit events are immutable once written; there is no update or delete API for audit records.
