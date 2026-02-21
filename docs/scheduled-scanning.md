# Scheduled Scanning

Malwar supports periodic re-scanning of SKILL.md files on configurable cron schedules. This feature enables continuous monitoring of skill files for emerging threats without manual intervention.

## Overview

The scheduler runs as an asyncio background task inside the `malwar serve` process. It checks for due jobs every 30 seconds and executes scans using the same `ScanPipeline` as manual and API-triggered scans.

## Architecture

```
SchedulerEngine (asyncio loop)
    |
    +-- JobStore (SQLite: scheduled_jobs, job_runs)
    |
    +-- ScanPipeline (rule_engine -> url_crawler -> llm_analyzer -> threat_intel)
```

**Key modules:**

| Module | Description |
|--------|-------------|
| `malwar.scheduler.engine` | `SchedulerEngine` class — asyncio background loop |
| `malwar.scheduler.jobs` | `ScanJob` and `JobRun` dataclasses |
| `malwar.scheduler.cron` | Cron expression parser and next-run calculator |
| `malwar.scheduler.store` | `JobStore` for SQLite persistence |

## Cron Expression Format

The scheduler uses standard 5-field cron expressions:

```
minute  hour  day  month  weekday
```

Each field supports:

- `*` — any value
- `N` — specific value (e.g., `5`)
- `N,M` — list of values (e.g., `1,15`)
- `N-M` — range of values (e.g., `9-17`)
- `*/N` — step values (e.g., `*/15`)

**Weekday values:** 0=Sunday, 1=Monday, ..., 6=Saturday

### Examples

| Expression | Meaning |
|-----------|---------|
| `0 */6 * * *` | Every 6 hours |
| `*/15 * * * *` | Every 15 minutes |
| `0 2 * * *` | Daily at 2:00 AM |
| `0 0 1 * *` | Monthly on the 1st at midnight |
| `0 9-17 * * 1-5` | Hourly during business hours, weekdays only |

## CLI Usage

### Create a scheduled scan

```bash
malwar schedule create /path/to/SKILL.md \
  --cron "0 */6 * * *" \
  --name "My 6-hourly scan"
```

Options:

- `--cron` (required) — Cron expression for the schedule
- `--name` / `-n` — Human-readable name
- `--layers` — Comma-separated list of detection layers to run
- `--disabled` — Create in disabled state

### List scheduled jobs

```bash
malwar schedule list
```

### Run a job immediately

```bash
malwar schedule run <job_id>
```

## API Endpoints

All endpoints are under `/api/v1/schedules` and require authentication when API keys are configured.

### Create a schedule

```http
POST /api/v1/schedules
Content-Type: application/json

{
  "name": "Nightly full scan",
  "target_path": "/skills/production/SKILL.md",
  "schedule": "0 2 * * *",
  "layers": ["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"],
  "enabled": true
}
```

### List all schedules

```http
GET /api/v1/schedules
```

### Get schedule details (includes recent runs)

```http
GET /api/v1/schedules/{job_id}
```

### Update a schedule

```http
PUT /api/v1/schedules/{job_id}
Content-Type: application/json

{
  "schedule": "0 */12 * * *",
  "enabled": false
}
```

### Delete a schedule

```http
DELETE /api/v1/schedules/{job_id}
```

### Trigger immediate run

```http
POST /api/v1/schedules/{job_id}/run
```

## Server Integration

The scheduler starts automatically when `malwar serve` is called. To disable it:

```bash
malwar serve --no-scheduler
```

This is useful for development or when running multiple worker processes (only one worker should run the scheduler).

## Database Schema

The feature adds two tables via migration 005:

**scheduled_jobs:**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | Job identifier |
| name | TEXT | Human-readable name |
| target_path | TEXT | Path to SKILL.md file |
| schedule | TEXT | Cron expression |
| layers | TEXT | Comma-separated detection layers |
| enabled | INTEGER | 1=enabled, 0=disabled |
| last_run | TEXT | ISO timestamp of last execution |
| next_run | TEXT | ISO timestamp of next scheduled run |
| created_at | TEXT | ISO timestamp of creation |

**job_runs:**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PK | Run identifier |
| job_id | TEXT FK | References scheduled_jobs(id) |
| scan_id | TEXT | Associated scan result ID |
| status | TEXT | pending, running, completed, failed |
| verdict | TEXT | Scan verdict (CLEAN, CAUTION, etc.) |
| risk_score | INTEGER | Computed risk score |
| error | TEXT | Error message if failed |
| started_at | TEXT | ISO timestamp |
| completed_at | TEXT | ISO timestamp |
