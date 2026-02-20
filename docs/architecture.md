<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# malwar Architecture

## Overview

malwar is a 4-layer malware detection engine purpose-built for scanning agentic skills -- specifically SKILL.md files used in the OpenClaw/ClawHub ecosystem. Unlike traditional malware scanners that analyze binary executables or source code, malwar detects threats embedded in natural language markdown instructions that direct AI agents to perform malicious actions.

The threat landscape is significant: approximately 20% of ClawHub's 10,700+ published skills are confirmed malicious. The ClawHavoc campaign alone accounts for 824+ malicious skills delivering the AMOS infostealer. Existing security tools (VirusTotal, Cisco Skill Scanner, SecureClaw, Snyk ToxicSkills) all fail at natural language threat detection because attacks are markdown instructions, not code.

## System Architecture Diagram

```
                    +------------------+
                    |   Entry Points   |
                    +------------------+
                    |  CLI  |   API    |
                    | typer | FastAPI  |
                    +---+-------+------+
                        |       |
                        v       v
              +--------------------------+
              |     SKILL.md Parser      |
              | (frontmatter + markdown) |
              +------------+-------------+
                           |
                           v
              +---------------------------+
              |     Scan Pipeline          |
              |    (ScanPipeline)          |
              +---------------------------+
              |                           |
              |  +---------------------+  |
              |  |  Layer 1 (order=10) |  |
              |  |   Rule Engine       |  |
              |  | Pattern matching    |  |
              |  +--------+------------+  |
              |           |               |
              |           v               |
              |  +---------------------+  |
              |  |  Layer 2 (order=20) |  |
              |  |   URL Crawler       |  |
              |  | Fetch & analyze URLs|  |
              |  +--------+------------+  |
              |           |               |
              |           v               |
              |  +---------------------+  |
              |  |  Layer 3 (order=30) |  |
              |  |   LLM Analyzer      |  |
              |  | Semantic analysis   |  |
              |  +--------+------------+  |
              |           |               |
              |           v               |
              |  +---------------------+  |
              |  |  Layer 4 (order=40) |  |
              |  |   Threat Intel      |  |
              |  | IOC correlation     |  |
              |  +--------+------------+  |
              |           |               |
              +---------------------------+
                          |
                          v
              +---------------------------+
              |       ScanResult          |
              | verdict / risk_score /    |
              | findings / severity       |
              +---------------------------+
                    |           |
                    v           v
              +---------+  +---------+
              | SQLite  |  | Output  |
              |   DB    |  | Console |
              |         |  | JSON    |
              |         |  | SARIF   |
              +---------+  +---------+
```

## Core Components

### Entry Points

malwar provides two interfaces for users:

1. **CLI** (`malwar.cli.app`) -- A Typer-based command-line interface for scanning files, managing the database, listing signatures, and starting the API server.

2. **REST API** (`malwar.api.app`) -- A FastAPI web server with endpoints for scanning, retrieving results, managing threat signatures, viewing campaigns, and generating reports. Includes a React frontend served from `web/dist/` in production mode.

### SKILL.md Parser

The parser (`malwar.parsers.skill_parser`) transforms raw SKILL.md content into a structured `SkillContent` object:

1. **Frontmatter Extraction** -- Uses the `python-frontmatter` library to parse YAML frontmatter into `SkillMetadata` (name, author, description, tags, tools, source_url, author_url, version, icon).

2. **Markdown Body Parsing** (`malwar.parsers.markdown_parser`) -- Extracts:
   - **URLs** -- Both markdown links `[text](url)` and bare `https://` URLs
   - **Code Blocks** -- Fenced code blocks with language, content, and line numbers
   - **Sections** -- Heading-delimited sections with level, content, and line ranges

3. **Content Hashing** -- Computes SHA-256 hash of the raw content for deduplication and tracking.

### ScanContext

The `ScanContext` dataclass (`malwar.scanner.context`) is the mutable state object that flows through the pipeline:

```
ScanContext
  +-- skill: SkillContent           # Parsed skill content
  +-- scan_id: str                  # Unique scan identifier
  +-- findings: list[Finding]       # Accumulated findings from all layers
  +-- url_analysis_results: dict    # URL crawler enrichment data
  +-- llm_analysis: dict            # LLM analyzer enrichment data
  +-- matched_campaigns: list[str]  # Campaigns matched by threat intel
  +-- errors: list[str]             # Non-fatal errors from any layer
  +-- metadata: dict                # Arbitrary enrichment metadata
```

Each layer reads the context to access previous layers' findings and enrichments, then adds its own findings to the shared list via `context.add_findings()`.

The context also computes a running `current_risk_score` property used for cost-control decisions (e.g., skipping expensive LLM analysis when early layers found nothing suspicious).

## The 4-Layer Detection Pipeline

### Pipeline Orchestration

The `ScanPipeline` class (`malwar.scanner.pipeline`) orchestrates the 4 detection layers sequentially. Detectors are registered with the pipeline and sorted by their `order` property.

**Execution flow:**

```
1. Create ScanContext with parsed SkillContent
2. Create ScanResult (status=RUNNING)
3. For each registered detector (sorted by order):
   a. Check if layer is in the allowed layers list
   b. Check cost-control skip conditions
   c. Run detector.detect(context) -> list[Finding]
   d. Add findings to context
   e. Record layer in result.layers_executed
4. Compute final risk_score, verdict, severity
5. Return ScanResult (status=COMPLETED)
```

**Layer selection:** The `layers` parameter allows callers to specify which layers to run. If omitted, all registered layers execute.

**Error isolation:** If a detector raises an exception, the error is logged and recorded in `context.errors` and `result.errors`, but the pipeline continues to the next layer.

### Layer 1: Rule Engine (order=10)

**Module:** `malwar.detectors.rule_engine`

The rule engine performs fast, deterministic pattern matching against the skill content. It is always the first layer to run and produces the initial risk signal.

**Architecture:**

- `BaseRule` -- Abstract base class defining the rule interface (`check(skill) -> list[Finding]`)
- `RuleRegistry` -- Central registry using a `@rule` decorator for auto-registration
- `RuleEngineDetector` -- The `BaseDetector` implementation that iterates all enabled rules

**Rule categories:**

| Category | Rules | What it Detects |
|---|---|---|
| Obfuscation | MALWAR-OBF-001 to OBF-003 | Base64 commands, hex payloads, raw IP in commands |
| Prompt Injection | MALWAR-PI-001 to PI-003 | Instruction overrides, Unicode smuggling, hidden HTML comments |
| Credential Exposure | MALWAR-CRED-001 to CRED-002 | Hardcoded secrets, credential harvesting instructions |
| Data Exfiltration | MALWAR-EXFIL-001 to EXFIL-003 | Agent memory access, curl POST exfil, crypto wallet access |
| Known Malware | MALWAR-MAL-001 | ClawHavoc C2 IPs, domains, repos, known authors |
| Social Engineering | MALWAR-SE-001 to SE-003 | ClickFix fake prerequisites, suspicious downloads, typosquatting |
| Suspicious Commands | MALWAR-CMD-001 to CMD-004 | Piped execution, npx -y, password archives, download-and-execute |

### Layer 2: URL Crawler (order=20)

**Module:** `malwar.detectors.url_crawler`

The URL crawler extracts, evaluates, fetches, and analyzes all URLs found in the skill content. It operates in 5 steps:

```
Step 1: Extract URLs
  |  (extractor.py: markdown links, bare URLs, frontmatter URLs, code blocks)
  v
Step 2: Check Domain Reputation
  |  (reputation.py: known-malicious=0.0, IP=0.2, paste-site=0.3, safe=1.0, unknown=0.5)
  v
Step 3: Fetch Suspicious URLs (reputation <= 0.6)
  |  (fetcher.py: HEAD pre-check, concurrent GET with safety bounds)
  v
Step 4: Analyze Fetched Content
  |  (analyzer.py: redirect chains, content-type mismatch, shell/PS scripts, binaries, malware patterns)
  v
Step 5: Store Enrichment in Context
```

**Safety bounds:** The `SafeFetcher` class enforces configurable limits:
- Maximum URLs per batch (default: 10)
- Per-request timeout (default: 5s)
- Maximum redirects (default: 3)
- Maximum response body size (default: 1 MB)
- Concurrency limit (default: 5)

**Known-safe domains** are never fetched (score=1.0): github.com, docs.python.org, pypi.org, npmjs.com, developer.mozilla.org, stackoverflow.com, wikipedia.org, docs.anthropic.com, openai.com, google.com.

### Layer 3: LLM Analyzer (order=30)

**Module:** `malwar.detectors.llm_analyzer`

The LLM analyzer sends the full skill content to Claude (via the Anthropic API) for semantic threat analysis. This layer detects attacks that rules cannot catch -- social engineering, deceptive intent, and sophisticated prompt injection.

**Cost control:** The LLM layer is skipped when the current risk score from earlier layers is below the `llm_skip_below_risk` threshold (default: 15). This means benign-looking skills avoid the API call entirely.

**Prompt structure:**

1. **System prompt** -- Instructs Claude to act as a cybersecurity analyst. Includes critical anti-prompt-injection safeguards telling Claude to treat all skill content as data, never as instructions.

2. **User prompt** -- Contains:
   - Skill metadata (name, author, tags, tools)
   - Summary of prior findings from layers 1 and 2
   - Full SKILL.md content

3. **Response format** -- Structured JSON with `threat_assessment`, `confidence`, `findings[]`, and `summary`.

**Response parsing** (`parser.py`):
- Handles raw JSON, JSON in markdown fences, trailing text
- Maps LLM categories to `ThreatCategory` enum values
- Maps LLM severity strings to `Severity` enum values
- Resolves `line_hint` strings to actual line numbers in the source

### Layer 4: Threat Intelligence (order=40)

**Module:** `malwar.detectors.threat_intel`

The threat intelligence layer correlates IOCs (Indicators of Compromise) extracted from all previous layers against a known threat signature database.

**IOC extraction sources:**
- `ioc_values` and `evidence` from all prior findings
- Skill metadata: author, source_url, author_url
- Extracted URLs from the skill
- Full raw content (for substring matching)

**Signature matching:**
- **Exact match** -- Substring search of the pattern value in any IOC
- **Regex match** -- Compiled regex pattern searched across all IOCs

**Campaign attribution:** When a signature matches, the associated campaign is recorded in `context.matched_campaigns`. This enables campaign-level tracking and reporting.

**Hardcoded fallback signatures:** When no database signatures are available, the matcher falls back to hardcoded ClawHavoc signatures (C2 IP, Glot snippet, payload domain, known author).

## Scoring and Verdict System

### Risk Score Calculation

Risk score is computed as a weighted sum of all findings, capped at 100:

```
risk_score = min(100, sum(SEVERITY_WEIGHT[f.severity] * f.confidence for f in findings))
```

**Severity weights:**

| Severity | Weight |
|---|---|
| CRITICAL | 100 |
| HIGH | 75 |
| MEDIUM | 50 |
| LOW | 25 |
| INFO | 0 |

A single CRITICAL finding with confidence 0.95 produces a risk score of 95. A single HIGH finding with confidence 0.85 produces 63.

### Verdict Mapping

| Risk Score Range | Verdict |
|---|---|
| 75 -- 100 | MALICIOUS |
| 40 -- 74 | SUSPICIOUS |
| 15 -- 39 | CAUTION |
| 0 -- 14 | CLEAN |

### Overall Severity

The `overall_severity` of a scan is the highest severity among all findings. If no findings exist, it defaults to `info`.

## Data Flow

```
SKILL.md file/content
        |
        v
  parse_skill_content() / parse_skill_file()
        |
        v
  SkillContent (metadata + body + code_blocks + URLs + sections + SHA-256)
        |
        v
  ScanPipeline.scan(skill, layers)
        |
        +---> ScanContext created
        |
        +---> Layer 1: RuleEngine  --> findings added to context
        |
        +---> Layer 2: URLCrawler  --> findings + url_analysis_results added
        |
        +---> Layer 3: LLMAnalyzer --> findings + llm_analysis added
        |                              (skipped if risk < threshold)
        |
        +---> Layer 4: ThreatIntel --> findings + matched_campaigns added
        |
        v
  ScanResult
    +-- scan_id, target, status
    +-- risk_score (computed property)
    +-- verdict (computed property: MALICIOUS/SUSPICIOUS/CAUTION/CLEAN)
    +-- overall_severity (computed property)
    +-- findings[] (all findings from all layers)
    +-- layers_executed[]
    +-- errors[]
    +-- duration_ms
```

## Storage Layer

malwar uses SQLite with WAL mode via `aiosqlite` for persistence.

**Database tables:**

| Table | Purpose |
|---|---|
| `scans` | Scan results with verdict, risk score, timing |
| `findings` | Individual threat findings linked to scans (FK cascade) |
| `signatures` | Threat intelligence signatures for IOC matching |
| `campaigns` | Tracked malware campaigns with IOCs and attribution |
| `publishers` | Author/publisher reputation tracking |
| `url_analysis` | URL fetch results linked to scans |

**Indexes** are created on scans (target, sha256, verdict, created_at) and findings (scan_id, rule_id, severity, category) for query performance.

**Migrations** run automatically on database initialization using `CREATE TABLE IF NOT EXISTS` and `INSERT OR IGNORE` for idempotent schema and seed data creation.

## Notification System

The webhook notifier (`malwar.notifications.webhook`) dispatches JSON payloads to configured webhook URLs when a scan produces a MALICIOUS or SUSPICIOUS verdict. Webhooks are fire-and-forget: failures are logged but never block the scan pipeline.

**Webhook payload:**
```json
{
  "scan_id": "abc123",
  "verdict": "MALICIOUS",
  "risk_score": 95,
  "finding_count": 7,
  "skill_name": "Suspicious Tool",
  "top_findings": [
    {
      "rule_id": "MALWAR-CMD-001",
      "title": "Remote script piped to shell",
      "severity": "critical",
      "confidence": 0.92,
      "category": "suspicious_command"
    }
  ]
}
```

## Frontend

malwar includes a React + TypeScript frontend (in `web/`) built with Vite. In production, the compiled frontend assets are served by FastAPI from `web/dist/`. In development, the Vite dev server runs on port 3000 with CORS configured to proxy API calls to the FastAPI backend on port 8000.

## Output Formats

malwar supports three output formats for scan results:

1. **Console** -- Rich-formatted terminal output with color-coded severity, verdict banners, and finding details.

2. **JSON** -- Full Pydantic model serialization of `ScanResult`.

3. **SARIF 2.1.0** -- Static Analysis Results Interchange Format for integration with GitHub Code Scanning, VS Code, and other SARIF-compatible tools. Severity is mapped: CRITICAL/HIGH to `error`, MEDIUM to `warning`, LOW/INFO to `note`.

## Configuration

All settings are managed via environment variables with the `MALWAR_` prefix, loaded from `.env` files using Pydantic Settings. Key configuration areas:

- **Database** -- `MALWAR_DB_PATH`
- **API Server** -- `MALWAR_API_HOST`, `MALWAR_API_PORT`, `MALWAR_API_WORKERS`
- **Authentication** -- `MALWAR_API_KEYS` (comma-separated)
- **LLM** -- `MALWAR_ANTHROPIC_API_KEY`, `MALWAR_LLM_MODEL`, `MALWAR_LLM_SKIP_BELOW_RISK`
- **URL Crawler** -- `MALWAR_CRAWLER_MAX_URLS`, `MALWAR_CRAWLER_TIMEOUT`, `MALWAR_CRAWLER_CONCURRENCY`
- **Rate Limiting** -- `MALWAR_RATE_LIMIT_RPM`
- **Logging** -- `MALWAR_LOG_LEVEL`, `MALWAR_LOG_FORMAT`
- **Webhooks** -- `MALWAR_WEBHOOK_URLS` (comma-separated)
