# malwar

**Malware detection engine for agentic skills (SKILL.md)**

Agentic skill marketplaces like ClawHub host over 10,700 community-contributed skills, and research shows roughly 20% contain malicious content -- from credential stealers to prompt injection attacks. Traditional security tools like VirusTotal were designed for binary executables, not natural language threats embedded in Markdown files. malwar is a purpose-built static analysis engine that scans SKILL.md files through a multi-layer detection pipeline to identify obfuscated commands, social engineering tactics, data exfiltration patterns, and known threat campaign indicators before they reach your agent runtime.

---

## Key Features

- **4-layer detection pipeline** -- rule engine, URL crawler, LLM semantic analysis, and threat intelligence correlation
- **20 built-in detection rules** covering obfuscation, prompt injection, social engineering, credential theft, data exfiltration, and known malware campaigns
- **Sub-50ms rule engine scans** with optional deeper analysis layers
- **SARIF 2.1.0 output** for integration with GitHub Code Scanning, VS Code, and CI/CD pipelines
- **REST API** with batch scanning, signature management, campaign tracking, and reporting
- **Web dashboard** with scan history, threat visualizations, signature management, and campaign tracking
- **CLI-first design** -- scan files, directories, or pipe output to downstream tools
- **Extensible signature database** -- add custom IOC patterns (regex, exact, fuzzy) at runtime
- **Campaign attribution** -- link findings to known threat campaigns with IOC correlation
- **API key authentication** with configurable access control

---

## Architecture

malwar processes each SKILL.md file through four sequential detection layers. Layers can be selectively enabled or disabled per scan.

```
                    +------------------+
                    |   SKILL.md Input |
                    +--------+---------+
                             |
                    +--------v---------+
  Layer 1           |   Rule Engine    |  Pattern matching, regex, IOC signatures
  < 50ms            |   20 built-in    |  Obfuscation, prompt injection, exfiltration
                    +--------+---------+
                             |
                    +--------v---------+
  Layer 2           |   URL Crawler    |  Follow external references (links, repos)
  1-5s              |   Async HTTP     |  Detect redirects to malicious infrastructure
                    +--------+---------+
                             |
                    +--------v---------+
  Layer 3           |  LLM Analyzer    |  Semantic threat analysis via language model
  2-10s             |  Intent analysis |  Catches obfuscated social engineering
                    +--------+---------+
                             |
                    +--------v---------+
  Layer 4           |  Threat Intel    |  IOC correlation against signature database
  < 100ms          |  Campaign match  |  Known malware families, C2 infrastructure
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Scan Result     |
                    |  Verdict + Score |
                    +------------------+

  Verdicts: MALICIOUS | SUSPICIOUS | CAUTION | CLEAN
  Risk Score: 0-100 (weighted by severity)
```

---

## Detection Rules

| Rule ID | Title | Category | Severity | Description |
|---|---|---|---|---|
| `MALWAR-MAL-001` | ClawHavoc campaign indicator | Known Malware | Critical | C2 IPs, payload domains, malicious repos, known threat actors |
| `MALWAR-OBF-001` | Base64-encoded command execution | Obfuscated Command | Critical | Base64 strings piped to bash/sh for execution |
| `MALWAR-OBF-002` | Hex-encoded payload | Obfuscated Command | High | Long hex-encoded sequences hiding shell commands |
| `MALWAR-OBF-003` | Direct IP in curl/wget | Obfuscated Command | High | curl/wget using raw IPs instead of domains |
| `MALWAR-PI-001` | Direct prompt injection | Prompt Injection | Critical | Instruction override patterns (ignore previous, DAN, jailbreak) |
| `MALWAR-PI-002` | Unicode smuggling / homoglyph injection | Prompt Injection | High | Invisible Unicode characters hiding instructions |
| `MALWAR-PI-003` | Hidden instructions in HTML comments | Prompt Injection | High | HTML comments containing execution/exfiltration keywords |
| `MALWAR-SE-001` | ClickFix-style fake prerequisite | Social Engineering | High | Fake "Prerequisites" sections with dangerous commands |
| `MALWAR-SE-002` | Deceptive skill name (typosquatting) | Typosquatting | Medium | Misspellings of popular skill names |
| `MALWAR-SE-003` | Suspicious binary download in prerequisites | Social Engineering | Critical | Archive/binary downloads with passwords from paste sites |
| `MALWAR-CMD-001` | Remote script piped to shell | Suspicious Command | Critical | `curl ... \| bash` and variants |
| `MALWAR-CMD-002` | npx -y auto-execute | Suspicious Command | Medium | npx -y bypasses installation confirmation |
| `MALWAR-CMD-003` | Password-protected archive download | Suspicious Command | High | Password-protected archives bypass malware scanning |
| `MALWAR-CMD-004` | Download-and-execute pattern | Suspicious Command | High | Multi-step download then execute sequences |
| `MALWAR-CRED-001` | Hardcoded secret or API key | Credential Exposure | High | AWS keys, GitHub tokens, private keys, Slack tokens |
| `MALWAR-CRED-002` | Credential harvesting instruction | Credential Exposure | Critical | Instructions directing users to expose credentials |
| `MALWAR-EXFIL-001` | Agent memory/identity file access | Data Exfiltration | Critical | Access to SOUL.md, .env, .ssh, .aws/credentials |
| `MALWAR-EXFIL-002` | Cryptocurrency wallet file access | Data Exfiltration | Critical | Access to Bitcoin, Ethereum, MetaMask, Exodus wallet files |
| `MALWAR-EXFIL-003` | Data exfiltration via curl POST | Data Exfiltration | Critical | curl POST with command substitution sending local data |

---

## Quick Start

### Prerequisites

- Python 3.13+
- Node.js 20+ (optional, for the web dashboard)

### Installation

```bash
# Clone the repository
git clone <repo-url> malwar
cd malwar

# Install in development mode
pip install -e ".[dev]"

# Initialize the database
malwar db init
```

### First Scan

```bash
# Scan a single SKILL.md file
malwar scan path/to/SKILL.md

# Scan all .md files in a directory
malwar scan skills/

# Output as JSON
malwar scan SKILL.md --format json

# Fast scan (rule engine + threat intel only, no network calls)
malwar scan SKILL.md --no-llm --no-urls
```

---

## CLI Usage

```
malwar [COMMAND] [OPTIONS]
```

### `malwar scan`

Scan a SKILL.md file or directory for malware.

```bash
# Basic scan (all 4 layers)
malwar scan SKILL.md

# Scan a directory (processes all .md files)
malwar scan ./skills/

# Output formats
malwar scan SKILL.md --format console    # default, rich terminal output
malwar scan SKILL.md --format json       # structured JSON
malwar scan SKILL.md --format sarif      # SARIF 2.1.0 for CI/CD

# Write output to file
malwar scan SKILL.md --format sarif -o report.sarif

# Disable specific layers
malwar scan SKILL.md --no-llm            # skip LLM analysis
malwar scan SKILL.md --no-urls           # skip URL crawling
malwar scan SKILL.md --no-llm --no-urls  # rule engine + threat intel only

# Run specific layers
malwar scan SKILL.md --layers rule_engine,threat_intel
```

### `malwar serve`

Start the REST API server.

```bash
malwar serve                              # default: 127.0.0.1:8000
malwar serve --host 0.0.0.0 --port 9000  # custom bind address
malwar serve --workers 4                  # multi-worker mode
```

### `malwar db`

Database management commands.

```bash
malwar db init     # create schema and seed data
malwar db stats    # show row counts per table
```

### `malwar db-seed`

```bash
malwar db-seed     # insert seed data (campaigns, signatures, publishers)
```

### `malwar signature-list`

List all threat signatures in the database.

```bash
malwar signature-list
```

### `malwar signature-add`

Add a custom threat signature.

```bash
# Add a regex signature
malwar signature-add regex "evil-domain\.com" \
  --name "Evil Domain" \
  --severity critical \
  --category known_malware \
  --source manual

# Add an IOC signature
malwar signature-add ioc "198.51.100.23" \
  --name "Suspicious C2 Server" \
  --severity high \
  --ioc-type ip \
  --campaign-id campaign-001
```

### `malwar report-show`

Display a detailed scan report.

```bash
malwar report-show <scan-id>
```

### `malwar version`

```bash
malwar version
```

---

## API Reference

All endpoints are prefixed with `/api/v1`. Authentication is via the `X-API-Key` header when `MALWAR_API_KEYS` is configured.

### Health

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Service health check |
| `GET` | `/api/v1/ready` | Readiness check (database connectivity) |

### Scanning

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/scan` | Submit a SKILL.md for scanning |
| `POST` | `/api/v1/scan/batch` | Submit multiple SKILL.md files for batch scanning |
| `GET` | `/api/v1/scan/{scan_id}` | Retrieve a scan result by ID |
| `GET` | `/api/v1/scan/{scan_id}/sarif` | Get SARIF 2.1.0 output for a scan |
| `GET` | `/api/v1/scans` | List recent scans (query: `limit`) |

### Signatures

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/signatures` | List all signatures (query: `pattern_type`, `ioc_type`, `campaign_id`) |
| `GET` | `/api/v1/signatures/{sig_id}` | Get a signature by ID |
| `POST` | `/api/v1/signatures` | Create a new threat signature |
| `PUT` | `/api/v1/signatures/{sig_id}` | Update an existing signature |
| `DELETE` | `/api/v1/signatures/{sig_id}` | Delete a signature |

### Campaigns

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/campaigns` | List all active campaigns |
| `GET` | `/api/v1/campaigns/{campaign_id}` | Get campaign details with signature count |

### Reports

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/reports` | List scan reports (query: `verdict`, `min_risk_score`, `limit`) |
| `GET` | `/api/v1/reports/{scan_id}` | Full report with findings and severity/category/detector breakdowns |

### Scan Request Body

```json
{
  "content": "---\nname: my-skill\n---\n# My Skill\n...",
  "file_name": "SKILL.md",
  "layers": ["rule_engine", "url_crawler", "llm_analyzer", "threat_intel"],
  "use_llm": true
}
```

---

## Web Dashboard

The web dashboard provides a browser-based interface for scanning, reviewing results, and managing threat intelligence.

### Pages

| Page | Path | Description |
|---|---|---|
| Dashboard | `/` | Overview with scan statistics, recent activity, and risk distribution charts |
| Scan | `/scan` | Submit SKILL.md content for scanning via the browser |
| Scan Detail | `/scan/:scanId` | Detailed view of a scan result with findings, severity breakdown, and evidence |
| Scan History | `/scans` | Searchable list of all past scans with verdicts and risk scores |
| Signatures | `/signatures` | Browse and manage threat signatures in the database |
| Campaigns | `/campaigns` | View active threat campaigns, associated IOCs, and attribution |

### Development Mode

```bash
# Terminal 1: Start the API server
malwar serve

# Terminal 2: Start the Vite dev server
cd web
npm install
npm run dev
# Dashboard available at http://localhost:3000
```

### Production Build

```bash
cd web
npm run build    # outputs to web/dist/

# The API server automatically serves web/dist/ as static files
malwar serve
# Dashboard available at http://localhost:8000
```

---

## Configuration

All settings are configurable via environment variables with the `MALWAR_` prefix, or via a `.env` file in the working directory.

| Variable | Default | Description |
|---|---|---|
| `MALWAR_DB_PATH` | `malwar.db` | Path to the SQLite database file |
| `MALWAR_API_HOST` | `127.0.0.1` | API server bind address |
| `MALWAR_API_PORT` | `8000` | API server bind port |
| `MALWAR_API_WORKERS` | `1` | Number of uvicorn worker processes |
| `MALWAR_API_KEYS` | *(empty)* | Comma-separated API keys. Empty = auth disabled |
| `MALWAR_ANTHROPIC_API_KEY` | *(empty)* | Anthropic API key for the LLM analysis layer |
| `MALWAR_LLM_MODEL` | `claude-sonnet-4-20250514` | Model ID for LLM analysis |
| `MALWAR_LLM_MAX_TOKENS` | `4096` | Maximum tokens for LLM responses |
| `MALWAR_LLM_TEMPERATURE` | `0.0` | LLM temperature (0.0 = deterministic) |
| `MALWAR_LLM_SKIP_BELOW_RISK` | `15` | Skip LLM analysis if rule engine risk score is below this threshold |
| `MALWAR_CRAWLER_MAX_URLS` | `10` | Maximum URLs to crawl per scan |
| `MALWAR_CRAWLER_TIMEOUT` | `5.0` | HTTP timeout for URL crawling (seconds) |
| `MALWAR_CRAWLER_MAX_REDIRECTS` | `3` | Maximum redirect hops per URL |
| `MALWAR_CRAWLER_MAX_RESPONSE_BYTES` | `1048576` | Maximum response body size (1 MB) |
| `MALWAR_CRAWLER_CONCURRENCY` | `5` | Concurrent URL crawl requests |
| `MALWAR_SCAN_MAX_FILE_SIZE` | `524288` | Maximum SKILL.md file size (512 KB) |
| `MALWAR_SCAN_DEFAULT_LAYERS` | `rule_engine,url_crawler,llm_analyzer,threat_intel` | Layers to run by default |
| `MALWAR_LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARNING, ERROR) |
| `MALWAR_LOG_FORMAT` | `json` | Log format (json or text) |

---

## Testing

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run the full test suite
pytest

# Run with coverage report
pytest --cov=malwar --cov-report=term-missing

# Run specific test categories
pytest tests/unit/                    # unit tests
pytest tests/integration/             # integration tests
pytest tests/e2e/                     # end-to-end tests
pytest -m slow                        # slow tests only

# Linting and type checking
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/
```

**Current coverage**: 345 tests, 89% line coverage (minimum threshold: 85%).

---

## Tech Stack

### Backend

- **Python 3.13** -- runtime
- **FastAPI** -- REST API framework
- **Typer** -- CLI framework with Rich terminal output
- **Pydantic v2** -- data validation and settings management
- **aiosqlite** -- async SQLite database
- **httpx** -- async HTTP client for URL crawling
- **Anthropic SDK** -- LLM integration for semantic analysis
- **python-frontmatter** -- YAML frontmatter parsing for SKILL.md metadata
- **uvicorn** -- ASGI server

### Frontend

- **React 19** -- UI framework
- **TypeScript 5.9** -- type-safe frontend
- **Vite 7** -- build tooling and dev server
- **Tailwind CSS 4** -- utility-first styling
- **React Router 7** -- client-side routing
- **Recharts 3** -- data visualization and charts
- **Lucide React** -- icons

### Development

- **pytest** -- test framework with asyncio support
- **ruff** -- linter and formatter
- **mypy** -- static type checking
- **Hatchling** -- build system

---

## License

Proprietary -- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.

Unauthorized copying, modification, distribution, or use of this software, via any medium, is strictly prohibited without prior written permission from the copyright holder.
