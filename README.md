<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

<div align="center">

# Malwar

**Static analysis engine purpose-built for detecting malware in agentic AI skill files.**

[![PyPI version](https://img.shields.io/pypi/v/malwar)](https://pypi.org/project/malwar/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io%2Fap6pack%2Fmalwar-blue)](https://ghcr.io/ap6pack/malwar)
[![Docs](https://img.shields.io/badge/docs-ap6pack.github.io%2Fmalwar-blue)](https://ap6pack.github.io/malwar)
[![License](https://img.shields.io/badge/license-BSL--1.1-blue)](LICENSE)
[![CI](https://github.com/Ap6pack/malwar/actions/workflows/ci.yml/badge.svg)](https://github.com/Ap6pack/malwar/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13+-3776AB?logo=python&logoColor=white)](https://python.org)

![Detection Rules](https://img.shields.io/badge/detection_rules-19-orange)
![Pipeline Layers](https://img.shields.io/badge/pipeline_layers-4-green)
![SARIF](https://img.shields.io/badge/output-SARIF_2.1.0-purple)
![Coverage](https://img.shields.io/badge/coverage-89%25-brightgreen)

[Web Dashboard](#web-dashboard) &nbsp;&middot;&nbsp; [API Docs](docs/api-reference.md) &nbsp;&middot;&nbsp; [Detection Rules](docs/detection-rules.md) &nbsp;&middot;&nbsp; [Deployment](docs/deployment.md)

</div>

---

## Why

**20% of ClawHub's 10,700+ skills are malicious.** The [ClawHavoc campaign](docs/threat-campaigns.md) alone trojanized 824+ skills to deliver the AMOS infostealer. These attacks aren't binaries — they're natural language instructions hidden in Markdown files. VirusTotal sees nothing. Code scanners see nothing. Malwar was built to catch them.

## How It Works

```
SKILL.md → Rule Engine → URL Crawler → LLM Analyzer → Threat Intel → Verdict
             <50ms         1-5s          2-10s           <100ms
```

| Layer | What it catches |
|-------|-----------------|
| **Rule Engine** | Obfuscated commands, prompt injection, credential exposure, exfiltration patterns ([19 rules](docs/detection-rules.md)) |
| **URL Crawler** | Malicious URLs, domain reputation, redirect chains to C2 infrastructure |
| **LLM Analyzer** | Social engineering, hidden intent, context-dependent attacks invisible to regex |
| **Threat Intel** | Known IOCs, [campaign attribution](docs/threat-campaigns.md), threat actor fingerprints |

Full pipeline details: **[Architecture](docs/architecture.md)**

## Quick Start

```bash
pip install malwar
malwar db init
```

For development:

```bash
git clone https://github.com/Ap6pack/malwar.git && cd malwar
pip install -e ".[dev]"
malwar db init
```

```bash
malwar scan SKILL.md                    # scan a file
malwar scan skills/                     # scan a directory
malwar scan SKILL.md --format sarif     # CI/CD output
malwar scan SKILL.md --no-llm          # skip LLM (fast + free)
```

```
$ malwar scan suspicious-skill.md

  MALICIOUS  Risk: 95/100  Findings: 4

  MALWAR-OBF-001   Base64-encoded command execution        critical   L14
  MALWAR-CMD-001   Remote script piped to shell            critical   L22
  MALWAR-EXFIL-001 Agent memory/identity file access       critical   L31
  MALWAR-MAL-001   ClawHavoc campaign indicator            critical   L14

  Scan completed in 42ms (rule_engine, threat_intel)
```

Full command reference: **[CLI Guide](docs/cli-reference.md)**

## API

```bash
malwar serve    # http://localhost:8000
```

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"content": "...", "file_name": "SKILL.md"}'
```

16 endpoints covering scan submission, results, SARIF export, signatures CRUD, campaigns, and reports. Auth via `X-API-Key` header.

Full endpoint reference: **[API Docs](docs/api-reference.md)**

## Web Dashboard

Built-in browser UI at `http://localhost:8000` when running the API server.

![Dashboard](docs/images/dashboard.png)

| | |
|---|---|
| ![Scan Detail](docs/images/scan-detail.png) | ![Campaigns](docs/images/campaigns.png) |
| ![Signatures](docs/images/signatures.png) | ![Scan History](docs/images/scans.png) |

React 19 &middot; TypeScript &middot; Vite &middot; Tailwind CSS 4 &middot; Recharts

## Docker

```bash
docker compose up -d    # API + Dashboard at http://localhost:8000
```

Multi-stage build: Node.js compiles the frontend, Python 3.13-slim runs the backend.

Full deployment guide: **[Deployment](docs/deployment.md)**

## Configuration

All settings via environment variables with `MALWAR_` prefix or `.env` file. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `MALWAR_API_KEYS` | *(empty)* | API keys (empty = auth disabled) |
| `MALWAR_ANTHROPIC_API_KEY` | *(empty)* | Anthropic key for LLM layer |
| `MALWAR_DB_PATH` | `malwar.db` | SQLite database path |

[All 17 configuration options →](docs/deployment.md#configuration)

## Development

```bash
pytest                                # 345 tests
ruff check src/ tests/                # lint
mypy src/                             # type check
```

37 test fixtures: 5 benign, 10 malicious (synthetic), 22 real-world samples from ClawHub and Snyk research.

Full dev guide: **[Development](docs/development.md)**

## Documentation

| | |
|---|---|
| **[Architecture](docs/architecture.md)** | Pipeline design, scoring logic, storage layer |
| **[API Reference](docs/api-reference.md)** | All 16 endpoints with schemas and examples |
| **[Detection Rules](docs/detection-rules.md)** | All 19 rules with patterns and false positive guidance |
| **[Threat Campaigns](docs/threat-campaigns.md)** | Campaign tracking, ClawHavoc case study |
| **[CLI Reference](docs/cli-reference.md)** | Every command with flags and examples |
| **[Deployment](docs/deployment.md)** | pip, Docker, nginx, production config |
| **[Development](docs/development.md)** | Adding rules, endpoints, testing, conventions |

---

**BSL-1.1** — Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
