<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Malwar

**Static analysis engine purpose-built for detecting malware in agentic AI skill files.**

---

## What is Malwar?

Malwar is a 4-layer malware detection engine designed to catch threats embedded in natural language markdown instructions -- the kind that direct AI agents to perform malicious actions. Unlike traditional scanners that analyze binaries or source code, Malwar detects prompt injection, social engineering, obfuscated commands, and data exfiltration hidden inside SKILL.md files used by agentic AI platforms.

**20% of ClawHub's 10,700+ skills are malicious.** The [ClawHavoc campaign](guide/threat-campaigns.md) alone trojanized 824+ skills to deliver the AMOS infostealer. VirusTotal sees nothing. Code scanners see nothing. Malwar was built to catch them.

---

## How It Works

```
SKILL.md --> Rule Engine --> URL Crawler --> LLM Analyzer --> Threat Intel --> Verdict
              <50ms          1-5s           2-10s            <100ms
```

| Layer | What It Catches |
|-------|-----------------|
| **Rule Engine** | Obfuscated commands, prompt injection, credential exposure, exfiltration patterns ([19 rules](guide/detection-rules.md)) |
| **URL Crawler** | Malicious URLs, domain reputation, redirect chains to C2 infrastructure |
| **LLM Analyzer** | Social engineering, hidden intent, context-dependent attacks invisible to regex |
| **Threat Intel** | Known IOCs, [campaign attribution](guide/threat-campaigns.md), threat actor fingerprints |

Full pipeline details: **[Architecture](development/architecture.md)**

---

## Key Features

- **19 detection rules** covering 7 threat categories
- **4-layer pipeline** combining speed with depth
- **Sub-50ms scans** for rule-based detection
- **SARIF 2.1.0 output** for CI/CD integration
- **REST API** with 16 endpoints, authentication, and rate limiting
- **Web dashboard** built with React 19 and TypeScript
- **Campaign tracking** with IOC correlation and attribution
- **STIX/TAXII export** for SIEM integration
- **Python SDK** for embedding scans in your tools
- **LangChain integration** with scan-before-execute guards
- **GitHub Action** for scanning skills in pull requests
- **Docker and Kubernetes** deployment with Helm chart

---

## Quick Install

```bash
git clone https://github.com/Ap6pack/malwar.git && cd malwar
pip install -e ".[dev]"
malwar db init
```

Or with Docker:

```bash
docker compose up -d    # API + Dashboard at http://localhost:8000
```

See the full [Installation Guide](getting-started/installation.md) for all options.

---

## Quick Scan

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

See the full [CLI Reference](guide/cli-reference.md) and [Quick Start Guide](getting-started/quickstart.md).

---

## Documentation

| Section | Description |
|---------|-------------|
| **[Getting Started](getting-started/installation.md)** | Installation, quick start, first scan |
| **[User Guide](guide/cli-reference.md)** | CLI, API, detection rules, threat campaigns |
| **[Integrations](integrations/sdk.md)** | Python SDK, LangChain, GitHub Action, STIX/TAXII |
| **[Deployment](deployment/docker.md)** | Docker, Kubernetes, production configuration |
| **[Development](development/architecture.md)** | Architecture, contributing, benchmarks |

---

## Detection Accuracy

Tested against 44 fixtures (31 labeled, 13 real-world ClawHub samples):

| Metric | Value |
|--------|-------|
| **Accuracy** | 96.8% |
| **Precision** | 95.8% |
| **Recall** | 100.0% |
| **F1 Score** | 97.9% |

Every malicious sample is detected. See the full [Accuracy Report](guide/accuracy-report.md).

---

**Proprietary** -- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved.
