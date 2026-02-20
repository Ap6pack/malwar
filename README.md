# malwar

Malware detection engine for agentic skills (SKILL.md).

## Overview

4-layer detection pipeline for identifying malicious content in SKILL.md files:

1. **Rule Engine** — Pattern matching, regex, signatures
2. **URL Crawler** — External reference analysis
3. **LLM Analyzer** — Semantic threat analysis
4. **Threat Intel** — IOC correlation and campaign attribution

## Usage

```bash
# Scan a single file
malwar scan path/to/SKILL.md

# Scan a directory
malwar scan skills/

# Output as SARIF
malwar scan SKILL.md --format sarif -o report.sarif

# Skip LLM layer
malwar scan SKILL.md --no-llm

# Start API server
malwar serve
```

## License

Proprietary — Veritas Aequitas Holdings LLC.
