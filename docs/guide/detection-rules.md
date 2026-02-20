<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Detection Rules Reference

## Overview

malwar's Layer 1 (Rule Engine) contains a comprehensive set of pattern-matching rules that detect known malicious patterns in SKILL.md files. Each rule is identified by a unique ID following the `MALWAR-{CATEGORY}-{NUMBER}` convention.

Rules are organized into 7 categories covering the primary attack vectors observed in the agentic skill threat landscape.

## Rule Categories

| Category Prefix | Category Name | Description |
|---|---|---|
| `MALWAR-OBF-*` | Obfuscation | Encoded/obfuscated commands designed to evade detection |
| `MALWAR-PI-*` | Prompt Injection | Attempts to override AI agent instructions |
| `MALWAR-CRED-*` | Credential Exposure | Hardcoded secrets and credential harvesting |
| `MALWAR-EXFIL-*` | Data Exfiltration | Access to sensitive files and data transmission |
| `MALWAR-MAL-*` | Known Malware | IOCs from known malware campaigns |
| `MALWAR-SE-*` | Social Engineering | Deceptive instructions including ClickFix attacks |
| `MALWAR-CMD-*` | Suspicious Commands | Dangerous shell execution patterns |

---

## Obfuscation Rules

### MALWAR-OBF-001 -- Base64-encoded command execution

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | obfuscated_command |
| **Confidence** | 0.95 |

Detects base64-encoded strings piped to bash/sh execution. The rule attempts to decode the base64 string and includes the decoded content as evidence.

**Patterns detected:**

- `echo '<base64>' | base64 -d | bash`
- `$(echo '<base64>' | base64 ...)`
- `base64 -d <<< '<base64>'`

---

### MALWAR-OBF-002 -- Hex-encoded payload

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | obfuscated_command |
| **Confidence** | 0.85 |

Detects long sequences of hex-encoded characters (`\xNN`) that may decode to shell commands. Sequences must contain 11 or more consecutive hex escapes.

---

### MALWAR-OBF-003 -- Direct IP address in curl/wget command

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | obfuscated_command |
| **Confidence** | 0.80 |

Detects `curl` or `wget` commands using raw IP addresses instead of domain names. Private/loopback IP ranges are excluded.

---

## Prompt Injection Rules

### MALWAR-PI-001 -- Direct prompt injection

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | prompt_injection |
| **Confidence** | 0.90 |

Detects explicit instruction override patterns: `ignore all previous instructions`, `disregard your rules`, `you are now DAN`, `new system prompt:`, etc.

---

### MALWAR-PI-002 -- Unicode smuggling / homoglyph injection

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | prompt_injection |
| **Confidence** | 0.75 |

Detects invisible Unicode characters or homoglyphs used to hide instructions from human review. Triggers when 3 or more suspicious Unicode characters are found on a single line.

---

### MALWAR-PI-003 -- Hidden instructions in HTML comments

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | prompt_injection |
| **Confidence** | 0.80 |

Detects HTML comments containing instruction-like content with 2 or more action-oriented keywords.

---

## Credential Exposure Rules

### MALWAR-CRED-001 -- Hardcoded secret or API key

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | credential_exposure |
| **Confidence** | 0.85 |

Detects hardcoded API keys (AWS, GitHub, Anthropic, OpenAI, Slack) and private keys embedded in skill content.

---

### MALWAR-CRED-002 -- Credential harvesting instruction

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | credential_exposure |
| **Confidence** | 0.88 |

Detects instructions that direct users to expose credentials to external services.

---

## Data Exfiltration Rules

### MALWAR-EXFIL-001 -- Agent memory/identity file access

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | data_exfiltration |
| **Confidence** | 0.90 |

Detects access to AI agent identity and memory files (SOUL.md, MEMORY.md, ~/.claude/, ~/.ssh/, ~/.aws/credentials).

---

### MALWAR-EXFIL-002 -- Cryptocurrency wallet file access

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | data_exfiltration |
| **Confidence** | 0.88 |

Detects access to known cryptocurrency wallet file paths and browser extension data directories.

---

### MALWAR-EXFIL-003 -- Data exfiltration via curl POST

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | data_exfiltration |
| **Confidence** | 0.88 |

Detects `curl` commands that send local data to external endpoints using command substitution.

---

## Known Malware Rules

### MALWAR-MAL-001 -- ClawHavoc campaign indicator

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | known_malware |
| **Confidence** | 0.95 -- 0.99 |

Detects known IOCs associated with the ClawHavoc campaign: C2 IP (`91.92.242.30`), payload domains, malicious repos, and known threat actor accounts.

See [Threat Campaigns](threat-campaigns.md) for full campaign details.

---

## Social Engineering Rules

### MALWAR-SE-001 -- ClickFix-style fake prerequisite installation

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | social_engineering |
| **Confidence** | 0.90 |

Detects fake "Prerequisites" sections that instruct users to run dangerous commands (`curl | bash`, `npx -y`, non-HTTPS pip install, etc.).

---

### MALWAR-SE-002 -- Deceptive skill name (potential typosquatting)

| Property | Value |
|---|---|
| **Severity** | MEDIUM |
| **Category** | typosquatting |
| **Confidence** | 0.70 |

Detects skill names containing common misspellings of popular skill names.

---

### MALWAR-SE-003 -- Suspicious binary download in prerequisites

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | social_engineering |
| **Confidence** | 0.92 |

Detects prerequisite sections that direct users to download executables from untrusted sources, especially with passwords or paste site links.

---

## Suspicious Command Rules

### MALWAR-CMD-001 -- Remote script piped to shell

| Property | Value |
|---|---|
| **Severity** | CRITICAL |
| **Category** | suspicious_command |
| **Confidence** | 0.92 |

Detects `curl` or `wget` output piped directly to `bash` or `sh` for execution.

---

### MALWAR-CMD-002 -- npx -y auto-execute without review

| Property | Value |
|---|---|
| **Severity** | MEDIUM |
| **Category** | suspicious_command |
| **Confidence** | 0.60 |

Detects `npx -y` which auto-installs and executes npm packages without confirmation.

---

### MALWAR-CMD-003 -- Password-protected archive download

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | suspicious_command |
| **Confidence** | 0.82 |

Detects downloads of password-protected archives, which prevent automated scanning.

---

### MALWAR-CMD-004 -- Download-and-execute pattern

| Property | Value |
|---|---|
| **Severity** | HIGH |
| **Category** | suspicious_command |
| **Confidence** | 0.78 |

Detects multi-step patterns where a script is downloaded and then executed.

---

## URL Crawler Findings (Layer 2)

The URL crawler produces runtime detections including:

- **url_known_malicious** -- Known-malicious domain (CRITICAL, 0.95)
- **url_redirect_chain** -- Cross-domain redirect chain (MEDIUM, 0.70)
- **url_content_type_mismatch** -- Content-type mismatch (HIGH, 0.80)
- **url_serves_shell_script** -- URL serves shell script (HIGH, 0.85)
- **url_serves_powershell_script** -- URL serves PowerShell script (HIGH, 0.85)
- **url_serves_binary** -- URL serves binary/archive content (MEDIUM, 0.75)
- **url_malware_pattern** -- Malware indicator in URL response (HIGH, 0.80)

---

## LLM Analyzer Findings (Layer 3)

LLM findings have dynamic IDs (`MALWAR-LLM-{NNN}`) and are produced by Claude's semantic analysis covering social engineering, prompt injection, data exfiltration, malware delivery, credential theft, and deception.

---

## Threat Intelligence Findings (Layer 4)

Threat intel findings (`MALWAR-TI-{SIGNATURE_ID}`) are produced by matching IOCs against the signature database with campaign attribution.
