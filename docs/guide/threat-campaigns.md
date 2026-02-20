<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Threat Campaigns

## Overview

Malwar tracks coordinated malware campaigns that target the agentic skill ecosystem. A campaign represents an organized effort by threat actors to distribute malicious skills through platforms like ClawHub. Campaign tracking enables attribution, IOC sharing, and proactive detection of new variants.

## Campaign Data Model

Each campaign is stored in the `campaigns` database table with the following fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique campaign identifier (e.g., `campaign-clawhavoc-001`) |
| `name` | string | Human-readable campaign name |
| `description` | string | Detailed description of the campaign's tactics, techniques, and procedures |
| `first_seen` | datetime | Date the campaign was first observed |
| `last_seen` | datetime | Date of the most recent observed activity |
| `attributed_to` | string | Known threat actor handles or groups |
| `iocs` | string[] | List of Indicators of Compromise |
| `total_skills_affected` | integer | Number of skills confirmed to be part of this campaign |
| `status` | string | Campaign status: `active`, `inactive`, or `monitoring` |

## How Campaigns Work in malwar

### Detection Flow

1. **Layer 1 (Rule Engine):** The `MALWAR-MAL-001` rule performs hardcoded IOC matching for known campaigns.
2. **Layer 2 (URL Crawler):** Domain reputation checks identify URLs pointing to known-malicious infrastructure.
3. **Layer 3 (LLM Analyzer):** Semantic analysis identifies campaign-specific patterns.
4. **Layer 4 (Threat Intelligence):** The `ThreatIntelMatcher` correlates all IOCs against the signature database and attributes findings to campaigns.

### API Access

Campaigns can be queried via the REST API:

- `GET /api/v1/campaigns` -- List all active campaigns
- `GET /api/v1/campaigns/{campaign_id}` -- Get campaign details with signature count

---

## Case Study: The ClawHavoc Campaign

### Background

ClawHavoc is the largest known malware campaign targeting the agentic skill ecosystem. First observed in January 2026, it has compromised 824+ skills on ClawHub, representing a significant portion of the platform's malicious content.

### Threat Actor Profile

| Attribute | Details |
|---|---|
| **Campaign Name** | ClawHavoc |
| **First Seen** | 2026-01-15 |
| **Last Seen** | 2026-02-10 |
| **Status** | Active |
| **Malware Payload** | AMOS (Atomic macOS Stealer) infostealer |
| **Primary Target** | macOS users of AI agent tools |
| **Affected Skills** | 824+ confirmed |

### Known Threat Actors

| Handle | Role |
|---|---|
| zaycv | Primary operator, most prolific publisher |
| Ddoy233 | GitHub repository operator |
| hightower6eu | Secondary operator |
| clawdhub1 | Publisher account for mass skill uploads |
| Aslaep123, moonshine-100rze, pepe276, hedefbari | Publisher accounts |

### Attack Chain

```
1. PUBLISH: Attacker publishes a skill on ClawHub
2. PREREQUISITES: Skill directs user to download a "required tool"
3. DOWNLOAD: User downloads a trojanized archive (.zip, .dmg, .pkg)
4. EXECUTE: AMOS infostealer activates
5. EXFILTRATE: Stolen data sent to C2 at 91.92.242.30
```

### Indicators of Compromise

| IOC Type | Value | Description |
|---|---|---|
| C2 IP | `91.92.242.30` | Primary command-and-control server |
| Domain | `download.setup-service.com` | Payload delivery domain |
| Domain | `openclawcli.vercel.app` | Trojanized CLI hosting |
| URL | `glot.io/snippets/hfd3x9ueu5` | Payload staging snippet |
| GitHub Repo | `Ddoy233/openclawcli` | Trojanized OpenClaw CLI repository |

---

## Case Study: The SnykToxic Campaign

### Background

SnykToxic is a data exfiltration campaign discovered through Snyk's ToxicSkills research. The research scanned 3,984 skills from ClawHub and skills.sh, finding 76 confirmed malicious payloads. SnykToxic skills exfiltrate host information, environment variables, and credentials via Vercel deployments and Google Apps Script webhooks.

### Threat Actor Profile

| Attribute | Details |
|---|---|
| **Campaign Name** | SnykToxic |
| **First Seen** | 2026-01-20 |
| **Last Seen** | 2026-02-15 |
| **Status** | Active |
| **Affected Skills** | 76 confirmed |

### Known Threat Actors

| Handle | Role |
|---|---|
| aztr0nutzs | Primary operator, NET_NiNjA repository maintainer |
| denboss99 | Repository operator, openclaw-core payload distributor |

### References

- [Snyk ToxicSkills Research](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- [How a Malicious Google Skill on ClawHub Tricks Users Into Installing Malware](https://snyk.io/blog/clawhub-malicious-google-skill-openclaw-malware/)

---

## Case Study: The ShadowPkg Campaign

### Background

ShadowPkg is a supply chain campaign that distributes trojanized npm and pip packages through the prerequisites sections of agent skills. Rather than embedding malware directly in the skill, ShadowPkg skills instruct users to install typosquatted packages or pull from attacker-controlled registries.

### Threat Actor Profile

| Attribute | Details |
|---|---|
| **Campaign Name** | ShadowPkg |
| **First Seen** | 2026-01-28 |
| **Last Seen** | 2026-02-18 |
| **Status** | Active |
| **Affected Skills** | 42 confirmed |

### Known Threat Actors

| Handle | Role |
|---|---|
| ScaffoldPro | Primary operator |

### Package IOCs

| Package | Description |
|---|---|
| `crossenv` | Typosquat of `cross-env` |
| `colourfool` | Typosquat of `colorful` |
| `python3-dateutil` | Typosquat of `python-dateutil` |
| `babelcli` | Typosquat of `babel-cli` |
| `lodash-utils` | Typosquat of `lodash` |

---

## Adding New Campaigns

### Step 1: Define the Campaign

Add a campaign record via the API or SQL.

### Step 2: Create Threat Signatures

```bash
malwar signature-add exact "198.51.100.1" \
  --name "NewCampaign C2" \
  --severity critical \
  --category known_malware \
  --ioc-type ip \
  --campaign-id campaign-newcampaign-001
```

### Step 3: Add Known Publishers

Add threat actor handles to the publishers table with `is_known_threat_actor=1`.

### Step 4: Verify Detection

```bash
malwar scan tests/fixtures/skills/malicious/new_campaign_sample.md
```

### Best Practices

1. **Use multiple signature types** -- Add signatures for IPs, domains, URLs, and author handles.
2. **Update `last_seen` dates** when new activity is observed.
3. **Track skill counts** as new malicious skills are attributed.
4. **Use regex signatures** for IOCs with predictable variations.
