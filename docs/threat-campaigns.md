<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Threat Campaigns

## Overview

malwar tracks coordinated malware campaigns that target the agentic skill ecosystem. A campaign represents an organized effort by threat actors to distribute malicious skills through platforms like ClawHub. Campaign tracking enables attribution, IOC sharing, and proactive detection of new variants.

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
| `iocs` | string[] | List of Indicators of Compromise (IPs, domains, URLs, hashes, usernames) |
| `total_skills_affected` | integer | Number of skills confirmed to be part of this campaign |
| `status` | string | Campaign status: `active`, `inactive`, or `monitoring` |
| `signature_ids` | string[] | IDs of threat signatures linked to this campaign |

## How Campaigns Work in malwar

### Campaign-Signature Relationship

Campaigns are linked to threat signatures through the `campaign_id` field on the `signatures` table. When a signature matches during Layer 4 (Threat Intelligence) detection, the associated campaign is recorded in the scan context.

```
Campaign
  |
  +-- has many -> Signatures
  |     |
  |     +-- pattern_type: exact | regex
  |     +-- pattern_value: "91.92.242.30"
  |     +-- ioc_type: ip | domain | url | hash | email
  |
  +-- has many -> IOCs (stored as JSON array)
  +-- attributed_to -> Threat actor handles
```

### Detection Flow

1. **Layer 1 (Rule Engine):** The `MALWAR-MAL-001` rule performs hardcoded IOC matching for known campaigns (e.g., ClawHavoc C2 IPs, domains, repos, authors).

2. **Layer 2 (URL Crawler):** Domain reputation checks identify URLs pointing to known-malicious infrastructure. The reputation database includes campaign-specific domains.

3. **Layer 3 (LLM Analyzer):** Semantic analysis may identify campaign-specific patterns (e.g., the AMOS infostealer's characteristic prerequisite-download-execute flow).

4. **Layer 4 (Threat Intelligence):** The `ThreatIntelMatcher` correlates all IOCs from prior layers against the signature database. When a signature matches, its `campaign_id` is used to attribute the finding to a specific campaign.

### Campaign Attribution in Results

When a scan matches one or more campaigns, the campaign names are recorded in:

- `ScanContext.matched_campaigns` -- Available to subsequent detection layers
- `Finding.metadata.campaign` -- On each threat-intel finding
- `Finding.metadata.signature_id` -- The specific signature that matched

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
| Ddoy233 | GitHub repository operator, hosted trojanized OpenClaw CLI |
| hightower6eu | Secondary operator |
| clawdhub1 | Publisher account for mass skill uploads |
| Aslaep123 | Publisher account |
| moonshine-100rze | Publisher account |
| pepe276 | Publisher account |
| hedefbari | Publisher account |

### Attack Chain

The ClawHavoc attack chain follows a consistent pattern:

```
1. PUBLISH: Attacker publishes a skill on ClawHub
   - Skill appears legitimate (e.g., "bankrbot", "metamask helper")
   - Uses popular keywords to attract downloads
   - Author is one of the known operator accounts

2. PREREQUISITES: Skill contains a "Prerequisites" section
   - Directs user to download a "required tool" or "CLI helper"
   - Download link points to a paste site or GitHub repo
   - Archive is password-protected to evade scanning

3. DOWNLOAD: User downloads a trojanized archive
   - Source: rentry.co, glot.io, GitHub (Ddoy233/openclawcli)
   - File types: .zip, .dmg, .pkg
   - Password provided in the skill instructions

4. EXECUTE: User extracts and runs the payload
   - AMOS infostealer activates
   - Targets: browser passwords, crypto wallets, SSH keys, cloud credentials
   - Data exfiltrated to C2 server at 91.92.242.30

5. EXFILTRATE: Stolen data sent to C2 infrastructure
   - Primary C2: 91.92.242.30
   - Secondary staging: download.setup-service.com
   - Payload hosting: openclawcli.vercel.app
```

### Indicators of Compromise (IOCs)

#### Network IOCs

| IOC Type | Value | Description |
|---|---|---|
| C2 IP | `91.92.242.30` | Primary command-and-control server |
| Domain | `download.setup-service.com` | Payload delivery domain |
| Domain | `openclawcli.vercel.app` | Trojanized CLI hosting |
| URL | `glot.io/snippets/hfd3x9ueu5` | Payload staging snippet |
| GitHub Repo | `Ddoy233/openclawcli` | Trojanized OpenClaw CLI repository |

#### Publisher IOCs

All of the following ClawHub usernames are confirmed ClawHavoc operators:

- zaycv
- clawdhub1
- Aslaep123
- pepe276
- moonshine-100rze
- Ddoy233
- hightower6eu
- hedefbari

### malwar Detection Coverage

malwar detects ClawHavoc skills through multiple layers:

| Layer | Detection | Rule/Mechanism |
|---|---|---|
| Layer 1 | C2 IP match | MALWAR-MAL-001 |
| Layer 1 | Domain match | MALWAR-MAL-001 |
| Layer 1 | Repo match | MALWAR-MAL-001 |
| Layer 1 | Author match | MALWAR-MAL-001 |
| Layer 1 | Fake prerequisite | MALWAR-SE-001, MALWAR-SE-003 |
| Layer 1 | Password archive | MALWAR-CMD-003 |
| Layer 1 | Piped execution | MALWAR-CMD-001 |
| Layer 1 | Crypto wallet access | MALWAR-EXFIL-002 |
| Layer 2 | Known-malicious domain | url_known_malicious |
| Layer 2 | Paste site URL | Domain reputation scoring |
| Layer 3 | Deceptive intent analysis | LLM semantic analysis |
| Layer 4 | Signature correlation | sig-clawhavoc-c2-ip, sig-clawhavoc-glot, sig-clawhavoc-github, sig-clawhavoc-domain |

### Seed Data

malwar ships with pre-seeded campaign and signature data for ClawHavoc. This data is automatically inserted during database initialization:

**Campaign record:**
```sql
INSERT INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
VALUES (
    'campaign-clawhavoc-001',
    'ClawHavoc',
    'Mass poisoning campaign delivering AMOS infostealer...',
    '2026-01-15',
    '2026-02-10',
    'zaycv / Ddoy233 / hightower6eu',
    '["91.92.242.30", "glot.io/snippets/hfd3x9ueu5", ...]',
    824,
    'active'
);
```

**Signature records:**

| Signature ID | Name | Pattern Value | IOC Type |
|---|---|---|---|
| sig-clawhavoc-c2-ip | ClawHavoc C2 IP | 91.92.242.30 | ip |
| sig-clawhavoc-glot | ClawHavoc Glot Snippet | glot.io/snippets/hfd3x9ueu5 | url |
| sig-clawhavoc-github | ClawHavoc GitHub Repo | Ddoy233/openclawcli | url |
| sig-clawhavoc-domain | ClawHavoc Malicious Domain | download.setup-service.com | domain |

**Publisher records:** All known threat actor handles are pre-seeded with `is_known_threat_actor=1` and `reputation_score=0.0`.

---

## Adding New Campaigns

### Step 1: Define the Campaign

Add a campaign record to the database via the API or directly using SQL:

```sql
INSERT INTO campaigns (id, name, description, first_seen, last_seen, attributed_to, iocs, total_skills_affected, status)
VALUES (
    'campaign-newcampaign-001',
    'NewCampaign',
    'Description of the campaign tactics and targets',
    '2026-02-01',
    '2026-02-20',
    'threat-actor-handle',
    '["ioc1", "ioc2", "ioc3"]',
    50,
    'active'
);
```

### Step 2: Create Threat Signatures

Add signatures linked to the campaign. This can be done via the API or CLI.

**Via API:**

```bash
curl -X POST http://localhost:8000/api/v1/signatures \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "name": "NewCampaign C2 Server",
    "description": "C2 server for NewCampaign",
    "severity": "critical",
    "category": "known_malware",
    "pattern_type": "exact",
    "pattern_value": "198.51.100.1",
    "ioc_type": "ip",
    "campaign_id": "campaign-newcampaign-001",
    "source": "threat-intel-feed"
  }'
```

**Via CLI:**

```bash
malwar signature-add exact "198.51.100.1" \
  --name "NewCampaign C2 Server" \
  --severity critical \
  --category known_malware \
  --ioc-type ip \
  --campaign-id campaign-newcampaign-001 \
  --source threat-intel-feed \
  --description "C2 server for NewCampaign"
```

### Step 3: Add Known Publishers

If the campaign has known threat actor accounts, add them to the publishers table:

```sql
INSERT INTO publishers (id, is_known_threat_actor, reputation_score)
VALUES ('threat-actor-handle', 1, 0.0);
```

### Step 4: Add Hardcoded Detection Rules (Optional)

For campaigns with distinct, high-confidence IOCs, consider adding a dedicated rule in `src/malwar/detectors/rule_engine/rules/known_malware.py`. This provides Layer 1 detection even when the database is unavailable.

```python
@rule
class NewCampaignIndicators(BaseRule):
    rule_id = "MALWAR-MAL-002"
    title = "NewCampaign indicator"
    severity = Severity.CRITICAL
    category = ThreatCategory.KNOWN_MALWARE
    description = "Detects known NewCampaign infrastructure"

    KNOWN_C2_IPS = ["198.51.100.1"]
    KNOWN_DOMAINS = ["evil-domain.example.com"]

    def check(self, skill: SkillContent) -> list[Finding]:
        # ... pattern matching logic ...
```

### Step 5: Verify Detection

Scan a test skill containing the new campaign's IOCs to verify detection:

```bash
malwar scan tests/fixtures/skills/malicious/new_campaign_sample.md
```

### Best Practices for Campaign Tracking

1. **Use multiple signature types** -- Add signatures for IPs, domains, URLs, and author handles to maximize detection coverage.

2. **Update `last_seen` dates** -- When new campaign activity is observed, update the campaign's `last_seen` field.

3. **Track skill counts** -- Update `total_skills_affected` as new malicious skills are attributed to the campaign.

4. **Set appropriate status** -- Use `active` for ongoing campaigns, `inactive` for campaigns that have ceased, and `monitoring` for campaigns under observation.

5. **Document attribution** -- Record all known threat actor handles in `attributed_to` and as publisher records.

6. **Regex signatures for variants** -- Use `pattern_type: regex` for IOCs that have predictable variations (e.g., rotating subdomains, incremental URL paths).
