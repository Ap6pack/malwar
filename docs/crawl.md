<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# ClawHub Registry Crawling

Malwar can fetch and scan skills directly from the [ClawHub registry](https://clawhub.ai) -- the largest community skill marketplace with 5,700+ skills. This lets you audit remote skills for threats without manually downloading them.

---

## Quick Start

```bash
# Scan a skill by slug
malwar crawl scan beszel-check

# Search the registry
malwar crawl search "crypto wallet"

# Browse all skills
malwar crawl list

# View details and moderation flags
malwar crawl info beszel-check

# Scan any remote SKILL.md by URL
malwar crawl url https://example.com/SKILL.md
```

---

## Commands

### crawl scan

Fetch a skill's SKILL.md from ClawHub and run it through the full detection pipeline.

```bash
malwar crawl scan <slug> [--version <ver>] [--format console|json|sarif] [--no-llm] [--no-urls]
```

The scan uses the same 4-layer pipeline as `malwar scan` -- rule engine, URL crawler, LLM analyzer, and threat intel. Results include the same verdict, risk score, and findings.

**Exit codes:** 0 if risk score < 40, 1 if >= 40 (SUSPICIOUS or MALICIOUS).

**Examples:**

```bash
malwar crawl scan beszel-check                     # latest version
malwar crawl scan beszel-check --version 1.0.0     # specific version
malwar crawl scan beszel-check --format sarif -o results.sarif.json
malwar crawl scan beszel-check --no-llm            # fast scan, no API cost
```

### crawl search

Search ClawHub by keyword. Returns matching skills with slug, name, summary, version, and relevance score.

```bash
malwar crawl search "hello world"
malwar crawl search "api client" --limit 10
```

### crawl list

Browse skills from the registry with cursor-based pagination.

```bash
malwar crawl list
malwar crawl list --limit 50
malwar crawl list --cursor <cursor-from-previous-page>
```

### crawl info

Show details for a specific skill including author, download stats, version history, and **moderation flags** from ClawHub's VirusTotal integration.

```bash
malwar crawl info beszel-check
```

Moderation flags include:

- **BLOCKED** -- Malware detected by VirusTotal
- **SUSPICIOUS** -- Flagged for review
- **PENDING** -- Awaiting security scan
- **HIDDEN** -- Hidden by moderator
- **REMOVED** -- Removed from registry

### crawl url

Fetch and scan any remote SKILL.md by URL. Not limited to ClawHub -- works with any publicly hosted SKILL.md file.

```bash
malwar crawl url https://example.com/SKILL.md
malwar crawl url https://raw.githubusercontent.com/user/repo/main/SKILL.md --format json
```

---

## How It Works

1. The ClawHub client fetches skill metadata via the public API at `clawhub.ai/api/v1/`
2. For `crawl scan`, it fetches the raw SKILL.md content via the file endpoint
3. The content is passed to `malwar.sdk.scan()` -- the same pipeline used by `malwar scan`
4. Results are displayed using the same formatters (console, JSON, SARIF)

The ClawHub API is public and unauthenticated, with a rate limit of 120 requests/minute per IP.

---

## See Also

- [CLI Reference](guide/cli-reference.md#malwar-crawl) -- Full option reference for all crawl commands
- [Quick Start](getting-started/quickstart.md#scan-a-clawhub-skill) -- First-time walkthrough
- [Detection Rules](guide/detection-rules.md) -- What the scan pipeline detects
