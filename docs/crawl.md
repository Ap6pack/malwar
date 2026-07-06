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

# Sweep the whole registry and diff against the previous snapshot
malwar crawl monitor
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

### crawl monitor

Sweep the registry, fast-scan skills (rule engine + threat intel, escalating flagged ones to the LLM), and diff the result against the previous snapshot to surface what changed -- newly published skills, removed skills, trojanized updates (content changed under the same version), and verdict regressions, with a headline list of skills that newly turned malicious. Snapshots persist under `data/registry-snapshots/` (`latest.json` is the diff baseline, plus a dated archive per run), so committing that directory makes `git diff` a permanent day-over-day record. Designed to run on a schedule.

**Incremental by default.** The monitor only re-fetches and re-scans skills whose `version`/`updated_at` changed since the last snapshot; unchanged skills are carried forward untouched. The **first run scans everything**; every run after only pays for what actually changed — so a daily sweep is fast and cheap. Because incremental detection trusts the registry's version metadata, run a periodic **`--full`** sweep (e.g. weekly) to also catch *silent same-version content swaps* — trojanized updates that keep the same version number. Each snapshot records `scanned_count` vs `reused_count` so you can see how much a run actually did.

```bash
malwar crawl monitor                     # incremental sweep -> snapshot -> diff
malwar crawl monitor --full              # re-scan every skill (catches same-version tampering)
malwar crawl monitor --digest            # also print a shareable digest + draft post
malwar crawl monitor --publish           # post the digest to X when skills newly turn malicious
malwar crawl monitor --fail-on-malicious # exit non-zero when newly-flagged skills are found (CI/cron)
malwar crawl monitor --max 100 --no-escalate   # quick partial run, rules only
```

**Options:** `--snapshot-dir`, `--full`, `--max`, `--no-escalate`, `--concurrency`, `--format`/`-f` (`console`|`json`), `--output`/`-o`, `--no-save`, `--digest`, `--publish`, `--fail-on-malicious`. Publishing to X requires the `MALWAR_X_*` credentials (see [Configuration](deployment/configuration.md#x-twitter-publishing)).

The bundled GitHub Actions workflow (`.github/workflows/registry-monitor.yml`) runs this on two cadences: **daily incremental** and a **weekly `--full`** re-scan, committing each snapshot to the `registry-snapshots` branch.

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
