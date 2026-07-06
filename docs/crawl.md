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

**One request per skill.** Skill metadata (version, updated_at, display name, install count) is taken from the enumeration listing, so scanning a skill costs a single request — the `SKILL.md` file — rather than a separate detail lookup. This roughly halves crawl time. The trade-off: per-skill publisher and moderation flags aren't captured by the sweep (the scan verdict, version, and installs are).

**Budgeted, resumable baseline.** ClawHub is rate-limited (~120 req/min), so a full ~6k-skill registry can't be swept in one shot. `--max-scans N` caps how many skills are actually scanned per run; any overflow is recorded as an `UNKNOWN` placeholder and picked up on the next run. So the **first full baseline builds up over several runs** rather than dying to a timeout, and once complete, daily incremental runs only touch what changed. `scanned_count`/`reused_count`/`pending_count` on each snapshot show the split.

**Targeted, tiered escalation.** The rules pass is confident at the two ends (obviously clean, obviously malicious) but there's an **ambiguous middle** where a sneaky skill hides — it scores just under the line. Rather than pay for a deep look at *every* flagged skill, an escalation **policy** selects only that middle band (rule risk ~8–74, below the confident-malicious line), ranks by suspicion, and caps it with `--escalate-budget`. A pluggable **backend** then gives those a second opinion:

| `--escalate-backend` | What runs | Cost |
|---|---|---|
| `none` | nothing (policy still records candidates) | free |
| `hf` | a free local Hugging Face classifier (CPU) — `pip install malwar[hf]` | free |
| `anthropic` | the full LLM analyzer (rules + LLM + false-positive suppression) | paid API |
| `tiered` | `hf` triages first; escalates to `anthropic` **only** on a hit | paid on the residual only |

`tiered` is the money-saver: the free tier filters the band, and the LLM is spent only on what the free tier still finds suspicious. An `anthropic`/`tiered` result is *authoritative* — it can raise a sneaky skill or clear a rule-engine false positive; an `hf` result is recorded as a triage signal (`escalation_backend`/`escalation_verdict`/`escalation_score` on the snapshot) without overriding the rule verdict. `escalated_count` shows how many skills were sent to the backend.

> **Note:** a "rule-clean but ML-anomalous" escalation path exists (`EscalationPolicy.ml_threshold`) but is **off by default** — the stock ML scorer saturates near 1.0 for both benign and malicious skills, so it can't discriminate yet. Enable it only once the model is recalibrated.

```bash
malwar crawl monitor                          # incremental sweep -> snapshot -> diff (LLM on the ambiguous band)
malwar crawl monitor --no-escalate            # rules only, no second opinion (fast, free)
malwar crawl monitor --escalate-backend hf    # free local classifier on the ambiguous band
malwar crawl monitor --escalate-backend tiered --escalate-budget 50  # hf triage -> LLM on hits, capped
malwar crawl monitor --full                   # re-scan every skill (catches same-version tampering)
malwar crawl monitor --fail-on-malicious      # exit non-zero when newly-flagged skills are found (CI/cron)
```

**Options:** `--snapshot-dir`, `--full`, `--max-scans`, `--max`, `--escalate-backend` (`none`|`hf`|`anthropic`|`tiered`), `--escalate-budget`, `--no-escalate`, `--concurrency`, `--format`/`-f` (`console`|`json`), `--output`/`-o`, `--no-save`, `--digest`, `--publish`, `--fail-on-malicious`. Publishing to X requires the `MALWAR_X_*` credentials (see [Configuration](deployment/configuration.md#x-twitter-publishing)).

The bundled GitHub Actions workflow (`.github/workflows/registry-monitor.yml`) runs this on two cadences: **daily incremental** and a **weekly `--full`** re-scan, committing each snapshot to the `registry-snapshots` branch. It runs **rules-only (`--no-escalate`)** so a whole-registry sweep stays fast and cheap — the rule engine alone catches every malicious sample in the benchmark; use `malwar crawl scan <slug>` for an LLM deep-dive on an individual flagged skill.

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
