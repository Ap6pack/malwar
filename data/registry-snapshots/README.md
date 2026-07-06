# Registry snapshots

This directory is the on-disk history for `malwar crawl monitor`.

- **`latest.json`** — the most recent full-registry snapshot. It is the
  baseline the next run diffs against.
- **`snapshot-<date>.json`** — one archived snapshot per run.

Each snapshot records, per skill: the published version, a SHA-256 of the
`SKILL.md`, the scan verdict and risk score, matched rule IDs, install count,
and ClawHub moderation flags. It also records `scanned_count` vs `reused_count`
for the run. Because the files are committed to the repo, `git diff` (or
`git log -p`) is a permanent, auditable record of exactly what changed in the
registry day over day — new skills, removed skills, trojanized updates, and
verdict regressions.

The sweep is **incremental**: only skills whose version/updated_at changed since
`latest.json` are re-scanned; the rest are carried forward. The first run scans
everything. A periodic `--full` run re-scans every skill to catch silent
same-version content swaps.

Run the monitor:

```bash
malwar crawl monitor                 # incremental sweep, diff against latest.json, save
malwar crawl monitor --full          # full re-scan (weekly cadence recommended)
malwar crawl monitor --fail-on-malicious   # non-zero exit on newly-flagged skills
```
