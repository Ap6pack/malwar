# Registry snapshots

This directory is the on-disk history for `malwar crawl monitor`.

- **`latest.json`** — the most recent full-registry snapshot. It is the
  baseline the next run diffs against.
- **`snapshot-<date>.json`** — one archived snapshot per run.

Each snapshot records, per skill: the published version, a SHA-256 of the
`SKILL.md`, the scan verdict and risk score, matched rule IDs, install count,
and ClawHub moderation flags. Because the files are committed to the repo,
`git diff` (or `git log -p`) is a permanent, auditable record of exactly what
changed in the registry day over day — new skills, removed skills, trojanized
updates, and verdict regressions.

Run the monitor:

```bash
malwar crawl monitor                 # full sweep, diff against latest.json, save
malwar crawl monitor --fail-on-malicious   # non-zero exit on newly-flagged skills
```
