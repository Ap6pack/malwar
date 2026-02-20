<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Performance Benchmarks

Latency benchmarks for malwar's scan pipeline, measured across the full fixture
set (46 skill files). Each fixture is scanned 3 times per configuration; the
**median** of those 3 runs is used as the representative timing.

## Test Environment

| Property      | Value                                            |
|---------------|--------------------------------------------------|
| OS            | Linux 6.17.0-14-generic                          |
| Python        | 3.13.7                                           |
| pytest        | 7.4.4 with pytest-asyncio 0.23.3                 |
| Timer         | `time.perf_counter` (wall-clock, sub-microsecond)|
| Runs per scan | 3 (median selected)                              |
| Date          | 2026-02-20                                       |

## Scan Configurations

| Config             | Layers                          | Network | LLM |
|--------------------|---------------------------------|---------|-----|
| `rules_only`       | `rule_engine`                   | No      | No  |
| `rules_and_intel`  | `rule_engine`, `threat_intel`   | No      | No  |
| `full_no_network`  | All layers except url_crawler & llm_analyzer | No | No |

## Overall Latency Summary

Percentile statistics computed across the median timings of all 46 fixtures.

| Config             | Fixtures | p50 (ms) | p95 (ms) | p99 (ms) |
|--------------------|----------|----------|----------|----------|
| `rules_only`       | 46       |     9.30 |    47.14 |    98.49 |
| `rules_and_intel`  | 46       |     9.26 |    50.69 |    99.47 |
| `full_no_network`  | 46       |     9.23 |    60.98 |   100.12 |

**Assertion:** `rules_only` p95 must stay under 100 ms (currently 47.14 ms).

## Per-Fixture Breakdown

### Benign Fixtures

| Fixture | Config | Median (ms) | Verdict | Findings |
|---------|--------|-------------|---------|----------|
| benign/code_formatter.md | rules_only | 8.04 | CLEAN | 0 |
| benign/git_helper.md | rules_only | 5.21 | CLEAN | 0 |
| benign/hello_world.md | rules_only | 4.28 | CLEAN | 0 |
| benign/legitimate_with_urls.md | rules_only | 5.26 | CLEAN | 0 |
| benign/web_search.md | rules_only | 8.72 | CLEAN | 0 |

### Malicious Fixtures

| Fixture | Config | Median (ms) | Verdict | Findings |
|---------|--------|-------------|---------|----------|
| malicious/agent_hijacking.md | rules_only | 7.69 | MALICIOUS | 5 |
| malicious/base64_reverse_shell.md | rules_only | 7.92 | MALICIOUS | 2 |
| malicious/clawhavoc_amos.md | rules_only | 5.69 | MALICIOUS | 3 |
| malicious/credential_harvester.md | rules_only | 10.19 | MALICIOUS | 4 |
| malicious/env_harvesting.md | rules_only | 6.55 | MALICIOUS | 7 |
| malicious/exfil_soul_md.md | rules_only | 8.02 | MALICIOUS | 8 |
| malicious/persistence_mechanism.md | rules_only | 7.85 | MALICIOUS | 10 |

### Real-World Fixtures

| Fixture | Config | Median (ms) | Verdict | Findings |
|---------|--------|-------------|---------|----------|
| real/benign/anthropic_frontend_design.md | rules_only | 18.76 | CLEAN | 0 |
| real/benign/anthropic_pdf.md | rules_only | 19.94 | CLEAN | 0 |
| real/malicious/snyk_clawhub.md | rules_only | 45.08 | MALICIOUS | 2 |
| real/malicious/snyk_vercel_exfil.md | rules_only | 10.74 | MALICIOUS | 2 |
| real/clawhub/bankrbot_bankr.md | rules_only | 103.18 | CLEAN | 0 |

## Key Observations

- Adding `threat_intel` on top of `rule_engine` adds minimal overhead (typically < 2 ms)
- Scan time scales roughly linearly with input size
- The `bankrbot_bankr.md` and `metamask_smart_accounts.md` fixtures are the largest and account for most of the p95/p99 tail latency
- The `full_no_network` configuration resolves to the same layers as `rules_and_intel` when both `use_llm=False` and `use_urls=False`

## Memory

The scan pipeline is designed to be lightweight: each scan constructs a small in-memory context object with no persistent caches, database connections, or large allocations. Memory consumption is dominated by the fixture text itself and the compiled regex patterns. For fixtures up to ~100 KB each, peak RSS overhead per scan is negligible.
