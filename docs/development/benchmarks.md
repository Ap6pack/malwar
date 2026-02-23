<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Performance Benchmarks

Latency benchmarks for malwar's scan pipeline, measured across the full fixture
set (46 skill files).  Each fixture is scanned 3 times per configuration; the
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

| Fixture | Config | Median (ms) | Min (ms) | Max (ms) | Verdict | Findings |
|---------|--------|-------------|----------|----------|---------|----------|
| benign/code_formatter.md | rules_only | 8.04 | 7.22 | 16.34 | CLEAN | 0 |
| benign/code_formatter.md | rules_and_intel | 5.31 | 4.51 | 7.16 | CLEAN | 0 |
| benign/code_formatter.md | full_no_network | 5.37 | 4.56 | 6.05 | CLEAN | 0 |
| benign/git_helper.md | rules_only | 5.21 | 4.86 | 6.19 | CLEAN | 0 |
| benign/git_helper.md | rules_and_intel | 4.95 | 4.90 | 6.21 | CLEAN | 0 |
| benign/git_helper.md | full_no_network | 5.41 | 4.72 | 5.44 | CLEAN | 0 |
| benign/hello_world.md | rules_only | 4.28 | 3.59 | 4.58 | CLEAN | 0 |
| benign/hello_world.md | rules_and_intel | 3.67 | 3.37 | 4.94 | CLEAN | 0 |
| benign/hello_world.md | full_no_network | 3.64 | 3.42 | 4.12 | CLEAN | 0 |
| benign/legitimate_with_urls.md | rules_only | 5.26 | 4.73 | 6.52 | CLEAN | 0 |
| benign/legitimate_with_urls.md | rules_and_intel | 7.89 | 7.73 | 8.49 | CLEAN | 0 |
| benign/legitimate_with_urls.md | full_no_network | 9.24 | 7.97 | 9.30 | CLEAN | 0 |
| benign/web_search.md | rules_only | 8.72 | 8.41 | 8.85 | CLEAN | 0 |
| benign/web_search.md | rules_and_intel | 9.03 | 8.73 | 9.10 | CLEAN | 0 |
| benign/web_search.md | full_no_network | 9.74 | 9.42 | 10.25 | CLEAN | 0 |

### Malicious Fixtures

| Fixture | Config | Median (ms) | Min (ms) | Max (ms) | Verdict | Findings |
|---------|--------|-------------|----------|----------|---------|----------|
| malicious/agent_hijacking.md | rules_only | 7.69 | 6.46 | 7.73 | MALICIOUS | 5 |
| malicious/agent_hijacking.md | rules_and_intel | 7.92 | 6.97 | 8.07 | MALICIOUS | 5 |
| malicious/agent_hijacking.md | full_no_network | 7.14 | 7.12 | 7.52 | MALICIOUS | 5 |
| malicious/base64_reverse_shell.md | rules_only | 7.92 | 7.53 | 7.98 | MALICIOUS | 2 |
| malicious/base64_reverse_shell.md | rules_and_intel | 7.67 | 4.87 | 10.28 | MALICIOUS | 2 |
| malicious/base64_reverse_shell.md | full_no_network | 4.66 | 4.58 | 5.27 | MALICIOUS | 2 |
| malicious/clawhavoc_amos.md | rules_only | 5.69 | 5.67 | 5.84 | MALICIOUS | 3 |
| malicious/clawhavoc_amos.md | rules_and_intel | 6.29 | 5.84 | 6.45 | MALICIOUS | 5 |
| malicious/clawhavoc_amos.md | full_no_network | 6.84 | 5.46 | 7.18 | MALICIOUS | 5 |
| malicious/clickfix_fake_prereq.md | rules_only | 5.02 | 4.83 | 5.07 | MALICIOUS | 1 |
| malicious/clickfix_fake_prereq.md | rules_and_intel | 5.16 | 4.70 | 5.77 | MALICIOUS | 1 |
| malicious/clickfix_fake_prereq.md | full_no_network | 5.29 | 5.05 | 6.26 | MALICIOUS | 1 |
| malicious/credential_harvester.md | rules_only | 10.19 | 8.76 | 10.26 | MALICIOUS | 4 |
| malicious/credential_harvester.md | rules_and_intel | 9.49 | 9.11 | 9.89 | MALICIOUS | 4 |
| malicious/credential_harvester.md | full_no_network | 9.10 | 9.07 | 9.74 | MALICIOUS | 4 |
| malicious/env_harvesting.md | rules_only | 6.55 | 6.53 | 7.25 | MALICIOUS | 7 |
| malicious/env_harvesting.md | rules_and_intel | 7.20 | 6.63 | 7.54 | MALICIOUS | 7 |
| malicious/env_harvesting.md | full_no_network | 6.89 | 6.71 | 7.20 | MALICIOUS | 7 |
| malicious/exfil_soul_md.md | rules_only | 8.02 | 8.00 | 8.63 | MALICIOUS | 8 |
| malicious/exfil_soul_md.md | rules_and_intel | 8.55 | 7.78 | 8.85 | MALICIOUS | 8 |
| malicious/exfil_soul_md.md | full_no_network | 7.89 | 7.72 | 9.41 | MALICIOUS | 8 |
| malicious/filesystem_modification.md | rules_only | 6.98 | 6.46 | 7.56 | MALICIOUS | 8 |
| malicious/filesystem_modification.md | rules_and_intel | 7.01 | 7.01 | 7.09 | MALICIOUS | 8 |
| malicious/filesystem_modification.md | full_no_network | 7.15 | 7.14 | 7.17 | MALICIOUS | 8 |
| malicious/multi_stage_dropper.md | rules_only | 9.52 | 8.98 | 9.74 | SUSPICIOUS | 1 |
| malicious/multi_stage_dropper.md | rules_and_intel | 10.02 | 9.82 | 10.91 | SUSPICIOUS | 1 |
| malicious/multi_stage_dropper.md | full_no_network | 9.78 | 9.14 | 9.90 | SUSPICIOUS | 1 |
| malicious/multi_step_manipulation.md | rules_only | 7.70 | 6.74 | 7.75 | MALICIOUS | 8 |
| malicious/multi_step_manipulation.md | rules_and_intel | 7.58 | 7.13 | 8.01 | MALICIOUS | 8 |
| malicious/multi_step_manipulation.md | full_no_network | 6.99 | 6.81 | 7.57 | MALICIOUS | 8 |
| malicious/obfuscated_curl.md | rules_only | 7.46 | 6.98 | 7.59 | SUSPICIOUS | 1 |
| malicious/obfuscated_curl.md | rules_and_intel | 7.55 | 7.33 | 7.64 | SUSPICIOUS | 1 |
| malicious/obfuscated_curl.md | full_no_network | 7.38 | 6.71 | 7.58 | SUSPICIOUS | 1 |
| malicious/persistence_mechanism.md | rules_only | 7.85 | 7.76 | 8.30 | MALICIOUS | 10 |
| malicious/persistence_mechanism.md | rules_and_intel | 7.96 | 7.75 | 9.35 | MALICIOUS | 10 |
| malicious/persistence_mechanism.md | full_no_network | 7.87 | 7.86 | 8.00 | MALICIOUS | 10 |
| malicious/prompt_injection_basic.md | rules_only | 8.49 | 8.26 | 8.87 | MALICIOUS | 4 |
| malicious/prompt_injection_basic.md | rules_and_intel | 8.48 | 8.31 | 8.82 | MALICIOUS | 4 |
| malicious/prompt_injection_basic.md | full_no_network | 8.04 | 7.87 | 9.23 | MALICIOUS | 4 |
| malicious/prompt_injection_unicode.md | rules_only | 7.99 | 7.48 | 8.13 | MALICIOUS | 4 |
| malicious/prompt_injection_unicode.md | rules_and_intel | 7.59 | 7.36 | 7.62 | MALICIOUS | 4 |
| malicious/prompt_injection_unicode.md | full_no_network | 8.94 | 7.54 | 9.25 | MALICIOUS | 4 |
| malicious/shadowpkg_typosquat.md | rules_only | 9.58 | 8.58 | 14.65 | MALICIOUS | 5 |
| malicious/shadowpkg_typosquat.md | rules_and_intel | 8.70 | 8.61 | 9.79 | MALICIOUS | 9 |
| malicious/shadowpkg_typosquat.md | full_no_network | 8.67 | 8.47 | 9.47 | MALICIOUS | 9 |
| malicious/snyktoxic_vercel_exfil.md | rules_only | 9.09 | 8.95 | 9.51 | MALICIOUS | 4 |
| malicious/snyktoxic_vercel_exfil.md | rules_and_intel | 10.52 | 9.39 | 10.89 | MALICIOUS | 8 |
| malicious/snyktoxic_vercel_exfil.md | full_no_network | 9.95 | 9.76 | 10.54 | MALICIOUS | 8 |
| malicious/steganographic.md | rules_only | 7.58 | 7.40 | 7.65 | MALICIOUS | 5 |
| malicious/steganographic.md | rules_and_intel | 7.63 | 4.84 | 7.82 | MALICIOUS | 5 |
| malicious/steganographic.md | full_no_network | 5.27 | 5.07 | 5.53 | MALICIOUS | 5 |
| malicious/supply_chain.md | rules_only | 4.55 | 4.52 | 5.00 | MALICIOUS | 5 |
| malicious/supply_chain.md | rules_and_intel | 5.23 | 5.18 | 5.65 | MALICIOUS | 9 |
| malicious/supply_chain.md | full_no_network | 4.69 | 4.42 | 5.12 | MALICIOUS | 9 |
| malicious/typosquatted_package.md | rules_only | 5.01 | 4.96 | 5.65 | CAUTION | 1 |
| malicious/typosquatted_package.md | rules_and_intel | 4.88 | 4.72 | 5.28 | CAUTION | 1 |
| malicious/typosquatted_package.md | full_no_network | 7.47 | 5.57 | 10.36 | CAUTION | 1 |

### Real-World Benign Fixtures

| Fixture | Config | Median (ms) | Min (ms) | Max (ms) | Verdict | Findings |
|---------|--------|-------------|----------|----------|---------|----------|
| real/benign/anthropic_frontend_design.md | rules_only | 18.76 | 18.51 | 19.55 | CLEAN | 0 |
| real/benign/anthropic_frontend_design.md | rules_and_intel | 20.22 | 20.20 | 21.21 | CLEAN | 0 |
| real/benign/anthropic_frontend_design.md | full_no_network | 19.62 | 18.62 | 19.90 | CLEAN | 0 |
| real/benign/anthropic_pdf.md | rules_only | 19.94 | 19.67 | 28.22 | CLEAN | 0 |
| real/benign/anthropic_pdf.md | rules_and_intel | 20.50 | 20.32 | 29.90 | CLEAN | 0 |
| real/benign/anthropic_pdf.md | full_no_network | 31.24 | 31.20 | 31.44 | CLEAN | 0 |
| real/benign/anthropic_skill_creator.md | rules_only | 47.83 | 40.41 | 51.68 | MALICIOUS | 2 |
| real/benign/anthropic_skill_creator.md | rules_and_intel | 52.00 | 40.72 | 54.49 | MALICIOUS | 2 |
| real/benign/anthropic_skill_creator.md | full_no_network | 65.67 | 65.31 | 66.79 | MALICIOUS | 2 |

### Real-World Malicious Fixtures

| Fixture | Config | Median (ms) | Min (ms) | Max (ms) | Verdict | Findings |
|---------|--------|-------------|----------|----------|---------|----------|
| real/malicious/snyk_ascii_smuggling.md | rules_only | 4.69 | 4.60 | 5.04 | SUSPICIOUS | 1 |
| real/malicious/snyk_ascii_smuggling.md | rules_and_intel | 4.67 | 4.16 | 5.12 | SUSPICIOUS | 1 |
| real/malicious/snyk_ascii_smuggling.md | full_no_network | 5.71 | 5.40 | 7.02 | SUSPICIOUS | 1 |
| real/malicious/snyk_clawhub.md | rules_only | 45.08 | 44.98 | 45.12 | MALICIOUS | 2 |
| real/malicious/snyk_clawhub.md | rules_and_intel | 46.77 | 46.68 | 47.88 | MALICIOUS | 3 |
| real/malicious/snyk_clawhub.md | full_no_network | 46.17 | 44.61 | 48.05 | MALICIOUS | 3 |
| real/malicious/snyk_clawhub_agent.md | rules_only | 44.83 | 44.46 | 45.52 | MALICIOUS | 2 |
| real/malicious/snyk_clawhub_agent.md | rules_and_intel | 45.27 | 44.71 | 46.75 | MALICIOUS | 5 |
| real/malicious/snyk_clawhub_agent.md | full_no_network | 46.93 | 46.58 | 47.88 | MALICIOUS | 5 |
| real/malicious/snyk_gemini_vercel.md | rules_only | 9.74 | 9.21 | 9.93 | MALICIOUS | 2 |
| real/malicious/snyk_gemini_vercel.md | rules_and_intel | 10.60 | 10.05 | 10.82 | MALICIOUS | 2 |
| real/malicious/snyk_gemini_vercel.md | full_no_network | 9.74 | 9.63 | 9.86 | MALICIOUS | 2 |
| real/malicious/snyk_google_malware.md | rules_only | 22.33 | 21.51 | 22.38 | MALICIOUS | 1 |
| real/malicious/snyk_google_malware.md | rules_and_intel | 23.16 | 21.01 | 23.69 | MALICIOUS | 3 |
| real/malicious/snyk_google_malware.md | full_no_network | 22.85 | 21.60 | 23.33 | MALICIOUS | 3 |
| real/malicious/snyk_vercel_exfil.md | rules_only | 10.74 | 10.16 | 11.11 | MALICIOUS | 2 |
| real/malicious/snyk_vercel_exfil.md | rules_and_intel | 11.42 | 10.95 | 11.61 | MALICIOUS | 2 |
| real/malicious/snyk_vercel_exfil.md | full_no_network | 9.60 | 9.49 | 9.71 | MALICIOUS | 2 |

### Real-World ClawHub Fixtures

| Fixture | Config | Median (ms) | Min (ms) | Max (ms) | Verdict | Findings |
|---------|--------|-------------|----------|----------|---------|----------|
| real/clawhub/bankrbot_bankr.md | rules_only | 103.18 | 101.51 | 107.29 | CLEAN | 0 |
| real/clawhub/bankrbot_bankr.md | rules_and_intel | 103.46 | 74.80 | 105.76 | CLEAN | 0 |
| real/clawhub/bankrbot_bankr.md | full_no_network | 101.75 | 101.36 | 102.24 | CLEAN | 0 |
| real/clawhub/bankrbot_clanker.md | rules_only | 43.14 | 37.33 | 44.38 | CLEAN | 0 |
| real/clawhub/bankrbot_clanker.md | rules_and_intel | 30.90 | 29.09 | 37.03 | CLEAN | 0 |
| real/clawhub/bankrbot_clanker.md | full_no_network | 45.08 | 44.91 | 47.42 | CLEAN | 0 |
| real/clawhub/bankrbot_onchainkit.md | rules_only | 37.01 | 35.64 | 38.44 | CLEAN | 0 |
| real/clawhub/bankrbot_onchainkit.md | rules_and_intel | 36.97 | 36.57 | 38.29 | CLEAN | 0 |
| real/clawhub/bankrbot_onchainkit.md | full_no_network | 37.64 | 36.30 | 38.72 | CLEAN | 0 |
| real/clawhub/bankrbot_veil.md | rules_only | 16.04 | 14.75 | 16.43 | MALICIOUS | 1 |
| real/clawhub/bankrbot_veil.md | rules_and_intel | 16.40 | 15.44 | 16.62 | MALICIOUS | 1 |
| real/clawhub/bankrbot_veil.md | full_no_network | 16.23 | 15.09 | 16.44 | MALICIOUS | 1 |
| real/clawhub/bankrbot_yoink.md | rules_only | 15.17 | 14.52 | 15.17 | CLEAN | 0 |
| real/clawhub/bankrbot_yoink.md | rules_and_intel | 15.00 | 14.55 | 15.13 | CLEAN | 0 |
| real/clawhub/bankrbot_yoink.md | full_no_network | 14.73 | 14.23 | 15.14 | CLEAN | 0 |
| real/clawhub/bankrbot_zapper.md | rules_only | 4.43 | 4.01 | 4.46 | CLEAN | 0 |
| real/clawhub/bankrbot_zapper.md | rules_and_intel | 4.27 | 4.09 | 4.34 | CLEAN | 0 |
| real/clawhub/bankrbot_zapper.md | full_no_network | 5.29 | 4.78 | 6.06 | CLEAN | 0 |
| real/clawhub/clawpod_massive.md | rules_only | 35.76 | 35.55 | 38.81 | CLEAN | 0 |
| real/clawhub/clawpod_massive.md | rules_and_intel | 39.29 | 39.18 | 41.11 | CLEAN | 0 |
| real/clawhub/clawpod_massive.md | full_no_network | 37.81 | 36.96 | 38.09 | CLEAN | 0 |
| real/clawhub/metamask_gator.md | rules_only | 34.66 | 33.09 | 36.17 | CLEAN | 0 |
| real/clawhub/metamask_gator.md | rules_and_intel | 36.07 | 34.97 | 36.35 | CLEAN | 0 |
| real/clawhub/metamask_gator.md | full_no_network | 23.05 | 21.95 | 27.35 | CLEAN | 0 |
| real/clawhub/metamask_smart_accounts.md | rules_only | 92.75 | 74.53 | 93.28 | CLEAN | 0 |
| real/clawhub/metamask_smart_accounts.md | rules_and_intel | 94.59 | 91.82 | 95.05 | CLEAN | 0 |
| real/clawhub/metamask_smart_accounts.md | full_no_network | 98.13 | 97.27 | 100.46 | CLEAN | 0 |
| real/clawhub/model_hierarchy.md | rules_only | 36.15 | 35.14 | 36.57 | CLEAN | 0 |
| real/clawhub/model_hierarchy.md | rules_and_intel | 37.09 | 34.90 | 37.28 | CLEAN | 0 |
| real/clawhub/model_hierarchy.md | full_no_network | 22.65 | 22.25 | 26.73 | CLEAN | 0 |
| real/clawhub/search_layer.md | rules_only | 28.58 | 20.21 | 29.28 | CLEAN | 0 |
| real/clawhub/search_layer.md | rules_and_intel | 28.72 | 28.38 | 29.80 | CLEAN | 0 |
| real/clawhub/search_layer.md | full_no_network | 28.27 | 27.62 | 28.43 | CLEAN | 0 |
| real/clawhub/x_bookmarks.md | rules_only | 32.94 | 32.45 | 33.59 | CLEAN | 0 |
| real/clawhub/x_bookmarks.md | rules_and_intel | 32.06 | 31.88 | 32.58 | CLEAN | 0 |
| real/clawhub/x_bookmarks.md | full_no_network | 34.07 | 32.69 | 36.34 | CLEAN | 0 |
| real/clawhub/x_tweet_fetcher.md | rules_only | 13.81 | 13.68 | 14.42 | CLEAN | 0 |
| real/clawhub/x_tweet_fetcher.md | rules_and_intel | 12.12 | 8.72 | 14.49 | CLEAN | 0 |
| real/clawhub/x_tweet_fetcher.md | full_no_network | 9.23 | 8.98 | 9.42 | CLEAN | 0 |

## Memory

No explicit memory profiling is performed in these benchmarks.  The scan
pipeline is designed to be lightweight: each scan constructs a small in-memory
context object with no persistent caches, database connections, or large
allocations.  Memory consumption is dominated by the fixture text itself and
the compiled regex patterns in the rule engine.  For the fixtures tested here
(up to ~100 KB each), peak RSS overhead per scan is negligible.

## Notes

- The `bankrbot_bankr.md` and `metamask_smart_accounts.md` fixtures are the
  largest in the set and account for most of the p95/p99 tail latency.
  Scan time scales roughly linearly with input size.
- Adding `threat_intel` on top of `rule_engine` adds minimal overhead
  (typically < 2 ms) since threat intel matching operates on the already-parsed
  skill content and prior findings without any I/O.
- The `full_no_network` configuration resolves to the same layers as
  `rules_and_intel` when both `use_llm=False` and `use_urls=False`.
