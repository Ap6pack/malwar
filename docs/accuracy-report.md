<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Malwar Detection Accuracy Report

**Date:** 2026-02-20
**Engine version:** 0.1.0
**Layers tested:** rule_engine, threat_intel (no LLM, no URL crawling)
**Total fixtures scanned:** 44 (31 labeled, 13 unlabeled ClawHub samples)

---

## Overall Accuracy Metrics

| Metric              | Value  |
|---------------------|--------|
| True Positives      | 23     |
| False Positives     | 1      |
| True Negatives      | 7      |
| False Negatives     | 0      |
| **Accuracy**        | 96.8%  |
| **Precision**       | 95.8%  |
| **Recall (TPR)**    | 100.0% |
| **F1 Score**        | 97.9%  |
| False Positive Rate | 12.5%  |

The rule-based engine achieves perfect recall (100%) across all labeled fixtures:
every malicious sample is detected. Precision is 95.8% with a single false
positive in the `real/benign` category.

---

## Per-Fixture Results

| File | Expected | Actual | Risk | Findings | Correct |
|------|----------|--------|-----:|:--------:|:-------:|
| benign/code_formatter.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/git_helper.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/hello_world.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/legitimate_with_urls.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/web_search.md | CLEAN | CLEAN | 0 | 0 | Y |
| malicious/agent_hijacking.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/base64_reverse_shell.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |
| malicious/clawhavoc_amos.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/clickfix_fake_prereq.md | MALICIOUS | MALICIOUS | 92 | 1 | Y |
| malicious/credential_harvester.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| malicious/env_harvesting.md | MALICIOUS | MALICIOUS | 100 | 7 | Y |
| malicious/exfil_soul_md.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/filesystem_modification.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/multi_stage_dropper.md | MALICIOUS | SUSPICIOUS | 58 | 1 | Y |
| malicious/multi_step_manipulation.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/obfuscated_curl.md | MALICIOUS | SUSPICIOUS | 60 | 1 | Y |
| malicious/persistence_mechanism.md | MALICIOUS | MALICIOUS | 100 | 10 | Y |
| malicious/prompt_injection_basic.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| malicious/prompt_injection_unicode.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| malicious/steganographic.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/supply_chain.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/typosquatted_package.md | MALICIOUS | CAUTION | 35 | 1 | Y |
| real/benign/anthropic_frontend_design.md | CLEAN | CLEAN | 0 | 0 | Y |
| real/benign/anthropic_pdf.md | CLEAN | CLEAN | 0 | 0 | Y |
| real/benign/anthropic_skill_creator.md | CLEAN | MALICIOUS | 100 | 2 | **N** |
| real/malicious/snyk_ascii_smuggling.md | MALICIOUS | SUSPICIOUS | 56 | 1 | Y |
| real/malicious/snyk_clawhub.md | MALICIOUS | MALICIOUS | 100 | 3 | Y |
| real/malicious/snyk_clawhub_agent.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| real/malicious/snyk_gemini_vercel.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |
| real/malicious/snyk_google_malware.md | MALICIOUS | MALICIOUS | 92 | 1 | Y |
| real/malicious/snyk_vercel_exfil.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |

**Note:** For malicious samples, any non-CLEAN verdict (MALICIOUS, SUSPICIOUS,
or CAUTION) counts as a true positive — the sample was detected as threatening.

---

## Per-Rule Hit Counts

The following table shows how many fixtures each rule fires on. Rules that
trigger frequently across many malicious samples are effective broad-spectrum
detectors; rules that trigger only once or twice may be highly specialized.

| Rule ID | Hits |
|---------|-----:|
| MALWAR-PERSIST-002 | 13 |
| MALWAR-ENV-001 | 12 |
| MALWAR-MULTI-001 | 8 |
| MALWAR-PERSIST-001 | 8 |
| MALWAR-HIJACK-001 | 5 |
| MALWAR-MAL-001 | 5 |
| MALWAR-SUPPLY-001 | 5 |
| MALWAR-CMD-001 | 4 |
| MALWAR-EXFIL-001 | 4 |
| MALWAR-PI-002 | 4 |
| MALWAR-STEG-001 | 4 |
| MALWAR-EXFIL-003 | 4 |
| MALWAR-OBF-001 | 3 |
| MALWAR-PI-001 | 3 |
| MALWAR-OBF-003 | 2 |
| threat-intel-sig-clawhavoc-c2-ip | 2 |
| threat-intel-sig-clawhavoc-glot | 2 |
| MALWAR-CRED-002 | 2 |
| MALWAR-CMD-004 | 1 |
| MALWAR-PI-003 | 1 |
| MALWAR-SE-002 | 1 |
| threat-intel-sig-clawhavoc-domain | 1 |
| MALWAR-SE-003 | 1 |

The most frequently triggering rules are persistence detection
(`MALWAR-PERSIST-002`, 13 hits), environment variable harvesting
(`MALWAR-ENV-001`, 12 hits), and multi-step manipulation detection
(`MALWAR-MULTI-001`, 8 hits). Threat intel signatures fire only on samples
containing known ClawHavoc campaign IOCs.

---

## Per-Category Breakdown

| Category | TP | FP | TN | FN | Accuracy |
|----------|---:|---:|---:|---:|---------:|
| benign | 0 | 0 | 5 | 0 | 100.0% |
| malicious | 17 | 0 | 0 | 0 | 100.0% |
| real/benign | 0 | 1 | 2 | 0 | 66.7% |
| real/malicious | 6 | 0 | 0 | 0 | 100.0% |

- **Synthetic benign** (5 files): 100% accuracy. All simple, well-structured
  skills with no suspicious patterns are correctly classified as CLEAN.
- **Synthetic malicious** (17 files): 100% detection rate. Every crafted
  malicious sample is flagged, though detection confidence varies — some subtle
  samples (e.g., `multi_stage_dropper.md`, `obfuscated_curl.md`,
  `typosquatted_package.md`) receive lower risk scores (SUSPICIOUS or CAUTION)
  rather than MALICIOUS.
- **Real-world benign** (3 files): 66.7% accuracy due to one false positive.
- **Real-world malicious** (6 files): 100% detection rate across all Snyk
  research samples.

---

## ClawHub Samples (Real-World, No Ground Truth)

These 13 samples are real skills from the ClawHub registry. They have no
pre-labeled ground truth and are not included in precision/recall calculations.

| File | Verdict | Risk | Findings | Matched Rules |
|------|---------|-----:|:--------:|---------------|
| bankrbot_bankr.md | CLEAN | 0 | 0 | — |
| bankrbot_clanker.md | CLEAN | 0 | 0 | — |
| bankrbot_onchainkit.md | CLEAN | 0 | 0 | — |
| bankrbot_veil.md | MALICIOUS | 86 | 1 | MALWAR-ENV-001 |
| bankrbot_yoink.md | CLEAN | 0 | 0 | — |
| bankrbot_zapper.md | CLEAN | 0 | 0 | — |
| clawpod_massive.md | CLEAN | 0 | 0 | — |
| metamask_gator.md | CLEAN | 0 | 0 | — |
| metamask_smart_accounts.md | CLEAN | 0 | 0 | — |
| model_hierarchy.md | CLEAN | 0 | 0 | — |
| search_layer.md | CLEAN | 0 | 0 | — |
| x_bookmarks.md | CLEAN | 0 | 0 | — |
| x_tweet_fetcher.md | CLEAN | 0 | 0 | — |

12 of 13 ClawHub samples scan as CLEAN. One sample — `bankrbot_veil.md` — is
flagged as MALICIOUS (risk 86) due to the `MALWAR-ENV-001` rule, which detects
environment variable harvesting patterns. The Veil skill involves private key
management and `.env` file creation with `chmod 600`, which matches the
environment harvesting heuristic. This may warrant a rule refinement to
distinguish legitimate key management from malicious credential harvesting.

---

## Notes on False Positives

### `real/benign/anthropic_skill_creator.md` (FP)

This is Anthropic's official skill-creation guide. It is incorrectly flagged as
MALICIOUS (risk 100) by the `MALWAR-PERSIST-002` rule (persistence mechanism
detection), which fires twice. The skill contains instructional examples showing
bash commands, directory creation patterns (`mkdir -p`, `scripts/`), and file
path conventions that match persistence heuristics. Since the content describes
*how to create skills* rather than *executing* malicious operations, this is a
false positive caused by instructional/educational content triggering behavioral
pattern matching.

**Recommended mitigation:** Consider adding context-awareness to persistence
rules to distinguish instructional/template content (fenced code blocks used
as examples) from actual executable directives.

---

## Notes on Detection Confidence Variation

While all malicious samples are detected (100% recall), three samples receive
lower confidence verdicts:

- **`multi_stage_dropper.md`**: SUSPICIOUS (risk 58) — only 1 rule fires.
  The dropper technique uses subtle multi-stage patterns that partially evade
  individual rules.
- **`obfuscated_curl.md`**: SUSPICIOUS (risk 60) — only 1 rule fires.
  The obfuscation is effective enough to bypass most pattern-matching rules.
- **`typosquatted_package.md`**: CAUTION (risk 35) — only 1 rule fires.
  Typosquatting detection is inherently difficult with static analysis alone.

These samples would benefit from LLM-layer analysis for higher-confidence
verdicts. The rule engine correctly flags them as non-CLEAN, but the risk scores
are below the MALICIOUS threshold (75).
