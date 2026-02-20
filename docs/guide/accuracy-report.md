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

!!! note
    For malicious samples, any non-CLEAN verdict (MALICIOUS, SUSPICIOUS, or CAUTION) counts as a true positive.

---

## Per-Category Breakdown

| Category | TP | FP | TN | FN | Accuracy |
|----------|---:|---:|---:|---:|---------:|
| benign | 0 | 0 | 5 | 0 | 100.0% |
| malicious | 17 | 0 | 0 | 0 | 100.0% |
| real/benign | 0 | 1 | 2 | 0 | 66.7% |
| real/malicious | 6 | 0 | 0 | 0 | 100.0% |

---

## Per-Rule Hit Counts

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

---

## Notes on False Positives

### `real/benign/anthropic_skill_creator.md` (FP)

This is Anthropic's official skill-creation guide. It is incorrectly flagged as MALICIOUS by the `MALWAR-PERSIST-002` rule. The skill contains instructional examples showing bash commands and file path conventions that match persistence heuristics. Since the content describes *how to create skills* rather than *executing* malicious operations, this is a false positive caused by instructional content triggering behavioral pattern matching.

**Recommended mitigation:** Consider adding context-awareness to persistence rules to distinguish instructional/template content from actual executable directives.

---

## Notes on Detection Confidence Variation

While all malicious samples are detected (100% recall), three samples receive lower confidence verdicts:

- **`multi_stage_dropper.md`**: SUSPICIOUS (risk 58)
- **`obfuscated_curl.md`**: SUSPICIOUS (risk 60)
- **`typosquatted_package.md`**: CAUTION (risk 35)

These samples would benefit from LLM-layer analysis for higher-confidence verdicts.
