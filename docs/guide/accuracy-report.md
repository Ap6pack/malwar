# Malwar Detection Accuracy Report

**Date:** 2026-07-05
**Engine version:** 0.4.0
**Layers tested:** rule_engine, threat_intel (no LLM, no URL crawling)
**Total fixtures scanned:** 51 (38 labeled, 13 unlabeled ClawHub samples)

---

## Overall Accuracy Metrics

| Metric              | Value  |
|---------------------|--------|
| True Positives      | 29     |
| False Positives     | 0      |
| True Negatives      | 9      |
| False Negatives     | 0      |
| **Accuracy**        | 100.0% |
| **Precision**       | 100.0% |
| **Recall (TPR)**    | 100.0% |
| **F1 Score**        | 100.0% |
| False Positive Rate | 0.0%   |

On the labeled corpus the offline layers (rule engine + threat intel, no LLM or
URL crawling) detect every malicious sample and flag no benign sample. The
previous report's single false positive — Anthropic's official skill-creation
guide flagged by `MALWAR-PERSIST-002` — was fixed by word-anchoring that rule
(see issue #2), bringing precision from 95.8% to 100%.

---

## Per-Fixture Results

| File | Expected | Actual | Risk | Findings | Correct |
|------|----------|--------|-----:|:--------:|:-------:|
| benign/code_formatter.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/git_helper.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/hello_world.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/legitimate_with_urls.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/powershell_docs.md | CLEAN | CLEAN | 0 | 0 | Y |
| benign/web_search.md | CLEAN | CLEAN | 0 | 0 | Y |
| malicious/agent_hijacking.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/base64_reverse_shell.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |
| malicious/clawhavoc_amos.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/clickfix_fake_prereq.md | MALICIOUS | MALICIOUS | 92 | 1 | Y |
| malicious/credential_harvester.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| malicious/env_harvesting.md | MALICIOUS | MALICIOUS | 100 | 7 | Y |
| malicious/exfil_soul_md.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/filesystem_modification.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/letssendit_pump.md | MALICIOUS | MALICIOUS | 88 | 1 | Y |
| malicious/money_radar_affiliate.md | MALICIOUS | SUSPICIOUS | 63 | 1 | Y |
| malicious/multi_stage_dropper.md | MALICIOUS | SUSPICIOUS | 58 | 1 | Y |
| malicious/multi_step_manipulation.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/obfuscated_curl.md | MALICIOUS | SUSPICIOUS | 60 | 1 | Y |
| malicious/omnicogg_padded.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |
| malicious/persistence_mechanism.md | MALICIOUS | MALICIOUS | 100 | 10 | Y |
| malicious/powershell_cradle.md | MALICIOUS | MALICIOUS | 90 | 1 | Y |
| malicious/prompt_injection_basic.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| malicious/prompt_injection_unicode.md | MALICIOUS | MALICIOUS | 100 | 4 | Y |
| malicious/shadowpkg_typosquat.md | MALICIOUS | MALICIOUS | 100 | 9 | Y |
| malicious/snyktoxic_vercel_exfil.md | MALICIOUS | MALICIOUS | 100 | 8 | Y |
| malicious/steganographic.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| malicious/supply_chain.md | MALICIOUS | MALICIOUS | 100 | 9 | Y |
| malicious/typosquatted_package.md | MALICIOUS | CAUTION | 35 | 1 | Y |
| real/benign/anthropic_frontend_design.md | CLEAN | CLEAN | 0 | 0 | Y |
| real/benign/anthropic_pdf.md | CLEAN | CLEAN | 0 | 0 | Y |
| real/benign/anthropic_skill_creator.md | CLEAN | CLEAN | 0 | 0 | Y |
| real/malicious/snyk_ascii_smuggling.md | MALICIOUS | SUSPICIOUS | 56 | 1 | Y |
| real/malicious/snyk_clawhub.md | MALICIOUS | MALICIOUS | 100 | 3 | Y |
| real/malicious/snyk_clawhub_agent.md | MALICIOUS | MALICIOUS | 100 | 5 | Y |
| real/malicious/snyk_gemini_vercel.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |
| real/malicious/snyk_google_malware.md | MALICIOUS | MALICIOUS | 100 | 3 | Y |
| real/malicious/snyk_vercel_exfil.md | MALICIOUS | MALICIOUS | 100 | 2 | Y |

!!! note
    For malicious samples, any non-CLEAN verdict (MALICIOUS, SUSPICIOUS, or CAUTION) counts as a true positive.

---

## Per-Category Breakdown

| Category | TP | FP | TN | FN | Accuracy |
|----------|---:|---:|---:|---:|---------:|
| benign | 0 | 0 | 6 | 0 | 100.0% |
| malicious | 23 | 0 | 0 | 0 | 100.0% |
| real/benign | 0 | 0 | 3 | 0 | 100.0% |
| real/malicious | 6 | 0 | 0 | 0 | 100.0% |

---

## Unlabeled ClawHub Samples

13 real skills pulled from ClawHub are scanned without a ground-truth label (for
manual review, not scored in the metrics above). **2 of 13** are flagged as
non-CLEAN by the offline layers; the remainder are CLEAN.

---

## Per-Rule Hit Counts

Rule-engine rules that fired across the labeled corpus (threat-intel signature
hits omitted for brevity):

| Rule ID | Hits |
|---------|-----:|
| MALWAR-ENV-001 | 11 |
| MALWAR-PERSIST-002 | 11 |
| MALWAR-SUPPLY-001 | 10 |
| MALWAR-MULTI-001 | 8 |
| MALWAR-PERSIST-001 | 8 |
| MALWAR-CMD-001 | 6 |
| MALWAR-HIJACK-001 | 5 |
| MALWAR-MAL-001 | 5 |
| MALWAR-EXFIL-001 | 5 |
| MALWAR-PI-002 | 4 |
| MALWAR-STEG-001 | 4 |
| MALWAR-EXFIL-003 | 4 |
| MALWAR-OBF-001 | 3 |
| MALWAR-PI-001 | 3 |
| MALWAR-OBF-003 | 2 |
| MALWAR-CRED-002 | 2 |
| MALWAR-SE-003 | 2 |
| MALWAR-FRAUD-001 | 1 |
| MALWAR-FRAUD-002 | 1 |
| MALWAR-EVADE-001 | 1 |
| MALWAR-OBF-004 | 1 |
| MALWAR-CMD-003 | 1 |
| MALWAR-CMD-004 | 1 |
| MALWAR-PI-003 | 1 |
| MALWAR-SE-002 | 1 |

The newest rules all fire on their target fixtures: `MALWAR-FRAUD-001`
(money-radar affiliate injection), `MALWAR-FRAUD-002` (letssendit
front-running), `MALWAR-EVADE-001` (omnicogg padding), and `MALWAR-OBF-004`
(PowerShell download cradle).

---

## Notes on Detection Confidence Variation

While all malicious samples are detected (100% recall), a few receive lower
non-MALICIOUS verdicts from the offline layers alone:

- **`money_radar_affiliate.md`**: SUSPICIOUS (risk 63)
- **`obfuscated_curl.md`**: SUSPICIOUS (risk 60)
- **`multi_stage_dropper.md`**: SUSPICIOUS (risk 58)
- **`snyk_ascii_smuggling.md`**: SUSPICIOUS (risk 56)
- **`typosquatted_package.md`**: CAUTION (risk 35)

These are still true positives (any non-CLEAN verdict on a malicious sample
counts), and would receive higher-confidence verdicts with the LLM layer
enabled.

---

*Reproduce this report by scanning `tests/fixtures/skills/` with the rule engine
and threat-intel layers (`use_llm=False, use_urls=False`); see
`tests/benchmark/test_accuracy.py`.*
