# ML-Based Risk Scoring

## Overview

Malwar includes an ML-based risk scoring model that complements the rule engine by computing a probability that a SKILL.md file is malicious. The ML model uses a logistic regression trained on labeled examples, implemented in pure Python with no external ML library dependencies.

## Architecture

```
SKILL.md
  |
  v
[Feature Extractor] --> 20-dimensional feature vector
  |
  v
[Risk Scorer] --> P(malicious) in [0.0, 1.0]
  |
  v
[Calibrator] --> Blended score (weighted avg of rule + ML scores)
```

### Components

- **`malwar.ml.features.FeatureExtractor`** -- Extracts 20 numerical features from a `SkillContent` object
- **`malwar.ml.model.RiskScorer`** -- Logistic regression model: `P(malicious) = sigmoid(X @ weights + bias)`
- **`malwar.ml.trainer.ModelTrainer`** -- Trains/retrains the model from labeled skill files
- **`malwar.ml.calibrator.RiskCalibrator`** -- Blends ML and rule engine scores

## Features Extracted

| # | Feature | Description |
|---|---------|-------------|
| 1 | `line_count` | Total number of lines in the file |
| 2 | `file_size_bytes` | File size in bytes |
| 3 | `code_block_count` | Number of fenced code blocks |
| 4 | `code_block_ratio` | Ratio of code block characters to total characters |
| 5 | `url_count` | Total number of URLs found |
| 6 | `external_url_ratio` | URL count normalized by line count |
| 7 | `unique_domain_count` | Number of unique domains in URLs |
| 8 | `untrusted_domain_ratio` | Fraction of domains not in trusted list |
| 9 | `encoded_content_ratio` | Ratio of base64-like content to total |
| 10 | `command_pattern_density` | Suspicious command patterns per line |
| 11 | `env_var_reference_count` | References to sensitive environment variables |
| 12 | `pipe_to_bash_count` | `| bash` / `| sh` patterns |
| 13 | `prompt_injection_score` | Prompt injection indicator density [0, 1] |
| 14 | `content_entropy` | Shannon entropy of the content (bits/char) |
| 15 | `section_count` | Number of markdown sections |
| 16 | `metadata_completeness` | How complete the YAML frontmatter is [0, 1] |
| 17 | `hidden_content_ratio` | HTML comments / total content ratio |
| 18 | `exfiltration_pattern_count` | Data exfiltration pattern matches |
| 19 | `avg_code_block_length` | Average length of code blocks |
| 20 | `hex_escape_density` | Hex escape sequences per body character |

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `MALWAR_ML_ENABLED` | `true` | Enable/disable ML scoring |
| `MALWAR_ML_WEIGHT` | `0.3` | Weight of ML score in blended result (0.0-1.0) |

When `MALWAR_ML_WEIGHT=0.3`, the blended score is:

```
blended = 0.7 * rule_score + 0.3 * (ml_probability * 100)
```

## Model Format

The model is stored as a JSON file (`src/malwar/ml/weights.json`) containing:

```json
{
  "weights": [w1, w2, ..., w20],
  "bias": 0.123,
  "feature_means": [m1, m2, ..., m20],
  "feature_stds": [s1, s2, ..., s20],
  "metadata": {
    "version": "1.0.0",
    "trained_at": "2026-02-20T...",
    "num_features": 20,
    "training_samples": 24,
    "training_accuracy": 1.0,
    "feature_names": ["line_count", ...]
  }
}
```

JSON is used instead of pickle for security -- no arbitrary code execution on model load.

## CLI Commands

### Train/retrain the model

```bash
malwar ml train
malwar ml train --fixtures-dir /path/to/labeled/skills
malwar ml train --lr 0.5 --epochs 1000 --output /path/to/weights.json
```

### View model info

```bash
malwar ml info
```

## Pipeline Integration

When ML scoring is enabled, after all detection layers complete, the pipeline:

1. Extracts features from the scanned `SkillContent`
2. Runs the logistic regression model to get `P(malicious)`
3. Stores `ml_risk_score` on the `ScanResult` object
4. Logs the blended score for observability

The `ml_risk_score` field on `ScanResult` is optional and does not affect existing rule-based verdicts.

## Training

The initial model is trained on the test fixture files (5 benign + 19 malicious). To retrain with additional labeled data:

1. Place benign `.md` files in a `benign/` subdirectory
2. Place malicious `.md` files in a `malicious/` subdirectory
3. Run `malwar ml train --fixtures-dir /path/to/directory`

The trainer uses gradient descent with L2 regularization on binary cross-entropy loss. All math is implemented in pure Python -- no numpy or scikit-learn dependency.
