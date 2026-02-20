# Writing Custom YAML Rules

Malwar supports custom detection rules defined in YAML files. This allows you
to enforce organisation-specific policies, block known-bad domains, or add
detection patterns without writing Python code.

## Quick start

1. Create a directory for your rules (e.g. `~/.malwar/rules/`).
2. Write one or more `.yml` / `.yaml` files following the schema below.
3. Set the `MALWAR_CUSTOM_RULES_DIR` environment variable (or the
   `custom_rules_dir` config field) to point to that directory.
4. Run Malwar as usual — custom rules are loaded automatically alongside the
   built-in Python rules.

```bash
export MALWAR_CUSTOM_RULES_DIR=~/.malwar/rules
malwar scan skill.md
```

## Rule schema

Every YAML rule file must be a single mapping with the following fields:

| Field               | Required | Type          | Default              | Description |
|---------------------|----------|---------------|----------------------|-------------|
| `id`                | yes      | string        | —                    | Unique rule identifier (e.g. `CUSTOM-001`). |
| `title`             | yes      | string        | —                    | Short human-readable title. |
| `description`       | no       | string        | `""`                 | Longer explanation of what the rule detects. |
| `severity`          | no       | enum          | `medium`             | One of `critical`, `high`, `medium`, `low`, `info`. |
| `category`          | no       | enum          | `suspicious_command`  | A `ThreatCategory` value (see below). |
| `confidence`        | no       | float 0..1    | `0.80`               | How confident the rule is when it triggers. |
| `enabled`           | no       | bool          | `true`               | Set to `false` to disable the rule without deleting the file. |
| `match`             | no       | `all` or `any`| `all`                | `all` = AND (every pattern must match). `any` = OR (at least one). |
| `patterns`          | yes      | list          | —                    | One or more pattern definitions (see below). |
| `evidence_template` | no       | string        | `"Matched custom rule: ${rule_id}"` | Template for the evidence string (see Templating). |

### Threat categories

Use any of these values for `category`:

- `obfuscated_command`
- `social_engineering`
- `prompt_injection`
- `known_malware`
- `credential_exposure`
- `suspicious_command`
- `data_exfiltration`
- `malicious_url`
- `suspicious_dependency`
- `typosquatting`
- `security_disablement`

## Pattern definitions

Each entry in the `patterns` list is a mapping with three fields:

| Field        | Required | Default    | Description |
|--------------|----------|------------|-------------|
| `pattern`    | yes      | —          | The string or regex to search for. |
| `match_type` | no       | `contains` | How to apply the pattern (see below). |
| `target`     | no       | `content`  | Where in the skill to look (see below). |

### Match types

| Match type    | Behaviour |
|---------------|-----------|
| `contains`    | Substring match — the target text must contain the pattern. |
| `exact`       | Full-string equality — the target text must equal the pattern exactly. |
| `starts_with` | The target text must start with the pattern. |
| `ends_with`   | The target text must end with the pattern. |
| `regex`       | The pattern is treated as a Python regular expression. |

### Targets

| Target                  | What is searched |
|-------------------------|------------------|
| `content`               | The entire raw skill file content. |
| `metadata.name`         | The `name` field from the skill's YAML front-matter. |
| `metadata.author`       | The `author` field from the front-matter. |
| `metadata.description`  | The `description` field from the front-matter. |
| `metadata.tags`         | Each tag in the `tags` list is tested individually. |
| `urls`                  | Each URL extracted from the skill is tested individually. |
| `code_blocks`           | Each fenced code block's content is tested individually. |

## Evidence templating

The `evidence_template` field supports `${variable}` substitution with these
variables:

| Variable     | Replaced with |
|--------------|---------------|
| `${rule_id}` | The rule's `id`. |
| `${pattern}` | The pattern string that matched. |
| `${match_type}` | The match type used (`contains`, `regex`, etc.). |
| `${target}`  | The target searched (`content`, `urls`, etc.). |
| `${value}`   | The actual matched text (for regex, the captured group). |

## Examples

### Block specific domains

```yaml
id: CUSTOM-DOMAIN-001
title: Blocked domain detected
description: Flags skills that reference blocklisted domains.
severity: high
category: malicious_url
confidence: 0.90
match: any

patterns:
  - pattern: "evil-domain\\.example\\.com"
    match_type: regex
    target: urls

  - pattern: "malware-c2.example.net"
    match_type: contains
    target: urls

evidence_template: "Blocked domain '${pattern}' found in ${target}"
```

### Enforce internal policies

```yaml
id: CUSTOM-POLICY-001
title: Internal security policy violation
description: Flags sudo usage and curl to raw IPs.
severity: medium
category: suspicious_command
confidence: 0.85
match: any

patterns:
  - pattern: "\\bsudo\\b"
    match_type: regex
    target: code_blocks

  - pattern: "curl\\s+https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
    match_type: regex
    target: content

evidence_template: "Policy violation: '${pattern}' in ${target}"
```

### Require all patterns to match (AND logic)

```yaml
id: CUSTOM-COMBO-001
title: Suspicious download-and-execute
description: Flags skills that both download a file and execute it.
severity: critical
category: suspicious_command
confidence: 0.95
match: all

patterns:
  - pattern: "\\bcurl\\b|\\bwget\\b"
    match_type: regex
    target: code_blocks

  - pattern: "\\bchmod\\s+\\+x\\b|\\bsh\\b|\\bbash\\b"
    match_type: regex
    target: code_blocks

evidence_template: "Download-and-execute: matched '${pattern}' in ${target}"
```

## Troubleshooting

- **Rule not loading?** Check the Malwar logs for warnings. Invalid YAML
  syntax or schema violations are logged but do not crash the scanner.
- **Rule not triggering?** Verify the `target` matches where the suspicious
  content actually appears. Use `match: any` if only one pattern needs to hit.
- **Regex not matching?** Remember that YAML requires escaping backslashes
  (`\\b` not `\b`). Test your regex with a tool like regex101.com first.
