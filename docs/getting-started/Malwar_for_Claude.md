# Getting Started with Malwar for Claude Code

Claude Code uses SKILL.md files to extend its capabilities. Because these files can execute shell commands, They pose a serious risk to your system's security. A malicious skill file could contain hidden commands designed to:
* Exposing sensitive credentials
* Delete local files or modify system configurations.
* Install backdoors on your machine.

Malwar allows you to verify these files with a risk verdict.
---

## 1. Installation
Install the package via pip and initialize the local threat database to ensure you have the latest detection rules.

```bash
pip install malwar
malwar db init
```

## 2. Scanning a Skill before Installing
Before moving a third-party skill into your .claude/commands/ directory, run a scan. You can scan a skill file directly from a URL (e.g., from a GitHub repository) or from a file you have already downloaded.

Scan a Local File

``` bash
malwar scan ./path/to/your-skill.md
```
![Local scan output](../images/malwar-scan-local.png)

Scan a Remote URL

``` bash
malwar crawl url https://example.com/path/to/remote-skill.md
```
 
## 3. Understanding Results
Malwar categorizes files based on a **risk score (0-100)**. Use the table below to determine your next steps:

| Verdict | Risk Score | Recommended Action |
| :-- | :-- | :-- |
| CLEAN | 0-14 | Safe to install in your Claude commands folder. |
| CAUTION | 15-39 | Review the flagged lines before installing. |
| SUSPICIOUS | 40-74 | Review carefully; check for unusual shell commands. |
| MALICIOUS | 75+ | Do not install. Potential data exfiltration or harmful scripts. |

![Malwar Verdict](../images/malwar-verdict.png)

## 4. Safe Installation Workflow
To maintain a secure environment, adopt this two-step process:

Download: Save the new .md skill to a temporary folder.

Scan: 
```Bash
Run malwar scan <filename>.
```

If the verdict is CLEAN, move it to your Claude configuration

## Advanced: Registry Crawling
If you are exploring a repository like ClawHub, you can scan an entire registry or a specific slug using the crawl feature:

```Bash
# Scan by slug
malwar crawl scan <slug-name>

# Scan by repository URL
malwar crawl url <repository-url>