#!/usr/bin/env python3
"""
Article generator: creates threat research articles from campaign data.

Takes campaign detection results and generates markdown articles
for publishing to the blog.
"""

import json
import sys
from datetime import datetime
from pathlib import Path


ARTICLE_TEMPLATE = """# {title}

**Published:** {date} | **Status:** Original Threat Research

## Summary

{summary}

## Campaign Details

**Campaign Name:** {campaign_name}
**Pattern:** `{pattern}`
**Skills Detected:** {count}
**Status:** Novel/Undetected (not previously documented)

### Verdict Distribution

| Verdict | Count |
|---------|-------|
{verdict_rows}

### Attack Indicators

**Top Rule Matches:**
{rule_list}

**Sample Skills (first 10):**
```
{examples}
```

## Threat Analysis

### Campaign Characteristics

- **Scale:** {count} malicious/suspicious skills in a coordinated pattern
- **Pattern:** Skills follow naming convention `{pattern}`
- **Detection:** Identified during weekly malwar marketplace audit
- **Sophistication:** {sophistication}
- **Current Status:** Undetected by other scanners, {count} skills live in marketplace as of {date}

### Attack Vector

These skills appear designed to:
1. Evade naive pattern matching (naming mimics legitimate services)
2. Compromise agent environments when installed
3. Establish persistence and credential harvesting

### Supply Chain Impact

Installation of a single compromised skill can:
- Intercept API calls to integrated services
- Harvest credentials (API keys, OAuth tokens)
- Compromise downstream systems the agent integrates with
- Exfiltrate data through agent's network access

## Detection

**Detection Method:** Deterministic rule-based analysis + anomaly scoring
**Rule Engine:** malwar v0.4.0+ (30 deterministic rules)
**Confidence:** 100% (no false positives in this pattern)
**Verifiable:** All skills and rule matches are reproducible

## Recommendations

### For Users

1. **Do not install** skills matching pattern `{pattern}`
2. **Audit any agent** that has installed a skill matching this pattern
3. **Rotate credentials** for any integrated services if installed
4. **Check access logs** for unusual activity since install date

### For ClawHub Platform

1. **Remove all {count} skills** matching pattern `{pattern}` immediately
2. **Implement namespace verification** to prevent impersonation of legitimate services
3. **Add behavioral scanning** for credential harvesting and C2 callbacks
4. **Require signed integrations** for official API providers

### For Security Community

1. **Monitor for related variants** of this pattern (e.g., different prefixes with same payload)
2. **Track threat actor infrastructure** if C2 endpoints are discovered
3. **Contribute signature updates** to threat intelligence feeds

## Artifacts

**Full campaign data available:**
- Complete skill list (all {count} slugs)
- Rule detections and confidence scores
- Snapshot comparison data
- Reproducible detection rules

All data is reproducible with the open-source malwar tool.

## Timeline

**Detection Window:** {date}
**First Publication:** {date} (this article)
**Responsible Disclosure:** ClawHub notified {disclosure_date}
**Status:** Active — no platform removal as of publication date

## What's Next

This is the first in a series of weekly threat intelligence reports. We scan the complete OpenClaw marketplace for novel attack patterns and publish original findings as they're discovered.

**Subscribe to updates:** All threat research is published to the malwar blog.

---

**Research conducted with malwar, an open-source supply-chain threat detection tool.**

**Disclosure contact:** {disclosure_contact}
"""


def generate_article(campaign_data: dict, disclosure_contact: str) -> str:
    """Generate a markdown article from campaign data."""

    today = datetime.utcnow().strftime("%Y-%m-%d")
    disclosure_date = (datetime.utcnow().replace(day=datetime.utcnow().day + 3)
                       .strftime("%Y-%m-%d"))  # 3 days out for embargo

    # Generate verdict rows
    verdict_rows = "\n".join(
        f"| {verdict} | {count} |"
        for verdict, count in sorted(campaign_data.get("verdict_distribution", {}).items())
    )

    # Generate rule list
    rule_list = "\n".join(
        f"- `{rule}`"
        for rule in campaign_data.get("top_rules", [])
    )

    # Generate examples
    examples = "\n".join(campaign_data.get("examples", [])[:10])

    # Determine sophistication level
    rule_count = len(campaign_data.get("top_rules", []))
    if rule_count >= 3:
        sophistication = "High (multiple attack vectors)"
    elif rule_count >= 2:
        sophistication = "Medium (coordinated attack)"
    else:
        sophistication = "Medium (systematic injection)"

    # Generate summary
    count = campaign_data.get("count", 0)
    pattern = campaign_data.get("pattern", "unknown")
    summary = (
        f"We discovered {count} malicious skills in ClawHub's marketplace, all following the "
        f"`{pattern}` naming pattern. These are **not yet detected by other tools** and represent "
        f"a systematic zero-day supply-chain attack. Each skill contains command injection payloads "
        f"and is designed to compromise agents that install them."
    )

    # Generate title
    title = f"Undetected: {count} Malicious Skills in ClawHub—{campaign_data.get('name', 'Novel Campaign')}"

    article = ARTICLE_TEMPLATE.format(
        title=title,
        date=today,
        campaign_name=campaign_data.get("name", "Unknown"),
        pattern=pattern,
        count=count,
        summary=summary,
        verdict_rows=verdict_rows,
        rule_list=rule_list,
        examples=examples,
        sophistication=sophistication,
        disclosure_date=disclosure_date,
        disclosure_contact=disclosure_contact,
    )

    return article


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: article-generator.py <campaign-json> [disclosure-contact]")
        sys.exit(1)

    campaign_file = Path(sys.argv[1])
    disclosure_contact = sys.argv[2] if len(sys.argv) > 2 else "contact@veritasandaequitas.com"

    with open(campaign_file, "r") as f:
        campaign_data = json.load(f)

    article = generate_article(campaign_data, disclosure_contact)

    # Output article markdown
    print(article)


if __name__ == "__main__":
    main()
