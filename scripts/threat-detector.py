#!/usr/bin/env python3
"""
Threat pattern detector: identifies novel malware campaigns in registry snapshots.

Compares latest snapshot to previous, groups new flagged skills by patterns,
and detects novel campaigns for automated threat research publication.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
import yaml
from dataclasses import dataclass, asdict


@dataclass
class Campaign:
    """A detected malware campaign."""
    name: str
    pattern: str  # naming pattern, publisher, etc.
    count: int
    verdict_distribution: dict  # {"MALICIOUS": 10, "SUSPICIOUS": 5}
    examples: list  # sample skill slugs
    top_rules: list  # most common rule IDs
    is_novel: bool = False
    first_detected: str = ""  # ISO date


def load_snapshot(path: Path) -> dict:
    """Load a registry snapshot from JSON."""
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return json.load(f)


def load_campaigns_db(path: Path) -> dict:
    """Load the known campaigns database."""
    if not path.exists():
        return {"campaigns": []}
    with open(path, "r") as f:
        return yaml.safe_load(f) or {"campaigns": []}


def detect_naming_pattern(slug: str) -> str:
    """Extract naming pattern (e.g., 'oo-*', 'linkfox-*', 'tianapi-*')."""
    parts = slug.split("-")
    if len(parts) >= 2:
        prefix = parts[0]
        if len(prefix) <= 4:  # short prefixes like "oo", "linkfox", "oo"
            return f"{prefix}-*"
    return "other"


def group_skills_by_pattern(skills: dict) -> dict:
    """Group skills by detected patterns."""
    patterns = defaultdict(lambda: {
        "skills": [],
        "verdicts": defaultdict(int),
        "rules": defaultdict(int),
    })

    for slug, record in skills.items():
        if record.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            pattern = detect_naming_pattern(slug)
            patterns[pattern]["skills"].append(slug)
            patterns[pattern]["verdicts"][record.get("verdict", "UNKNOWN")] += 1

            # Track top rules
            for rule in record.get("finding_rule_ids", [])[:3]:
                patterns[pattern]["rules"][rule] += 1

    return patterns


def is_novel_campaign(pattern_name: str, count: int, known_campaigns: list) -> bool:
    """Check if a pattern is novel (not in known campaigns database)."""
    known_patterns = {c["pattern"] for c in known_campaigns}
    return pattern_name not in known_patterns and count >= 5  # novel if 5+ skills


def detect_campaigns(
    latest_snapshot: dict,
    previous_snapshot: dict,
    campaigns_db: dict,
) -> list:
    """Detect novel threat campaigns in the snapshot diff."""

    latest_skills = latest_snapshot.get("skills", {})
    previous_skills = previous_snapshot.get("skills", {})

    # Find NEW flagged skills (not in previous, or verdict changed)
    new_flagged = {}
    for slug, record in latest_skills.items():
        if record.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            prev = previous_skills.get(slug, {})
            prev_verdict = prev.get("verdict", "CLEAN")

            # New if wasn't flagged before
            if prev_verdict not in ("MALICIOUS", "SUSPICIOUS"):
                new_flagged[slug] = record

    if not new_flagged:
        return []

    # Group by pattern
    patterns = group_skills_by_pattern(new_flagged)
    known_campaigns = campaigns_db.get("campaigns", [])

    campaigns = []
    for pattern_name, data in patterns.items():
        if len(data["skills"]) >= 5:  # minimum campaign size
            is_novel = is_novel_campaign(pattern_name, len(data["skills"]), known_campaigns)

            if is_novel:
                top_rules = sorted(
                    data["rules"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:3]

                campaign = Campaign(
                    name=f"Campaign-{pattern_name.replace('-', '_').upper()}",
                    pattern=pattern_name,
                    count=len(data["skills"]),
                    verdict_distribution=dict(data["verdicts"]),
                    examples=sorted(data["skills"])[:10],
                    top_rules=[r[0] for r in top_rules],
                    is_novel=True,
                )
                campaigns.append(campaign)

    return campaigns


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: threat-detector.py <latest-snapshot> [previous-snapshot] [campaigns.yml]")
        sys.exit(1)

    latest_path = Path(sys.argv[1])
    previous_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    campaigns_db_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    latest = load_snapshot(latest_path)
    previous = load_snapshot(previous_path) if previous_path else {}
    campaigns_db = load_campaigns_db(campaigns_db_path) if campaigns_db_path else {}

    campaigns = detect_campaigns(latest, previous, campaigns_db)

    # Output JSON for GitHub Actions to parse
    output = {
        "novel_campaigns": [asdict(c) for c in campaigns],
        "count": len(campaigns),
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
