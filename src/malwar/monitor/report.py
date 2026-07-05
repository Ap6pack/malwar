"""Human-shareable digests of a snapshot diff.

`render_digest` produces a compact plaintext summary of a day's registry sweep
suitable for a Slack post, an email body, or a blog note. `render_tweet`
produces a <=280-char variant for a public threat feed.

Deliberately non-accusatory: findings are heuristic and can be false positives,
so the digest reports *detections* ("flagged by <rules>"), never a verdict on a
named publisher's intent, and a public post should be reviewed by a human
before it goes out.
"""

from __future__ import annotations

from malwar.monitor.models import RegistrySnapshot, SnapshotDiff

TWEET_LIMIT = 280


def _date(created_at: str) -> str:
    return created_at[:10] if created_at else "?"


def render_digest(diff: SnapshotDiff, snapshot: RegistrySnapshot) -> str:
    """Return a compact, shareable plaintext summary of the sweep."""
    lines: list[str] = []
    lines.append(f"Malwar ClawHub sweep — {_date(diff.current_created_at)}")
    lines.append(
        f"Scanned {snapshot.skill_count} skills · {snapshot.flagged_count} flagged"
    )

    if diff.is_first_run:
        lines.append("(baseline run — no previous snapshot to diff against)")

    if diff.newly_malicious:
        lines.append("")
        lines.append(f"Newly flagged ({len(diff.newly_malicious)}):")
        for r in diff.newly_malicious:
            rules = ", ".join(r.finding_rule_ids[:3]) or "—"
            lines.append(
                f"  • {r.slug} — {r.verdict} (risk {r.risk_score}) · "
                f"{r.installs:,} installs · {rules}"
            )
    else:
        lines.append("")
        lines.append("No skills newly flagged since the last sweep.")

    lines.append("")
    lines.append(
        f"+{len(diff.added)} new · -{len(diff.removed)} removed · "
        f"{len(diff.modified)} updated · {len(diff.verdict_changed)} verdict changes"
    )
    return "\n".join(lines)


def render_tweet(diff: SnapshotDiff, snapshot: RegistrySnapshot) -> str:
    """Return a <=280-char summary for a public threat feed.

    Names at most a few slugs; truncates with a count if there are more.
    """
    date = _date(diff.current_created_at)
    n = len(diff.newly_malicious)

    if n == 0:
        text = (
            f"Malwar ClawHub sweep {date}: scanned {snapshot.skill_count} skills, "
            f"no new threats since yesterday. #ClawHub #AISecurity"
        )
        return text[:TWEET_LIMIT]

    head = (
        f"Malwar ClawHub sweep {date}: {n} skill(s) newly flagged "
        f"out of {snapshot.skill_count}."
    )
    tail = " #ClawHub #AISupplyChain"

    slugs: list[str] = []
    for r in diff.newly_malicious:
        candidate = f" {r.slug}({r.verdict[:4]})"
        if len(head) + len("".join(slugs)) + len(candidate) + len(tail) > TWEET_LIMIT:
            slugs.append(" …")
            break
        slugs.append(candidate)

    return (head + "".join(slugs) + tail)[:TWEET_LIMIT]
