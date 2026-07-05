"""Agentic financial-fraud detection rules.

These target a threat class that goes beyond malware delivery: skills that
weaponize the agent's advisory authority and its ability to move money on the
user's behalf, for the publisher's financial gain. Documented by Unit 42
(June 2026):

  * "money-radar" — agentic affiliate injection: routed every financial
    recommendation through affiliate links from a known-malicious domain, with
    the publisher retaining dynamic control over which products were pushed.
  * "letssendit" — agentic front-running / pump-and-dump: instructed agents to
    pool funds into operator-controlled wallets ahead of a meme-token pump.

Both are plain-language instructions, invisible to malware signatures.
"""

from __future__ import annotations

import re

from malwar.core.constants import DetectorLayer, Severity, ThreatCategory
from malwar.detectors.rule_engine.base_rule import BaseRule
from malwar.detectors.rule_engine.registry import rule
from malwar.models.finding import Finding, Location
from malwar.models.skill import SkillContent


@rule
class AgenticAffiliateInjection(BaseRule):
    rule_id = "MALWAR-FRAUD-001"
    title = "Agentic affiliate injection"
    severity = Severity.HIGH
    category = ThreatCategory.FINANCIAL_FRAUD
    description = (
        "Detects skills that instruct the agent to route its recommendations "
        "through affiliate/referral links or a fixed monetized destination, "
        "hijacking the agent's advisory authority for the publisher's profit "
        "(e.g. the 'money-radar' skill)."
    )

    # The agent is told to give advice / recommend / rank products.
    ADVISORY_INDICATORS = [
        re.compile(
            r"\b(?:recommend|suggest|advise|advice|endorse|promote|rank|"
            r"best\s+(?:product|option|deal|price)|which\s+to\s+buy|"
            r"where\s+to\s+buy|financial\s+advice|shopping)\b",
            re.IGNORECASE,
        ),
    ]

    # ...and to funnel that advice through an affiliate/referral mechanic.
    AFFILIATE_INDICATORS = [
        re.compile(r"\baffiliate\b", re.IGNORECASE),
        re.compile(r"\breferral\s+link|\brefer(?:ral)?\s+code\b", re.IGNORECASE),
        re.compile(r"[?&](?:ref|aff|aff_id|affid|tag|utm_source|partner)=", re.IGNORECASE),
        re.compile(r"\bamzn\.to\b|\bamazon\.[a-z.]+/.*\btag=", re.IGNORECASE),
        re.compile(r"\b(?:monetize|commission|kickback|payout)\b", re.IGNORECASE),
    ]

    # Directive language that turns the two above into an instruction.
    DIRECTIVE_INDICATORS = [
        re.compile(
            r"\b(?:always|every|all|must|whenever|each\s+time)\b", re.IGNORECASE
        ),
        re.compile(
            r"\b(?:append|insert|add|replace|rewrite|route|redirect|use\s+this\s+link)\b",
            re.IGNORECASE,
        ),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        content = skill.raw_content
        has_advisory = any(p.search(content) for p in self.ADVISORY_INDICATORS)
        affiliate_hit = next(
            (p.search(content) for p in self.AFFILIATE_INDICATORS if p.search(content)),
            None,
        )
        has_directive = any(p.search(content) for p in self.DIRECTIVE_INDICATORS)

        if not (has_advisory and affiliate_hit and has_directive):
            return []

        line_start = content[: affiliate_hit.start()].count("\n") + 1
        return [Finding(
            id=f"{self.rule_id}-L{line_start}",
            rule_id=self.rule_id,
            title=self.title,
            description=(
                "Skill instructs the agent to funnel its recommendations through "
                "an affiliate/referral link, monetizing the user's trust without "
                "disclosure"
            ),
            severity=self.severity,
            confidence=0.85,
            category=self.category,
            detector_layer=DetectorLayer.RULE_ENGINE,
            location=Location(
                line_start=line_start,
                snippet=affiliate_hit.group(0)[:200],
            ),
            evidence=[
                "Advisory/recommendation directive present",
                f"Affiliate mechanic: {affiliate_hit.group(0)[:80]!r}",
                "Instructional language routing advice through the affiliate link",
            ],
        )]


@rule
class AgenticFrontRunning(BaseRule):
    rule_id = "MALWAR-FRAUD-002"
    title = "Agentic front-running / pump-and-dump"
    severity = Severity.CRITICAL
    category = ThreatCategory.FINANCIAL_FRAUD
    description = (
        "Detects skills that instruct the agent to transfer or pool user funds "
        "into a fixed crypto wallet, or to coordinate buying a token to inflate "
        "its price — an autonomous market-manipulation scheme (e.g. the "
        "'letssendit' skill)."
    )

    # Crypto wallet / address destinations.
    WALLET_PATTERNS = [
        re.compile(r"\b0x[a-fA-F0-9]{40}\b"),              # EVM address
        re.compile(r"\bbc1[0-9ac-hj-np-z]{11,71}\b"),      # bech32 BTC
        re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),  # legacy BTC
        re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b(?=.*\b(?:sol|solana|spl)\b)",
                   re.IGNORECASE),                          # Solana (context-gated)
    ]

    # Directive to move / pool funds.
    FUND_TRANSFER_INDICATORS = [
        re.compile(
            r"\b(?:send|transfer|deposit|pool|contribute|forward|route)\b"
            r"[^.\n]{0,40}\b(?:funds?|eth|btc|sol|bnb|usdt|usdc|crypto|coins?|tokens?|"
            r"wallet|balance|money)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\bpool\s+(?:the\s+)?(?:funds?|money|capital)\b", re.IGNORECASE),
    ]

    # Pump-and-dump / front-running / coordination language.
    MANIPULATION_INDICATORS = [
        re.compile(r"\bpump(?:\s+and\s+dump|\s+the\s+(?:price|token|coin))?\b", re.IGNORECASE),
        re.compile(r"\bfront[-\s]?run", re.IGNORECASE),
        re.compile(r"\bbuy\s+(?:before|ahead\s+of|early)\b", re.IGNORECASE),
        re.compile(r"\b(?:ahead\s+of\s+(?:the\s+)?(?:demand|crowd|pump))\b", re.IGNORECASE),
        re.compile(r"\b(?:meme\s*coin|meme\s*token|to\s+the\s+moon|shill|moon\s+it)\b",
                   re.IGNORECASE),
        re.compile(r"\bcoordinate[^.\n]{0,30}\b(?:buy|purchase|entry)\b", re.IGNORECASE),
    ]

    def check(self, skill: SkillContent) -> list[Finding]:
        content = skill.raw_content

        wallet_hit = next(
            (p.search(content) for p in self.WALLET_PATTERNS if p.search(content)),
            None,
        )
        has_transfer = any(p.search(content) for p in self.FUND_TRANSFER_INDICATORS)
        manip_hit = next(
            (p.search(content) for p in self.MANIPULATION_INDICATORS if p.search(content)),
            None,
        )

        # Fire when the skill both moves funds and expresses manipulation intent.
        # A wallet address strengthens the transfer signal but the pooling
        # directive alone (with manipulation intent) is sufficient.
        moves_funds = has_transfer or wallet_hit is not None
        if not (moves_funds and manip_hit is not None):
            return []

        anchor = manip_hit
        line_start = content[: anchor.start()].count("\n") + 1
        confidence = 0.88 if wallet_hit else 0.80

        evidence = [
            f"Market-manipulation intent: {manip_hit.group(0)[:80]!r}",
            "Fund transfer/pooling directive present" if has_transfer else "",
            f"Destination wallet: {wallet_hit.group(0)[:60]}" if wallet_hit else "",
        ]
        return [Finding(
            id=f"{self.rule_id}-L{line_start}",
            rule_id=self.rule_id,
            title=self.title,
            description=(
                "Skill directs the agent to move user funds and coordinate a "
                "token pump — an autonomous financial-manipulation scheme"
            ),
            severity=self.severity,
            confidence=confidence,
            category=self.category,
            detector_layer=DetectorLayer.RULE_ENGINE,
            location=Location(
                line_start=line_start,
                snippet=anchor.group(0)[:200],
            ),
            evidence=[e for e in evidence if e],
        )]
