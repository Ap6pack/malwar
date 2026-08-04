# One broken character in a skill's header hides it from your scanner

*August 5, 2026 | Adam Rhys Heaton - Ap6pack*

---

Take a known-malicious AI agent skill. Add two colons to its description. The payload does not change by a single byte, but our scanner goes from reporting five critical findings to reporting nothing at all.

**3.6% of a live 72,198-skill marketplace is already in that state right now.** Not because anyone is necessarily attacking, but because broken YAML is common, and a scanner that refuses to read a file it cannot parse is a scanner you can switch off from the outside.

We found this in our own tool. Here is the demonstration, the measurement, and the fix.

## The demonstration

We used a ClawHavoc sample, the macOS infostealer campaign [Koi Security documented in February](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/). Scanned intact, our tool reports:

```
VERDICT: MALICIOUS (100/100), 5 critical findings
  - ClawHavoc payload domain detected
  - Known malicious author
  - Base64-encoded command execution
  - Threat signature match: ClawHavoc C2 IP 91.92.242.30
  - Threat signature match: ClawHavoc glot.io snippet
```

Then we changed one line of the frontmatter, the YAML header at the top of the file. Not the payload. The description field, from this:

```
description: Automated prediction market trading with real-time odds analysis
```

to this:

```
description: Automated trading: real-time odds: smart execution
```

Unquoted colons are not valid YAML in that position. The parser raises, and our scanner does not fall back. It stops. The `base64 -D | bash` dropper and the C2 address are still sitting in the file in plain text, and we report nothing.

That is a one-character-class change, requiring no obfuscation, no encoding, and no knowledge of which rules the scanner runs.

## The measurement

We scanned the whole marketplace: 72,198 skills, of which 68,064 could be read. **2,580 could not be parsed at all** because their frontmatter is malformed. That is 3.6% of the registry sitting in the blind spot today, before anyone deliberately abuses it.

We are not claiming those 2,580 are malicious. Most are probably ordinary mistakes, an unquoted colon in a description being by far the most common. The point is that the blind spot is not hypothetical or narrow. It is a large, already-populated region of the marketplace that a hard-failing scanner never looks at, and any of those files could contain anything.

For completeness, the rest of what we could not read: 396 return a 404 despite being listed, 1,072 fail with an ambiguous slug error because more than one skill is published under the same name, and 86 hit a temporary rate limit and will simply be retried on the next sweep.

The malformed group is the one that matters here, because it is the only one where the file exists, we successfully downloaded it, and we then chose not to look at it.

## Why this is not new, and what is

The idea that a scanner should degrade rather than fail is known. [Adversa's review of eight open-source skill scanners](https://adversa.ai/blog/agent-skill-scanners-bypass-eight-tested/) notes that files which fail to parse should "fall through to text rules rather than being silently dropped, so broken skills still get scanned." We did not do that, and we should have.

What we have not seen published is the measurement: how much of a live marketplace is *currently* unparseable, and therefore how big the blind spot actually is in practice. 3.6% of 72,198 skills is our contribution here, along with a reproducible demonstration that the evasion works end to end against a real sample.

If you maintain a skill scanner, the test takes two minutes. Take a sample you detect, break its frontmatter, and scan it again. If you get an error instead of a verdict, you have this problem.

## The fix

Our parser now falls back to scanning the raw body when the frontmatter will not parse, stripping only the leading fence so header keys are not read as prose. Metadata is left empty rather than guessed, because we genuinely could not read it.

The same malformed sample now returns MALICIOUS with four of the five original findings. The one that disappears is "known malicious author," which is derived from the author field, and is unreadable by definition when the header is broken. That is the honest cost: you lose metadata-derived signals, and you keep everything that comes from the payload, which is where the malware actually is.

We also checked the obvious way to get this wrong. A benign skill with equally broken frontmatter still scores CLEAN. The fallback does not buy detection by trading it for false positives.

## The rest of what we found, in context

We ran the full scan mostly to have a baseline. The headline number is **1,973 malicious out of 68,064 scannable skills, or 2.9%**.

That figure needs context, and the context makes it much less interesting than it first looks. Prior complete audits reported far higher rates: [Koi Security found 341 of 2,857 skills malicious in February, 11.9%](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/), Bitdefender reported around 17% of early skills, and [a 12% figure prompted the platform to ship verified skill screening in March](https://www.tradingview.com/news/reuters.com,2026-03-26:newsml_ACN105904:0-openclawd-ships-verified-skill-screening-after-security-researchers-find-12-of-openclaw-marketplace-skills-are-malware/).

Our number is much lower, and we cannot tell you why with any confidence. The registry has grown roughly twenty-five times since those audits, which dilutes any fixed set of bad skills. The platform ran a cleanup after partnering with VirusTotal. And we count more conservatively than a naive scanner would, because we refuse to convict on a single uncorroborated rule match. Those three explanations have very different implications and we cannot separate them from the outside, so we are not going to pretend a 2.9% figure means the marketplace got safer.

We will say what the number is measured on: 1,064 of the 1,973 were corroborated by two or more independent rules, 315 were confirmed by a semantic check, and the remainder rest on single rules we specifically tested against legitimate content to confirm they do not over-flag.

One more thing we cannot tell you: how many people installed any of it. The install count is zero for all 72,198 skills, which means the field is not populated, not that nothing is installed. We could have written "none of the malicious skills have any installs." It would have been technically true and completely misleading.

## What we would take from this

- **A scanner that errors is a scanner that is off.** Every parse failure is a decision to look at nothing. Make the failure mode "scan it anyway with less context," never "skip it."
- **Measure your blind spots, not just your findings.** We had a number for how many skills were malicious long before we had a number for how many we were not reading.
- **Check the boring failures.** 2,580 skills returning a parse error looked like a data quality annoyance for weeks. It was the most interesting thing in the dataset.

The scanner, its rules and this fix are open source, and the snapshot behind these numbers is published alongside the project.
