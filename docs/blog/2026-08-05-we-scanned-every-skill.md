# Two colons can switch off your AI skill scanner

*August 5, 2026 | Adam Rhys Heaton - Ap6pack*

---

If you rely on a scanner to tell you an AI agent skill is safe, here is a two minute test worth running today.

Take a skill your scanner correctly flags as malicious. Do not touch the payload. Go to the YAML header at the top of the file and put two unquoted colons in the description, like this:

```
description: Automated trading: real-time odds: smart execution
```

That is not valid YAML. Now scan it again.

If you get an error instead of a verdict, your scanner is not protecting you against that file. And it is not protecting you against **2,580 skills sitting in a live marketplace right now**, because they are already in exactly that state.

## Why this works

Every skill is two things: a header describing it, and a body containing the actual instructions and shell commands. The dangerous part is always the body. The header is a label.

A lot of scanners parse the header first. If the header is broken, the parse throws, and the scan stops before anything looks at the body. The payload is right there in plain text and nobody reads it.

That is the whole trick. No obfuscation, no encoding, no knowledge of which rules the scanner runs. Break the label and the bag goes through unopened.

## What it looks like end to end

We ran this against a real ClawHavoc sample, the macOS infostealer campaign [Koi Security documented in February](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/). Scanned intact:

```
VERDICT: MALICIOUS (100/100), 5 critical findings
  - ClawHavoc payload domain detected
  - Known malicious author
  - Base64-encoded command execution
  - Threat signature match: C2 IP 91.92.242.30
  - Threat signature match: ClawHavoc glot.io snippet
```

Then the two colons, body byte identical. Result: a parse error and no scan at all. The C2 address and the `base64 -D | bash` dropper were still sitting in the file, unread.

We used our own scanner for this because it is the one whose full trace we can publish. It is not the only one that behaves this way, and the point is not which tool we used. The point is that the failure mode is invisible: the scan does not say "I could not check this." It just does not produce a verdict, and a missing verdict is easy to read as nothing to worry about.

## How much of the marketplace is in the gap

We scanned a public marketplace end to end: 72,198 skills. **2,580 of them, 3.6%, cannot be parsed at all.** Their headers are malformed.

We are not saying those 2,580 are malicious. Most are probably ordinary mistakes, an unquoted colon in a description being far and away the most common. That is exactly what makes it useful cover. The gap is not hypothetical, it is not rare, and it is already populated with thousands of files that a hard failing scanner has never looked inside.

For completeness, the other things we could not read: 396 return a 404 despite being listed, 1,072 fail because more than one skill is published under the same name, and 86 hit a temporary rate limit and get retried. The malformed group is the one that matters, because it is the only one where the file exists, downloads fine, and the scanner then chooses not to look at it.

## What to do about it

**Test your scanner.** Break a header, rescan, and see whether you get a verdict or an error. Two minutes.

**Make the failure mode "scan it anyway."** When a header will not parse, fall back to scanning the raw body. Strip the leading fence so header keys are not read as prose, and leave the metadata empty rather than guessing at it.

You lose the signals that come from the header. In our case the malformed sample went from 5 findings to 4, and the one that disappeared was "known malicious author," which is read from the author field and is genuinely unreadable when the header is broken. You keep everything that comes from the payload, which is where the malware actually is.

**Check you have not traded it for false positives.** A benign skill with an equally broken header should still come back clean. Ours does.

The principle here is not new. [Adversa's review of eight open source skill scanners](https://adversa.ai/blog/agent-skill-scanners-bypass-eight-tested/) already notes that files failing to parse should "fall through to text rules rather than being silently dropped." What we have not seen published is how much of a live marketplace currently sits in that blind spot, which is the 3.6% above, and a full demonstration that the evasion works against a real sample.

## The rest of the scan, briefly

We ran the full sweep to have a baseline: **1,973 malicious out of 68,064 scannable skills, or 2.9%**.

That number is less interesting than it looks, and we would rather say so than dress it up. Earlier complete audits reported much higher rates: [Koi Security found 11.9% in February](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/), Bitdefender around 17%, and [a 12% figure prompted the platform to ship verified skill screening in March](https://www.tradingview.com/news/reuters.com,2026-03-26:newsml_ACN105904:0-openclawd-ships-verified-skill-screening-after-security-researchers-find-12-of-openclaw-marketplace-skills-are-malware/).

Ours is far lower and we cannot tell you why with confidence. The registry has grown roughly twenty five times since those audits, which dilutes any fixed set of bad skills. There was a platform cleanup. And we count conservatively, refusing to convict on a single uncorroborated rule match. Those explanations have very different implications, we cannot separate them from the outside, and so we are not going to claim the marketplace got safer.

For what the number is worth: 1,064 of the 1,973 were corroborated by two or more independent rules, 315 were confirmed by a semantic check, and the rest rest on single rules we tested against legitimate content to confirm they do not over flag.

One thing we cannot tell you at all is how many people installed any of it. The install count reads zero for all 72,198 skills, which means the field is not populated, not that nothing is installed. We could have written "none of the malicious skills have any installs." It would have been technically true and completely misleading.

## The short version

A scanner that errors is a scanner that is off, and it will not tell you it is off. Measure what you are not reading, not just what you found. We had a number for how many skills were malicious long before we had a number for how many we were never opening.

The scanner, its rules and this fix are open source, and the snapshot behind these numbers is published alongside the project.
