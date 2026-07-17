# Most "malicious" AI skills aren't. What we learned scanning a marketplace.

*July 17, 2026 | Adam Rhys Heaton - Ap6pack*

---

We built a scanner for AI agent skills and pointed it at a public marketplace. Our first pass flagged 476 skills as malicious. After we added two verification steps, that number fell to 184, and 132 of the original "malicious" skills turned out to be completely clean. If you're making decisions off a scanner's raw verdict, or off a scary headline about how much malware is in these marketplaces, this is worth ten minutes of your time.

## Why we were looking

AI agents increasingly install "skills," small packages that are usually a markdown file with instructions and shell snippets, from public marketplaces. A skill runs with real access to the agent's environment: its files, its network, its credentials. That makes a skill marketplace a supply chain, and supply chains attract abuse.

So the obvious question is: how much of what's published is actually dangerous? We wrote a rule engine to find out, about thirty deterministic rules for the usual patterns: remote code execution, credential theft, persistence, exfiltration. Fast, cheap, and it runs on every skill.

Then we made the mistake that this whole post is about.

## The first number was wrong

Our rule engine scored a skill as `MALICIOUS` the moment a single rule matched a single line. One line containing `curl ... | sh`, a script downloaded and piped straight into a shell, scored as critical and the skill was convicted. On our first full pass, 476 skills came back malicious.

That looked like a story. It wasn't. It was a bug in how we were reasoning.

Here is the problem with a single line deciding a verdict. `curl ... | sh` is a genuine malware delivery pattern. It is also the officially documented way to install a large slice of legitimate developer tools. This is how Rust tells you to install rustup. It's how Docker, Deno, Homebrew, and dozens of others tell you to install them. A rule that flags `curl | sh` flags real attacks and real installers with exactly equal confidence, because at the level of one line of text they are identical.

We proved it to ourselves by running our own rule against the official rustup, Docker, and Homebrew install commands. All three came back `MALICIOUS`. So did an ordinary sentence that happened to end in the word "set," because a second rule meant to catch environment-variable theft matched prose as readily as code.

When a large fraction of your "malicious" findings rest on a single line that legitimate software produces every day, your headline number is inflated. Ours was.

## Two fixes

We changed two things.

**First, context for the install pattern.** A `curl ... | sh` line is only interesting if you can't see where it's downloading from. If the download host is a dedicated, project-controlled installer domain, the kind of host that only ever serves that one project's install script, it's the vendor's documented path, not an attack, and we stop flagging it. We deliberately did not extend that trust to multi-tenant hosts like raw file servers or gists, because those serve anything anyone uploads. And we checked the obvious evasion: a lookalike domain like `sh.rustup.rs.evil.com` still gets flagged, and so does a second, untrusted download hiding on the same line.

**Second, a real second opinion.** A verdict that rests on a single one of these high-false-positive rules is no longer allowed to stand as a conviction on its own. It gets sent to a slower, more expensive semantic check, a language model reading the whole skill in context, which can confirm it or clear it. If that check can't run for some reason, the verdict is downgraded to "suspicious," not published as "malicious." We would rather under-claim than convict something innocent.

## The second number

We re-scanned with both fixes on. The same population that produced 476 malicious verdicts produced 184.

Following the original 476 individually tells the story better than the totals:

- 154 were confirmed malicious.
- 153 dropped to "caution," worth noting, not worth alarm.
- 36 dropped to "suspicious."
- 132 were clean. Outright false positives.

Two out of three of our original "malicious" findings did not survive contact with verification. One in four was not a threat at all.

The most humbling example was a cluster of 242 similarly named skills, integrations for well-known APIs, that our first pass flagged as a coordinated 242-skill malicious campaign. It was the kind of finding you write a blog post about. After verification, 16 were malicious and 77 were completely clean; the rest sat in the low-concern middle. The "campaign" was mostly an artifact of those skills sharing one legitimate install line in a common template.

We came close to publishing that campaign. The only reason we didn't is that the numbers looked too clean: 242 skills, identical score, one rule. Identical is what a false positive looks like, not what independent attacks look like.

## What we'd tell anyone scanning a marketplace

None of this means the marketplace is safe or that scanning is pointless. 184 genuinely bad skills is a real problem, and the rules did their job: they have recall, they surface the right candidates. The lesson is narrower and more useful than "scanning doesn't work."

- **A pattern match is a lead, not a verdict.** The distance between "this line looks like X" and "this skill does X" is exactly where false positives live.
- **Corroboration matters.** A finding that rests on one signal is fragile. Two independent signals, or one signal plus a semantic read, is a different level of confidence.
- **Fail toward under-claiming.** When you can't verify, downgrade. A missed detection is a cost; a false accusation published as fact is a worse one.
- **Be suspicious of clean numbers.** Real-world threats are messy and varied. A large group of items with identical scores usually means your rule found a common template, not a common attacker.

And even 184 is provisional. A portion of those still rest on a single rule we haven't independently verified, and we expect the number to keep moving as we tighten the checks. That isn't a hedge. It's the same discipline that took 476 down to 184: a number you haven't verified is a lead, not a result.

We're still scanning, and we'll write about what we find. But we'll publish the number that survived verification, not the one that made the better headline. That's the whole point.

---

*The scanner, its rules, and the verification logic are open source. The verified snapshot behind these numbers is published alongside the project.*
