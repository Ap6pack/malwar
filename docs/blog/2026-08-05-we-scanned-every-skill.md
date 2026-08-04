# 2.9% of AI agent skills are malicious. Getting to that number took three corrections.

*August 5, 2026 | Adam Rhys Heaton - Ap6pack*

---

We finished scanning every skill in a public AI agent marketplace: 72,198 of them. Of the 68,064 we could actually read, **1,973 are malicious, or 2.9%**. That is the number we are willing to stand behind.

It is also the fourth number we produced. The first three were wrong, and the ways they were wrong are more useful than the answer.

## Why this matters if you use an AI agent

AI agents install "skills" from public marketplaces. A skill is usually just a markdown file with instructions and shell snippets, and it runs with real access to the agent's environment: files, network, credentials. That makes a skill marketplace a supply chain, and supply chains attract abuse. Nobody had audited this one end to end, so we did.

## Wrong number one: 476

Our rule engine scored a skill as malicious the moment a single rule matched a single line. One line containing `curl ... | sh`, a script downloaded and piped straight into a shell, scored as critical and the skill was convicted. On our first pass, 476 skills came back malicious.

That looked like a story. It was a bug in how we were reasoning.

`curl ... | sh` is a genuine malware delivery pattern. It is also the officially documented way to install a large slice of legitimate developer tools. It is how Rust tells you to install rustup, and how Docker and Deno tell you to install them. At the level of one line of text, the attack and the installer are identical.

We proved it against our own rule: the official rustup, Docker and Homebrew install commands all came back malicious. So did an ordinary sentence ending in the word "set," because a second rule meant to catch credential theft matched prose as readily as code.

We added two things. Install commands pointing at a project's own dedicated installer domain stopped being flagged, while multi-tenant hosts that serve anything anyone uploads did not get that trust. And a verdict resting on a single one of these high false positive rules stopped being allowed to convict on its own; it now goes to a slower semantic check, and if that cannot run, it is downgraded rather than published as a conviction.

The same population then produced **184**. Of the original 476: 154 confirmed, 153 dropped to caution, 36 to suspicious, and **132 were clean**. Two out of three did not survive verification.

## Wrong number two: we were looking at 5% of the marketplace

184 was better. It was also measured against a few thousand skills, and we had been assuming that was most of the registry.

It was not. The listing endpoint returns skills in pages, and some entries come back with a null description field. Our parser required a string there, so that one record raised an error, and because we validated the whole page at once, a single bad record silently discarded up to 250 skills. Then, because the code treated whatever it had managed to list as the complete registry, every skill it had not seen was dropped from our records.

For about three weeks we were scanning a few thousand skills and reporting confidently on them. The registry is **72,198**.

The tell was there the whole time and we were not looking at it. Our monitoring reported verdict counts, which looked perfectly healthy, and said nothing about whether we had seen the whole registry. A dashboard that only shows you what you found cannot tell you what you missed.

## Wrong number three: the fix did not apply to the tool people run

The false positive work above lived in our monitoring pipeline. The command line tool, the SDK and the API, which is how anyone actually uses this, still convicted on a single regex.

The same input gave two different answers depending on which door you came in: a lone credential-harvesting match returned malicious from the command line and suspicious from the monitor. There was a mechanism that could have caught it, but only if you had configured an API key. Without one there was no protection at all on the path most people take.

The cause was mundane. The risk score was computed in three separate places. Fixing one did not fix the others.

## The number we will defend

With all of that corrected, and every scannable skill scanned:

| | count |
|---|---|
| Registry | 72,198 |
| Scanned | 68,064 (100% of scannable) |
| Unscannable | 4,134 |
| **Malicious** | **1,973 (2.9%)** |
| Suspicious | 6,133 |
| Caution | 461 |
| Clean | 59,497 |

Of the 1,973 malicious: 1,064 were corroborated by two or more independent rules, 315 were confirmed by a semantic check, and the remainder rest on single rules we specifically tested against legitimate content and found did not over-flag.

Watching that number converge is the part we would point at. At 35% coverage it read 4.2%. Then 3.9%, 3.5%, 3.2%, 3.0%, and 2.9% across the last two runs. The early figure was high because we deliberately scan never-seen skills first, and newly published skills skew worse. If we had published at 35% we would have overstated the problem by nearly half.

## Two things we cannot tell you

**4,134 skills could not be scanned at all**, despite the marketplace listing every one of them as available. 2,580 have a malformed file whose frontmatter will not parse. 396 return a 404: listed, but the file is not there. The remaining 1,158 fail with an ambiguous slug error, meaning two or more different skills are published under the same name and the API cannot tell you which one you meant.

That last group is worth its own look. If a name resolves to more than one skill, then "install this skill" is not a precise instruction, and which code you end up running depends on how the ambiguity gets broken. We have not investigated whether any of it is deliberate, and we are not going to speculate. We are flagging it because it is the kind of thing worth someone checking.

We are not counting any of the 4,134 as clean or malicious, because we genuinely do not know. Nobody else can scan them either.

**We cannot tell you how many people installed any of this.** The install count is zero for all 72,198 skills, which means the field is not populated rather than that nothing is installed. We could have written "none of the malicious skills have any installs," and it would have been technically true and completely misleading.

## What we would tell anyone scanning a marketplace

- **A pattern match is a lead, not a verdict.** The distance between "this line looks like X" and "this skill does X" is where false positives live.
- **Corroboration matters.** One signal is fragile. Two independent signals, or one signal plus a semantic read, is a different level of confidence.
- **Measure coverage, not just findings.** Our worst error was not a wrong verdict, it was three weeks of confident reporting on 5% of the data. Track what you have not looked at as carefully as what you have.
- **Check that your fix reaches the thing people use.** Ours did not, for a while.
- **Watch a number converge before you publish it.** If it is still moving, you do not have it yet.

We are still scanning, daily. The marketplace grows by roughly 150 skills a day, and new skills are where new malware appears. When we find something worth reporting, we will report it, and we will say how confident we are and what we have not checked.

---

*The scanner, its rules and the verification logic are open source. The snapshot behind these numbers is published alongside the project and updated on every run.*
