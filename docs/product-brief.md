<!-- Copyright (c) 2026 Veritas Aequitas Holdings LLC. All rights reserved. -->

# Malwar: Product Brief

**Static analysis for the agentic AI attack surface.**

---

## Problem

Agentic AI systems execute skills defined in natural language files (SKILL.md), not compiled binaries. These skill files contain markdown instructions that tell agents what to do, what tools to call, and what data to access. This creates an entirely new attack surface: malicious instructions embedded in prose. Prompt injection, social engineering, obfuscated shell commands, and data exfiltration directives all live inside what looks like a normal text file.

The threat is not theoretical. ClawHub, the largest community skill marketplace, hosts 10,700+ skills. Roughly 20% are confirmed malicious. The ClawHavoc campaign alone trojanized 824+ skills to deliver the AMOS infostealer. No existing security tool handles this. VirusTotal returns clean on markdown files. SAST scanners like Semgrep and CodeQL parse code, not prose. LLM-only analysis is too slow and expensive for pipeline-speed scanning. Manual review does not scale past a few dozen skills. There is zero infrastructure for securing agent skill supply chains.

## Solution

Malwar is a 4-layer static analysis engine purpose-built for detecting malware in agentic AI skill files.

- **Layer 1 -- Pattern Matching:** 19 detection rules covering prompt injection, obfuscated commands, data exfiltration patterns, hidden instructions, and social engineering techniques.
- **Layer 2 -- URL Crawling:** Extracts and follows all URLs in skill files, checking against threat intelligence databases and analyzing destination content.
- **Layer 3 -- LLM Semantic Analysis:** Uses language models to evaluate intent, catching sophisticated attacks that evade pattern-based rules.
- **Layer 4 -- Threat Intelligence Correlation:** Matches against known campaigns, IOCs, and signature databases -- including the seeded ClawHavoc campaign data.

The engine runs in milliseconds for layers 1-2 and seconds for the full pipeline. It returns structured verdicts with confidence scores, matched rules, and campaign attribution. It is exposed as a REST API (16 endpoints, auth, rate limiting), a CLI tool, and a Docker container.

## Why Now

The agentic AI market is inflecting. LangChain, CrewAI, AutoGen, OpenAI Assistants, and Claude tool use are creating an ecosystem where autonomous agents consume third-party skills at scale. Skill marketplaces are proliferating. Enterprise agent deployments are moving from experimentation to production. Yet there is no security layer between "skill published" and "skill executed." This is the same gap that Snyk filled for open-source dependencies and that container scanning filled for Docker images -- except the attack vector is natural language, and no one else is building for it.

## Go-to-Market

**Primary path: API / Usage-Based Integration.** Skill marketplaces (ClawHub and future platforms) integrate the Malwar API into their publish pipeline. Every skill upload is scanned before it reaches users. Per-scan pricing. This is the "Stripe for agent security" model -- infrastructure that platforms integrate, not a product end-users log into.

**Secondary paths, in priority order:**

- **CI/CD Integration.** Enterprises add `malwar scan` to agent deployment pipelines, the same way Snyk and Semgrep sit in build pipelines today. Per-scan or per-repo pricing.
- **SDK / Embedded.** Agent frameworks (LangChain, CrewAI, AutoGen, Claude tools) embed Malwar as a dependency -- scan before execute. License + usage.
- **Threat Intel Feed.** The signature database and campaign data sold as a subscription to security teams monitoring agent ecosystems.
- **Open Core.** Rule engine open-sourced for adoption and community contribution. LLM layer, threat intel API, and enterprise features as paid tiers.

The distribution strategy is deliberately infrastructure-first. Traditional per-seat SaaS is commoditizing under AI pressure. Usage-based and embedded models survive.

## Business Model

| Tier | Target | Pricing |
|------|--------|---------|
| **API Standard** | Skill marketplaces, small teams | Per-scan (e.g., $0.01-0.05/scan for pattern + URL layers) |
| **API Full Pipeline** | Enterprises, high-assurance use cases | Per-scan (e.g., $0.10-0.25/scan including LLM layer) |
| **Threat Intel Feed** | Security operations teams | Monthly/annual subscription |
| **Enterprise** | Large deployments, on-prem, custom rules | Annual contract + usage |

Volume discounts at scale. Free tier for open-source projects and individual developers to drive adoption.

## Competitive Landscape

| Tool | Approach | Why It Fails on Skill Files |
|------|----------|-----------------------------|
| **VirusTotal** | Binary/file hash analysis | Returns clean on markdown. No natural language understanding. |
| **Snyk (ToxicSkills research)** | Published research on malicious skills | Research, not a product. No scanning engine or API. |
| **Cisco Skill Scanner** | LLM-only analysis | Slow, expensive at scale, no pattern layer, no threat intel correlation. |
| **SecureClaw** | Compliance-focused agent security | Policy and governance tooling, not malware detection. |
| **SAST Scanners (Semgrep, CodeQL)** | Code parsing | Cannot parse natural language instructions. Wrong abstraction entirely. |

Malwar is the only tool that combines rule-based speed with LLM depth and threat intelligence context, purpose-built for the skill file format.

## Current Status

**Built and working:**
- Detection engine: 4 layers, 19 rules, fully operational
- Test suite: 354 tests, 89% coverage, 37 real-world malicious fixtures (sourced from ClawHub and Snyk research)
- REST API: 16 endpoints with authentication and rate limiting
- CLI: `malwar scan`, `malwar serve`, signature and campaign management
- Threat intel: ClawHavoc campaign seeded with IOCs and signatures
- Packaging: Docker container, CI/CD pipeline

**Next milestones:**
- Marketplace integration pilot (ClawHub or equivalent)
- Agent framework SDK (LangChain plugin as first target)
- Expanded rule set based on emerging attack patterns
- Threat intel feed packaging and API
- SOC 2 / security audit for enterprise readiness

## Ask

1. **Marketplace partnerships.** A design partner to pilot API integration into a skill publish pipeline. ClawHub is the obvious first target given the scale of the problem there.
2. **Agent framework integrations.** Collaborations with LangChain, CrewAI, or AutoGen to embed scan-before-execute as a native capability.
3. **Seed funding.** To scale the threat research team, expand the rule set, and build out enterprise features (on-prem deployment, custom rule authoring, SIEM integration).
4. **Security research collaborators.** To contribute to the detection rule set and validate against emerging attack campaigns.

---

*Malwar: The security infrastructure layer for agentic AI.*
