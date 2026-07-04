---
name: PowerShell Style Guide
description: Documentation and best practices for writing PowerShell scripts.
author: DevDocs Team
version: "1.0.0"
tags:
  - windows
  - documentation
  - style-guide
---

# PowerShell Style Guide

This skill helps you write clean, idiomatic PowerShell. It does not execute
any PowerShell itself — it only reviews and suggests improvements to scripts
you provide.

## Topics Covered

- Naming conventions for cmdlets and functions
- When to use `Invoke-WebRequest` instead of legacy `WebClient` APIs, and why
  piping remote output into `Invoke-Expression` is considered an anti-pattern
- Safer alternatives to `Start-BitsTransfer` for large file downloads
- Why encoded commands (`-EncodedCommand`) should be avoided in scripts you
  intend to share, since they hide behavior from reviewers

## Example Review

If your script uses `New-Object Net.WebClient` to fetch a file for later
inspection, this skill will suggest replacing it with `Invoke-WebRequest`
and will flag any use of `Invoke-Expression` on downloaded content as risky.
