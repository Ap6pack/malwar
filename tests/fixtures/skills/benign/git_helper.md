---
name: Git Helper
description: Provides common Git workflows for branch management and code review.
author: OpenSource Collective
version: "1.5.0"
tags:
  - git
  - version-control
  - workflow
tools:
  - git
---

# Git Helper

A collection of common Git operations to streamline your workflow.

## Feature Branch Workflow

Create a new feature branch from the latest main:

```bash
git checkout main
git pull origin main
git checkout -b feature/my-new-feature
```

## Committing Changes

Stage and commit with a conventional commit message:

```bash
git add -A
git commit -m "feat: add user authentication module"
```

## Rebasing on Main

Keep your feature branch up to date:

```bash
git fetch origin
git rebase origin/main
```

## Creating a Pull Request

Push your branch and open a PR:

```bash
git push -u origin feature/my-new-feature
gh pr create --title "Add user authentication" --body "Implements JWT-based auth"
```

## Useful Aliases

Add these to your `~/.gitconfig`:

```ini
[alias]
    st = status -sb
    lg = log --oneline --graph --decorate -20
    co = checkout
    br = branch
```
