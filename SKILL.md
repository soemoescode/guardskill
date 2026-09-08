---
name: guardskill
description: Scan a project for git settings and hook scripts that make a coding agent execute code when it opens the folder (the GitSpawn research and CVE-2026-45033). Use before opening an unfamiliar, downloaded, forked or client-supplied repository, after merging an outside contribution, and periodically on active projects.
---

# GuardSkill

A read-only scanner. It reads git configuration and hook scripts, reports what it finds, and changes nothing in the project it inspects.

## When to use it

- Before opening a repository you did not clone yourself: a zip, a shared drive, a sync folder, a client hand-off, an unpacked archive. This is the delivery path the attack needs — a plain `git clone` does not carry `.git/config`.
- After merging a pull request from outside your team.
- Periodically on projects you work in every day.

## How to run it

```bash
npx guardskill <path>          # human-readable
npx guardskill <path> --json   # to parse the result
```

## Reading the result

The exit code is the summary:

| Code | Status | What it means for you |
|---|---|---|
| 0 | CLEAN | Nothing at or above the threshold, and the whole tree was inspected |
| 1 | FINDINGS | Something was found — read it before running git here |
| 2 | ERROR | The scan did not run. Do not treat this as clean |
| 3 | INCOMPLETE | Part of the tree was not inspected. Also not clean |

Each finding carries a severity, the exact file and line, why the setting matters, the value that was found, and what to do.

- **critical** — runs a command during ordinary git operations, or a hook that downloads code, or a git directory shipped as content that also carries an execution key. Do not open the project with an agent before looking.
- **high** — runs a command in a narrower situation (ssh, merge, diff tooling), or something that could not be inspected and therefore cannot be cleared.
- **medium** — configuration that can introduce such a setting later, or a structure that is unusual but carries nothing executable.
- **low** — informational. Recognised hook managers and followed includes land here.

A finding is a signal to investigate, not proof of malice. Some patterns are legitimate: a shared `include` you wrote yourself, a monorepo with a custom hooks directory, a project that checks bare repositories in as test data. Read the evidence line before removing anything.

## Limits

This covers git-level execution vectors. Four executing keys are deliberately out of scope, listed with reasons in `rules/git-exec-keys-inventory.md`. It does not check npm dependencies, agent settings files, or MCP server definitions.
