---
name: guardskill
description: Scan a project for git settings and hook scripts that make a coding agent execute code when it opens the folder (the GitSpawn class and CVE-2026-45033). Use before opening an unfamiliar, downloaded, forked or client-supplied repository, after merging an outside contribution, and periodically on active projects.
---

# GuardSkill

A read-only scanner. It reads git configuration and hook scripts, reports what it finds, and changes nothing.

## When to use it

- Before opening a repository you did not clone yourself: a zip, a shared drive, a sync folder, a client hand-off, an unpacked archive. This is the delivery path the attack needs — a plain `git clone` does not carry `.git/config`.
- After merging a pull request from outside your team.
- Periodically on projects you work in every day.

## How to run it

```bash
npx guardskill <path>          # human-readable
npx guardskill <path> --json   # to parse the result
```

Exit code 0 means nothing at or above the threshold; 1 means findings; 2 means the scan failed.

## Reading a finding

Each finding carries a severity, the exact file and line, the reason the setting matters, the value that was found, and what to do about it.

- **critical** — a setting or structure that runs a command during ordinary git operations, or a hook that downloads code. Do not open the project with an agent before looking.
- **high** — a setting that runs a command in a narrower situation (ssh, merge, diff tooling).
- **medium** — configuration that can introduce such a setting later, or an unusual editor or pager.
- **low** — informational. Recognised hook managers such as husky land here.

A finding is a signal to investigate, not proof of malice. Some patterns are legitimate: a shared `include` you wrote yourself, a monorepo with a custom hooks directory. Read the evidence line before removing anything.

## Limits

This covers git-level execution vectors only. It does not check npm dependencies, agent settings files, or MCP server definitions.
