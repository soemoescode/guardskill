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

GuardSkill checks two classes. **Git configuration** — the keys that make git run a
program — reaches you only when a repository arrives as files, because a clone does
not carry `.git/config`. **Agent settings** — `.mcp.json`, `.claude/settings.json`,
`.vscode/mcp.json` and their siblings — arrive with an ordinary `git clone`, and a
coding agent reads them when it opens the project.

Add `--sarif-out results.sarif` in CI to send the findings to GitHub code scanning.

## Reading the result

The exit code is the summary:

| Code | What it means for you |
|---|---|
| 0 | Nothing at or above the threshold, and the whole tree was inspected |
| 1 | Something at or above the threshold was found — read it before running git here |
| 2 | The scan did not run. Do not treat this as clean |
| 3 | Part of the tree was not inspected. Also not clean |

The `status` field in `--json` is a separate answer: `CLEAN` only when there were zero findings, `FINDINGS` whenever something was found — including findings below the threshold, which exit 0. If you are reading the JSON rather than the exit code, read `status` and the findings, not the exit code alone.

Each finding carries a severity, the exact file and line, why the setting matters, the value that was found, and what to do.

- **critical** — runs a command during ordinary git operations, or a hook that downloads code, or a git directory shipped as content that also carries an execution key. Do not open the project with an agent before looking.
- **high** — runs a command in a narrower situation (ssh, merge, diff tooling), or something that could not be inspected and therefore cannot be cleared.
- **medium** — configuration that can introduce such a setting later, or a structure that is unusual but carries nothing executable.
- **low** — informational. Recognised hook managers and followed includes land here.

A finding is a signal to investigate, not proof of malice. Some patterns are legitimate: a shared `include` you wrote yourself, a monorepo with a custom hooks directory, a project that checks bare repositories in as test data. Read the evidence line before removing anything.

## Limits

This covers git-level execution vectors. Four executing keys are deliberately out of scope, listed with reasons in `rules/git-exec-keys-inventory.md`. It does not check npm dependencies, agent settings files, or MCP server definitions.
