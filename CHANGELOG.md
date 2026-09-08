# Changelog

## 0.2.0 — 2026-09-08

Rewritten after checking v0.1 against the primary sources. v0.1 scanned only the top-level `.git/config`, which is the one configuration in a normally cloned project that is *least* likely to be hostile. The documented attack needs the repository to arrive as files, and CVE-2026-45033 shows a bare repository anywhere in the tree is enough on its own.

**Added**
- Tree-walking discovery: nested `.git` directories and bare repositories anywhere under the scanned path, each with its configuration inspected.
- Structural findings for bare repositories in the tree (critical) and unregistered nested `.git` directories (high); registered submodules are recognised and not flagged.
- Detection for indirect execution keys that v0.1 missed entirely: shell aliases (`alias.* = !…`), filter drivers, `diff.*.textconv`, merge drivers, `mergetool`/`difftool` commands, `credential.helper`, `diff.external`, `core.gitProxy`, `core.editor`, `sequence.editor`, `uploadpack.packObjectsHook`.
- Hook-content inspection: scripts that pipe a download into a shell or decode base64 escalate to critical.
- Recognition of husky, lefthook, pre-commit and the `.githooks` convention, so ordinary projects are not spammed with warnings.
- `--json`, `--fail-on <severity>`, `--max-depth`, `--exclude <path>`, `--no-color`, `--version`.
- `SECURITY.md` describing the scanner's own threat model.

**Changed**
- Everything is in English.
- Clean fixture set 20 → 29, vulnerable fixture set 10 → 22. The suite now also asserts that each vulnerable fixture is caught by the rule it was written for, not merely caught.
- Traversal never follows symlinks, and is bounded by depth and entry count.

## 0.3.0 — 2026-09-08

Hardening pass driven by attacking the previous version rather than by adding features. Everything below was a real miss on 0.2.0, and each one now has a regression test.

**Fixed — evasions**
- An allowlisted command name matched on basename, so `core.pager = /tmp/less` passed as `less`. Allowlists now apply only to bare command names, never to paths.
- A hooks directory named `.husky` or `.githooks` was downgraded to informational on the strength of its name. Scripts are now classified individually: remote fetch or decode is critical, a reference to a temporary or hidden path is high, ordinary project tooling stays informational — and the informational finding lists the scripts that will run.

**Fixed — configs that were never read**
- `config.worktree`, `.git/worktrees/*/config.worktree` and every `.git/modules/<name>/config` are now inspected. Submodule git directories live under `modules/`, and 0.2.0 never descended into `.git` at all.
- A `.git` *file* (`gitdir: …`), which is what a submodule or linked worktree leaves in the working tree, is now followed when it points inside the scanned tree, and ignored when it points outside.
- Bare-repository detection no longer requires a `refs/` directory. Creating an empty one costs an attacker nothing, so requiring it only bought false negatives.
- The default traversal depth was 8, shallow enough to miss a repository inside `node_modules`. It is now 24, and a walk that stops early is reported as an incomplete scan instead of "no findings".

**Added**
- `protocol.allow` / `protocol.<name>.allow` set to `always`, which re-enables transports that run commands.
- Remote and submodule URLs using the `ext::` transport, in `.git/config` and in `.gitmodules`.
- A finding when a config is too large to parse, rather than skipping it silently.

**Security of the tool itself**
- Findings quote attacker-controlled text. Control characters are now replaced before output, so a config value cannot inject ANSI escapes to clear the terminal and print a fake all-clear; values are length-capped, and Markdown output escapes table and code delimiters.

**Testing**
- New evasion suite (9 tests) and robustness suite (7 tests), both running on every commit. 27 tests total.
- The symlink test now clears its own directory and skips itself where the platform cannot create a symlink. It used to leave state behind and fail on a second run for a reason unrelated to the scanner, and a suite that is red for the wrong reason is how a real regression gets waved through.

## 0.2.1 — 2026-09-08

**Fixed**
- The test script used a shell glob (`node --test ./test/*.test.js`), which cmd.exe and PowerShell do not expand — CI failed on Windows with Node 18 and 20 while passing on Node 22, where node expands the pattern itself. `test/run.js` now resolves the file list in JavaScript, so the suite behaves the same on every platform and version.

## 0.1.0 — 2026-09-08

First internal build. `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.hooksPath`, `include.path` in the top-level `.git/config`, plus active hooks. Never published.
