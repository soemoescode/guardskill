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

## 0.1.0 — 2026-09-08

First internal build. `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.hooksPath`, `include.path` in the top-level `.git/config`, plus active hooks. Never published.
