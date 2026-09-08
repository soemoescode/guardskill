# GuardSkill

**A repository can make your coding agent run code the moment it opens the folder. GuardSkill checks for that before you do.**

```bash
npx guardskill .
```

Read-only. No network calls, no telemetry, no config, no account. It reads git configuration and hook scripts, prints what it found, and exits.

---

## The problem

Coding agents gather context by running ordinary git commands — `git status`, `git diff` — as soon as they open a project. Git reads its settings from the repository's own `.git/config`, and several of those settings name a program for git to execute. Put a command in `core.fsmonitor` and it runs, with your privileges, outside any sandbox, before you have typed anything.

Two pieces of public research make this concrete:

- **GitSpawn** — Manifold Security reported eight findings across seven coding agents (Claude Code, OpenAI Codex, Cursor, Goose, Grok Build, Qwen Code, Hermes Agent), several still unpatched at the time of publication. Their note on delivery matters: cloning a hostile URL does not trigger it, because `.git/config` is not transferred by a clone. The repository has to *arrive as files with its `.git` directory already inside* — a zip, a shared drive, a sync folder, a USB stick, an agent that unpacks an archive. ([Manifold Security](https://www.manifold.security/blog/ai-coding-agents-git-hijack), [The Hacker News](https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html))
- **CVE-2026-45033** — GitHub Copilot CLI, CVSS 8.5. A *bare repository hidden anywhere in the project tree* is enough: git discovers it while walking directories and applies its configuration, including keys that execute commands. Fixed in `@github/copilot` 1.0.43 by forcing `safe.bareRepository=explicit`. ([GitHub Advisory](https://github.com/advisories/GHSA-9ccr-r5hg-74gf))

The recommended user-side mitigation in both write-ups is the same: **inspect the git configuration before you open the directory with an agent.** That is a tedious thing to do by hand across a tree. This tool does it in a second.

## What it checks

GuardSkill walks the tree and finds every git configuration an agent could pick up: the project's own `.git`, any nested `.git` that arrived as content, any bare repository hidden in a subdirectory, the `.git` *file* a submodule or linked worktree leaves behind, and the configs git keeps beside the main one — `config.worktree` and every `.git/modules/<name>/config`. Each of them is inspected.

| Class | Checks |
|---|---|
| Direct execution keys | `core.fsmonitor`, `core.sshCommand`, `core.gitProxy`, `core.pager`, `core.editor`, `sequence.editor`, `diff.external`, `uploadpack.packObjectsHook` |
| Indirect execution keys | `filter.*.clean` / `.smudge` / `.process`, `diff.*.textconv`, `merge.*.driver`, `mergetool.*.cmd`, `difftool.*.cmd`, `credential.helper` |
| Shell aliases | any `alias.*` whose value starts with `!` |
| Configuration loaded from elsewhere | `include.path`, `includeIf.*.path` |
| Hooks | `core.hooksPath` overrides, active (non-`.sample`) scripts in `.git/hooks`, and hook scripts that pipe a download into a shell or decode base64 before running it |
| Transports | `protocol.allow` and `protocol.<name>.allow` set back to `always`, and any remote or submodule URL using the `ext::` transport, which hands the rest of the line to a shell |
| Structure | bare repositories inside the tree (the CVE-2026-45033 vector), nested `.git` directories that are not registered submodules, `.git` files pointing at a git directory inside the tree |

## Usage

```bash
npx guardskill .                      # scan the current project
npx guardskill ~/code/some-project    # scan a specific path
npx guardskill . --json               # machine-readable
npx guardskill . --out report.md      # also write a Markdown report
npx guardskill . --fail-on critical   # only fail the build on critical findings
npx guardskill . --exclude test/fixtures   # skip a directory
```

Exit codes: `0` nothing at or above the threshold, `1` findings at or above it (default threshold: `high`), `2` the scan itself failed.

In CI:

```yaml
- name: Check for git execution vectors
  run: npx guardskill . --fail-on high
```

Example output:

```
GuardSkill - git execution-vector scan (read-only)
Path: /Users/dev/projects/inherited-project
Git configurations inspected: 2   Directories walked: 148

[CRITICAL] vendor/payload.git - Bare git repository found inside the project tree
  what   Git discovers bare repositories while walking directories and applies their
         configuration, including keys that execute commands.
  found  bare repository at vendor/payload.git
  do     Do not open this project with a coding agent until you have inspected the directory.

[CRITICAL] vendor/payload.git/config:3 - core.fsmonitor runs an external command
  found  core.fsmonitor = /tmp/.x/run.sh

2 critical, 0 high, 0 medium, 0 low.
Nothing was changed - this scan only reads.
```

## False positives

A security tool that cries wolf gets uninstalled. The suite runs against **29 realistic clean repositories** — git-lfs, git-crypt, husky, the `.githooks` convention, registered submodules, credential helpers, custom editors and pagers, signing config — and the build fails if any of them produces a finding above informational level. It runs against **22 repositories built around a known attack pattern** and fails if any is missed, or is caught by the wrong rule.

On top of that sits an **evasion suite**: every case in it was found by attacking a version of GuardSkill that already passed its own tests, and it runs on every commit so a future change cannot quietly reopen one. It covers the same key spelled every way git still accepts (case, quoting, line continuations, CRLF, a byte-order mark, a key on the section line), payloads named after familiar tools, hooks directories named `.husky` to look routine, and configs hidden where the first version never looked. A **robustness suite** feeds it binary, empty, truncated and 200,000-line configs, unreadable directories, symlink loops and pointers aimed outside the tree, and requires a report rather than a stack trace.

Two deliberate design choices:

- **Hook managers are recognised, not flagged.** husky, lefthook, pre-commit and a `.githooks` directory are reported as informational (`low`) rather than as a risk — but GuardSkill still reads the scripts, and escalates to `critical` if one of them fetches or decodes code before running it.
- **`include` / `includeIf` is always reported.** An include can introduce any key on this list later, which is exactly how you would hide one. A shared `~/.gitconfig` you wrote yourself is a normal finding to dismiss.
- **A hooks directory is judged by its scripts, not its name.** `.husky` running `npm test` is informational, and the finding lists what will run. The same directory running something out of `/tmp` is not.
- **An incomplete walk never reads as a clean result.** If the traversal stops at its depth or size limit, the report says so instead of printing "no findings".

## What it does not do

It does not modify anything, ever. It does not execute anything it finds. It makes no network calls and collects no telemetry — run it offline and it behaves identically. It does not scan npm dependencies, `.claude/settings.json`, `.vscode/tasks.json` or MCP server definitions yet; those are the next class, not this one. And it is a signal, not a verdict: read the finding, look at the evidence, decide for yourself.

## Use it as an agent skill

`SKILL.md` in this repository lets a coding agent run the scan itself before it opens an unfamiliar project. Copy the directory into your skills folder, or point your agent at the repository.

## Development

```bash
npm test        # regenerates the fixtures, then runs the suite
```

Fixtures are generated by code (`test/fixtures/generate.js`), not committed by hand, so extending the clean or vulnerable set is a few lines. New detection rules go in `rules/git-exec-keys.json` — a rule without a fixture on both sides will not be merged.

## Roadmap

Continuous monitoring, Slack/Teams alerts and auto-fix pull requests are planned as a paid layer. The scanner itself stays free and MIT-licensed. Detection rules stay in the open repository — a security tool whose rules you cannot read is not one you should trust.

## License and provenance

MIT. Built and maintained by [Helios IT Solutions](https://helios-it.nl), a Dutch IT service provider. Security issues: see `SECURITY.md`.
