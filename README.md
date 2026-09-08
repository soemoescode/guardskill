# GuardSkill

**A repository can make your coding agent run code the moment it opens the folder. GuardSkill checks for that before you do.**

```bash
# not yet on npm - clone and run it until the first release is published
git clone https://github.com/soemoescode/guardskill && node guardskill/src/cli.js .
```

Read-only. No network calls, no telemetry, no configuration, no account, no dependencies. It reads git configuration and hook scripts, prints what it found, and exits.

---

## The problem

Coding agents gather context by running ordinary git commands — `git status`, `git diff` — as soon as they open a project. Git reads its settings from the repository's own `.git/config`, and roughly two dozen of those settings name a program for git to execute. Put a command in `core.fsmonitor` and it runs, with your privileges, outside any sandbox, before you have typed anything.

Two pieces of public research make this concrete:

- **GitSpawn** — Manifold Security reported eight findings across seven coding agents (Claude Code, OpenAI Codex, Cursor, Goose, Grok Build, Qwen Code, Hermes Agent), several still unpatched at the time of publication. Their note on delivery matters: cloning a hostile URL does not trigger it, because `.git/config` is not transferred by a clone. The repository has to *arrive as files with its `.git` directory already inside* — a zip, a shared drive, a sync folder, a USB stick, an agent that unpacks an archive. ([Manifold Security](https://www.manifold.security/blog/ai-coding-agents-git-hijack), [The Hacker News](https://thehackernews.com/2026/09/malicious-git-configs-can-make-claude.html))
- **CVE-2026-45033** — GitHub Copilot CLI, CVSS 8.5. A *bare repository hidden anywhere in the project tree* is enough: git discovers it while walking directories and applies its configuration, including keys that execute commands. Fixed in `@github/copilot` 1.0.43 by forcing `safe.bareRepository=explicit`. ([GitHub Advisory](https://github.com/advisories/GHSA-9ccr-r5hg-74gf))

The recommended user-side mitigation in both write-ups is the same: **inspect the git configuration before you open the directory with an agent.** That is tedious to do by hand across a tree. This tool does it in a second.

## Where it looks

Every git configuration an agent could pick up, not only the obvious one: the project's own `.git`, any nested `.git` that arrived as content, any bare repository hidden in a subdirectory, the `.git` *file* a submodule or linked worktree leaves behind, `config.worktree`, every `.git/modules/<name>/config`, and any file pulled in through `include.path` that lies inside the tree.

## What it checks

The full list, key by key, with a source and a coverage status for each, is in [`rules/git-exec-keys-inventory.md`](rules/git-exec-keys-inventory.md). A test fails if that inventory and the rule set drift apart, so the list is auditable rather than aspirational. In summary:

| Class | Checks |
|---|---|
| Runs on ordinary commands | `core.fsmonitor`, `core.pager`, `pager.<cmd>`, `core.editor`, `sequence.editor`, `diff.external`, `core.askPass`, `core.alternateRefsCommand` |
| Runs on network operations | `core.sshCommand`, `core.gitProxy`, `remote.<n>.uploadPack` / `receivePack`, `uploadpack.packObjectsHook` |
| Runs through `.gitattributes` | `filter.<d>.clean` / `.smudge` / `.process`, `diff.<d>.textconv`, `merge.<d>.driver` |
| Runs on demand | `mergetool` / `difftool` / `browser` / `guitool` / `man` `.cmd`, `credential.helper`, `gpg.program`, `trailer.<t>.command`, any `alias.*` that shells out or re-enters git with `-c` |
| Introduces settings later | `include.path`, `includeIf.*.path` (followed and inspected), `init.templateDir` |
| Transports that execute | `protocol.allow`, remote and submodule URLs using `ext::` |
| Hooks | `core.hooksPath`, active scripts in `.git/hooks`, hook scripts that download or decode code, hook scripts that are symlinks |
| Structure | bare repositories in the tree, nested `.git` directories that are not registered submodules, directories named `.git` in a different case |

Four keys are deliberately **out of scope**, each with a reason in the inventory: `sendemail.smtpServer`, `instaweb.httpd`, `ssh.variant` and the HTTP proxy settings. That is why this README lists what it checks instead of claiming to cover a whole vulnerability class — a claim would only be true when that column is empty.

## Usage

```bash
node src/cli.js .                        # scan the current project
node src/cli.js ~/code/some-project      # scan a specific path
node src/cli.js . --json                 # machine-readable
node src/cli.js . --out report.md        # also write a Markdown report
node src/cli.js . --fail-on critical     # only fail the build on critical findings
node src/cli.js . --allow-incomplete     # accept a partial walk
node src/cli.js . --exclude test/fixtures
```

### Exit codes

| Code | Status | Meaning |
|---|---|---|
| `0` | CLEAN | Nothing at or above `--fail-on`, and the whole tree was inspected |
| `1` | FINDINGS | Findings at or above `--fail-on` (default: `high`) |
| `2` | ERROR | The scan could not run: bad path, bad options, invalid rule set |
| `3` | INCOMPLETE | Part of the tree was not inspected — a truncated walk, a refused symlink, an include outside the tree |

`--fail-on` moves the severity threshold and nothing else. Completeness is a separate axis: an incomplete scan fails unless you pass `--allow-incomplete`, because "we did not look there" is not the same as "there is nothing there".

In CI:

```yaml
- name: Check for git execution vectors
  run: npx guardskill . --fail-on high
```

The JSON output carries `schemaVersion: 1`. Fields will be added within version 1; existing ones will not change meaning.

Example output:

```
GuardSkill - git execution-vector scan (read-only)
Path: /Users/dev/clients/handover-package
Git configurations inspected: 3   Directories walked: 412

[CRITICAL] vendor/tooling.git - Bare git repository found inside the project tree
  what   Git discovers bare repositories while walking directories and applies their
         configuration, including keys that execute commands.
  found  bare repository at vendor/tooling.git
  do     Do not open this project with a coding agent until you have inspected it.

[CRITICAL] vendor/tooling.git/config:4 - core.fsmonitor runs an external command
  found  core.fsmonitor = /tmp/.cache/fsmonitor-helper.sh

2 critical, 0 high, 0 medium, 0 low.
Nothing was changed - this scan only reads.
```

## False positives

A security tool that cries wolf gets uninstalled. Four things hold the line, and all four run on every commit:

- **29 synthetic clean repositories** — git-lfs, git-crypt, husky, `.githooks`, registered submodules, credential helpers, custom editors and pagers, signing config. The build fails if any produces a finding above informational.
- **A real-world corpus** ([`test/corpus/PROVENANCE.md`](test/corpus/PROVENANCE.md)) — five repository shapes people actually have. No fixture may produce a `critical`, and every `high` must be declared. This is the check that catches a severity model which is technically right and practically unusable.
- **22 hostile fixtures**, each of which must be caught by the specific rule written for it. Catching it for the wrong reason does not count.
- **An evasion suite and a robustness suite**, every case found by attacking a version that already passed its own tests.

Three deliberate design choices come out of that:

- **Severity is not fixed per rule; it depends on what the value names.** A filter running a bare command resolved from PATH (`cat`, `sops`, `jupyter nbconvert`) is informational. The same key naming `/tmp/x.sh`, carrying a shell metacharacter, or re-entering git with `-c` is not.
- **Structure is graded the same way.** A git directory shipped as content is unusual on its own — medium — and becomes critical the moment that same configuration carries something git executes. Projects that check bare repositories in as test data are common; that is why this distinction exists.
- **A hooks directory is judged by its scripts, never by its name.** `.husky` running `npm test` is informational, and the finding lists what will run. The same directory reaching into `/tmp` is not.

## What it does not do

It never modifies the project it inspects; the only file it writes is the report you ask for with `--out`. It never executes anything it finds. It makes no network calls and collects no telemetry — run it offline and it behaves identically. It has no dependencies, so installing it does not pull in a supply chain of its own. The directory walk does not follow symlinks, and a config file reached through one is refused and reported rather than read.

It does not scan npm dependencies, `.claude/settings.json`, `.vscode/tasks.json` or MCP server definitions. That is the next class, and it is not in this version.

Every one of those sentences is tied to the test that proves it in [`SECURITY.md`](SECURITY.md). A claim without a test does not belong in this file.

## Use it as an agent skill

`SKILL.md` lets a coding agent run the scan itself before it opens an unfamiliar project. Copy the directory into your skills folder, or point your agent at the repository.

## Development

```bash
npm test                          # regenerates fixtures, then runs every suite
node tools/generate-golden.mjs    # only when the parser's golden table changes; needs git, run offline
```

New detection rules go in `rules/git-exec-keys.json` and must be listed in `rules/git-exec-keys-inventory.md`, with a fixture on both sides — one repository that must trigger it, one realistic repository that must stay quiet. A rule with only a positive case will not be merged.

## Roadmap

A separate confidence axis alongside severity, and the next detection class, are planned for 0.5.0. Continuous monitoring, Slack and Teams alerts and auto-fix pull requests are planned as a paid layer. The scanner stays free and MIT-licensed, and the detection rules stay in the open repository — a security tool whose rules you cannot read is not one you should trust.

## License and provenance

MIT. Built and maintained by [Helios IT Solutions](https://helios-it.nl), a Dutch IT service provider. Security issues: see [`SECURITY.md`](SECURITY.md).
