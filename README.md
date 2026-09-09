# GuardSkill

**A repository can make your coding agent run code the moment it opens the folder. GuardSkill checks for that before you do.**

```bash
npx guardskill .
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
npx guardskill .                        # scan the current project
npx guardskill ~/code/some-project      # scan a specific path
npx guardskill . --json                 # machine-readable
npx guardskill . --out report.md        # also write a Markdown report
npx guardskill . --fail-on critical     # only fail the build on critical findings
npx guardskill . --allow-incomplete     # accept a partial walk
npx guardskill . --exclude test/fixtures
```

Or install it once: `npm install -g guardskill`, then `guardskill .`.

From a clone the entry point is `node bin/guardskill.js`. `src/` is a library — running
it does nothing, which is deliberate: the bug that shipped in the first release
candidate was a CLI that guarded its own execution and lost that guard to npm's bin
symlink. The published binary is now the only thing that starts a scan, and a
packaging test drives it on all three platforms.

### Status and exit code

These are two different answers and the tool reports both. The **status** in the JSON says what was found. The **exit code** says whether that is bad enough to fail on, given the threshold you set.

| `status` | Meaning |
|---|---|
| `CLEAN` | Zero findings, and the whole tree was inspected |
| `FINDINGS` | At least one finding, at any severity — including ones below your threshold |
| `INCOMPLETE` | No findings, but part of the tree was not inspected |
| `ERROR` | The scan did not run |

| Code | Meaning |
|---|---|
| `0` | Nothing at or above `--fail-on`, and the whole tree was inspected |
| `1` | Findings at or above `--fail-on` (default: `high`) |
| `2` | The scan could not run: bad path, bad options, invalid rule set |
| `3` | Part of the tree was not inspected — a truncated walk, a refused symlink, an include outside the tree |

So a repository with one medium finding and a default threshold reports `status: FINDINGS` and exits `0`. That combination is deliberate: exit `0` is a policy answer, and a consumer reading the JSON still has to be able to see what was found before deciding. `CLEAN` means zero findings and nothing else.

`--fail-on` moves the severity threshold and nothing else — it never removes a finding from the report. Completeness is a separate axis again: an incomplete scan fails unless you pass `--allow-incomplete`, because "we did not look there" is not the same as "there is nothing there".

With `--json`, a failure answers in JSON too: an error document with the same fields, `status: "ERROR"`, `scanned: false` and the reason in `reason`, so a consumer piping into a parser gets a diagnosis instead of a parse error. The human-readable reason also goes to stderr.

In CI:

```yaml
- name: Check for git execution vectors
  run: npx guardskill . --fail-on high
```

Or as an action, which pins the version for you:

```yaml
- uses: soemoescode/guardskill@v0.4.0
  with:
    fail-on: high          # critical, high, medium or low
    exclude: test/fixtures # comma-separated, optional
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

`SKILL.md` lets a coding agent run the scan itself before it opens an unfamiliar project — so the check happens without you remembering to ask for it.

```bash
npx skills add soemoescode/guardskill
```

That installs the skill for Claude Code, Cursor and Codex; `--agent claude-code` narrows it to one. You can also copy `SKILL.md` into your skills folder by hand, or point your agent at this repository.

## Development

```bash
npm test                          # regenerates fixtures, then runs every suite
node tools/generate-golden.mjs    # only when the parser's golden table changes; needs git, run offline
```

New detection rules go in `rules/git-exec-keys.json` and must be listed in `rules/git-exec-keys-inventory.md`, with a fixture on both sides — one repository that must trigger it, one realistic repository that must stay quiet. A rule with only a positive case will not be merged.

## Roadmap

A separate confidence axis alongside severity is planned for 0.5.0, together with the next detection class: the agent's own settings files — `.claude/settings.json`, `.mcp.json` and comparable MCP server definitions — which reach the same outcome by a different route, and unlike the git-level vectors they travel with an ordinary `git clone`. Continuous monitoring, Slack and Teams alerts and auto-fix pull requests are planned as a paid layer. The scanner stays free and MIT-licensed, and the detection rules stay in the open repository — a security tool whose rules you cannot read is not one you should trust.

## License and provenance

MIT. Built and maintained by [Helios IT Solutions](https://helios-it.nl), a Dutch IT service provider. Security issues: see [`SECURITY.md`](SECURITY.md).

Every release is published from a tag by GitHub Actions with npm provenance, so the package on the registry is traceable to the workflow run and the commit that produced it. Check it yourself before you trust it:

```bash
npm audit signatures
```

The independent security reviews this tool was put through, and the acceptance gate they were judged against, are in [`docs/`](docs/).
