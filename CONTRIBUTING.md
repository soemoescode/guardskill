# Contributing

## The one rule for detection rules

Every new rule needs a fixture on **both** sides: a repository that must trigger it, and a realistic repository that must not. The suite fails if a clean fixture produces anything above informational severity, and it fails if a vulnerable fixture is missed or is caught by a different rule than the one it was written for. A rule with only a positive case will not be merged — false positives are how a security tool loses its users.

## Working on it

```bash
npm test    # regenerates fixtures, then runs the suite
```

Any file in `test/` ending in `.test.js` is picked up automatically — `test/run.js` resolves the list itself rather than relying on a shell glob, which does not exist on Windows.

Fixtures live in `test/fixtures/generate.js` and are generated, not hand-maintained. Add yours there.

Rules live in `rules/git-exec-keys.json`. Each rule needs an `id`, a `match`, a `matchType`, a severity, a plain-language `explanation` of *why the key matters*, and a `remediation` telling the reader what to do. Write the explanation for someone who has never read the git config manual.

## Scope

In scope: anything that causes code to run as a side effect of an ordinary git operation.
Not in scope (yet): npm dependency analysis, agent settings files, MCP server definitions. Those are planned as separate scanners rather than bolted onto this one.

## Style

No runtime dependencies. Node 18+. Keep the output readable in a terminal that is 80 columns wide.

## Adding a detection class

Three rounds of independent review found the same four mistakes twice: once in
the git class, and again in the agent-settings class, because the lessons lived
in the git code and its tests rather than anywhere you would look while building
something new. This list is where they live now. Work through it before a new
class is proposed, not after it is reviewed.

1. **Normalise names before comparing them.** Windows and macOS fold case;
   Windows also ignores trailing spaces and dots. Match through
   `normaliseName()`, and on a case-sensitive volume report the variant at a
   capped severity with the reason in the finding, rather than staying silent.
   (F-06, R3-01 — the same bug, twice.)
2. **Say so when you do not understand something.** An input in an unfamiliar
   shape gets its own finding and marks the scan INCOMPLETE. Silence is
   indistinguishable from "this is fine", and every class has at least one shape
   nobody anticipated. (F-07, R3-03.)
3. **Bound the input on every axis, not just the obvious one.** Size *and*
   depth, reads *and* recursion. A 360 KB file 60,000 levels deep was inside
   every limit the agent class had. (N-3, R3-02.)
4. **Isolate per file.** One unreadable or hostile file may cost its own
   finding and nothing else. A run that already found a payload must never be
   turned into "nothing to report" by a second file — suppressing a scanner is
   cheaper than evading one. (R3-02.)
5. **Grade severity by what the value names, never by which key it is.** A
   command from PATH is informational; a path inside the tree is high; a shell,
   a download-and-run or a temporary location is critical. Apply the ladder to
   every value of that kind in the class — a flat severity on one of them is how
   `npx prettier --write` became a build failure. (F-10, R3-04.)
6. **Check the vendor documentation before encoding a claim about a setting**,
   and quote it in the inventory. `acceptEdits` was reported as an approval
   bypass when the documentation says it is not, and `bypassPermissions` was
   reported as switching the step off when the client ignores it from exactly
   the files we read. (R3-04.)
7. **Every promise gets a row in the claim table and a test behind it** — and
   check that the test proves the promise rather than freezing the current
   behaviour. `only the documented file names are read` was passing on the exact
   matching that R3-01 turned out to be a bug.
8. **Two clean fixtures for every hostile one**, and they must be the shapes
   people really use. The three clean agent fixtures did not include the two
   most common configurations in the wild, which is why the calibration error
   reached a release.
