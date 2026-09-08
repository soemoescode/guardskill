# Contributing

## The one rule for detection rules

Every new rule needs a fixture on **both** sides: a repository that must trigger it, and a realistic repository that must not. The suite fails if a clean fixture produces anything above informational severity, and it fails if a vulnerable fixture is missed or is caught by a different rule than the one it was written for. A rule with only a positive case will not be merged — false positives are how a security tool loses its users.

## Working on it

```bash
npm test    # regenerates fixtures, then runs the suite
```

Fixtures live in `test/fixtures/generate.js` and are generated, not hand-maintained. Add yours there.

Rules live in `rules/git-exec-keys.json`. Each rule needs an `id`, a `match`, a `matchType`, a severity, a plain-language `explanation` of *why the key matters*, and a `remediation` telling the reader what to do. Write the explanation for someone who has never read the git config manual.

## Scope

In scope: anything that causes code to run as a side effect of an ordinary git operation.
Not in scope (yet): npm dependency analysis, agent settings files, MCP server definitions. Those are planned as separate scanners rather than bolted onto this one.

## Style

No runtime dependencies. Node 18+. Keep the output readable in a terminal that is 80 columns wide.
