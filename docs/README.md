# Review documents

GuardSkill was reviewed twice by an independent security and code-quality reviewer
before it was published, and both rounds found a blocking defect. These are the
unedited documents. They are in Dutch, because that is the language they were
written in; the summaries below say what each one contains.

| File | What it is |
| ---- | ---- |
| [`review-01-v0.3.0.md`](review-01-v0.3.0.md) | First review, against v0.3.0. Nine working attacks the test suite did not catch, and three legitimate setups it wrongly flagged. Seventeen findings. |
| [`acceptatiepoort-v0.4.0.md`](acceptatiepoort-v0.4.0.md) | The definition of done for the release: each condition either machine-checkable or tied to a named test. Two rules override everything else — a test skipped on Linux fails the gate, and a claim in the documentation without a test behind it fails the gate. |
| [`review-02-v0.4.0-rc1.md`](review-02-v0.4.0-rc1.md) | Second review, against the first release candidate. Five further findings, one of which was only visible in the packaged artifact and not in a clone: the published binary did not start a scan at all. |
| [`N-01-fix-bin-entrypoint.patch`](N-01-fix-bin-entrypoint.patch) | The patch for that finding. |

The residual risks that were accepted rather than fixed are listed in
[`SECURITY.md`](../SECURITY.md), with the reason for each. An accepted risk that is
not written down publicly is not accepted, it is concealed — so if you find one here
that is missing there, that is a bug worth reporting.

What the scanner deliberately does not cover is in the README under *What it does
not do*, and the full key-by-key coverage list, with a source reference and a status
for every git setting that can execute a command, is in
[`rules/git-exec-keys-inventory.md`](../rules/git-exec-keys-inventory.md).
