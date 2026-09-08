# Corpus provenance

Five repository shapes that a real user is likely to scan. The acceptance rule is
simple and it is enforced by `test/corpus.test.js`: **no fixture may produce a
`critical`, and any `high` must be listed and explained here.** Today the list of
expected highs is empty.

The corpus runs offline. Nothing is cloned at test time, and the test is never
skipped — a corpus test that quietly stands down when the network is missing is
the same failure mode as a test that swallows an error.

## Honest note on provenance — read this before trusting the label

The acceptance gate asks for reductions of real public repositories, pinned by
commit SHA. **These five are reconstructions, not reductions of a verified
checkout.** They reproduce the *shapes* review 01 reported, from that report and
from the projects' documented layouts, and every path and config line here was
written for this repository. No SHA is claimed, because no SHA was verified.

Why it still earns its place: the false positives in review 01 came from those
shapes, not from any particular commit — eight checked-in `*.git` fixtures, a
husky hooks directory, PATH-resolved notebook and sops filters, a submodule
registered by a subproject. The reconstruction reproduces all four, and each one
fails the build if the severity model regresses.

Why it is not enough: a reconstruction cannot surprise you, and a real checkout
can. Replacing these with SHA-pinned reductions of the actual repositories is an
open item, tracked in the disposition table, and it needs one deliberate network
fetch that has not been authorised.

| Fixture | Shape taken from | Licence of the original | Expected outcome |
|---|---|---|---|
| `git-lfs-shaped` | `github.com/git-lfs/git-lfs` — bare repositories checked in as test data, plus the git-lfs filter | MIT | 8 × medium `bare-repo-in-tree`, no high, no critical. This is the case that produced 8 criticals in review 01. |
| `husky-project` | The standard husky v9 layout | — | Informational only. The finding lists the scripts that will run. |
| `monorepo-submodules` | A monorepo with registered submodules, one registering submodules of its own | — | No finding for a registered submodule, at any level. |
| `data-science` | nbstripout + sops + a `cat` no-op filter | — | Informational only. These produced 7 false highs in review 01. |
| `dotfiles-include` | A dotfiles repository splitting config across an include | — | The include is followed; nothing executable inside. |

## What each fixture pins down

- **git-lfs-shaped** — a git directory shipped as content is unusual, not alarming. It becomes critical only when that same config carries something git runs. This is the boundary that `test/review01.test.js` (`F-10a`) and `test/scan.test.js` (bare repo *with* `fsmonitor`) pin from both sides.
- **husky-project** — a hooks directory is judged by its scripts, never by its name.
- **monorepo-submodules** — `.gitmodules` is read for every repository found, not only the scan root.
- **data-science** — a filter naming a bare command resolved from PATH is not the same risk as one naming `/tmp/x.sh`.
- **dotfiles-include** — following an include must not turn an ordinary split config into noise.
