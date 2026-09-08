# Inventory of git configuration keys that can run a command

Checked against **git 2.43.0**, `git-config(1)`. This file is the answer to "is the
coverage complete?" — not a promise that it is, but a list you can audit. A key is
either `covered` by a named rule, or `out-of-scope` with a reason. `test/coverage.test.js`
fails when a rule exists that is not listed here, or when a key claims a rule that
does not exist.

Adding a key here as `covered` without a rule breaks the build. That is the point.

| Key | Runs when | Status | Rule / reason |
|---|---|---|---|
| `core.fsmonitor` | index refresh: status, diff, add | covered | `core-fsmonitor` |
| `core.sshCommand` | fetch, pull, push over ssh | covered | `core-sshcommand` |
| `core.gitProxy` | git:// connections | covered | `core-gitproxy` |
| `core.pager` | any paged output | covered | `core-pager` |
| `core.editor` | commit, tag, rebase | covered | `core-editor` |
| `core.hooksPath` | every hook | covered | `core-hookspath` |
| `core.askPass` | any credential prompt | covered | `core-askpass` |
| `core.alternateRefsCommand` | ref advertisement for alternates | covered | `core-alternaterefs` |
| `sequence.editor` | interactive rebase | covered | `sequence-editor` |
| `pager.<cmd>` | that subcommand's paged output | covered | `pager-subcommand` |
| `diff.external` | every diff | covered | `diff-external` |
| `diff.<driver>.textconv` | diff of files assigned to it in .gitattributes | covered | `diff-textconv` |
| `filter.<driver>.clean` | staging files assigned to it | covered | `filter-driver` |
| `filter.<driver>.smudge` | checkout of files assigned to it | covered | `filter-driver` |
| `filter.<driver>.process` | staging and checkout, long-running | covered | `filter-driver` |
| `merge.<driver>.driver` | merge of files assigned to it | covered | `merge-driver` |
| `mergetool.<tool>.cmd` / `.path` | git mergetool | covered | `tool-cmd` |
| `difftool.<tool>.cmd` / `.path` | git difftool | covered | `tool-cmd` |
| `browser.<tool>.cmd` / `.path` | git web--browse, git help -w | covered | `tool-cmd` |
| `guitool.<name>.cmd` | git gui | covered | `tool-cmd` |
| `man.<viewer>.cmd` | git help | covered | `tool-cmd` |
| `credential.helper` | any credential lookup | covered | `credential-helper` |
| `credential.<url>.helper` | credential lookup for that host | covered | `credential-helper` |
| `alias.<name>` | that alias | covered | `alias-shell` |
| `gpg.program` / `gpg.<fmt>.program` | signing and verification | covered | `gpg-program` |
| `remote.<name>.uploadPack` | fetch | covered | `remote-packcmd` |
| `remote.<name>.receivePack` | push | covered | `remote-packcmd` |
| `uploadpack.packObjectsHook` | being fetched from | covered | `uploadpack-hook` |
| `trailer.<token>.command` | commit, interpret-trailers | covered | `trailer-command` |
| `init.templateDir` | init, clone: copies hooks in | covered | `init-templatedir` |
| `include.path` / `includeIf.*.path` | config load: can introduce any key above | covered | `include-path` |
| `protocol.allow` / `protocol.<name>.allow` | enables transports that run commands | covered | `protocol-allow` |
| `remote.<name>.url` / `pushurl` with `ext::` | fetch, push, submodule init | covered | `remote-ext-url` |
| `sendemail.smtpServer` | `git send-email` only, when set to a program path | out-of-scope | Reachable only through a command a coding agent does not run, and unusual in repository-local config. Revisit if it ever appears in the wild. |
| `instaweb.httpd` | `git instaweb` only | out-of-scope | Same reason; `git instaweb` is an interactive developer command. |
| `ssh.variant` | ssh invocation | out-of-scope | Selects how git formats ssh arguments; it names a known variant, not a program. |
| `http.proxy`, `remote.<n>.proxy` | HTTP transport | out-of-scope | A URL, not a command. `core.gitProxy` is the one that names a program. |
| `core.editor` via `GIT_EDITOR` etc. | — | out-of-scope | Environment, not repository config; a delivered directory cannot set it. |

## Structural checks (not config keys)

| Check | Rule |
|---|---|
| Bare repository inside the tree | `bare-repo-in-tree` |
| Nested `.git` that is not a registered submodule | `nested-git-dir` |
| Directory named like `.git` in another case | `case-variant-git-dir` |
| Active hook script | `active-hook` |
| Hook script installed by a known manager | `managed-hook-script` |
| Hook script that downloads or decodes code | `hook-fetches-remote-code` |
| Hook script reaching into a temporary or hidden path | `unknown-hook-in-managed-dir` |
| Repository-managed hooks directory | `managed-hooks-dir` |
| Hook script that is a symlink out of the tree | `hook-symlink-outside` |
| Config reached through a symlink | `symlinked-config` |
| Include that could not be inspected | `include-not-followed` |
| Submodule URL using the `ext::` transport | `submodule-ext-url` |
