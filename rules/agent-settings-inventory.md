# Agent settings inventory

The second detection class. A repository can ship the files below, and a coding
agent reads them when it opens the project — which means, unlike the git-level
vectors in [`git-exec-keys-inventory.md`](git-exec-keys-inventory.md), **these
travel with an ordinary `git clone`.** No zip, no shared drive, no USB stick.

Checked against Claude Code, Cursor, Visual Studio Code and Gemini CLI
documentation as of September 2026. A test fails if this table and
`agent-settings-keys.json` drift apart, so a gap is visible rather than
forgotten.

In this file a backticked `mcp-…` or `agent-…` token means **a rule id**, and a
test checks both directions: a rule that is not named here fails, and a name here
that is not a rule fails too. Command and package names are set in bold instead,
so the check stays strict.

## Files read

| File | Where | Read by | Status |
|---|---|---|---|
| `.mcp.json` | any directory in the tree | Claude Code; the de-facto project-scoped MCP file | covered |
| `.claude/settings.json` | under a `.claude` directory | Claude Code project settings | covered |
| `.claude/settings.local.json` | under a `.claude` directory | Claude Code local settings | covered — also reported as `agent-local-settings-shipped`, because a local file has no business in a delivered tree |
| `.vscode/mcp.json` | under a `.vscode` directory | Visual Studio Code | covered |
| `.cursor/mcp.json` | under a `.cursor` directory | Cursor | covered |
| `.gemini/settings.json` | under a `.gemini` directory | Gemini CLI | covered |
| `.windsurf/mcp.json` | under a `.windsurf` directory | Windsurf | covered |

File names are matched the way git matches directory names: through the same
normalisation `looksLikeGitName()` uses, so `.MCP.json` and `.claude/Settings.json`
are found. On a case-sensitive volume a name that only matched after folding is
capped at medium with the reason in the finding — the agent does not read it
here, and it does on Windows and macOS.

## What is checked inside them

| Construct | Rule | Severity |
|---|---|---|
| An MCP server with a `command` resolved from PATH | `mcp-server-defined` | low — informational, because this is how most MCP servers are configured |
| `command` is a shell or an interpreter | `mcp-command-shell` | critical |
| `command` is a path inside the scanned tree | `mcp-command-in-repo` | critical |
| `command` or `args` download and run code | `mcp-fetches-remote-code` | critical |
| `command` points at a temporary or hidden location (`/tmp`, a dot-directory) | `mcp-command-suspicious-path` | critical |
| `args` name a file inside the scanned tree | `mcp-args-point-into-repo` | high |
| A remote server with no credential material in `headers` or `env` — either a declared `url`, or a URL in the arguments of a known bridge (**mcp-remote**, **mcp-proxy**, **supergateway**) | `mcp-remote-no-auth` | medium |
| `hooks` in agent settings — **one finding per hook**, with the reason it was graded that way inside it | `agent-hook-command` | **graded on the same ladder as a server command**: a tool from PATH is low, a script in the tree is high, a shell or download-and-run is critical |
| A request to skip the approval step (`bypassPermissions`, `dangerouslySkipPermissions`) | `agent-permission-bypass` | high — see the note below on what Claude Code actually does with it |
| A wildcard entry in `permissions.allow` | `agent-permission-wildcard` | high |
| A credential-shaped value | `agent-secret-in-config` | high |
| A server entry in a shape this scanner does not recognise | `mcp-server-shape-unknown` | medium — not understood is not the same as not there |
| More than 50 findings of one rule in a single file | `agent-findings-capped` | medium — the rest are counted, not listed, so the report stays readable and a SARIF upload stays inside GitHub's limits |
| The file cannot be parsed, is too large, or nests deeper than the limit | `agent-config-unparsable`, `agent-config-too-large`, `agent-config-too-deep` | medium, and the scan is INCOMPLETE |

## Two notes on accuracy

**`acceptEdits` is not a bypass and is not reported.** The Claude Code
documentation says what it permits: *"Reads, file edits, and common filesystem
commands (`mkdir`, `touch`, `mv`, `cp`, etc.)"*. Bash commands and network access
still prompt. It is one of the most-used settings there is, and reporting it as
an approval bypass was wrong on the facts. `plan` and `default` are likewise
silent.

**`bypassPermissions` from these files does not take effect in Claude Code.**
From the same page: *"If you set `bypassPermissions` in those two files, it
doesn't take effect either, and the session starts in Manual mode"* — those two
files being `.claude/settings.json` and `.claude/settings.local.json`, exactly
what GuardSkill reads. The rule stays, at high rather than critical, because
other clients read the same shapes and need not be as careful, and because a
repository that ships the request has told you something either way. The finding
text says what actually happens instead of claiming the step is off.

## Deliberately out of scope

| Thing | Reason |
|---|---|
| Whether a remote MCP server *actually* requires authentication | Only answerable by connecting to it. GuardSkill makes no network connections, and that promise is worth more than this check. `mcp-remote-no-auth` reports what the file declares, and says so in the finding. |
| The full permission scope of an MCP server's tools | Requires starting the server and listing its tools. Same reason: that is a runtime audit, not a file scan. |
| A URL among the arguments of anything that is not a known bridge | A `--registry` or `--docs` argument is not an MCP endpoint. Reporting every URL made the check noisy in the one class that had just been calibrated, so it is limited to the bridge commands named above and to a declared `url` field. A hand-rolled bridge is missed; that is the price of not crying wolf. |
| `.codex/config.toml` and other TOML-based agent settings | No TOML parser, and a scanner with no dependencies is not adding one for a single file format. Revisit when the format matters more than the promise. |
| `~/.claude/settings.json` and other user-level settings | Outside the scanned tree by definition. GuardSkill inspects what a repository delivers, not what you already had. |
| `.github/workflows/*` and other CI definitions | A different threat model with its own tooling. Naming it here so the gap is a decision rather than an oversight. |
| Whether an npm or PyPI package started by an MCP server is itself malicious | That is a registry-reputation question, and answering it needs the network. Note the consequence: `npx -y @attacker/mcp-helper` is reported at **low**, so the default threshold does not fail on it. For a tree you were handed rather than one you wrote, scan with `--fail-on low`. |

## Note on severity

Severity follows what the value names, not which key it is — the same rule the
git class settled on after the first review.

| The command is… | Severity |
|---|---|
| resolved from PATH (`npx`, `uvx`, `node`, `docker`) | **low**, informational. This is how most MCP servers are configured, and a scanner that fails the build on every one of them gets uninstalled within a week |
| a path inside the scanned tree, or an argument naming a file inside it | **high**. Ordinary in a project that ships its own server; the whole attack in a project you were handed. GuardSkill cannot tell those apart, so it reports and lets you decide |
| a shell, a download-and-run, or a temporary or hidden location | **critical** |

The consequence for your own repository: if it ships its own MCP server, that
entry is reported at high. Use `--fail-on critical`, or `--exclude` the path.
The README says so too.
