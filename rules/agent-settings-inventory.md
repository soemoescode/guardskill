# Agent settings inventory

The second detection class. A repository can ship the files below, and a coding
agent reads them when it opens the project — which means, unlike the git-level
vectors in [`git-exec-keys-inventory.md`](git-exec-keys-inventory.md), **these
travel with an ordinary `git clone`.** No zip, no shared drive, no USB stick.

Checked against Claude Code, Cursor, Visual Studio Code and Gemini CLI
documentation as of September 2026. A test fails if this table and
`agent-settings-keys.json` drift apart, so a gap is visible rather than
forgotten.

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

## What is checked inside them

| Construct | Rule | Severity |
|---|---|---|
| An MCP server with a `command` resolved from PATH | `mcp-server-defined` | low — informational, because this is how most MCP servers are configured |
| `command` is a shell or an interpreter | `mcp-command-shell` | critical |
| `command` is a path inside the scanned tree | `mcp-command-in-repo` | critical |
| `command` or `args` download and run code | `mcp-fetches-remote-code` | critical |
| `command` points at a temporary or hidden location (`/tmp`, a dot-directory) | `mcp-command-suspicious-path` | critical |
| `args` name a file inside the scanned tree | `mcp-args-point-into-repo` | high |
| A remote server (`url`) with no credential material in `headers` or `env` | `mcp-remote-no-auth` | medium |
| `hooks` in agent settings | `agent-hook-command` | high |
| A permission mode that skips approval (`bypassPermissions`, `acceptEdits`, …) | `agent-permission-bypass` | critical |
| A wildcard entry in `permissions.allow` | `agent-permission-wildcard` | high |
| A credential-shaped value | `agent-secret-in-config` | high |
| The file cannot be parsed or is too large | `agent-config-unparsable`, `agent-config-too-large` | medium, and the scan is INCOMPLETE |

## Deliberately out of scope

| Thing | Reason |
|---|---|
| Whether a remote MCP server *actually* requires authentication | Only answerable by connecting to it. GuardSkill makes no network connections, and that promise is worth more than this check. `mcp-remote-no-auth` reports what the file declares, and says so in the finding. |
| The full permission scope of an MCP server's tools | Requires starting the server and listing its tools. Same reason: that is a runtime audit, not a file scan. |
| `.codex/config.toml` and other TOML-based agent settings | No TOML parser, and a scanner with no dependencies is not adding one for a single file format. Revisit when the format matters more than the promise. |
| `~/.claude/settings.json` and other user-level settings | Outside the scanned tree by definition. GuardSkill inspects what a repository delivers, not what you already had. |
| `.github/workflows/*` and other CI definitions | A different threat model with its own tooling. Naming it here so the gap is a decision rather than an oversight. |
| Whether an npm or PyPI package started by an MCP server is itself malicious | That is a registry-reputation question, and answering it needs the network. |

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
