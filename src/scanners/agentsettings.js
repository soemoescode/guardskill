// The second detection class: settings files a repository ships that make a
// coding agent run a program, or hand out access, when it opens the project.
//
// Why this class matters more than another git key. The GitSpawn vectors need
// the `.git` directory to arrive as files - a zip, a shared drive, a sync
// folder, a USB stick - because a clone does not transfer `.git/config`. A
// `.mcp.json` has no such requirement. It is an ordinary tracked file, and it
// arrives with `git clone` like any other.
//
// Read-only and offline, like the rest of this tool. In particular: whether a
// remote MCP server *requires* authentication is only answerable by connecting
// to it, and this scanner never connects to anything. It reports what the file
// declares, and the finding says so in as many words.

import { readFile, stat } from 'node:fs/promises';
import { statSync } from 'node:fs';
import path from 'node:path';
import { safeToRead } from '../discovery.js';

const MAX_SETTINGS_BYTES = 2 * 1024 * 1024;
const MAX_EVIDENCE_CHARS = 200;

const cap = text => {
  const s = String(text);
  return s.length > MAX_EVIDENCE_CHARS ? s.slice(0, MAX_EVIDENCE_CHARS) + '… [truncated]' : s;
};

const baseName = cmd => path.basename(String(cmd).replace(/\\/g, '/')).toLowerCase().replace(/\.exe$/, '');

function finding(rules, id, location, evidence, severityOverride) {
  const r = rules.byId[id];
  return {
    ruleId: r.id,
    severity: severityOverride ?? r.baseSeverity ?? r.severity,
    title: r.title,
    explanation: r.explanation,
    remediation: r.remediation,
    location,
    evidence: cap(evidence),
  };
}

// ------------------------------------------------------------------ value tests

/** Does this path, as written, name something inside the scanned tree? */
function pointsIntoTree(value, fileDir, root) {
  const v = String(value);
  if (!v || /^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return false;
  if (!/[/\\]/.test(v) && !v.startsWith('.')) return false;   // a bare command name
  const resolved = path.isAbsolute(v) ? path.normalize(v) : path.resolve(fileDir, v);
  const rel = path.relative(root, resolved);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

function isExistingFile(value, fileDir) {
  const v = String(value);
  if (v === '.' || v === '..' || /^\.\.?[/\\]?$/.test(v)) return false;
  try {
    return statSync(path.isAbsolute(v) ? v : path.resolve(fileDir, v)).isFile();
  } catch {
    return false;
  }
}

function looksLikeCredential(rules, key, value) {
  if (typeof value !== 'string' || value.length < 8) return false;
  if (rules.compiled.credentialValuePatterns.some(re => re.test(value))) return true;
  const k = String(key).toLowerCase();
  if (!rules.credentialKeyNames.some(n => k.includes(n))) return false;
  // A key called "token" pointing at an env var or a placeholder is the correct
  // way to do this, and must not be reported as a leak.
  if (/^\$?\{?\$?[A-Z0-9_]+\}?$/.test(value)) return false;
  if (/^(xxx+|your[-_ ]|<|\.\.\.|changeme|placeholder|example)/i.test(value)) return false;
  return value.length >= 16;
}

const MAX_JSON_DEPTH = 100;

/**
 * Walk a parsed JSON document, yielding [pathString, value] for every leaf.
 *
 * Iterative, with an explicit depth cap. The recursive version blew the stack on
 * a 360 KB file nested 60,000 deep - comfortably inside the size limit, because
 * size was bounded and depth was not. The RangeError escaped the whole scan, so
 * one harmless-looking JSON file next to a payload turned a run that had already
 * found the payload into ERROR with zero findings. Suppressing a scanner is
 * cheaper than evading it, and this was the cheap way. (review 03, R3-02)
 *
 * @returns {{leaves: Array, tooDeep: boolean}}
 */
function leaves(root) {
  const out = [];
  let tooDeep = false;
  const stack = [{ node: root, trail: [], depth: 0 }];

  while (stack.length) {
    const { node, trail, depth } = stack.pop();
    if (node === null || node === undefined) continue;
    if (typeof node !== 'object') { out.push([trail.join('.'), node]); continue; }
    if (depth >= MAX_JSON_DEPTH) { tooDeep = true; continue; }

    const entries = Array.isArray(node)
      ? node.map((v, i) => [String(i), v])
      : Object.entries(node);
    for (const [k, v] of entries) stack.push({ node: v, trail: [...trail, k], depth: depth + 1 });
  }
  return { leaves: out, tooDeep };
}

// ------------------------------------------------------------------ the checks

function serverEntries(doc) {
  // Every shape in the wild puts the servers under one of these keys, and
  // VS Code nests them one level deeper.
  const out = [];
  const buckets = [doc?.mcpServers, doc?.servers, doc?.mcp?.servers, doc?.mcp?.mcpServers];
  for (const bucket of buckets) {
    if (!bucket || typeof bucket !== 'object' || Array.isArray(bucket)) continue;
    for (const [name, entry] of Object.entries(bucket)) {
      if (entry && typeof entry === 'object' && !Array.isArray(entry)) out.push([name, entry]);
    }
  }
  return out;
}

const URL_IN_TEXT = /\bhttps?:\/\/[^\s"']+/i;

/**
 * Pull the command and arguments out of a server entry.
 *
 * Three shapes are recognised: a string `command`, an array `command` (the whole
 * command line in one field), and either of those nested under `transport`.
 * Anything else returns nothing, and the caller reports that it did not
 * understand the entry rather than staying silent about it. (review 03, R3-03)
 */
function commandOf(entry) {
  for (const holder of [entry, entry.transport, entry.connection]) {
    if (!holder || typeof holder !== 'object') continue;
    const raw = holder.command;
    const args = Array.isArray(holder.args) ? holder.args.filter(a => typeof a === 'string') : [];
    if (typeof raw === 'string' && raw.trim()) return { command: raw, args };
    if (Array.isArray(raw) && raw.length && raw.every(a => typeof a === 'string')) {
      return { command: raw[0], args: [...raw.slice(1), ...args] };
    }
  }
  return { command: '', args: [] };
}

function urlOf(entry, args) {
  for (const holder of [entry, entry.transport, entry.connection]) {
    if (!holder || typeof holder !== 'object') continue;
    for (const key of ['url', 'serverUrl', 'endpoint', 'uri']) {
      if (typeof holder[key] === 'string' && holder[key].trim()) return holder[key];
    }
  }
  // The bridge form: `npx -y mcp-remote https://…`. The URL is the whole point of
  // the entry, and skipping the auth check because a command happens to be
  // present left the most common remote setup unexamined. (review 03, R3-05)
  const inArgs = args.map(a => (a.match(URL_IN_TEXT) || [])[0]).find(Boolean);
  return inArgs ?? null;
}

function checkServer(rules, name, entry, location, fileDir, root) {
  const found = [];
  const { command, args } = commandOf(entry);
  const whole = [command, ...args].join(' ');

  let shellish = false;
  if (command) {
    const { escalated, hits } = gradeCommand(rules, command, args, fileDir, root);
    for (const [id, evidence] of hits) found.push(finding(rules, id, location, `${name}: ${evidence}`));
    shellish = hits.some(([id]) => id === 'mcp-command-shell' || id === 'mcp-fetches-remote-code');

    if (!escalated) {
      found.push(finding(rules, 'mcp-server-defined', location, `${name}: ${command} ${args.join(' ')}`.trim()));
    }
  }

  // A URL inside a shell pipeline is a download target, not an MCP endpoint, and
  // the command rules have already said something much sharper about it. Only a
  // declared `url`, or a URL in the arguments of an ordinary command, counts as
  // a remote server.
  const url = urlOf(entry, shellish ? [] : args);
  if (url) {
    const headerKeys = Object.keys(entry.headers ?? entry.transport?.headers ?? {}).map(k => k.toLowerCase());
    const envKeys = Object.keys(entry.env ?? {}).map(k => k.toLowerCase());
    const hasAuth =
      headerKeys.some(k => rules.authHeaderNames.includes(k)) ||
      envKeys.some(k => rules.credentialKeyNames.some(n => k.includes(n)));
    if (!hasAuth) found.push(finding(rules, 'mcp-remote-no-auth', location, `${name}: ${url}`));
  }

  if (!command && !url) {
    // Not understood is not the same as not there. Every other unreadable thing
    // in this scanner says so; an entry in an unfamiliar shape must too.
    const keys = Object.keys(entry).slice(0, 8).join(', ');
    found.push(finding(rules, 'mcp-server-shape-unknown', location, `${name}: keys = ${keys || '(none)'}`));
  }

  return found;
}

/**
 * The severity ladder, in one place because two rules use it: an MCP server
 * command and a hook command are the same kind of value, and grading one on a
 * ladder while the other is a flat high is how `npx prettier --write` became a
 * build failure. (review 03, R3-04c)
 */
function gradeCommand(rules, command, args, fileDir, root) {
  const hits = [];
  let escalated = null;
  const whole = [command, ...args].join(' ');
  const base = baseName(command);

  if (rules.shellCommands.includes(base)) {
    hits.push(['mcp-command-shell', `${command} ${args.join(' ')}`.trim()]);
    escalated = 'critical';
  }
  if (rules.compiled.suspiciousPathIndicators.some(re => re.test(command))) {
    hits.push(['mcp-command-suspicious-path', command]);
    escalated = 'critical';
  }
  if (rules.compiled.remoteExecIndicators.some(re => re.test(whole))) {
    hits.push(['mcp-fetches-remote-code', whole]);
    escalated = 'critical';
  }
  if (pointsIntoTree(command, fileDir, root)) {
    hits.push(['mcp-command-in-repo', command]);
    escalated = escalated ?? 'high';
  }

  // Arguments are held to a stricter test than the command. `.` and a workspace
  // directory are the two most common arguments an MCP server takes - the
  // filesystem server's own documented example is exactly that - so a directory
  // must not be a finding. A *file* inside the tree is different: that is code
  // the repository delivered and told your agent to load.
  const argInTree = args.find(a => pointsIntoTree(a, fileDir, root) && isExistingFile(a, fileDir));
  if (argInTree && !escalated) {
    hits.push(['mcp-args-point-into-repo', `${command} ${args.join(' ')}`.trim()]);
    escalated = 'high';
  }

  return { escalated, hits };
}

function checkSettings(rules, doc, location, fileDir, root) {
  const found = [];
  const { leaves: all, tooDeep } = leaves(doc);

  if (doc?.hooks && typeof doc.hooks === 'object') {
    const { leaves: hookLeaves } = leaves(doc.hooks);
    for (const [pathString, value] of hookLeaves) {
      if (typeof value !== 'string' || !value.trim()) continue;
      if (!/(^|\.)(command|run|script)$/.test(pathString)) continue;

      // Same ladder as an MCP server command. `npx prettier --write` is a
      // formatter, not an attack, and grading it high failed the default build
      // on one of the most ordinary configurations there is. (review 03, R3-04c)
      const words = value.trim().split(/\s+/);
      const { escalated, hits } = gradeCommand(rules, words[0], words.slice(1), fileDir, root);
      const r = rules.byId['agent-hook-command'];
      found.push(finding(rules, 'agent-hook-command', location, `hooks.${pathString} = ${value}`,
        escalated === 'critical' ? (r.escalatedSeverity ?? 'critical')
          : escalated ? escalated : (r.baseSeverity ?? r.severity)));
      for (const [id, evidence] of hits) found.push(finding(rules, id, location, `hook: ${evidence}`));
    }
  }

  const modes = [doc?.permissions?.defaultMode, doc?.defaultMode, doc?.permissionMode, doc?.mode]
    .filter(v => typeof v === 'string');
  for (const mode of modes) {
    if (rules.bypassModes.includes(mode.toLowerCase().replace(/[\s_-]/g, ''))) {
      found.push(finding(rules, 'agent-permission-bypass', location, `permission mode = ${mode}`));
    }
  }
  for (const flag of ['dangerouslySkipPermissions', 'skipPermissions', 'autoApprove', 'yolo']) {
    if (doc?.[flag] === true || doc?.permissions?.[flag] === true) {
      found.push(finding(rules, 'agent-permission-bypass', location, `${flag} = true`));
    }
  }

  const allow = doc?.permissions?.allow ?? doc?.allow;
  if (Array.isArray(allow)) {
    for (const entry of allow) {
      if (typeof entry !== 'string') continue;
      if (rules.compiled.wildcardAllowPatterns.some(re => re.test(entry))) {
        found.push(finding(rules, 'agent-permission-wildcard', location, `permissions.allow: ${entry}`));
      }
    }
  }

  for (const [pathString, value] of all) {
    const key = pathString.split('.').pop();
    if (looksLikeCredential(rules, key, value)) {
      found.push(finding(rules, 'agent-secret-in-config', location,
        `${pathString} = ${String(value).slice(0, 6)}… [redacted]`));
    }
  }

  return { found, tooDeep };
}

// ------------------------------------------------------------------ entry point

/**
 * @param {string} root        the scanned tree
 * @param {Array}  files       { file, relPath, kind } from the directory walk
 * @param {object} rules       the loaded agent ruleset
 * @param {Set}    incomplete  shared with the git scanner: one INCOMPLETE list
 */
export async function scanAgentSettings(root, files, rules, incomplete) {
  const findings = [];

  for (const file of files) {
    // Per-file isolation. Before this, an exception raised by one settings file
    // escaped the whole run: the git class had already found a payload, and a
    // second file turned the result into ERROR with zero findings. One bad file
    // may cost its own finding and nothing else. (review 03, R3-02)
    try {
      findings.push(...await scanOneAgentFile(root, file, rules, incomplete));
    } catch (err) {
      incomplete.add(`agent settings could not be inspected: ${file.relPath}`);
      findings.push(finding(rules, 'agent-config-unparsable', file.relPath,
        err instanceof RangeError ? 'input exhausted the parser' : String(err.message ?? err).split('\n')[0]));
    }
  }

  return findings;
}

/**
 * The line a key sits on, for the SARIF region. Approximate by construction: the
 * document is already parsed, so this looks the key up in the raw text. First
 * occurrence wins, which is right for the server names and setting keys this is
 * used for. No line is better than a wrong line elsewhere, so a key that is not
 * found simply gets none.
 */
function lineOf(text, needle) {
  if (!needle) return null;
  const at = text.indexOf(`"${needle}"`);
  if (at === -1) return null;
  return text.slice(0, at).split('\n').length;
}

async function scanOneAgentFile(root, { file, relPath, kind, caseVariant }, rules, incomplete) {
  const findings = [];

  const safe = await safeToRead(file, root);
  if (!safe.ok) {
    incomplete.add(`agent settings not inspected (${safe.reason}): ${relPath}`);
    return [finding(rules, 'agent-config-unparsable', relPath, safe.reason)];
  }

  let info;
  try { info = await stat(file); } catch {
    incomplete.add(`agent settings could not be read: ${relPath}`);
    return [finding(rules, 'agent-config-unparsable', relPath, 'could not be stat-ed')];
  }
  if (info.size > MAX_SETTINGS_BYTES) {
    incomplete.add(`agent settings too large to parse: ${relPath}`);
    return [finding(rules, 'agent-config-too-large', relPath, `${info.size} bytes`)];
  }

  const text = await readFile(file, 'utf-8');
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (err) {
    // An unparsed file is the one thing a scanner must never present as an
    // absence of findings, so it is reported and the scan is INCOMPLETE.
    incomplete.add(`agent settings could not be parsed: ${relPath}`);
    return [finding(rules, 'agent-config-unparsable', relPath, err.message.split('\n')[0])];
  }
  if (doc === null || typeof doc !== 'object') return [];

  const fileDir = path.dirname(file);
  const at = name => {
    const line = lineOf(text, name);
    return line ? `${relPath}:${line}` : relPath;
  };

  if (kind === 'local-settings') {
    findings.push(finding(rules, 'agent-local-settings-shipped', relPath, path.basename(file)));
  }
  for (const [name, entry] of serverEntries(doc)) {
    findings.push(...checkServer(rules, name, entry, at(name), fileDir, root));
  }

  const { found, tooDeep } = checkSettings(rules, doc, relPath, fileDir, root);
  findings.push(...found);
  if (tooDeep) {
    incomplete.add(`agent settings nested deeper than the inspection limit: ${relPath}`);
    findings.push(finding(rules, 'agent-config-too-deep', relPath, `nesting beyond ${MAX_JSON_DEPTH} levels`));
  }

  if (caseVariant) {
    // The agent on this file system does not read this file at all, so nothing
    // in it is live here. It is live on Windows and macOS, which is why it is
    // reported - but at full severity next to a line saying it is inert, the
    // report would contradict itself. (review 03, R3-01; the same shape as N-5)
    for (const f of findings) {
      if (f.severity === 'critical' || f.severity === 'high') f.severity = 'medium';
      f.explanation += ' This file name differs in case from the one agents look for, and this file system is case-sensitive, so nothing here is applied on this machine; on Windows and macOS it is.';
    }
  }

  return findings;
}
