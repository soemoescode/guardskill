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

/** Walk a parsed JSON document, yielding [pathString, value] for every leaf. */
function* leaves(node, trail = []) {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) yield* leaves(node[i], [...trail, String(i)]);
    return;
  }
  if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) yield* leaves(v, [...trail, k]);
    return;
  }
  yield [trail.join('.'), node];
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

function checkServer(rules, name, entry, location, fileDir, root) {
  const found = [];
  const command = typeof entry.command === 'string' ? entry.command : '';
  const args = Array.isArray(entry.args) ? entry.args.filter(a => typeof a === 'string') : [];
  const url = ['url', 'serverUrl', 'endpoint'].map(k => entry[k]).find(v => typeof v === 'string');
  const whole = [command, ...args].join(' ');

  if (command) {
    let escalated = null;

    const base = baseName(command);
    if (rules.shellCommands.includes(base)) {
      found.push(finding(rules, 'mcp-command-shell', location, `${name}: ${command} ${args.join(' ')}`.trim()));
      escalated = 'critical';
    }
    if (rules.compiled.suspiciousPathIndicators.some(re => re.test(command))) {
      found.push(finding(rules, 'mcp-command-suspicious-path', location, `${name}: ${command}`));
      escalated = 'critical';
    }
    if (rules.compiled.remoteExecIndicators.some(re => re.test(whole))) {
      found.push(finding(rules, 'mcp-fetches-remote-code', location, `${name}: ${whole}`));
      escalated = 'critical';
    }
    if (pointsIntoTree(command, fileDir, root)) {
      found.push(finding(rules, 'mcp-command-in-repo', location, `${name}: ${command}`));
      escalated = escalated ?? 'high';
    }
    // Arguments are held to a stricter test than the command. `.` and a workspace
    // directory are the two most common arguments an MCP server takes - the
    // filesystem server's own documented example is exactly that - so a directory
    // must not be a finding. A *file* inside the tree is different: that is code
    // the repository delivered and told your agent to load.
    const argInTree = args.find(a => pointsIntoTree(a, fileDir, root) && isExistingFile(a, fileDir));
    if (argInTree && !escalated) {
      found.push(finding(rules, 'mcp-args-point-into-repo', location, `${name}: ${command} ${args.join(' ')}`.trim()));
      escalated = 'high';
    }

    // The structural finding is what is left when nothing specific applies: this
    // repository starts a program, and the program looks ordinary. Emitting it
    // alongside a rule that already said something sharper would print every
    // server twice at the same severity, which is noise, not evidence.
    if (!escalated) {
      found.push(finding(rules, 'mcp-server-defined', location,
        `${name}: ${command} ${args.join(' ')}`.trim()));
    }
  }

  if (url && !command) {
    const headerKeys = Object.keys(entry.headers ?? {}).map(k => k.toLowerCase());
    const envKeys = Object.keys(entry.env ?? {}).map(k => k.toLowerCase());
    const hasAuth =
      headerKeys.some(k => rules.authHeaderNames.includes(k)) ||
      envKeys.some(k => rules.credentialKeyNames.some(n => k.includes(n)));
    if (!hasAuth) found.push(finding(rules, 'mcp-remote-no-auth', location, `${name}: ${url}`));
  }

  return found;
}

function checkSettings(rules, doc, location) {
  const found = [];

  if (doc?.hooks && typeof doc.hooks === 'object') {
    for (const [pathString, value] of leaves(doc.hooks)) {
      if (typeof value !== 'string' || !value.trim()) continue;
      if (!/(^|\.)(command|run|script)$/.test(pathString)) continue;
      found.push(finding(rules, 'agent-hook-command', location, `hooks.${pathString} = ${value}`));
    }
  }

  const modes = [doc?.permissions?.defaultMode, doc?.defaultMode, doc?.permissionMode, doc?.mode]
    .filter(v => typeof v === 'string');
  for (const mode of modes) {
    if (rules.bypassModes.includes(mode.toLowerCase().replace(/[\s_-]/g, ''))
      || rules.bypassModes.includes(mode.toLowerCase())) {
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

  for (const [pathString, value] of leaves(doc)) {
    const key = pathString.split('.').pop();
    if (looksLikeCredential(rules, key, value)) {
      found.push(finding(rules, 'agent-secret-in-config', location,
        `${pathString} = ${String(value).slice(0, 6)}… [redacted]`));
    }
  }

  return found;
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

  for (const { file, relPath, kind } of files) {
    const safe = await safeToRead(file, root);
    if (!safe.ok) {
      incomplete.add(`agent settings not inspected (${safe.reason}): ${relPath}`);
      findings.push(finding(rules, 'agent-config-unparsable', relPath, safe.reason));
      continue;
    }

    let info;
    try { info = await stat(file); } catch {
      incomplete.add(`agent settings could not be read: ${relPath}`);
      findings.push(finding(rules, 'agent-config-unparsable', relPath, 'could not be stat-ed'));
      continue;
    }
    if (info.size > MAX_SETTINGS_BYTES) {
      incomplete.add(`agent settings too large to parse: ${relPath}`);
      findings.push(finding(rules, 'agent-config-too-large', relPath, `${info.size} bytes`));
      continue;
    }

    let doc;
    try {
      doc = JSON.parse(await readFile(file, 'utf-8'));
    } catch (err) {
      // An unparsed file is the one thing a scanner must never present as an
      // absence of findings, so it is reported and the scan is INCOMPLETE.
      incomplete.add(`agent settings could not be parsed: ${relPath}`);
      findings.push(finding(rules, 'agent-config-unparsable', relPath, err.message.split('\n')[0]));
      continue;
    }
    if (doc === null || typeof doc !== 'object') continue;

    const fileDir = path.dirname(file);
    if (kind === 'local-settings') {
      findings.push(finding(rules, 'agent-local-settings-shipped', relPath, path.basename(file)));
    }
    for (const [name, entry] of serverEntries(doc)) {
      findings.push(...checkServer(rules, name, entry, relPath, fileDir, root));
    }
    findings.push(...checkSettings(rules, doc, relPath));
  }

  return findings;
}
