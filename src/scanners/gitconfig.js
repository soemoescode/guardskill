import { readFile, readdir, stat, lstat, realpath, open } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { parseGitConfig } from '../gitconfig-parser.js';
import { discoverGitTargets, configFilesFor, safeToRead } from '../discovery.js';

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const MATCH_TYPES = new Set([
  'always-flag', 'exec-always', 'exec-unless-boolean', 'exec-unless-safe-pager',
  'exec-unless-safe-editor', 'exec-unless-known-command', 'exec-unless-known-helper',
  'exec-command-graded', 'credential-helper-graded', 'exec-unless-safe-gpg',
  'exec-unless-safe-pack', 'alias-executes', 'protocol-allow', 'command-url', 'hooks-path',
]);
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_EVIDENCE_CHARS = 200;
const HEAD_BYTES = 4096;
const MAX_INCLUDE_DEPTH = 10;

class RulesetError extends Error {}

/**
 * Load and validate the ruleset. An invalid ruleset is an error, not a surprise
 * at exit-code time: an unknown severity used to make every scan exit 1, silently.
 */
export async function loadRules(rulesPath) {
  let raw;
  try {
    raw = JSON.parse(await readFile(rulesPath, 'utf-8'));
  } catch (err) {
    throw new RulesetError(`ruleset ${rulesPath} could not be parsed: ${err.message}`);
  }

  const need = (obj, field, where) => {
    if (obj[field] === undefined || obj[field] === '') throw new RulesetError(`${where}: missing required field "${field}"`);
  };

  if (!Array.isArray(raw.rules)) throw new RulesetError('ruleset: "rules" must be an array');
  if (!Array.isArray(raw.structural)) throw new RulesetError('ruleset: "structural" must be an array');

  for (const rule of raw.rules) {
    const where = `rule "${rule.id ?? '(no id)'}"`;
    for (const f of ['id', 'match', 'matchType', 'severity', 'title', 'explanation']) need(rule, f, where);
    if (!SEVERITIES.includes(rule.severity)) {
      throw new RulesetError(`${where}: severity "${rule.severity}" is not one of ${SEVERITIES.join(', ')}`);
    }
    if (!MATCH_TYPES.has(rule.matchType)) {
      throw new RulesetError(`${where}: unknown matchType "${rule.matchType}"`);
    }
  }
  for (const rule of raw.structural) {
    const where = `structural rule "${rule.id ?? '(no id)'}"`;
    for (const f of ['id', 'severity', 'title', 'explanation']) need(rule, f, where);
    for (const key of ['severity', 'baseSeverity', 'escalatedSeverity']) {
      if (rule[key] !== undefined && !SEVERITIES.includes(rule[key])) {
        throw new RulesetError(`${where}: ${key} "${rule[key]}" is not one of ${SEVERITIES.join(', ')}`);
      }
    }
  }

  // Compile every pattern once, here, so a broken regex is a load-time error with
  // a name attached rather than a crash halfway through a scan.
  const compiled = {};
  for (const field of ['remoteExecIndicators', 'suspiciousPathIndicators']) {
    compiled[field] = (raw[field] ?? []).map(pattern => {
      try {
        return new RegExp(pattern, 'i');
      } catch (err) {
        throw new RulesetError(`${field}: pattern ${JSON.stringify(pattern)} is not a valid regular expression (${err.message})`);
      }
    });
  }

  return { ...raw, compiled, structuralById: Object.fromEntries(raw.structural.map(r => [r.id, r])) };
}

// ---------------------------------------------------------------- value helpers

const SHELL_META = /[;&|`$(){}<>]|\|\||&&/;

const firstWord = v => v.trim().replace(/^["']/, '').split(/\s+/)[0] || '';
const baseName = cmd => path.basename(cmd.replace(/\\/g, '/')).toLowerCase();
const hasPath = v => /[/\\]/.test(firstWord(v));
const matchesAny = (text, compiled) => compiled.some(re => re.test(text));

function cap(text) {
  const s = String(text);
  return s.length > MAX_EVIDENCE_CHARS ? s.slice(0, MAX_EVIDENCE_CHARS) + '… [truncated]' : s;
}

function looksExecutable(value) {
  const v = value.trim();
  if (!v) return false;
  return true; // every non-empty value for these keys names something to run
}

/** A git invocation that re-enters git with a configuration of its own choosing. */
function gitReconfigures(value, flags) {
  const words = value.trim().split(/\s+/);
  if (baseName(words[0] ?? '').replace(/\.exe$/, '') !== 'git') return false;
  return words.slice(1).some(w => flags.some(f => w === f || w.startsWith(f + '=')));
}

/**
 * Read at most `bytes` from the start of a file, without loading the rest.
 *
 * readFile().slice() allocated the whole file first: a 400 MB hook script pushed
 * peak RSS to 855 MB, and past Node's maximum string length the read threw, the
 * catch turned that into an empty head, and an empty head is indistinguishable
 * from "read it, found nothing" - so a padded hook silently dropped from critical
 * to high. The size of a file in an untrusted directory is the attacker's choice;
 * the memory we spend on it should not be. (review 02, N-3)
 *
 * @returns {{text: string, readable: boolean}}
 */
async function readPrefix(file, bytes = HEAD_BYTES) {
  let handle;
  try {
    handle = await open(file, 'r');
    const buf = Buffer.alloc(bytes);
    const { bytesRead } = await handle.read(buf, 0, bytes, 0);
    return { text: buf.subarray(0, bytesRead).toString('utf-8'), readable: true };
  } catch {
    return { text: '', readable: false };
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function readHead(file) {
  return (await readPrefix(file)).text;
}

// ---------------------------------------------------------------- rule matching

function matchRule(rule, entry) {
  const m = rule.match;
  if (m.section && m.section !== entry.section) return false;
  if (m.sectionPrefix && !m.sectionPrefix.split('|').includes(entry.section)) return false;
  if (m.anyKey) return true;
  if (m.keys) return m.keys.includes(entry.key);
  if (m.key) return m.key === entry.key;
  return false;
}

/** @returns {null | {severity: string, note?: string}} */
function evaluate(rule, entry, cfg) {
  const value = entry.value;
  const lower = value.trim().toLowerCase();
  const safeLiteral = (cfg.safeLiterals ?? []).includes(lower);
  const hit = severity => ({ severity });

  switch (rule.matchType) {
    case 'always-flag':
      return hit(rule.severity);

    case 'exec-always':
      return value.trim() !== '' && !safeLiteral ? hit(rule.severity) : null;

    case 'exec-unless-boolean':
      if (safeLiteral) return null;
      return looksExecutable(value) ? hit(rule.severity) : null;

    case 'exec-unless-safe-pager':
      if (safeLiteral) return null;
      if (SHELL_META.test(value) || hasPath(value)) return hit(rule.severity);
      return cfg.safePagers.includes(baseName(firstWord(value))) ? null : hit(rule.severity);

    case 'exec-unless-safe-editor':
      if (safeLiteral) return null;
      if (SHELL_META.test(value) || hasPath(value)) return hit(rule.severity);
      return cfg.safeEditors.includes(baseName(firstWord(value)).replace(/\.(exe|cmd|bat)$/, ''))
        ? null : hit(rule.severity);

    case 'exec-unless-safe-gpg':
      if (safeLiteral) return null;
      if (SHELL_META.test(value) || hasPath(value)) return hit(rule.severity);
      return cfg.safeGpgPrograms.includes(baseName(firstWord(value))) ? null : hit(rule.severity);

    case 'exec-unless-safe-pack':
      if (safeLiteral) return null;
      if (SHELL_META.test(value) || hasPath(value)) return hit(rule.severity);
      return ['git-upload-pack', 'git-receive-pack', 'git-upload-archive'].includes(baseName(firstWord(value)))
        ? null : hit(rule.severity);

    case 'exec-unless-known-command':
      if (safeLiteral) return null;
      if (SHELL_META.test(value) || hasPath(value)) return hit(rule.severity);
      return cfg.safeCommandValues.includes(value.trim()) ? null : hit(rule.severity);

    // Graded: the same key is a different risk depending on what it names.
    case 'exec-command-graded': {
      if (safeLiteral) return null;
      const v = value.trim();
      if (cfg.safeCommandValues.includes(v)) return null;                       // git-lfs, git-crypt
      if (gitReconfigures(v, cfg.gitReconfigureFlags)) {
        return { severity: 'critical', note: 'git is re-entered with a configuration of its own' };
      }
      if (SHELL_META.test(v)) return hit('high');
      if (matchesAny(v, cfg.compiled.suspiciousPathIndicators)) return hit('high');
      if (hasPath(v)) return hit('high');
      return { severity: 'low', note: 'a bare command resolved from PATH' };     // cat, sops, jupyter
    }

    case 'credential-helper-graded': {
      const v = value.trim();
      if (!v) return null;
      if (v.startsWith('!')) return hit('high');
      const name = baseName(firstWord(v)).replace(/^git-credential-/, '');
      const known = cfg.knownCredentialHelpers.includes(name);
      const args = v.split(/\s+/).slice(1);
      const redirects = args.some(a =>
        cfg.credentialHelperRedirectFlags.some(f => a === f || a.startsWith(f + '=')) || /[/\\]/.test(a));
      if (known && redirects) {
        return { severity: 'high', note: 'an allowlisted helper, but its arguments move where credentials are stored' };
      }
      if (known) return null;
      return hit(rule.severity);
    }

    case 'alias-executes': {
      const v = value.trim();
      if (v.startsWith('!')) return hit(rule.severity);
      const flags = cfg.gitReconfigureFlags;
      const firstArg = v.split(/\s+/)[0] ?? '';
      if (flags.some(f => firstArg === f || firstArg.startsWith(f + '='))) {
        return { severity: 'high', note: 'the alias re-enters git with its own configuration' };
      }
      return null;
    }

    case 'protocol-allow':
      return ['always', 'user'].includes(lower) ? hit(rule.severity) : null;

    case 'command-url':
      return /^\s*ext::/i.test(value) ? hit(rule.severity) : null;

    default:
      return null;
  }
}

const keyLabel = e => (e.subsection ? `${e.section}.${e.subsection}.${e.key}` : `${e.section}.${e.key}`);

// ---------------------------------------------------------------- hooks

async function classifyHookDir(dir, root, ruleset) {
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return { verdict: 'empty', scripts: [] }; }
  const scripts = [];
  let suspicious = null;
  for (const e of entries) {
    if (e.name.endsWith('.sample')) continue;
    if (!e.isFile() && !e.isSymbolicLink()) continue;
    scripts.push(e.name);
    const full = path.join(dir, e.name);
    if (e.isSymbolicLink()) {
      const safe = await safeToRead(full, root);
      if (!safe.ok && safe.reason !== 'symlink') return { verdict: 'symlink-outside', script: e.name, scripts };
      let real;
      try { real = await realpath(full); } catch { return { verdict: 'symlink-outside', script: e.name, scripts }; }
      const rel = path.relative(root, real);
      if (rel.startsWith('..') || path.isAbsolute(rel)) return { verdict: 'symlink-outside', script: e.name, scripts };
    }
    const head = await readHead(full);
    if (matchesAny(head, ruleset.compiled.remoteExecIndicators)) return { verdict: 'remote-exec', script: e.name, scripts };
    if (!suspicious && matchesAny(head, ruleset.compiled.suspiciousPathIndicators)) suspicious = e.name;
  }
  if (suspicious) return { verdict: 'suspicious-path', script: suspicious, scripts };
  return { verdict: scripts.length ? 'managed' : 'empty', scripts };
}

// ---------------------------------------------------------------- scanning

function structuralFinding(ruleset, id, location, evidence, severityOverride) {
  const r = ruleset.structuralById[id];
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

/**
 * A config that exists but cannot be opened. Reported rather than skipped: an
 * unread file is the one thing a scanner must never present as an absence of
 * findings, and the scan is INCOMPLETE for the same reason. (review 02, N-3)
 */
function unreadableConfigFinding(displayPath, reason) {
  return {
    ruleId: 'config-unreadable', severity: 'medium',
    title: 'Git config found but could not be read',
    explanation: 'This configuration file exists and git would apply it, but GuardSkill could not open it. Nothing in it has been checked, so this scan says nothing about its contents.',
    remediation: 'Open the file yourself, or fix the permissions and scan again, before running git here.',
    location: displayPath, evidence: String(reason),
  };
}

async function scanOneConfig(ctx, file, displayPath, target, chain) {
  const { ruleset, root } = ctx;
  const findings = [];

  const safe = await safeToRead(file, root);
  if (!safe.ok) {
    if (safe.reason === 'symlink' || safe.reason === 'outside-tree') {
      ctx.incomplete.add(`config not inspected (${safe.reason}): ${displayPath}`);
      findings.push(structuralFinding(ruleset, 'symlinked-config', displayPath, `${displayPath} (${safe.reason})`));
    } else {
      // 'unreadable' or 'not-a-file'. Discovery saw something at this path and we
      // cannot read it, so we know nothing about it - which is not the same as
      // knowing it is harmless. (review 02, N-3)
      ctx.incomplete.add(`config could not be read: ${displayPath}`);
      findings.push(unreadableConfigFinding(displayPath, safe.reason));
    }
    return findings;
  }

  let stats;
  try { stats = await stat(file); } catch {
    // The file was there a moment ago (discovery found it) and now cannot be
    // measured. Saying nothing here would report the repository as clean on the
    // strength of a file nobody read. (review 02, N-3)
    ctx.incomplete.add(`config could not be read: ${displayPath}`);
    findings.push(unreadableConfigFinding(displayPath, 'could not be stat-ed'));
    return findings;
  }
  if (stats.size > MAX_CONFIG_BYTES) {
    findings.push({
      ruleId: 'config-too-large', severity: 'medium',
      title: 'Git config file too large to parse',
      explanation: `This config is ${Math.round(stats.size / 1024 / 1024)} MB. GuardSkill refuses to parse a file that size, so it was not inspected. A config that large is itself unusual.`,
      remediation: 'Open the file and look at it yourself before running git here.',
      location: displayPath, evidence: `${stats.size} bytes`,
    });
    ctx.incomplete.add(`config too large to parse: ${displayPath}`);
    return findings;
  }

  let text;
  try { text = await readFile(file, 'utf-8'); } catch (err) {
    ctx.incomplete.add(`config could not be read: ${displayPath}`);
    findings.push(unreadableConfigFinding(displayPath, err.code ?? 'unreadable'));
    return findings;
  }

  for (const entry of parseGitConfig(text)) {
    // include / includeIf: git applies the target as if written here, so follow it.
    const isInclude = (entry.section === 'include' || entry.section === 'includeif') && entry.key === 'path';
    if (isInclude) {
      findings.push(...await followInclude(ctx, entry, file, displayPath, target, chain));
      continue;
    }

    for (const rule of ruleset.rules) {
      if (!matchRule(rule, entry)) continue;

      if (rule.matchType === 'hooks-path') {
        findings.push(...await scanHooksPath(ctx, entry, target, displayPath));
        break;
      }

      const verdict = evaluate(rule, entry, ruleset);
      if (!verdict) continue;
      findings.push({
        ruleId: rule.id,
        severity: verdict.severity,
        title: rule.title,
        explanation: verdict.note ? `${rule.explanation} Here, ${verdict.note}.` : rule.explanation,
        remediation: rule.remediation,
        location: `${displayPath}:${entry.line}`,
        evidence: cap(`${keyLabel(entry)} = ${entry.value}`),
      });
      break; // one finding per config entry
    }
  }
  return findings;
}

async function followInclude(ctx, entry, fromFile, displayPath, target, chain) {
  const { ruleset, root } = ctx;
  const raw = entry.value.trim();
  const findings = [];

  if (chain.length >= MAX_INCLUDE_DEPTH) {
    ctx.incomplete.add(`include chain deeper than ${MAX_INCLUDE_DEPTH}: ${displayPath}`);
    return [structuralFinding(ruleset, 'include-not-followed', `${displayPath}:${entry.line}`,
      `${keyLabel(entry)} = ${raw} (chain too deep)`)];
  }

  const expanded = raw.startsWith('~') ? null : path.resolve(path.dirname(fromFile), raw);
  const inTree = expanded && !path.relative(root, expanded).startsWith('..') && !path.isAbsolute(path.relative(root, expanded));

  if (!expanded || !inTree || !existsSync(expanded)) {
    ctx.incomplete.add(`include not inspected: ${raw} (from ${displayPath})`);
    return [structuralFinding(ruleset, 'include-not-followed', `${displayPath}:${entry.line}`,
      `${keyLabel(entry)} = ${raw}`)];
  }

  let realIncluded;
  try { realIncluded = await realpath(expanded); } catch { realIncluded = expanded; }
  if (ctx.visited.has(realIncluded)) return findings; // cycle
  ctx.visited.add(realIncluded);

  const includedDisplay = (path.relative(root, expanded) || raw).split(path.sep).join('/');
  const chained = `${displayPath} → ${includedDisplay}`;
  findings.push(...await scanOneConfig(ctx, expanded, chained, target, [...chain, realIncluded]));

  // The include itself is informational once we have actually read it.
  findings.push({
    ruleId: 'include-path', severity: 'low',
    title: 'Configuration is loaded from another file',
    explanation: 'This config includes another file; git applies its contents as if they were written here. GuardSkill followed it and inspected it, so any finding from that file appears above with the include chain in its location.',
    remediation: 'No action needed beyond the findings from the included file, if any.',
    location: `${displayPath}:${entry.line}`,
    evidence: cap(`${keyLabel(entry)} = ${raw}`),
  });
  return findings;
}

async function scanHooksPath(ctx, entry, target, displayPath) {
  const { ruleset, root } = ctx;
  const repoRoot = target.kind === 'bare-repo' ? target.gitDir : path.dirname(target.gitDir);
  const raw = entry.value.trim().replace(/\/+$/, '');
  const dir = path.resolve(repoRoot, raw);
  const known = ruleset.knownHooksDirs.includes(raw);
  const rule = ruleset.rules.find(r => r.id === 'core-hookspath');

  if (!known || !existsSync(dir)) {
    return [{
      ruleId: rule.id, severity: rule.severity, title: rule.title,
      explanation: rule.explanation, remediation: rule.remediation,
      location: `${displayPath}:${entry.line}`,
      evidence: cap(`${keyLabel(entry)} = ${entry.value}`),
    }];
  }

  const { verdict, script, scripts } = await classifyHookDir(dir, root, ruleset);
  const id = verdict === 'remote-exec' ? 'hook-fetches-remote-code'
    : verdict === 'symlink-outside' ? 'hook-symlink-outside'
      : verdict === 'suspicious-path' ? 'unknown-hook-in-managed-dir'
        : 'managed-hooks-dir';
  if (verdict === 'symlink-outside') ctx.incomplete.add(`hook symlink not inspected: ${raw}/${script}`);
  const atScript = id !== 'managed-hooks-dir';
  return [structuralFinding(ruleset, id,
    atScript ? `${raw}/${script}` : `${displayPath}:${entry.line}`,
    atScript ? `${raw}/${script}` : `core.hooksPath = ${entry.value}` + (scripts.length ? ` (runs: ${scripts.join(', ')})` : ''))];
}

async function scanHooksDir(ctx, target) {
  const { ruleset, root } = ctx;
  const hooksDir = path.join(target.gitDir, 'hooks');
  if (!existsSync(hooksDir)) return [];
  let entries;
  try { entries = await readdir(hooksDir, { withFileTypes: true }); } catch { return []; }

  const findings = [];
  for (const e of entries) {
    if (e.name.endsWith('.sample')) continue;
    if (!e.isFile() && !e.isSymbolicLink()) continue;
    const full = path.join(hooksDir, e.name);
    const location = `${target.relPath}/hooks/${e.name}`;

    if (e.isSymbolicLink()) {
      let real = null;
      try { real = await realpath(full); } catch { /* dangling */ }
      const outside = !real || path.relative(root, real).startsWith('..') || path.isAbsolute(path.relative(root, real));
      if (outside) {
        ctx.incomplete.add(`hook symlink not inspected: ${location}`);
        findings.push(structuralFinding(ruleset, 'hook-symlink-outside', location, `active hook symlink: ${e.name}`));
        continue;
      }
    }

    const { text: head, readable } = await readPrefix(full);
    if (!readable) {
      ctx.incomplete.add(`hook script could not be read: ${location}`);
      findings.push(structuralFinding(ruleset, 'active-hook', location,
        `active hook script: ${e.name} (could not be read - contents unknown)`, 'high'));
      continue;
    }
    const id = matchesAny(head, ruleset.compiled.remoteExecIndicators) ? 'hook-fetches-remote-code'
      : ruleset.hookManagerMarkers.some(m => head.toLowerCase().includes(m.toLowerCase())) ? 'managed-hook-script'
        : 'active-hook';
    findings.push(structuralFinding(ruleset, id, location, `active hook script: ${e.name}`));
  }
  return findings;
}

async function submodulePathsFor(repoRoot, root) {
  const file = path.join(repoRoot, '.gitmodules');
  if (!existsSync(file)) return [];
  const safe = await safeToRead(file, root);
  if (!safe.ok) return [];
  try {
    const info = await stat(file);
    if (info.size > MAX_CONFIG_BYTES) return [];
    const text = await readFile(file, 'utf-8');
    return parseGitConfig(text).filter(e => e.key === 'path').map(e => e.value.replace(/\/+$/, ''));
  } catch { return []; }
}

async function gitmodulesFindings(ctx, repoRoot, displayPrefix) {
  const { ruleset, root } = ctx;
  const file = path.join(repoRoot, '.gitmodules');
  if (!existsSync(file)) return [];
  const safe = await safeToRead(file, root);
  if (!safe.ok) {
    if (safe.reason === 'symlink' || safe.reason === 'outside-tree') {
      ctx.incomplete.add(`.gitmodules not inspected (${safe.reason})`);
      return [structuralFinding(ruleset, 'symlinked-config', `${displayPrefix}.gitmodules`, `.gitmodules (${safe.reason})`)];
    }
    return [];
  }
  try {
    const info = await stat(file);
    if (info.size > MAX_CONFIG_BYTES) {
      ctx.incomplete.add('.gitmodules too large to parse');
      return [{
        ruleId: 'config-too-large', severity: 'medium',
        title: 'Git config file too large to parse',
        explanation: `.gitmodules is ${Math.round(info.size / 1024 / 1024)} MB and was not inspected.`,
        remediation: 'Open the file and look at it yourself before running git here.',
        location: `${displayPrefix}.gitmodules`, evidence: `${info.size} bytes`,
      }];
    }
  } catch { return []; }
  let text;
  try { text = await readFile(file, 'utf-8'); } catch { return []; }
  const out = [];
  for (const e of parseGitConfig(text)) {
    if ((e.key === 'url' || e.key === 'pushurl') && /^\s*ext::/i.test(e.value)) {
      out.push(structuralFinding(ruleset, 'submodule-ext-url', `${displayPrefix}.gitmodules:${e.line}`,
        `${keyLabel(e)} = ${e.value}`));
    }
  }
  return out;
}

const worstOf = list => SEVERITIES.find(s => list.some(f => f.severity === s));

/**
 * Scan a directory tree. Read-only: nothing is written, nothing is executed.
 */
export async function scan(rootPath, ruleset, opts = {}) {
  const { targets, truncated, dirsVisited, caseInsensitive, caseVariants } =
    await discoverGitTargets(rootPath, opts);

  const ctx = { ruleset, root: rootPath, incomplete: new Set(), visited: new Set() };
  const findings = [];

  if (truncated) ctx.incomplete.add('the walk stopped at its depth or size limit');

  // Submodule registrations, per repository that owns them - not only the scan root.
  const registered = new Set();
  for (const target of targets) {
    const repoRoot = target.kind === 'bare-repo' ? target.gitDir : path.dirname(target.gitDir);
    for (const p of await submodulePathsFor(repoRoot, rootPath)) {
      const rel = path.relative(rootPath, path.resolve(repoRoot, p)).split(path.sep).join('/');
      registered.add(rel);
    }
    findings.push(...await gitmodulesFindings(ctx, repoRoot,
      target.kind === 'root-git' ? '' : path.relative(rootPath, repoRoot).split(path.sep).join('/') + '/'));
  }

  for (const variant of caseVariants) {
    findings.push(structuralFinding(ruleset, 'case-variant-git-dir', variant.relPath,
      `directory named "${variant.name}"`));
  }

  for (const target of targets) {
    const own = [];
    for (const file of await configFilesFor(target.gitDir)) {
      const rel = (path.relative(rootPath, file) || file).split(path.sep).join('/');
      own.push(...await scanOneConfig(ctx, file, rel, target, []));
    }
    own.push(...await scanHooksDir(ctx, target));

    if (target.caseVariant) {
      // git on this file system does not read this directory at all, so a payload
      // in it is not live here. It is live on Windows and macOS, which is why it
      // is reported - but reporting it at full severity next to a line saying git
      // ignores it here reads as a contradiction. (review 02, N-5)
      for (const f of own) {
        if (f.severity === 'critical' || f.severity === 'high') {
          f.severity = 'medium';
          f.explanation += ' On this file system git does not treat the containing directory as a git directory, so this value is not applied here; on Windows and macOS it is.';
        }
      }
    }

    // Structural severity is not fixed: a git directory shipped as content is
    // unusual on its own and alarming when it also carries something git runs.
    if (target.kind === 'bare-repo' || (target.kind === 'nested-git' && !registered.has(target.relPath.replace(/\/\.git$/, '')))) {
      const id = target.kind === 'bare-repo' ? 'bare-repo-in-tree' : 'nested-git-dir';
      const r = ruleset.structuralById[id];
      const worst = worstOf(own);
      const carriesExecution = worst === 'critical' || worst === 'high';
      findings.push(structuralFinding(ruleset, id, target.relPath,
        target.kind === 'bare-repo' ? `bare repository at ${target.relPath}` : `nested git directory at ${target.relPath}`,
        carriesExecution ? (r.escalatedSeverity ?? 'critical') : (r.baseSeverity ?? r.severity)));
    }
    findings.push(...own);
  }

  const seen = new Set();
  const deduped = findings.filter(f => {
    const key = `${f.ruleId}|${f.location}|${f.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const incompleteReasons = [...ctx.incomplete];
  return {
    rootPath,
    scanned: targets.length > 0,
    reason: targets.length === 0 ? 'no git repository or git directory found under this path' : undefined,
    targetCount: targets.length,
    dirsVisited,
    truncated,
    caseInsensitive,
    incompleteReasons,
    findings: deduped,
  };
}

/**
 * status says what was found; the exit code says whether that fails your build.
 * Keeping them apart matters: v0.4.0-rc1 reported status CLEAN alongside a filled
 * summary whenever every finding sat below the threshold, which is a lie to any
 * machine reading the field. (review 02, N-4)
 *
 * CLEAN = nothing found · FINDINGS = something found, at any severity ·
 * INCOMPLETE = nothing found but part of the tree was not inspected.
 * ERROR is decided by the caller.
 */
export function statusOf(result) {
  if (result.findings.length > 0) return 'FINDINGS';
  if (result.incompleteReasons.length > 0) return 'INCOMPLETE';
  return 'CLEAN';
}

/** 0 CLEAN · 1 FINDINGS at or above the threshold · 3 INCOMPLETE. */
export function exitCodeFor(result, failOn = 'high', allowIncomplete = false) {
  const threshold = SEVERITIES.indexOf(failOn);
  if (result.findings.some(f => SEVERITIES.indexOf(f.severity) <= threshold)) return 1;
  if (result.incompleteReasons.length > 0 && !allowIncomplete) return 3;
  return 0;
}
