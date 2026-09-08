import { readFile, readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { parseGitConfig } from '../gitconfig-parser.js';
import { discoverGitTargets, configFilesFor } from '../discovery.js';

export async function loadRules(rulesPath) {
  return JSON.parse(await readFile(rulesPath, 'utf-8'));
}

const SHELL_META = /[;&|`$(){}<>]|\|\||&&/;
const HEAD_BYTES = 4096;
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_EVIDENCE_CHARS = 200;

// Values come from a file an attacker controls. Anything that reaches a terminal
// or a Markdown report gets its control characters removed and its length capped,
// so a hostile config cannot rewrite the report it appears in.
function sanitise(text) {
  const clean = String(text).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, '\uFFFD').replace(/[\r\n]+/g, ' ');
  return clean.length > MAX_EVIDENCE_CHARS ? clean.slice(0, MAX_EVIDENCE_CHARS) + '\u2026 [truncated]' : clean;
}

async function readHead(file) {
  try {
    const text = await readFile(file, 'utf-8');
    return text.slice(0, HEAD_BYTES);
  } catch { return ''; }
}

function matchesAny(text, patterns) {
  return patterns.some(p => new RegExp(p, 'i').test(text));
}

function firstWord(value) {
  return value.trim().replace(/^["']/, '').split(/\s+/)[0] || '';
}

function baseName(cmd) {
  return path.basename(cmd.replace(/\\/g, '/')).toLowerCase();
}

// An allowlisted name only means "safe" when it is a bare command resolved from
// PATH. `/tmp/less` is not less; naming your payload after a familiar tool is the
// cheapest evasion there is.
function isBareCommand(value) {
  const first = firstWord(value);
  return first !== '' && !/[\/\\]/.test(first);
}

function looksExecutable(value) {
  const v = value.trim();
  if (!v) return false;
  if (SHELL_META.test(v)) return true;
  if (/[\/\\]/.test(v)) return true;                       // a path
  if (/\.(sh|bash|zsh|py|js|mjs|cjs|rb|pl|exe|bat|cmd|ps1)\b/i.test(v)) return true;
  if (/\s/.test(v)) return true;                            // command with arguments
  return true;                                              // a bare program name is still a program
}

function startsWithSafePrefix(value, prefixes) {
  const v = value.trim().toLowerCase();
  return prefixes.some(p => v === p.toLowerCase() || v.startsWith(p.toLowerCase() + ' '));
}

function matchRule(rule, entry) {
  const m = rule.match;
  if (m.section && m.section !== entry.section) return false;
  if (m.sectionPrefix) {
    const allowed = m.sectionPrefix.split('|');
    if (!allowed.includes(entry.section)) return false;
  }
  if (m.anyKey) return true;
  if (m.keys) return m.keys.includes(entry.key);
  if (m.key) return m.key === entry.key;
  return false;
}

function evaluate(rule, entry, cfg) {
  const value = entry.value;
  const lower = value.trim().toLowerCase();

  switch (rule.matchType) {
    case 'always-flag':
      return true;
    case 'exec-always':
      return value.trim() !== '' && !cfg.safeLiterals.includes(lower);
    case 'exec-unless-boolean':
      if (cfg.safeLiterals.includes(lower)) return false;
      return looksExecutable(value);
    case 'exec-unless-safe-pager':
      if (cfg.safeLiterals.includes(lower)) return false;
      if (SHELL_META.test(value)) return true;
      if (!isBareCommand(value)) return true;
      return !cfg.safePagers.includes(baseName(firstWord(value)));
    case 'exec-unless-safe-editor':
      if (cfg.safeLiterals.includes(lower)) return false;
      if (SHELL_META.test(value)) return true;
      if (!isBareCommand(value)) return true;
      return !cfg.safeEditors.includes(baseName(firstWord(value)).replace(/\.(exe|cmd|bat)$/, ''));
    case 'exec-unless-known-command':
      if (cfg.safeLiterals.includes(lower)) return false;
      if (SHELL_META.test(value)) return true;
      if (!isBareCommand(value)) return true;
      return !startsWithSafePrefix(value, cfg.safeCommandPrefixes);
    case 'protocol-allow':
      return ['always', 'user'].includes(lower);
    case 'command-url':
      return /^\s*ext::/i.test(value);
    case 'exec-unless-known-helper': {
      const known = ['store', 'cache', 'osxkeychain', 'manager', 'manager-core', 'wincred', 'libsecret', 'gnome-keyring'];
      if (!value.trim()) return false;
      if (value.trim().startsWith('!')) return true;
      return !known.includes(baseName(firstWord(value)).replace(/^git-credential-/, ''));
    }
    case 'shell-alias':
      return value.trim().startsWith('!');
    default:
      return false;
  }
}

function keyLabel(entry) {
  return entry.subsection
    ? `${entry.section}.${entry.subsection}.${entry.key}`
    : `${entry.section}.${entry.key}`;
}

async function inspectHooksDir(dir, ruleset) {
  // Classify every script in the directory. A conventional directory name is not
  // evidence of anything: the scripts are.
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return { verdict: 'empty', script: null }; }
  const scripts = [];
  let suspicious = null;
  for (const e of entries) {
    if (!e.isFile() || e.name.endsWith('.sample')) continue;
    scripts.push(e.name);
    const head = await readHead(path.join(dir, e.name));
    if (matchesAny(head, ruleset.remoteExecIndicators)) return { verdict: 'remote-exec', script: e.name, scripts };
    if (!suspicious && matchesAny(head, ruleset.suspiciousPathIndicators)) suspicious = e.name;
  }
  if (suspicious) return { verdict: 'suspicious-path', script: suspicious, scripts };
  return { verdict: scripts.length ? 'managed' : 'empty', script: null, scripts };
}

async function scanAllConfigs(target, ruleset, repoRoot, rootPath) {
  const findings = [];
  for (const file of await configFilesFor(target.gitDir)) {
    const rel = (path.relative(rootPath, file) || file).split(path.sep).join('/');
    findings.push(...await scanConfigFile({ ...target, configPath: file, relPath: rel.replace(/\/(config(\.worktree)?)$/, '') }, ruleset, repoRoot, rel));
  }
  return findings;
}

async function scanConfigFile(target, ruleset, repoRoot, displayPath) {
  const findings = [];
  let text;
  try {
    const stats = await stat(target.configPath);
    if (!stats.isFile()) return findings;
    if (stats.size > MAX_CONFIG_BYTES) {
      findings.push({
        ruleId: 'config-too-large', severity: 'medium',
        title: 'Git config file too large to parse',
        explanation: `This config is ${Math.round(stats.size / 1024 / 1024)} MB. GuardSkill refuses to parse a file that size, so it was not inspected. A config that large is itself unusual.`,
        remediation: 'Open the file and look at it yourself before running git here.',
        location: displayPath, evidence: `${stats.size} bytes`,
      });
      return findings;
    }
    text = await readFile(target.configPath, 'utf-8');
  } catch {
    return findings;
  }

  for (const entry of parseGitConfig(text)) {
    for (const rule of ruleset.rules) {
      if (!matchRule(rule, entry)) continue;

      if (rule.matchType === 'hooks-path') {
        const raw = entry.value.trim().replace(/\/+$/, '');
        const dir = path.resolve(repoRoot, raw);
        const known = ruleset.knownHooksDirs.includes(raw);
        const exists = existsSync(dir);
        if (known && exists) {
          const { verdict, script, scripts } = await inspectHooksDir(dir, ruleset);
          const id = verdict === 'remote-exec' ? 'hook-fetches-remote-code'
                   : verdict === 'suspicious-path' ? 'unknown-hook-in-managed-dir'
                   : 'managed-hooks-dir';
          const sr = ruleset.structural.find(r => r.id === id);
          const atScript = verdict === 'remote-exec' || verdict === 'suspicious-path';
          findings.push({
            ruleId: sr.id, severity: sr.severity, title: sr.title,
            explanation: sr.explanation, remediation: sr.remediation,
            location: atScript ? `${raw}/${script}` : `${displayPath}:${entry.line}`,
            evidence: atScript
              ? sanitise(`${raw}/${script}`)
              : sanitise(`core.hooksPath = ${entry.value}` + (scripts.length ? ` (runs: ${scripts.join(', ')})` : '')),
          });
        } else {
          findings.push({
            ruleId: rule.id, severity: rule.severity, title: rule.title,
            explanation: rule.explanation, remediation: rule.remediation,
            location: `${displayPath}:${entry.line}`,
            evidence: sanitise(`${keyLabel(entry)} = ${entry.value}`),
          });
        }
        break;
      }

      if (!evaluate(rule, entry, ruleset)) continue;
      findings.push({
        ruleId: rule.id,
        severity: rule.severity,
        title: rule.title,
        explanation: rule.explanation,
        remediation: rule.remediation,
        location: `${displayPath}:${entry.line}`,
        evidence: sanitise(`${keyLabel(entry)} = ${entry.value}`),
      });
      break; // one finding per config entry
    }
  }
  return findings;
}

async function scanHooks(target, ruleset) {
  const structural = ruleset.structural;
  const findings = [];
  const hooksDir = path.join(target.gitDir, 'hooks');
  if (!existsSync(hooksDir)) return findings;
  let entries;
  try { entries = await readdir(hooksDir, { withFileTypes: true }); } catch { return findings; }

  for (const e of entries) {
    if (!e.isFile() || e.name.endsWith('.sample')) continue;
    const head = await readHead(path.join(hooksDir, e.name));
    let id = 'active-hook';
    if (matchesAny(head, ruleset.remoteExecIndicators)) id = 'hook-fetches-remote-code';
    else if (ruleset.hookManagerMarkers.some(m => head.toLowerCase().includes(m.toLowerCase()))) id = 'managed-hook-script';
    const rule = structural.find(r => r.id === id);
    findings.push({
      ruleId: rule.id,
      severity: rule.severity,
      title: rule.title,
      explanation: rule.explanation,
      remediation: rule.remediation,
      location: `${target.relPath}/hooks/${e.name}`,
      evidence: sanitise(`active hook script: ${e.name}`),
    });
  }
  return findings;
}

/**
 * Scan a directory tree. Read-only: nothing is written, nothing is executed.
 */
export async function scan(rootPath, ruleset, opts = {}) {
  const { targets, truncated, dirsVisited } = await discoverGitTargets(rootPath, opts);
  const structural = ruleset.structural;
  const findings = [];
  const submodulePaths = new Set();

  const gitmodules = path.join(rootPath, '.gitmodules');
  if (existsSync(gitmodules)) {
    try {
      const text = await readFile(gitmodules, 'utf-8');
      for (const e of parseGitConfig(text)) {
        if (e.key === 'path') submodulePaths.add(e.value.replace(/\/+$/, ''));
        if ((e.key === 'url' || e.key === 'pushurl') && /^\s*ext::/i.test(e.value)) {
          const r = structural.find(x => x.id === 'submodule-ext-url');
          findings.push({
            ruleId: r.id, severity: r.severity, title: r.title,
            explanation: r.explanation, remediation: r.remediation,
            location: `.gitmodules:${e.line}`, evidence: sanitise(`${e.section}.${e.subsection ?? ''}.${e.key} = ${e.value}`),
          });
        }
      }
    } catch { /* unreadable .gitmodules is not a finding */ }
  }

  for (const target of targets) {
    if (target.kind === 'bare-repo') {
      const rule = structural.find(r => r.id === 'bare-repo-in-tree');
      findings.push({
        ruleId: rule.id, severity: rule.severity, title: rule.title,
        explanation: rule.explanation, remediation: rule.remediation,
        location: target.relPath, evidence: sanitise(`bare repository at ${target.relPath}`),
      });
    } else if (target.kind === 'nested-git') {
      const parent = path.dirname(target.relPath).replace(/\\/g, '/');
      const isSubmodule = submodulePaths.has(parent);
      if (!isSubmodule) {
        const rule = structural.find(r => r.id === 'nested-git-dir');
        findings.push({
          ruleId: rule.id, severity: rule.severity, title: rule.title,
          explanation: rule.explanation, remediation: rule.remediation,
          location: target.relPath, evidence: sanitise(`nested git directory at ${target.relPath}`),
        });
      }
    }
    const repoRoot = target.kind === 'bare-repo' ? target.gitDir : path.dirname(target.gitDir);
    findings.push(...await scanAllConfigs(target, ruleset, repoRoot, rootPath));
    findings.push(...await scanHooks(target, ruleset));
  }

  const seen = new Set();
  const deduped = findings.filter(f => {
    const key = `${f.ruleId}|${f.location}|${f.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    rootPath,
    scanned: targets.length > 0,
    reason: targets.length === 0 ? 'no git repository or git directory found under this path' : undefined,
    targetCount: targets.length,
    dirsVisited,
    truncated,
    findings: deduped,
  };
}
