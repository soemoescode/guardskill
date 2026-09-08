import { readFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { parseGitConfig } from '../gitconfig-parser.js';
import { discoverGitTargets } from '../discovery.js';

export async function loadRules(rulesPath) {
  return JSON.parse(await readFile(rulesPath, 'utf-8'));
}

const SHELL_META = /[;&|`$(){}<>]|\|\||&&/;
const HEAD_BYTES = 4096;

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
      return !cfg.safePagers.includes(baseName(firstWord(value)));
    case 'exec-unless-safe-editor':
      if (cfg.safeLiterals.includes(lower)) return false;
      if (SHELL_META.test(value)) return true;
      return !cfg.safeEditors.includes(baseName(firstWord(value)).replace(/\.(exe|cmd|bat)$/, ''));
    case 'exec-unless-known-command':
      if (cfg.safeLiterals.includes(lower)) return false;
      if (SHELL_META.test(value)) return true;
      return !startsWithSafePrefix(value, cfg.safeCommandPrefixes);
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
  // returns { suspicious: boolean, script: string|null }
  let entries;
  try { entries = await readdir(dir, { withFileTypes: true }); } catch { return { suspicious: false, script: null }; }
  for (const e of entries) {
    if (!e.isFile() || e.name.endsWith('.sample')) continue;
    const head = await readHead(path.join(dir, e.name));
    if (matchesAny(head, ruleset.remoteExecIndicators)) return { suspicious: true, script: e.name };
  }
  return { suspicious: false, script: null };
}

async function scanConfigFile(target, ruleset, repoRoot) {
  const findings = [];
  let text;
  try {
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
          const { suspicious, script } = await inspectHooksDir(dir, ruleset);
          const sr = ruleset.structural.find(r => r.id === (suspicious ? 'hook-fetches-remote-code' : 'managed-hooks-dir'));
          findings.push({
            ruleId: sr.id, severity: sr.severity, title: sr.title,
            explanation: sr.explanation, remediation: sr.remediation,
            location: suspicious ? `${raw}/${script}` : `${target.relPath}/config:${entry.line}`,
            evidence: suspicious ? `hook script ${raw}/${script} fetches or decodes code` : `core.hooksPath = ${entry.value}`,
          });
        } else {
          findings.push({
            ruleId: rule.id, severity: rule.severity, title: rule.title,
            explanation: rule.explanation, remediation: rule.remediation,
            location: `${target.relPath}/config:${entry.line}`,
            evidence: `${keyLabel(entry)} = ${entry.value}`,
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
        location: `${target.relPath}/config:${entry.line}`,
        evidence: `${keyLabel(entry)} = ${entry.value}`,
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
      evidence: `active hook script: ${e.name}`,
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
      }
    } catch { /* unreadable .gitmodules is not a finding */ }
  }

  for (const target of targets) {
    if (target.kind === 'bare-repo') {
      const rule = structural.find(r => r.id === 'bare-repo-in-tree');
      findings.push({
        ruleId: rule.id, severity: rule.severity, title: rule.title,
        explanation: rule.explanation, remediation: rule.remediation,
        location: target.relPath, evidence: `bare repository at ${target.relPath}`,
      });
    } else if (target.kind === 'nested-git') {
      const parent = path.dirname(target.relPath).replace(/\\/g, '/');
      const isSubmodule = submodulePaths.has(parent);
      if (!isSubmodule) {
        const rule = structural.find(r => r.id === 'nested-git-dir');
        findings.push({
          ruleId: rule.id, severity: rule.severity, title: rule.title,
          explanation: rule.explanation, remediation: rule.remediation,
          location: target.relPath, evidence: `nested git directory at ${target.relPath}`,
        });
      }
    }
    const repoRoot = target.kind === 'bare-repo' ? target.gitDir : path.dirname(target.gitDir);
    findings.push(...await scanConfigFile(target, ruleset, repoRoot));
    findings.push(...await scanHooks(target, ruleset));
  }

  return {
    rootPath,
    scanned: targets.length > 0,
    reason: targets.length === 0 ? 'no git repository or git directory found under this path' : undefined,
    targetCount: targets.length,
    dirsVisited,
    truncated,
    findings,
  };
}
