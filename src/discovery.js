// Finds every git configuration that a coding agent could pick up under a path:
// the project's own .git, any nested .git directories that arrived as content,
// and any bare repository hidden in the tree (the CVE-2026-45033 vector).
//
// Read-only. Never follows symlinks — a scanner must not be walked out of its
// own target directory by a link the attacker controls.

import { readdir, stat, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const ALWAYS_SKIP = new Set(['node_modules/.cache', '.terraform', '.venv', '__pycache__']);

async function isBareRepo(dir) {
  // git's own is_git_directory() wants HEAD, objects and refs. We deliberately do
  // not require refs: creating an empty refs/ costs an attacker nothing, so making
  // it a condition only buys false negatives.
  return (
    existsSync(path.join(dir, 'HEAD')) &&
    existsSync(path.join(dir, 'config')) &&
    existsSync(path.join(dir, 'objects'))
  );
}

// Every config file git reads for one git directory. A repository delivered as
// files carries all of these, and each one can hold an execution key.
export async function configFilesFor(gitDir) {
  const out = [];
  const add = p => { if (existsSync(p)) out.push(p); };

  add(path.join(gitDir, 'config'));
  add(path.join(gitDir, 'config.worktree'));

  const worktrees = path.join(gitDir, 'worktrees');
  if (existsSync(worktrees)) {
    try {
      for (const e of await readdir(worktrees, { withFileTypes: true })) {
        if (e.isDirectory()) add(path.join(worktrees, e.name, 'config.worktree'));
      }
    } catch { /* unreadable */ }
  }

  // Submodule git directories live under .git/modules/<name>[/modules/<name>...]
  const modules = path.join(gitDir, 'modules');
  if (existsSync(modules)) {
    const queue = [{ dir: modules, depth: 0 }];
    while (queue.length) {
      const { dir, depth } = queue.shift();
      if (depth > 6) continue;
      let entries;
      try { entries = await readdir(dir, { withFileTypes: true }); } catch { continue; }
      for (const e of entries) {
        if (!e.isDirectory()) continue;
        const full = path.join(dir, e.name);
        add(path.join(full, 'config'));
        add(path.join(full, 'config.worktree'));
        queue.push({ dir: full, depth: depth + 1 });
      }
    }
  }

  return out;
}

// A submodule or linked worktree has a .git FILE holding "gitdir: <path>".
async function resolveGitFile(file, root) {
  try {
    const text = (await readFile(file, 'utf-8')).trim();
    const m = text.match(/^gitdir:\s*(.+)$/m);
    if (!m) return null;
    const target = path.resolve(path.dirname(file), m[1].trim());
    const rel = path.relative(root, target);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return null; // points outside the scan
    return target;
  } catch { return null; }
}

/**
 * @param {string} root absolute path to scan
 * @param {{maxDepth?: number, maxEntries?: number}} opts
 * @returns {Promise<{targets: Array, truncated: boolean, dirsVisited: number}>}
 *   target = { kind: 'root-git'|'nested-git'|'bare-repo', gitDir, configPath, relPath }
 */
export async function discoverGitTargets(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? 24;
  const maxEntries = opts.maxEntries ?? 20000;
  const excludes = (opts.exclude ?? []).map(e => e.replace(/^\.\//, '').replace(/[\/\\]+$/, ''));
  const isExcluded = rel => excludes.some(e => rel === e || rel.startsWith(e + '/'));

  const targets = [];
  let dirsVisited = 0;
  let truncated = false;

  const rootGitDir = path.join(root, '.git');
  const rootIsRepo = existsSync(path.join(rootGitDir, 'config'));
  if (rootIsRepo) {
    targets.push({ kind: 'root-git', gitDir: rootGitDir, configPath: path.join(rootGitDir, 'config'), relPath: '.git' });
  } else if (await isBareRepo(root)) {
    targets.push({ kind: 'bare-repo', gitDir: root, configPath: path.join(root, 'config'), relPath: '.' });
  }

  const queue = [{ dir: root, depth: 0 }];
  while (queue.length) {
    if (dirsVisited >= maxEntries) { truncated = true; break; }
    const { dir, depth } = queue.shift();
    if (depth > maxDepth) { truncated = true; continue; }
    dirsVisited++;

    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory is not a finding, just not scannable
    }

    for (const entry of entries) {
      if (entry.isFile() && entry.name === '.git') {
        const target = await resolveGitFile(path.join(dir, entry.name), root);
        if (target && existsSync(path.join(target, 'config'))) {
          const trel = (path.relative(root, target) || '.').split(path.sep).join('/');
          if (!targets.some(t => t.gitDir === target)) {
            targets.push({ kind: 'linked-git', gitDir: target, configPath: path.join(target, 'config'), relPath: trel });
          }
        }
        continue;
      }
      if (!entry.isDirectory()) continue;      // isDirectory() is false for symlinks: they are skipped by design
      const full = path.join(dir, entry.name);
      const rel = (path.relative(root, full) || '.').split(path.sep).join('/');
      if (ALWAYS_SKIP.has(entry.name)) continue;
      if (isExcluded(rel)) continue;

      if (entry.name === '.git') {
        if (full !== rootGitDir && existsSync(path.join(full, 'config'))) {
          targets.push({ kind: 'nested-git', gitDir: full, configPath: path.join(full, 'config'), relPath: rel });
        }
        continue; // never descend into a .git directory
      }

      if (await isBareRepo(full)) {
        targets.push({ kind: 'bare-repo', gitDir: full, configPath: path.join(full, 'config'), relPath: rel });
        continue; // do not walk the object store
      }

      queue.push({ dir: full, depth: depth + 1 });
    }
  }

  return { targets, truncated, dirsVisited };
}

export async function pathExists(p) {
  try { await stat(p); return true; } catch { return false; }
}
