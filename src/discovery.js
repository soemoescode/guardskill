// Finds every git configuration that a coding agent could pick up under a path:
// the project's own .git, any nested .git directories that arrived as content,
// and any bare repository hidden in the tree (the CVE-2026-45033 vector).
//
// Read-only. Never follows symlinks — a scanner must not be walked out of its
// own target directory by a link the attacker controls.

import { readdir, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const ALWAYS_SKIP = new Set(['node_modules/.cache', '.terraform', '.venv', '__pycache__']);

async function isBareRepo(dir) {
  return (
    existsSync(path.join(dir, 'HEAD')) &&
    existsSync(path.join(dir, 'config')) &&
    existsSync(path.join(dir, 'objects')) &&
    existsSync(path.join(dir, 'refs'))
  );
}

/**
 * @param {string} root absolute path to scan
 * @param {{maxDepth?: number, maxEntries?: number}} opts
 * @returns {Promise<{targets: Array, truncated: boolean, dirsVisited: number}>}
 *   target = { kind: 'root-git'|'nested-git'|'bare-repo', gitDir, configPath, relPath }
 */
export async function discoverGitTargets(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? 8;
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
