// Finds every git configuration a coding agent could pick up under a path:
// the project's own .git, nested .git directories that arrived as content, the
// .git *file* a submodule or linked worktree leaves behind, and any bare
// repository hidden in the tree (the CVE-2026-45033 vector).
//
// Read-only, and deliberately so. The walk never follows symlinks, and it never
// writes - not even a probe file, which is why case sensitivity is detected by
// reading rather than by creating something.

import { readdir, stat, lstat, readFile, realpath } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';

const ALWAYS_SKIP = new Set(['.terraform', '.venv', '__pycache__']);

/** Windows ignores trailing spaces and dots in path names; git there does not see them. */
function normaliseName(name) {
  return name.replace(/[ .]+$/, '').toLowerCase();
}

export function looksLikeGitName(name) {
  return normaliseName(name) === '.git';
}

/**
 * Decide whether the scanned volume is case-insensitive, without writing anything.
 *
 * The usual probe creates a file in two cases and compares. That breaks the one
 * guarantee this tool sells. Inodes are no better: st_ino is the least reliable
 * field on Windows, and a probe that cannot decide there and then assumes
 * "case-sensitive" fails open on exactly the platform the finding comes from.
 *
 * So: take a name the directory already has, flip its case, and try to stat it.
 * Undecidable in every candidate means we assume case-insensitive, which produces
 * more findings, never fewer.
 */
export async function probeCaseInsensitive(root) {
  let entries;
  try {
    entries = await readdir(root);
  } catch {
    return true;
  }
  const present = new Set(entries);
  for (const name of entries) {
    if (!/[A-Za-z]/.test(name)) continue;
    const flipped = [...name]
      .map(ch => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()))
      .join('');
    if (flipped === name || present.has(flipped)) continue; // both cases exist: tells us nothing
    try {
      await stat(path.join(root, flipped));
      return true;   // the flipped name resolves, so the volume folds case
    } catch (err) {
      if (err.code === 'ENOENT') return false;
      // EACCES or anything else: undecidable, try the next candidate
    }
  }
  return true;
}

async function isBareRepo(dir) {
  // git's is_git_directory() also wants refs/, but creating an empty refs/ costs
  // an attacker nothing, so requiring it would only buy false negatives.
  return (
    existsSync(path.join(dir, 'HEAD')) &&
    existsSync(path.join(dir, 'config')) &&
    existsSync(path.join(dir, 'objects'))
  );
}

/**
 * Is this path safe to read as config? A config file must be a regular file that
 * is not a symlink and whose resolved path stays inside the scanned tree.
 * Returns { ok } or { ok: false, reason }.
 */
export async function safeToRead(file, root) {
  let info;
  try {
    info = await lstat(file);
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  if (info.isSymbolicLink()) return { ok: false, reason: 'symlink' };
  if (!info.isFile()) return { ok: false, reason: 'not-a-file' };
  try {
    const real = await realpath(file);
    const rel = path.relative(await realpath(root), real);
    if (rel.startsWith('..') || path.isAbsolute(rel)) return { ok: false, reason: 'outside-tree' };
  } catch {
    return { ok: false, reason: 'unreadable' };
  }
  return { ok: true };
}

/** Every config file git reads for one git directory. */
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
 * @returns {Promise<{targets: Array, truncated: boolean, dirsVisited: number, caseInsensitive: boolean, caseVariants: Array}>}
 *   target.kind = 'root-git' | 'nested-git' | 'bare-repo' | 'linked-git'
 */
export async function discoverGitTargets(root, opts = {}) {
  const maxDepth = opts.maxDepth ?? 24;
  const maxEntries = opts.maxEntries ?? 20000;
  const excludes = (opts.exclude ?? []).map(e => e.replace(/^\.\//, '').replace(/[/\\]+$/, ''));
  const isExcluded = rel => excludes.some(e => rel === e || rel.startsWith(e + '/'));
  const caseInsensitive = opts.caseInsensitive ?? await probeCaseInsensitive(root);

  const targets = [];
  const caseVariants = [];
  let dirsVisited = 0;
  let truncated = false;

  const rootGitDir = path.join(root, '.git');
  if (existsSync(path.join(rootGitDir, 'config'))) {
    targets.push({ kind: 'root-git', gitDir: rootGitDir, relPath: '.git' });
  } else if (await isBareRepo(root)) {
    targets.push({ kind: 'bare-repo', gitDir: root, relPath: '.' });
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
      continue; // an unreadable directory is not a finding, just not scannable
    }

    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      const rel = (path.relative(root, full) || '.').split(path.sep).join('/');
      if (isExcluded(rel)) continue;

      if (entry.isFile() && looksLikeGitName(entry.name)) {
        const target = await resolveGitFile(full, root);
        if (target && existsSync(path.join(target, 'config')) && !targets.some(t => t.gitDir === target)) {
          const trel = (path.relative(root, target) || '.').split(path.sep).join('/');
          targets.push({ kind: 'linked-git', gitDir: target, relPath: trel });
        }
        continue;
      }

      if (!entry.isDirectory()) continue;   // isDirectory() is false for symlinks: skipped by design
      if (ALWAYS_SKIP.has(entry.name)) continue;

      if (looksLikeGitName(entry.name)) {
        const exact = entry.name === '.git';
        if (!exact && !caseInsensitive) {
          // git here does not treat this as a git directory; on Windows and macOS it does.
          caseVariants.push({ relPath: rel, name: entry.name });
        }
        if ((exact || caseInsensitive) && full !== rootGitDir && existsSync(path.join(full, 'config'))) {
          targets.push({ kind: 'nested-git', gitDir: full, relPath: rel });
        }
        if (!exact && !caseInsensitive && existsSync(path.join(full, 'config'))) {
          targets.push({ kind: 'nested-git', gitDir: full, relPath: rel, caseVariant: true });
        }
        continue; // never descend into a git directory
      }

      if (await isBareRepo(full)) {
        targets.push({ kind: 'bare-repo', gitDir: full, relPath: rel });
        continue; // do not walk the object store
      }

      queue.push({ dir: full, depth: depth + 1 });
    }
  }

  return { targets, truncated, dirsVisited, caseInsensitive, caseVariants };
}
