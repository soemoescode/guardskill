// Documentation is a claim surface. This suite keeps it honest in both
// directions: the properties the docs promise are asserted here, and every test
// name SECURITY.md points at has to exist.
//
// Review 01 found six documented claims the code did not make true. The fix is
// not better proofreading; it is a test that fails when they drift apart.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

async function sourceFiles(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...await sourceFiles(full));
    else if (e.name.endsWith('.js')) out.push(full);
  }
  return out;
}

test('src/ contains no process-spawning code', async () => {
  // Covers the "never executes anything" and "no network, no telemetry" claims in
  // one assertion: neither is possible without one of these.
  const forbidden = [
    /require\(\s*['"]child_process['"]/, /from\s+['"]node:child_process['"]/,
    /\bexecSync\b/, /\bexecFile\b/, /\bspawn\b/, /\bfork\(/,
    /from\s+['"]node:(http|https|net|dgram|tls)['"]/, /\bfetch\s*\(/, /XMLHttpRequest/,
  ];
  const offenders = [];
  for (const file of await sourceFiles(path.join(ROOT, 'src'))) {
    const text = await readFile(file, 'utf-8');
    text.split('\n').forEach((line, i) => {
      if (line.trim().startsWith('//')) return;
      for (const re of forbidden) {
        if (re.test(line)) offenders.push(`${path.relative(ROOT, file)}:${i + 1}: ${line.trim()}`);
      }
    });
  }
  assert.deepEqual(offenders, [],
    `src/ must not be able to execute or connect out:\n${offenders.join('\n')}`);
});

test('no runtime dependencies', async () => {
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf-8'));
  assert.deepEqual(pkg.dependencies ?? {}, {}, 'a scanner that installs a supply chain of its own is a contradiction');
  assert.deepEqual(pkg.optionalDependencies ?? {}, {});
});

test('package metadata carries no placeholder', async () => {
  const pkg = await readFile(path.join(ROOT, 'package.json'), 'utf-8');
  assert.ok(!/REPLACE_|<your|TODO/i.test(pkg), 'package.json still contains a placeholder');
  const parsed = JSON.parse(pkg);
  assert.match(parsed.repository.url, /soemoescode\/guardskill/);
  assert.equal(parsed.version, JSON.parse(pkg).version);
});

test('every test SECURITY.md points at actually exists', async () => {
  const security = await readFile(path.join(ROOT, 'SECURITY.md'), 'utf-8');
  const rows = security.split('\n').filter(l => l.startsWith('|') && l.split('|').length >= 4);

  const names = new Set();
  for (const file of await readdir(__dirname)) {
    if (!file.endsWith('.test.js')) continue;
    const text = await readFile(path.join(__dirname, file), 'utf-8');
    for (const m of text.matchAll(/^test\(\s*'([^']+)'/gm)) names.add(m[1]);
  }

  const missing = [];
  for (const row of rows) {
    const cells = row.split('|').map(c => c.trim());
    const testCell = cells[cells.length - 2] ?? '';
    for (const m of testCell.matchAll(/`([^`]+)`/g)) {
      const claimed = m[1];
      if (!/[a-z].*\s/.test(claimed)) continue;   // not a test name, e.g. a file path
      if (!names.has(claimed)) missing.push(claimed);
    }
  }
  assert.deepEqual(missing, [],
    `SECURITY.md points at tests that do not exist - either write them or drop the claim:\n${missing.join('\n')}`);
});

test('the documented claim table covers the README claims that matter', async () => {
  const security = await readFile(path.join(ROOT, 'SECURITY.md'), 'utf-8');
  for (const phrase of [
    'never modifies the project', 'does not follow symlinks', 'incomplete walk',
    'default traversal depth is 24', 'schemaVersion', 'cannot be rewritten by its subject',
  ]) {
    assert.ok(security.includes(phrase), `the claim table is missing a row about: ${phrase}`);
  }
});

test('the README does not claim to cover a whole vulnerability class while keys are out of scope', async () => {
  const readme = await readFile(path.join(ROOT, 'README.md'), 'utf-8');
  const inventory = await readFile(path.join(ROOT, 'rules', 'git-exec-keys-inventory.md'), 'utf-8');
  const hasOutOfScope = /\|\s*out-of-scope\s*\|/.test(inventory);
  if (!hasOutOfScope) return;                        // nothing out of scope: the broad claim would be fair
  assert.ok(!/covers the GitSpawn class/i.test(readme),
    'while the inventory lists keys as out-of-scope, the README must list what it checks instead of claiming the class');
  assert.ok(/out of scope/i.test(readme),
    'the README must say that some keys are deliberately out of scope, and point at the inventory');
});

test('accepted residual risks are written down publicly', async () => {
  const security = await readFile(path.join(ROOT, 'SECURITY.md'), 'utf-8');
  assert.match(security, /## Accepted residual risk/,
    'an accepted risk that is not in the public documentation is concealed, not accepted');
  for (const phrase of ['out of scope', 'reconstructed', 'not a probe', 'not inspected']) {
    assert.ok(security.toLowerCase().includes(phrase.toLowerCase()),
      `the residual-risk section does not mention: ${phrase}`);
  }
});
