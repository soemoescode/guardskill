import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadRules, scan } from '../src/scanners/gitconfig.js';
import { EXPECTATIONS } from './fixtures/generate.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES = path.join(__dirname, '..', 'rules', 'git-exec-keys.json');
const CLEAN = path.join(__dirname, 'fixtures', 'clean');
const VULN = path.join(__dirname, 'fixtures', 'vulnerable');

const dirs = async d => (await readdir(d, { withFileTypes: true })).filter(e => e.isDirectory()).map(e => e.name);

test('no medium-or-higher finding on any clean fixture', async () => {
  const rules = await loadRules(RULES);
  const names = await dirs(CLEAN);
  assert.ok(names.length >= 25, `expected >=25 clean fixtures, found ${names.length}`);
  const fp = [];
  for (const name of names) {
    const r = await scan(path.join(CLEAN, name), rules);
    const notable = r.findings.filter(f => f.severity !== 'low');
    if (notable.length) fp.push({ name, findings: notable.map(f => `${f.ruleId} :: ${f.evidence}`) });
  }
  assert.deepEqual(fp, [], `false positives: ${JSON.stringify(fp, null, 2)}`);
});

test('husky and .githooks projects produce at most informational findings', async () => {
  const rules = await loadRules(RULES);
  for (const name of ['husky-project', 'githooks-convention']) {
    const r = await scan(path.join(CLEAN, name), rules);
    assert.ok(r.findings.every(f => f.severity === 'low'), `${name}: ${JSON.stringify(r.findings)}`);
  }
});

test('a repository-shipped hooks directory that pulls remote code is critical', async () => {
  const rules = await loadRules(RULES);
  const r = await scan(path.join(VULN, 'hookspath-fetches-remote'), rules);
  assert.ok(r.findings.some(f => f.ruleId === 'hook-fetches-remote-code' && f.severity === 'critical'),
    JSON.stringify(r.findings, null, 2));
});

test('every vulnerable fixture is detected', async () => {
  const rules = await loadRules(RULES);
  const names = await dirs(VULN);
  assert.ok(names.length >= 18, `expected >=18 vulnerable fixtures, found ${names.length}`);
  const missed = [];
  for (const name of names) {
    const r = await scan(path.join(VULN, name), rules);
    if (!r.findings.length) missed.push(name);
  }
  assert.deepEqual(missed, [], `missed: ${missed.join(', ')}`);
});

test('each vulnerable fixture is detected by the rule it was written for', async () => {
  const rules = await loadRules(RULES);
  const wrong = [];
  for (const [name, expected] of Object.entries(EXPECTATIONS)) {
    const r = await scan(path.join(VULN, name), rules);
    if (!r.findings.some(f => f.ruleId === expected)) {
      wrong.push({ name, expected, got: r.findings.map(f => f.ruleId) });
    }
  }
  assert.deepEqual(wrong, [], `rule mismatch: ${JSON.stringify(wrong, null, 2)}`);
});

test('a bare repository hidden in the tree is reported as critical', async () => {
  const rules = await loadRules(RULES);
  const r = await scan(path.join(VULN, 'bare-repo-in-tree'), rules);
  const f = r.findings.find(x => x.ruleId === 'bare-repo-in-tree');
  assert.ok(f, 'bare repo not detected');
  assert.equal(f.severity, 'critical');
  assert.ok(r.findings.some(x => x.ruleId === 'core-fsmonitor'), 'config inside the bare repo was not scanned');
});

test('an unregistered nested .git is reported, a registered submodule is not', async () => {
  const rules = await loadRules(RULES);
  const bad = await scan(path.join(VULN, 'nested-git-dir'), rules);
  assert.ok(bad.findings.some(f => f.ruleId === 'nested-git-dir'));

  const good = await scan(path.join(CLEAN, 'registered-submodule'), rules);
  assert.equal(good.findings.length, 0, JSON.stringify(good.findings));
});

test('a directory without any git data is reported as not scanned', async () => {
  const rules = await loadRules(RULES);
  const r = await scan(path.join(__dirname, 'fixtures'), rules, { maxDepth: 0 });
  assert.equal(r.scanned, false);
});

test('git-lfs and git-crypt filters are never flagged', async () => {
  const rules = await loadRules(RULES);
  for (const name of ['git-lfs', 'git-crypt-filter']) {
    const r = await scan(path.join(CLEAN, name), rules);
    assert.equal(r.findings.length, 0, `${name}: ${JSON.stringify(r.findings)}`);
  }
});

test('the scanner never follows symlinks out of the target', async t => {
  const { discoverGitTargets } = await import('../src/discovery.js');
  const { symlink, mkdir, writeFile, rm, lstat } = await import('node:fs/promises');
  const tmp = path.join(__dirname, 'fixtures', '.symlink-case');

  // Start from nothing. A leftover directory from an earlier run - or a filesystem
  // that materialises a symlink as a real directory, which a Windows share does -
  // would otherwise fail this test for a reason that has nothing to do with the
  // scanner. A flaky test in a security suite is worse than no test: it teaches
  // people to ignore a red run.
  await rm(tmp, { recursive: true, force: true });
  await mkdir(path.join(tmp, 'inside', '.git'), { recursive: true });
  await writeFile(path.join(tmp, 'inside', '.git', 'config'), '[core]\n', 'utf-8');

  const link = path.join(tmp, 'link');
  try {
    await symlink(path.join(VULN, 'bare-repo-in-tree'), link, 'dir');
  } catch (err) {
    // Never a silent pass: a run that could not create a symlink says so, so the
    // CI output shows on which platform this guarantee went untested (F-16).
    return t.skip(`platform cannot create a symlink (${err.code}) - this guarantee is UNTESTED here`);
  }
  if (!(await lstat(link)).isSymbolicLink()) {
    return t.skip('the file system materialised the symlink as a real directory - this guarantee is UNTESTED here');
  }

  const { targets } = await discoverGitTargets(tmp);
  assert.ok(!targets.some(t => t.relPath.startsWith('link')), 'scanner followed a symlink');
  await rm(tmp, { recursive: true, force: true });
});

test('--exclude keeps a directory out of the walk', async () => {
  const rules = await loadRules(RULES);
  const withFixtures = await scan(path.join(__dirname, '..'), rules, { exclude: [] });
  const without = await scan(path.join(__dirname, '..'), rules, { exclude: ['test/fixtures'] });
  assert.ok(withFixtures.findings.length > 0, 'expected the fixture tree to produce findings');
  assert.equal(without.findings.length, 0, JSON.stringify(without.findings.slice(0, 3), null, 2));
});
