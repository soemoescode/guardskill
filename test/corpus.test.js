// Real-world corpus.
//
// The synthetic fixtures prove the rules do what they say. They cannot prove the
// severities are usable, because they were written by the same person who wrote
// the rules. This corpus is the check on that: five shapes a user is likely to
// scan, and a hard ceiling on what they may produce.
//
// Review 01 found eight criticals on one real repository. That is what this test
// exists to prevent, and it would have found it first.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadRules, scan } from '../src/scanners/gitconfig.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES = path.join(__dirname, '..', 'rules', 'git-exec-keys.json');
const CORPUS = path.join(__dirname, 'corpus', 'corpus.json');
const WORK = path.join(__dirname, 'fixtures', '.corpus');

async function materialise(name, spec) {
  const dir = path.join(WORK, name);
  await rm(dir, { recursive: true, force: true });
  for (const [rel, content] of Object.entries(spec.files)) {
    const file = path.join(dir, rel);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, content, 'utf-8');
  }
  return dir;
}

test('no corpus repository produces a critical finding', async () => {
  const corpus = JSON.parse(await readFile(CORPUS, 'utf-8'));
  const rules = await loadRules(RULES);
  assert.ok(Object.keys(corpus).length >= 3, 'the corpus must hold at least three repositories');

  const offenders = [];
  for (const [name, spec] of Object.entries(corpus)) {
    const r = await scan(await materialise(name, spec), rules);
    const criticals = r.findings.filter(f => f.severity === 'critical');
    if (criticals.length) offenders.push({ name, criticals: criticals.map(f => `${f.ruleId} @ ${f.location}`) });
  }
  assert.deepEqual(offenders, [],
    `a repository people actually have produced a critical:\n${JSON.stringify(offenders, null, 2)}`);
});

test('no corpus repository produces an unexplained high finding', async () => {
  const corpus = JSON.parse(await readFile(CORPUS, 'utf-8'));
  const rules = await loadRules(RULES);
  const unexpected = [];
  for (const [name, spec] of Object.entries(corpus)) {
    const r = await scan(await materialise(name, spec), rules);
    const highs = r.findings.filter(f => f.severity === 'high');
    if (highs.length > (spec.expect.high ?? 0)) {
      unexpected.push({ name, expected: spec.expect.high ?? 0, got: highs.map(f => `${f.ruleId}: ${f.evidence}`) });
    }
  }
  assert.deepEqual(unexpected, [],
    `highs beyond what PROVENANCE.md declares:\n${JSON.stringify(unexpected, null, 2)}`);
});

test('the git-lfs shape still reports its checked-in repositories, just not as critical', async () => {
  const corpus = JSON.parse(await readFile(CORPUS, 'utf-8'));
  const rules = await loadRules(RULES);
  const r = await scan(await materialise('git-lfs-shaped', corpus['git-lfs-shaped']), rules);
  const bare = r.findings.filter(f => f.ruleId === 'bare-repo-in-tree');
  assert.equal(bare.length, 8, 'the checked-in repositories must still be reported');
  assert.ok(bare.every(f => f.severity === 'medium'), 'without an execution key they are medium, not critical');
});

test('PROVENANCE.md documents every fixture and is honest about how they were made', async () => {
  const corpus = JSON.parse(await readFile(CORPUS, 'utf-8'));
  const text = await readFile(path.join(__dirname, 'corpus', 'PROVENANCE.md'), 'utf-8');
  for (const name of Object.keys(corpus)) {
    assert.ok(text.includes(name), `PROVENANCE.md does not mention the fixture "${name}"`);
  }
  assert.match(text, /reconstruction/i,
    'PROVENANCE.md must say plainly how these fixtures were produced');
});

test.after(async () => { await rm(WORK, { recursive: true, force: true }); });
