// Is the rule set complete? This test cannot answer that - nothing can - but it
// makes the answer auditable. rules/git-exec-keys-inventory.md lists every git
// key known to run a command, each one either covered by a named rule or
// out-of-scope with a reason. Drift in either direction fails here, so a gap
// becomes visible rather than forgotten.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadRules } from '../src/scanners/gitconfig.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const RULES = path.join(ROOT, 'rules', 'git-exec-keys.json');
const INVENTORY = path.join(ROOT, 'rules', 'git-exec-keys-inventory.md');

async function inventory() {
  const text = await readFile(INVENTORY, 'utf-8');
  const rows = text.split('\n')
    .filter(l => l.startsWith('|') && !/^\|\s*-+/.test(l) && !/^\|\s*Key\s*\|/.test(l) && !/^\|\s*Check\s*\|/.test(l))
    .map(l => l.split('|').slice(1, -1).map(c => c.trim()));
  const keys = rows.filter(r => r.length === 4).map(([key, runsWhen, status, note]) => ({ key, runsWhen, status, note }));
  const structural = rows.filter(r => r.length === 2).map(([check, rule]) => ({ check, rule: rule.replace(/`/g, '') }));
  return { keys, structural, gitVersion: (text.match(/git \d+\.\d+\.\d+/) || [])[0] };
}

const ruleIdsIn = note => [...note.matchAll(/`([a-z0-9-]+)`/g)].map(m => m[1]);

test('every key marked covered names a rule that exists', async () => {
  const { keys } = await inventory();
  const rules = await loadRules(RULES);
  const known = new Set(rules.rules.map(r => r.id));
  const broken = [];
  for (const row of keys) {
    if (row.status !== 'covered') continue;
    for (const id of ruleIdsIn(row.note)) {
      if (!known.has(id)) broken.push(`${row.key} -> ${id}`);
    }
    if (ruleIdsIn(row.note).length === 0) broken.push(`${row.key} -> (no rule named)`);
  }
  assert.deepEqual(broken, [], `inventory claims coverage that does not exist:\n${broken.join('\n')}`);
});

test('every rule in the ruleset appears in the inventory', async () => {
  const { keys, structural } = await inventory();
  const rules = await loadRules(RULES);
  const mentioned = new Set([
    ...keys.flatMap(r => ruleIdsIn(r.note)),
    ...structural.map(s => s.rule),
  ]);
  const orphans = rules.rules.map(r => r.id).filter(id => !mentioned.has(id));
  assert.deepEqual(orphans, [],
    `these rules exist but are not listed in the inventory, so nobody can tell what they cover:\n${orphans.join('\n')}`);
});

test('every structural rule appears in the inventory', async () => {
  const { structural } = await inventory();
  const rules = await loadRules(RULES);
  const listed = new Set(structural.map(s => s.rule));
  const orphans = rules.structural.map(r => r.id).filter(id => !listed.has(id));
  assert.deepEqual(orphans, [], `structural rules missing from the inventory: ${orphans.join(', ')}`);
});

test('every out-of-scope key carries a reason', async () => {
  const { keys } = await inventory();
  const bare = keys.filter(r => r.status === 'out-of-scope' && r.note.length < 30).map(r => r.key);
  assert.deepEqual(bare, [],
    `out-of-scope without a real reason is a gap in disguise: ${bare.join(', ')}`);
});

test('the inventory names the git version it was checked against', async () => {
  const { gitVersion } = await inventory();
  assert.ok(gitVersion, 'the inventory must state which git version it was checked against');
});
