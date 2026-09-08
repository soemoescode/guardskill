// The parser measured against git itself.
//
// git is the only valid oracle for "what does git read from this file", but it is
// not a test-time dependency: tools/generate-golden.mjs ran it once, offline, and
// the answers are committed. No child_process here, and none in src/.
//
// Where the parser deliberately differs, the difference is named in DELIBERATE
// below with the reason it falls towards the safe side. An undeclared difference
// fails the suite.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { parseGitConfig } from '../src/gitconfig-parser.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const GOLDEN = path.join(__dirname, 'fixtures', 'gitconfig-golden.json');

// case name -> why our value differs from git's, and why that is the safe side.
// One entry left, and it is a rendering difference rather than a parsing one.
// Review 02 (N-2) replaced the three-stage value handling with a single pass that
// carries quote state, and that made the other four declarations disappear: the
// parser now agrees with git 2.43 on every value in the table, including the
// sixteen quote-position cases the sweep added.
const DELIBERATE = {
  'implicit-true':
    'A valueless key. `git config --list` prints the key with no value; git treats it as boolean true, ' +
    'and so do we, because a rule has to evaluate something. The difference is in how the listing renders ' +
    'it, not in what git reads.',
};

function ours(configText) {
  return parseGitConfig(configText).map(e =>
    `${e.section}${e.subsection ? '.' + e.subsection : ''}.${e.key}=${e.value}`);
}

test('the parser agrees with git, or declares why it does not', async () => {
  const golden = JSON.parse(await readFile(GOLDEN, 'utf-8'));
  assert.ok(Object.keys(golden.cases).length >= 23,
    `the golden table must keep at least the 23 differential cases from review 01, found ${Object.keys(golden.cases).length}`);

  const undeclared = [];
  const staleDeclarations = [];

  for (const [name, c] of Object.entries(golden.cases)) {
    if (c.gitError) continue; // git refuses it; no oracle, covered by the robustness suite
    const mine = ours(c.config);
    const same = JSON.stringify(mine) === JSON.stringify(c.git);
    if (!same && !DELIBERATE[name]) undeclared.push({ name, git: c.git, ours: mine });
    if (same && DELIBERATE[name]) staleDeclarations.push(name);
  }

  assert.deepEqual(undeclared, [],
    `the parser differs from git on cases that are not declared as deliberate:\n${JSON.stringify(undeclared, null, 2)}`);
  assert.deepEqual(staleDeclarations, [],
    `these cases now agree with git; remove them from DELIBERATE: ${staleDeclarations.join(', ')}`);
});

test('every value git accepts is at least seen by the parser', async () => {
  const golden = JSON.parse(await readFile(GOLDEN, 'utf-8'));
  const missing = [];
  for (const [name, c] of Object.entries(golden.cases)) {
    if (c.gitError || !c.git?.length) continue;
    const mine = ours(c.config);
    for (const line of c.git) {
      const key = line.split('=')[0];
      if (!mine.some(m => m.startsWith(key + '='))) missing.push(`${name}: ${key}`);
    }
  }
  assert.deepEqual(missing, [],
    `git reads these keys and the parser does not produce them at all - that is a detection gap, not a formatting one:\n${missing.join('\n')}`);
});

test('the golden table records which git produced it', async () => {
  const golden = JSON.parse(await readFile(GOLDEN, 'utf-8'));
  assert.match(golden._git, /^git version \d+\.\d+/, 'the table must name the git version it was generated with');
  assert.ok(golden._generated, 'the table must carry a generation date');
  assert.ok(golden._note.join(' ').includes('malformed'),
    'the table must state that malformed configs have no oracle here');
});
