// The GitHub Action is a second published artefact, and it can drift from the
// first. Its default `version:` input decides which npm version a Marketplace
// user actually runs: forget to bump it on release and every consumer silently
// keeps scanning with the old rules while the Marketplace listing says the new
// tag. That is the same failure shape as review 02's N-1 — a published entry
// point nobody tested — one layer out.
//
// No YAML parser: a security scanner with no dependencies does not gain one to
// read six fields out of its own manifest.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

const action = async () => readFile(path.join(ROOT, 'action.yml'), 'utf-8');

test('the Action runs the version this repository publishes', async () => {
  const yml = await action();
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf-8'));

  const block = yml.match(/\n {2}version:\n(?: {4}.*\n)+/);
  assert.ok(block, 'action.yml must declare a `version` input');
  const declared = block[0].match(/default:\s*'([^']+)'/);
  assert.ok(declared, 'the `version` input must have a quoted default');

  assert.equal(declared[1], pkg.version,
    `action.yml pins guardskill@${declared[1]} while this repository is ${pkg.version}. ` +
    'Bump the default in the same commit as the version, or Marketplace users keep running the old rules.');
});

test('the Action passes inputs through the environment, never by interpolation', async () => {
  const yml = await action();
  const run = yml.slice(yml.indexOf('run: |'))
    .split('\n').filter(l => !l.trim().startsWith('#')).join('\n');   // the comment names the anti-pattern

  // ${{ inputs.* }} inside the script body is a shell injection: the input is
  // substituted before bash sees the line. In the env: block it is a value.
  const interpolated = run.match(/\$\{\{\s*(inputs|github|env)\./g) ?? [];
  assert.deepEqual(interpolated, [],
    `the run script interpolates workflow expressions directly: ${interpolated.join(', ')} - ` +
    'pass them through env: and read them as "$VAR" instead');

  assert.match(run, /set -euo pipefail/, 'the script must fail loudly');
  assert.match(run, /npx --yes/, 'the script must install the published package, not a checkout');
  assert.match(run, /--ignore-scripts/,
    'this action installs a package into other people\'s CI: a lifecycle script must never run');
});

test('the Action validates the inputs that reach a command line', async () => {
  const yml = await action();
  for (const [input, guard] of [['fail-on', /case "\$GS_FAIL_ON"/], ['version', /case "\$GS_VERSION"/]]) {
    assert.match(yml, guard,
      `the "${input}" input reaches an argument list and must be checked against a fixed set first`);
  }
});
