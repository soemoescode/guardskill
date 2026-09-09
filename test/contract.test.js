// The output contract.
//
// From v0.4.0 other things depend on this: a CI step reads the exit code, a
// future hosted layer reads the JSON. Both are pinned here, and both are tested
// through the CLI rather than through scan(), because the bugs review 01 found
// (default depth, truncated stdout, exit 0 on a missing path) lived in the CLI
// and were invisible from the library.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'guardskill.js');
const WORK = path.join(__dirname, 'fixtures', '.contract');

const cli = (args, opts = {}) => new Promise(resolve => {
  execFile(process.execPath, [CLI, ...args], { maxBuffer: 64 * 1024 * 1024, ...opts },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
});

async function write(file, content) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, content);
}
async function repo(name, config) {
  const dir = path.join(WORK, name);
  await rm(dir, { recursive: true, force: true });
  await write(path.join(dir, '.git', 'config'), config);
  return dir;
}

const CLEAN = '[core]\n\trepositoryformatversion = 0\n';

test('exit codes: CLEAN 0, FINDINGS 1, ERROR 2, INCOMPLETE 3', async () => {
  const clean = await repo('clean', CLEAN);
  assert.equal((await cli([clean, '--no-color'])).code, 0, 'a clean repository must exit 0');

  const findings = await repo('findings', '[core]\n\tfsmonitor = /tmp/payload.sh\n');
  assert.equal((await cli([findings, '--no-color'])).code, 1, 'a finding at the threshold must exit 1');

  assert.equal((await cli([path.join(WORK, 'does-not-exist'), '--no-color'])).code, 2, 'a missing path must exit 2');
  assert.equal((await cli([clean, '--fail-on', 'nonsense'])).code, 2, 'a bad option value must exit 2');
  assert.equal((await cli([clean, '--not-an-option'])).code, 2, 'an unknown option must exit 2');
  assert.equal((await cli([clean, clean])).code, 2, 'a second positional argument must exit 2, not silently win');

  const deep = await repo('deep', CLEAN);
  let p = deep;
  for (let i = 0; i < 6; i++) p = path.join(p, `l${i}`);
  await mkdir(p, { recursive: true });
  assert.equal((await cli([deep, '--max-depth', '2', '--no-color'])).code, 3, 'an incomplete walk must exit 3');
  assert.equal((await cli([deep, '--max-depth', '2', '--allow-incomplete', '--no-color'])).code, 0,
    '--allow-incomplete must turn that into a pass, deliberately');
});

test('--fail-on changes severity, never completeness', async () => {
  const medium = await repo('medium-only', '[init]\n\ttemplateDir = ./tpl\n');
  assert.equal((await cli([medium, '--no-color'])).code, 0, 'a medium finding is below the default threshold');
  assert.equal((await cli([medium, '--fail-on', 'medium', '--no-color'])).code, 1, 'lowering the threshold catches it');

  const deep = await repo('deep-b', CLEAN);
  let p = deep;
  for (let i = 0; i < 6; i++) p = path.join(p, `l${i}`);
  await mkdir(p, { recursive: true });
  assert.equal((await cli([deep, '--max-depth', '2', '--fail-on', 'critical', '--no-color'])).code, 3,
    'raising --fail-on must not hide an incomplete scan');
});

test('the JSON output matches the documented schema in all four states', async () => {
  const required = ['tool', 'version', 'schemaVersion', 'path', 'status', 'scanned', 'reason',
    'targetCount', 'dirsVisited', 'truncated', 'incompleteReasons', 'summary', 'findings'];

  const clean = await repo('json-clean', CLEAN);
  const findings = await repo('json-findings', '[core]\n\tfsmonitor = /tmp/payload.sh\n');
  const incomplete = await repo('json-incomplete', CLEAN);
  let p = incomplete;
  for (let i = 0; i < 6; i++) p = path.join(p, `l${i}`);
  await mkdir(p, { recursive: true });

  const cases = [
    ['CLEAN', [clean, '--json']],
    ['FINDINGS', [findings, '--json']],
    ['INCOMPLETE', [incomplete, '--max-depth', '2', '--json']],
  ];
  for (const [expected, args] of cases) {
    const { stdout } = await cli(args);
    const doc = JSON.parse(stdout);
    for (const field of required) {
      assert.ok(Object.hasOwn(doc, field), `${expected}: JSON is missing the required field "${field}"`);
    }
    assert.equal(doc.status, expected, `${expected}: status field`);
    assert.equal(doc.schemaVersion, 1);
    assert.equal(doc.tool, 'guardskill');
    for (const f of doc.findings) {
      for (const field of ['ruleId', 'severity', 'title', 'explanation', 'remediation', 'location', 'evidence']) {
        assert.ok(Object.hasOwn(f, field), `${expected}: finding is missing "${field}"`);
      }
    }
  }
});

test('--json survives a pipe above one megabyte', async () => {
  // process.exit() after a write to a pipe truncates it. This used to cut the
  // document at exactly 65,536 bytes, mid-string, with the exit code unchanged.
  const lines = ['[core]'];
  for (let i = 0; i < 3000; i++) lines.push(`\tsshCommand = /tmp/payload-with-a-long-enough-name-${String(i).padStart(5, '0')}.sh`);
  const dir = await repo('big-report', lines.join('\n') + '\n');

  const piped = await cli([dir, '--json']);            // execFile pipes stdout: the failing condition
  const file = path.join(WORK, 'big-report.json');
  await cli([dir, '--json'], {}).then(r => writeFile(file, r.stdout));

  assert.ok(piped.stdout.length > 1_000_000, `expected over 1 MB, got ${piped.stdout.length} bytes`);
  assert.doesNotThrow(() => JSON.parse(piped.stdout),
    `stdout was truncated at ${piped.stdout.length} bytes`);
  const onDisk = await readFile(file, 'utf-8');
  assert.equal(piped.stdout.length, onDisk.length, 'the piped output must be byte-identical in length to the same scan captured whole');
});

test('no source file calls process.exit after writing to stdout', async () => {
  // The static half of the same guarantee: a future edit that reintroduces
  // process.exit() in the CLI would pass every functional test above until the
  // output happens to cross a buffer boundary.
  const sources = (await Promise.all([CLI, path.join(ROOT, 'src', 'cli.js')].map(f => readFile(f, 'utf-8')))).join('\n');
  const offending = sources.split('\n')
    .map((line, i) => ({ line: line.trim(), n: i + 1 }))
    .filter(l => /process\.exit\s*\(/.test(l.line) && !l.line.startsWith('//'));
  assert.deepEqual(offending, [],
    `process.exit() in the CLI truncates buffered stdout; set process.exitCode instead:\n${JSON.stringify(offending)}`);
});

test('the help text states the same default depth the code uses', async () => {
  const { DEFAULT_MAX_DEPTH, parseArgs } = await import('../src/cli.js');
  const { stdout } = await cli(['--help']);
  const stated = stdout.match(/--max-depth <n>\s+directory depth to walk \(default: (\d+)\)/);
  assert.ok(stated, 'the help text must state a default depth');
  assert.equal(Number(stated[1]), DEFAULT_MAX_DEPTH, 'help text and constant disagree');
  assert.equal(parseArgs([]).maxDepth, DEFAULT_MAX_DEPTH, 'the parsed default disagrees with the constant');
  assert.equal(DEFAULT_MAX_DEPTH, 24, 'the documented default is 24');
});

test('a wide tree stays within its measured budget', async () => {
  // What this used to measure, and why it stopped a release.
  //
  // The fixture was three levels deep, so depth 8 and depth 24 walked exactly the
  // same directories -- the "depth ratio" compared two identical scans. The deep
  // one ran first, on a cold page cache, straight after 4,000 mkdir calls; the
  // shallow one ran second, warm. On a workstation both are fast and the ratio
  // sits near 1. On a loaded CI runner the first scan took 2,185 ms and the second
  // 391 ms, the ratio read 5.6x, and the assertion reported a depth regression
  // that did not exist. It was measuring cache warmth. (v0.4.1)
  //
  // Fixed by making the claim true: the tree is now deeper than the shallow limit
  // so the two depths really do differ, a warm-up scan absorbs the cold cache, and
  // the ratio carries a floor so a few hundred milliseconds of runner jitter
  // cannot look like a blow-up.
  const dir = await repo('wide', CLEAN);
  const mk = [];
  for (let i = 0; i < 4000; i++) mk.push(mkdir(path.join(dir, `pkg${i % 50}`, `sub${i}`, 'src'), { recursive: true }));
  // One genuinely deep branch, so depth 8 cannot reach what depth 24 reaches.
  mk.push(mkdir(path.join(dir, 'deep', ...Array.from({ length: 20 }, (_, i) => `l${i}`)), { recursive: true }));
  await Promise.all(mk);
  await write(path.join(dir, 'pkg7', 'sub7', '.git', 'config'), '[core]\n\tfsmonitor = /tmp/x.sh\n');

  const { loadRules, scan } = await import('../src/scanners/gitconfig.js');
  const rules = await loadRules(path.join(ROOT, 'rules', 'git-exec-keys.json'));

  await scan(dir, rules, { maxDepth: 24 });          // warm-up: not measured

  const before = process.memoryUsage().heapUsed;
  const t0 = Date.now();
  const deep = await scan(dir, rules, { maxDepth: 24 });
  const deepMs = Date.now() - t0;
  const heapMb = (process.memoryUsage().heapUsed - before) / 1024 / 1024;

  const t1 = Date.now();
  const shallow = await scan(dir, rules, { maxDepth: 8 });
  const shallowMs = Math.max(Date.now() - t1, 1);

  assert.ok(deep.findings.some(f => f.ruleId === 'core-fsmonitor'), 'the hidden repository must still be found');
  assert.ok(deep.dirsVisited > 4000, `expected a wide walk, visited ${deep.dirsVisited}`);

  // The non-timing half of the depth claim, and the durable one: depth has to
  // change what is reached. This fails on a machine of any speed.
  assert.ok(deep.dirsVisited > shallow.dirsVisited,
    `depth 24 reached ${deep.dirsVisited} directories and depth 8 reached ${shallow.dirsVisited} - ` +
    'the deep branch in the fixture is no longer deeper than the shallow limit, so the comparison below means nothing');

  assert.ok(deepMs < 10_000, `scan of ${deep.dirsVisited} directories took ${deepMs}ms`);
  assert.ok(heapMb < 200, `scan retained ${heapMb.toFixed(0)} MB of heap`);

  // Both scans now walk a warm tree, so they should land within a fraction of
  // each other. The floor keeps runner jitter on a sub-second measurement from
  // producing a large ratio out of two small numbers.
  const budget = Math.max(shallowMs * 4, 3_000);
  assert.ok(deepMs < budget,
    `depth 24 cost ${deepMs}ms against ${shallowMs}ms at depth 8 (budget ${budget}ms) - ` +
    'that is superlinear in depth, which the walk should not be');
});

test('status reports what was found; the exit code reports what was asked (N-4)', async () => {
  // These two used to be the same value, so a finding below the threshold was
  // reported as CLEAN: exit 0 is a policy answer ("nothing worth failing on"),
  // not an observation ("nothing there"). A consumer reading the JSON has to be
  // able to see the medium finding it chose not to fail on.
  const medium = await repo('status-medium', '[init]\n\ttemplateDir = ./tpl\n');

  const below = await cli([medium, '--json']);
  const doc = JSON.parse(below.stdout);
  assert.equal(below.code, 0, 'a medium finding is below the default threshold, so the exit code is 0');
  assert.equal(doc.status, 'FINDINGS', 'status must say a finding exists even when the exit code forgives it');
  assert.ok(doc.findings.length > 0, 'the finding itself must be in the document');

  const above = await cli([medium, '--fail-on', 'medium', '--json']);
  const raised = JSON.parse(above.stdout);
  assert.equal(above.code, 1, 'lowering the threshold turns the same scan into a failure');
  assert.equal(raised.status, 'FINDINGS', 'the status is unchanged: the repository did not change, the policy did');
  assert.deepEqual(raised.findings.map(f => f.ruleId), doc.findings.map(f => f.ruleId),
    '--fail-on must not filter the findings out of the report');

  // CLEAN is reserved for zero findings, and nothing else may claim it.
  const clean = JSON.parse((await cli([await repo('status-clean', CLEAN), '--json'])).stdout);
  assert.equal(clean.status, 'CLEAN');
  assert.equal(clean.findings.length, 0);
});

test('--json answers in JSON when it fails, too', async () => {
  // A consumer that pipes --json into a parser gets a parse error instead of a
  // diagnosis if the failure path prints prose. The error document carries the
  // same required fields, with status ERROR and the reason in `reason`.
  const missing = path.join(WORK, 'no-such-path');
  const { code, stdout, stderr } = await cli([missing, '--json']);

  assert.equal(code, 2, 'a missing path is still an ERROR');
  const doc = JSON.parse(stdout);
  assert.equal(doc.status, 'ERROR');
  assert.equal(doc.tool, 'guardskill');
  assert.equal(doc.schemaVersion, 1);
  assert.equal(doc.scanned, false);
  assert.ok(doc.reason && doc.reason.length > 0, 'the error document must say what went wrong');
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf-8'));
  assert.equal(doc.version, pkg.version, 'the error document must name the version that produced it');
  assert.deepEqual(doc.findings, [], 'a failed scan must not imply a clean tree by listing no findings without saying so');
  for (const field of ['tool', 'version', 'schemaVersion', 'path', 'status', 'scanned', 'reason',
    'targetCount', 'dirsVisited', 'truncated', 'incompleteReasons', 'summary', 'findings']) {
    assert.ok(Object.hasOwn(doc, field), `the error document is missing the required field "${field}"`);
  }
  assert.match(stderr, /guardskill:/, 'the human-readable reason still goes to stderr');
});

test.after(async () => { await rm(WORK, { recursive: true, force: true }); });
