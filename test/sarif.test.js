// SARIF is the second published surface, after the exit code. GitHub reads it
// and turns each finding into a row in the repository's Security tab, so the
// shape has to be right for a consumer that is not a person reading a terminal.
//
// Two properties matter beyond "valid JSON". `security-severity` is what GitHub
// sorts and filters on, so it must track our own severity rather than a number
// somebody invented. And an incomplete scan has to stay visible: a Security tab
// that says "no more findings" about a tree half of which was never opened is
// the same fail-open this project keeps closing, one surface further out.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, writeFile, rm, readFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { formatSarif } from '../src/report/formatter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'bin', 'guardskill.js');
const WORK = path.join(__dirname, 'fixtures', '.sarif');

const cli = args => new Promise(resolve => {
  execFile(process.execPath, [CLI, ...args], { maxBuffer: 64 * 1024 * 1024 },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
});

async function repo(name, config, extra = {}) {
  const dir = path.join(WORK, name);
  await rm(dir, { recursive: true, force: true });
  await mkdir(path.join(dir, '.git'), { recursive: true });
  await writeFile(path.join(dir, '.git', 'config'), config);
  for (const [rel, content] of Object.entries(extra)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

const CLEAN = '[core]\n\trepositoryformatversion = 0\n';
const VULNERABLE = '[core]\n\trepositoryformatversion = 0\n\tfsmonitor = /tmp/payload.sh\n';

test('--sarif emits a document GitHub code scanning accepts', async () => {
  const dir = await repo('findings', VULNERABLE);
  const { stdout, code } = await cli([dir, '--sarif']);
  assert.equal(code, 1, 'the exit code is unchanged by the output format');

  const doc = JSON.parse(stdout);
  assert.equal(doc.version, '2.1.0');
  assert.match(doc.$schema, /sarif-2\.1\.0/);
  assert.equal(doc.runs.length, 1);

  const run = doc.runs[0];
  assert.equal(run.tool.driver.name, 'GuardSkill');
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf-8'));
  assert.equal(run.tool.driver.semanticVersion, pkg.version,
    'the SARIF run must name the version that produced it');

  assert.ok(run.results.length > 0);
  for (const result of run.results) {
    assert.ok(run.tool.driver.rules[result.ruleIndex],
      `ruleIndex ${result.ruleIndex} does not point at a rule; GitHub drops results whose index is wrong`);
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
    const loc = result.locations[0].physicalLocation.artifactLocation;
    assert.ok(loc.uri && !loc.uri.startsWith('/') && !loc.uri.includes('\\'),
      `a SARIF uri must be relative and use forward slashes, got ${JSON.stringify(loc.uri)}`);
    assert.equal(loc.uriBaseId, undefined,
      'an undeclared uriBaseId is rejected on upload; the uris here are already relative');
    assert.ok(result.partialFingerprints?.guardskill,
      'without a fingerprint GitHub cannot tell the same finding from a new one between runs');
  }
});

test('security-severity follows our severity, and is not invented', async () => {
  // GitHub sorts the Security tab on this number. It has to mean something, and
  // the only thing it can honestly mean here is our own four levels: GuardSkill
  // computes no CVSS score, so filling the field from one would be a claim.
  const severities = ['critical', 'high', 'medium', 'low'];
  const expected = { critical: ['9.0', 'error'], high: ['7.0', 'error'], medium: ['5.0', 'warning'], low: ['3.0', 'note'] };

  const fake = {
    rootPath: '/x', scanned: true, targetCount: 1, dirsVisited: 1, truncated: false,
    incompleteReasons: [],
    findings: severities.map(severity => ({
      ruleId: `rule-${severity}`, severity, title: `T ${severity}`, explanation: 'E',
      remediation: 'R', location: `file-${severity}.txt:7`, evidence: 'V',
    })),
  };
  const run = JSON.parse(formatSarif(fake, '9.9.9')).runs[0];

  for (const severity of severities) {
    const rule = run.tool.driver.rules.find(r => r.id === `rule-${severity}`);
    const [score, level] = expected[severity];
    assert.equal(rule.properties['security-severity'], score, `security-severity for ${severity}`);
    assert.equal(rule.defaultConfiguration.level, level, `level for ${severity}`);
    assert.equal(rule.properties.guardskillSeverity, severity,
      'the original severity must survive, so a consumer is not stuck with the four SARIF levels');
  }
  const region = run.results[0].locations[0].physicalLocation.region;
  assert.equal(region.startLine, 7, 'a "file:line" location must become a region GitHub can anchor to');
});

test('an incomplete scan stays visible in SARIF', async () => {
  const dir = await repo('deep', CLEAN);
  let p = dir;
  for (let i = 0; i < 6; i++) p = path.join(p, `l${i}`);
  await mkdir(p, { recursive: true });

  const { stdout, code } = await cli([dir, '--max-depth', '2', '--sarif']);
  assert.equal(code, 3);
  const run = JSON.parse(stdout).runs[0];
  const notes = run.invocations[0].toolExecutionNotifications ?? [];
  assert.ok(notes.length > 0,
    'a truncated walk must appear in the SARIF run; a Security tab that shows nothing about it reads as "all clear"');
  assert.match(notes[0].message.text, /not inspected/i);
});

test('--sarif-out writes the file while the readable report still goes to the terminal', async () => {
  const dir = await repo('both', VULNERABLE);
  const out = path.join(WORK, 'out.sarif');
  const { stdout, code } = await cli([dir, '--sarif-out', out, '--no-color']);

  assert.equal(code, 1);
  assert.match(stdout, /\[CRITICAL\]/, 'the human-readable report must still be printed');
  assert.match(stdout, /SARIF report written to/);
  const doc = JSON.parse(await readFile(out, 'utf-8'));
  assert.equal(doc.runs[0].results.length, JSON.parse((await cli([dir, '--sarif'])).stdout).runs[0].results.length,
    'the file and the stdout document must describe the same scan');
});

test('--json and --sarif refuse to share stdout', async () => {
  const dir = await repo('conflict', CLEAN);
  const { code, stderr } = await cli([dir, '--json', '--sarif']);
  assert.equal(code, 2, 'two formats on one stream is a usage error, not a silent winner');
  assert.match(stderr, /pick one/);
});

test('a clean scan produces an empty result list, not an empty file', async () => {
  const dir = await repo('clean', CLEAN);
  const { stdout, code } = await cli([dir, '--sarif']);
  assert.equal(code, 0);
  const run = JSON.parse(stdout).runs[0];
  assert.deepEqual(run.results, []);
  assert.equal(run.invocations[0].executionSuccessful, true);
});

test.after(async () => { await rm(WORK, { recursive: true, force: true }); });
