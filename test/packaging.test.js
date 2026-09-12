// The published artefact.
//
// Review 02 (N-1) found that `guardskill` installed from the registry printed
// nothing and exited 0: the CLI guarded its own execution with
// `import.meta.url === pathToFileURL(process.argv[1])`, and npm's bin symlink
// makes those two differ. Every functional test passed, because every functional
// test ran the file by path.
//
// So this suite does not run the repository. It packs it the way `npm publish`
// does, installs the tarball into a throwaway directory, and drives the binary
// npm put on the PATH. It is the only test that touches what a user gets.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdir, mkdtemp, writeFile, rm, readFile, readdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const WIN = process.platform === 'win32';

// npm is a .cmd shim on Windows, which execFile cannot start without a shell.
// The scanner binary lands as .cmd there too. Both are handled here rather than
// by skipping the test on the platform where the packaging differs most.
const run = (file, args, opts = {}) => new Promise(resolve => {
  // With shell:true the arguments go through cmd.exe, so a path containing a
  // space would split into two. Quote them there, and only there.
  const argv = WIN ? args.map(a => (/[\s"]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a)) : args;
  const target = WIN && /[\s"]/.test(file) ? `"${file}"` : file;
  execFile(target, argv, { maxBuffer: 64 * 1024 * 1024, windowsHide: true, shell: WIN, ...opts },
    (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
});
const npm = (args, opts) => run(WIN ? 'npm.cmd' : 'npm', args, opts);

let work, installed, cli, contents;

test('the tarball npm publish would upload contains the entry point', async t => {
  work = await mkdtemp(path.join(os.tmpdir(), 'guardskill-pack-'));

  const packed = await npm(['pack', '--pack-destination', work, '--loglevel', 'error'], { cwd: ROOT });
  assert.equal(packed.code, 0, `npm pack failed:\n${packed.stderr}`);

  const tarballs = (await readdir(work)).filter(f => f.endsWith('.tgz'));
  assert.equal(tarballs.length, 1, `expected one tarball, got ${JSON.stringify(tarballs)}`);
  const tarball = path.join(work, tarballs[0]);

  // Read the manifest out of the archive itself, not out of the source tree:
  // `files` in package.json is a claim, the tarball is the fact.
  const listed = await run('tar', ['-tzf', tarball]);
  assert.equal(listed.code, 0, `could not list the tarball:\n${listed.stderr}`);
  contents = listed.stdout.split('\n').map(l => l.trim().replace(/^package\//, '')).filter(Boolean);
  for (const required of ['bin/guardskill.js', 'src/cli.js', 'rules/git-exec-keys.json', 'package.json']) {
    assert.ok(contents.includes(required), `the tarball is missing ${required}:\n${contents.join('\n')}`);
  }

  installed = path.join(work, 'consumer');
  await mkdir(installed, { recursive: true });
  await writeFile(path.join(installed, 'package.json'),
    JSON.stringify({ name: 'guardskill-smoke', version: '1.0.0', private: true }, null, 2));

  const install = await npm(['install', tarball, '--no-audit', '--no-fund', '--ignore-scripts',
    '--no-package-lock', '--loglevel', 'error'], { cwd: installed });
  assert.equal(install.code, 0, `installing the tarball failed:\n${install.stderr}`);

  cli = path.join(installed, 'node_modules', '.bin', WIN ? 'guardskill.cmd' : 'guardskill');
});

test('the installed binary prints its version and exits 0', async () => {
  assert.ok(cli, 'the pack step did not complete');
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf-8'));

  const { code, stdout, stderr } = await run(cli, ['--version']);
  assert.equal(stdout.trim(), pkg.version,
    `the installed binary printed ${JSON.stringify(stdout)} instead of the version (stderr: ${stderr.trim()})`);
  assert.equal(code, 0);
});

test('the installed binary finds a real finding and exits 1', async () => {
  assert.ok(cli, 'the pack step did not complete');
  const victim = path.join(work, 'victim');
  await mkdir(path.join(victim, '.git'), { recursive: true });
  await writeFile(path.join(victim, '.git', 'config'),
    '[core]\n\trepositoryformatversion = 0\n\tfsmonitor = /tmp/payload.sh\n');

  const text = await run(cli, [victim, '--no-color']);
  assert.equal(text.code, 1, `expected exit 1 from the installed binary, got ${text.code}:\n${text.stdout}${text.stderr}`);
  assert.match(text.stdout, /fsmonitor/i, 'the finding is missing from the human-readable report');

  const json = await run(cli, [victim, '--json']);
  assert.equal(json.code, 1);
  const doc = JSON.parse(json.stdout);
  assert.equal(doc.tool, 'guardskill');
  assert.equal(doc.status, 'FINDINGS');
  assert.ok(doc.findings.some(f => f.ruleId === 'core-fsmonitor'),
    `the installed binary did not report core-fsmonitor: ${JSON.stringify(doc.findings.map(f => f.ruleId))}`);
});

test('the installed binary exits 0 on a clean repository', async () => {
  assert.ok(cli, 'the pack step did not complete');
  const clean = path.join(work, 'clean');
  await mkdir(path.join(clean, '.git'), { recursive: true });
  await writeFile(path.join(clean, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n');

  const { code, stdout } = await run(cli, [clean, '--no-color']);
  assert.equal(code, 0, `a clean scan through the installed binary must exit 0:\n${stdout}`);
});

test('the tarball ships nothing nobody meant to ship', async () => {
  // `files` in package.json is an allowlist of directories, so anything that
  // lands inside one of them travels to every user. A Word owner-lock file
  // (`~$...`) written next to a .md someone opened in Word made it into
  // rules/ exactly this way, and would have been published inside a security
  // tool's rule directory. `git add -A` does not know what is junk; this does.
  assert.ok(contents, 'the pack step did not complete');

  const allowedRoots = new Set(['bin', 'src', 'rules', 'package.json',
    'SKILL.md', 'README.md', 'SECURITY.md', 'CHANGELOG.md', 'LICENSE']);

  const junk = [];
  for (const entry of contents) {
    const [root] = entry.split('/');
    if (!allowedRoots.has(root)) junk.push(`${entry} (unexpected top-level "${root}")`);
    if (/(^|\/)~\$/.test(entry)) junk.push(`${entry} (editor lock file)`);
    if (/\s/.test(entry)) junk.push(`${entry} (path contains whitespace)`);
    if (/(^|\/)\.(DS_Store|env)/.test(entry)) junk.push(`${entry} (local artefact)`);
  }
  assert.deepEqual(junk, [],
    `these files would be published to every user of this package:\n${junk.join('\n')}`);

  // rules/ is read by the scanner and audited by the inventory test. Nothing
  // else belongs in it.
  const shipped = new Set([
    'rules/git-exec-keys.json', 'rules/git-exec-keys-inventory.md',
    'rules/agent-settings-keys.json', 'rules/agent-settings-inventory.md',
  ]);
  const strayRules = contents.filter(e => e.startsWith('rules/') && !shipped.has(e));
  assert.deepEqual(strayRules, [], `unexpected files in rules/: ${strayRules.join(', ')}`);

  // The rule files are not documentation: the scanner loads both at startup and
  // refuses to run without them, so leaving one out of `files` would ship a
  // package that cannot scan.
  for (const required of shipped) {
    assert.ok(contents.includes(required), `the tarball is missing ${required}, which the scanner loads at startup`);
  }
});

test.after(async () => { if (work) await rm(work, { recursive: true, force: true }); });
