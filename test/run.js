// Cross-platform test runner.
//
// `node --test ./test/*.test.js` looks portable but is not: cmd.exe and
// PowerShell do not expand globs, so on Windows the literal pattern reaches
// node and the run fails. Pointing `--test` at the directory is no better,
// because everything under test/ is treated as a test file, fixtures included.
// So we resolve the files ourselves and hand node an explicit list.

import { readdir } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const testDir = path.dirname(fileURLToPath(import.meta.url));
const entries = await readdir(testDir, { withFileTypes: true });
const files = entries
  .filter(e => e.isFile() && e.name.endsWith('.test.js'))
  .map(e => path.join(testDir, e.name))
  .sort();

if (files.length === 0) {
  console.error('no test files found in', testDir);
  process.exit(1);
}

spawn(process.execPath, ['--test', ...files], { stdio: 'inherit' })
  .on('exit', code => process.exit(code ?? 1));
