#!/usr/bin/env node
import path from 'node:path';
import { writeFile, readFile, stat } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { loadRules, scan, statusOf } from './scanners/gitconfig.js';
import { formatText, formatMarkdown, formatJson } from './report/formatter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_PATH = path.join(__dirname, '..', 'rules', 'git-exec-keys.json');
const PKG_PATH = path.join(__dirname, '..', 'package.json');
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const DEFAULT_MAX_DEPTH = 24;

// CLEAN 0 · FINDINGS 1 · ERROR 2 · INCOMPLETE 3
const EXIT = { CLEAN: 0, FINDINGS: 1, ERROR: 2, INCOMPLETE: 3 };

const HELP = `GuardSkill - scans a project for git settings that make a coding agent run code.

Usage
  npx guardskill [path] [options]
  npx guardskill scan [path] [options]

Options
  --json                 machine-readable output
  --out <file>           also write a Markdown report to <file>
  --fail-on <severity>   report FINDINGS from this severity up (default: high)
  --allow-incomplete     do not fail when part of the tree could not be inspected
  --exclude <path>       skip this directory (repeatable, relative to the scanned path)
  --max-depth <n>        directory depth to walk (default: ${DEFAULT_MAX_DEPTH})
  --no-color             plain output
  -v, --version          print version
  -h, --help             this text

Exit codes
  0  CLEAN       nothing at or above --fail-on, and the whole tree was inspected
  1  FINDINGS    findings at or above --fail-on
  2  ERROR       the scan could not run: bad path, bad options, invalid ruleset
  3  INCOMPLETE  part of the tree was not inspected; use --allow-incomplete to accept that

GuardSkill only reads the project it inspects. The only file it writes is the
report you ask for with --out. It never executes anything it finds.`;

class UsageError extends Error {}

export function parseArgs(argv) {
  const args = {
    target: null, out: null, json: false, failOn: 'high',
    maxDepth: DEFAULT_MAX_DEPTH, color: true, exclude: [], allowIncomplete: false,
  };
  const rest = argv[0] === 'scan' ? argv.slice(1) : argv;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--json') args.json = true;
    else if (a === '--no-color') args.color = false;
    else if (a === '--allow-incomplete') args.allowIncomplete = true;
    else if (a === '--out' || a === '-o') args.out = rest[++i];
    else if (a === '--fail-on') args.failOn = String(rest[++i] ?? '').toLowerCase();
    else if (a === '--exclude') args.exclude.push(String(rest[++i] ?? ''));
    else if (a === '--max-depth') args.maxDepth = Number(rest[++i]);
    else if (a.startsWith('-')) throw new UsageError(`unknown option: ${a}`);
    else if (args.target !== null) throw new UsageError(`only one path can be scanned at a time (got "${args.target}" and "${a}")`);
    else args.target = a;
  }
  if (args.target === null) args.target = '.';
  if (!SEVERITIES.includes(args.failOn)) throw new UsageError(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
  if (!Number.isInteger(args.maxDepth) || args.maxDepth < 0) throw new UsageError('--max-depth must be a non-negative integer');
  if (args.out === undefined) throw new UsageError('--out needs a file name');
  return args;
}

async function run() {
  const argv = process.argv.slice(2);
  if (argv.includes('-h') || argv.includes('--help')) { console.log(HELP); return EXIT.CLEAN; }

  const pkg = JSON.parse(await readFile(PKG_PATH, 'utf-8'));
  if (argv.includes('-v') || argv.includes('--version')) { console.log(pkg.version); return EXIT.CLEAN; }

  const args = parseArgs(argv);
  const target = path.resolve(args.target);

  try {
    const info = await stat(target);
    if (!info.isDirectory()) throw new UsageError(`not a directory: ${args.target}`);
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(`cannot read path: ${args.target} (${err.code ?? err.message})`);
  }

  const ruleset = await loadRules(RULES_PATH);
  const result = await scan(target, ruleset, { maxDepth: args.maxDepth, exclude: args.exclude });

  let status = statusOf(result, args.failOn);
  if (status === 'INCOMPLETE' && args.allowIncomplete) status = 'CLEAN';

  if (args.json) console.log(formatJson(result, pkg.version, status));
  else console.log(formatText(result, { color: args.color && process.stdout.isTTY }));

  if (args.out) {
    await writeFile(args.out, formatMarkdown(result), 'utf-8');
    if (!args.json) console.log(`\nMarkdown report written to ${args.out}`);
  }

  return EXIT[status];
}

// No process.exit() on any path that has written to stdout. Node's own docs are
// explicit: writes to stdout can be asynchronous, and exiting immediately after
// one truncates it. Through a pipe that cut used to land at exactly 64 KB, in
// the middle of the JSON, with the exit code still saying success.
// Only run when this file *is* the program. Importing it (the contract test does,
// to compare the help text against the real default) must not start a scan and
// must not touch the importer's exit code.
const invokedDirectly = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  run()
    .then(code => { process.exitCode = code; })
    .catch(err => {
      console.error(`guardskill: ${err.message}`);
      process.exitCode = EXIT.ERROR;
    });
}
