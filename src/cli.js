// Library half of the CLI: argument parsing, the scan, the four end states.
// It exports run() and does nothing on import - bin/guardskill.js is the program.
import path from 'node:path';
import { writeFile, stat } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { loadRules, scan, statusOf, exitCodeFor } from './scanners/gitconfig.js';
import { formatText, formatMarkdown, formatJson, formatSarif } from './report/formatter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_PATH = path.join(__dirname, '..', 'rules', 'git-exec-keys.json');
const PKG_PATH = path.join(__dirname, '..', 'package.json');
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

// Read once, synchronously, so the error path can name the version too: an error
// document that says version "0" is harder to act on than the failure it reports.
export const VERSION = (() => {
  try { return JSON.parse(readFileSync(PKG_PATH, 'utf-8')).version; } catch { return '0'; }
})();
export const DEFAULT_MAX_DEPTH = 24;

// CLEAN 0 · FINDINGS 1 · ERROR 2 · INCOMPLETE 3
export const EXIT = { CLEAN: 0, FINDINGS: 1, ERROR: 2, INCOMPLETE: 3 };

const HELP = `GuardSkill - scans a project for git settings that make a coding agent run code.

Usage
  npx guardskill [path] [options]
  npx guardskill scan [path] [options]

Options
  --json                 machine-readable output
  --sarif                SARIF 2.1.0 on stdout, for a code-scanning upload
  --sarif-out <file>     also write SARIF to <file>, alongside the readable report
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

GuardSkill only reads the project it inspects. The only files it writes are the
reports you ask for with --out and --sarif-out. It never executes anything it
finds.`;

class UsageError extends Error {}

// Remembered so an error can still answer in the shape the caller asked for.
let jsonRequested = false;
export function errorDocument(message, version = VERSION) {
  return JSON.stringify({
    tool: 'guardskill', version, schemaVersion: 1, path: null, status: 'ERROR',
    scanned: false, reason: message, targetCount: 0, dirsVisited: 0, truncated: false,
    incompleteReasons: [], summary: {}, findings: [],
  }, null, 2);
}
export const wantsJson = () => jsonRequested;

export function parseArgs(argv) {
  const args = {
    target: null, out: null, json: false, sarif: false, sarifOut: null, failOn: 'high',
    maxDepth: DEFAULT_MAX_DEPTH, color: true, exclude: [], allowIncomplete: false,
  };
  const rest = argv[0] === 'scan' ? argv.slice(1) : argv;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--json') args.json = true;
    else if (a === '--sarif') args.sarif = true;
    else if (a === '--sarif-out') args.sarifOut = rest[++i];
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
  if (args.sarifOut === undefined) throw new UsageError('--sarif-out needs a file name');
  if (args.json && args.sarif) throw new UsageError('--json and --sarif both write to stdout; pick one, or use --sarif-out');
  return args;
}

export async function run() {
  const argv = process.argv.slice(2);
  if (argv.includes('-h') || argv.includes('--help')) { console.log(HELP); return EXIT.CLEAN; }

  if (argv.includes('-v') || argv.includes('--version')) { console.log(VERSION); return EXIT.CLEAN; }

  const args = parseArgs(argv);
  const target = path.resolve(args.target);
  jsonRequested = args.json;

  try {
    const info = await stat(target);
    if (!info.isDirectory()) throw new UsageError(`not a directory: ${args.target}`);
  } catch (err) {
    if (err instanceof UsageError) throw err;
    throw new UsageError(`cannot read path: ${args.target} (${err.code ?? err.message})`);
  }

  const ruleset = await loadRules(RULES_PATH);
  const result = await scan(target, ruleset, { maxDepth: args.maxDepth, exclude: args.exclude });

  const status = statusOf(result);
  const code = exitCodeFor(result, args.failOn, args.allowIncomplete);

  if (args.json) console.log(formatJson(result, VERSION, status));
  else if (args.sarif) console.log(formatSarif(result, VERSION));
  else console.log(formatText(result, { color: args.color && process.stdout.isTTY }));

  if (args.sarifOut) {
    await writeFile(args.sarifOut, formatSarif(result, VERSION), 'utf-8');
    if (!args.json && !args.sarif) console.log(`\nSARIF report written to ${args.sarifOut}`);
  }

  if (args.out) {
    await writeFile(args.out, formatMarkdown(result), 'utf-8');
    if (!args.json) console.log(`\nMarkdown report written to ${args.out}`);
  }

  return code;
}
