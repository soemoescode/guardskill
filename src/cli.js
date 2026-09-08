#!/usr/bin/env node
import path from 'node:path';
import { writeFile, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { loadRules, scan } from './scanners/gitconfig.js';
import { formatText, formatMarkdown, formatJson } from './report/formatter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RULES_PATH = path.join(__dirname, '..', 'rules', 'git-exec-keys.json');
const PKG_PATH = path.join(__dirname, '..', 'package.json');
const SEVERITIES = ['critical', 'high', 'medium', 'low'];

const HELP = `GuardSkill - scans a project for git settings that make a coding agent run code.

Usage
  npx guardskill [path] [options]
  npx guardskill scan [path] [options]

Options
  --json                 machine-readable output
  --out <file>           also write a Markdown report to <file>
  --fail-on <severity>   exit 1 from this severity up (default: high)
  --exclude <path>       skip this directory (repeatable, relative to the scanned path)
  --max-depth <n>        directory depth to walk (default: 8)
  --no-color             plain output
  -v, --version          print version
  -h, --help             this text

Exit codes
  0  no findings at or above --fail-on
  1  findings at or above --fail-on
  2  the scan itself failed

GuardSkill only reads. It never writes to the project it scans and never
executes anything it finds.`;

function parseArgs(argv) {
  const args = { target: '.', out: null, json: false, failOn: 'high', maxDepth: 8, color: true, exclude: [] };
  const rest = argv[0] === 'scan' ? argv.slice(1) : argv;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--json') args.json = true;
    else if (a === '--no-color') args.color = false;
    else if (a === '--out' || a === '-o') args.out = rest[++i];
    else if (a === '--fail-on') args.failOn = String(rest[++i] || '').toLowerCase();
    else if (a === '--exclude') args.exclude.push(String(rest[++i] || ''));
    else if (a === '--max-depth') args.maxDepth = Number(rest[++i]);
    else if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
    else args.target = a;
  }
  if (!SEVERITIES.includes(args.failOn)) throw new Error(`--fail-on must be one of ${SEVERITIES.join(', ')}`);
  if (!Number.isInteger(args.maxDepth) || args.maxDepth < 0) throw new Error('--max-depth must be a non-negative integer');
  return args;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('-h') || argv.includes('--help')) { console.log(HELP); return 0; }

  const pkg = JSON.parse(await readFile(PKG_PATH, 'utf-8'));
  if (argv.includes('-v') || argv.includes('--version')) { console.log(pkg.version); return 0; }

  const args = parseArgs(argv);
  const target = path.resolve(args.target);
  const ruleset = await loadRules(RULES_PATH);
  const result = await scan(target, ruleset, { maxDepth: args.maxDepth, exclude: args.exclude });

  if (args.json) console.log(formatJson(result, pkg.version));
  else console.log(formatText(result, { color: args.color && process.stdout.isTTY }));

  if (args.out) {
    await writeFile(args.out, formatMarkdown(result), 'utf-8');
    if (!args.json) console.log(`\nMarkdown report written to ${args.out}`);
  }

  const threshold = SEVERITIES.indexOf(args.failOn);
  return result.findings.some(f => SEVERITIES.indexOf(f.severity) <= threshold) ? 1 : 0;
}

main()
  .then(code => process.exit(code))
  .catch(err => { console.error(`guardskill: ${err.message}`); process.exit(2); });
