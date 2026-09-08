#!/usr/bin/env node
// The published entry point, and deliberately nothing else.
//
// v0.4.0-rc1 decided whether to run by comparing import.meta.url with
// process.argv[1]. npm installs the bin as a symlink on Linux and macOS, so those
// two are never equal there: `npx guardskill` printed nothing and exited 0. On a
// security scanner, silence plus exit 0 reads as "clean". (review 02, N-1)
//
// A separate file removes the question. This one always runs; src/cli.js never
// does anything on import.
import { run, EXIT, errorDocument, wantsJson } from '../src/cli.js';

run()
  .then(code => { process.exitCode = code; })
  .catch(err => {
    // An error answers in the shape the caller asked for: a consumer parsing
    // --json should not have to special-case a plain-text failure.
    if (wantsJson()) console.log(errorDocument(err.message));
    console.error(`guardskill: ${err.message}`);
    process.exitCode = EXIT.ERROR;
  });
