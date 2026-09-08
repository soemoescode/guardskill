# Security policy

## Reporting a vulnerability

Report security issues privately through GitHub's "Report a vulnerability" flow on this repository, or by email to the maintainer address listed on https://helios-it.nl. Please do not open a public issue for an unpatched problem.

We aim to acknowledge a report within three working days.

## Threat model for GuardSkill itself

GuardSkill runs on directories that are, by assumption, untrusted. It is built for that:

- **It only reads.** No file in the scanned project is created, modified or deleted. The single exception is the `--out` file you ask for by name.
- **It never executes anything it finds.** Values from `.git/config` and hook scripts are treated as text and printed as evidence, never run, never passed to a shell.
- **It does not follow symlinks.** Directory traversal skips symbolic links, so a link inside a hostile repository cannot walk the scanner out of its target.
- **No network access.** GuardSkill makes no outbound connections and sends no telemetry. It behaves identically offline.
- **No dependencies.** The package has no runtime dependencies, so installing it does not pull in a supply chain of its own.
- **Bounded traversal.** Depth and entry count are capped (`--max-depth`) so a deep or generated tree cannot exhaust the process.

If you find a way to make GuardSkill write, execute, connect out, or escape its target directory, that is a vulnerability in this tool and we want to hear about it.
