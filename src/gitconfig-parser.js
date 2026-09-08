// Minimal .git/config (INI-style) parser. No dependencies on purpose: a security
// scanner should not pull a supply chain of its own.
//
// Handles: [section], [section "subsection"], key = value, quoted values,
// comments, and line continuations ending in a backslash.

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
    // verbatim, leading whitespace included. Trimming it here produced a value
    // git never sees (found by the golden table).
    while (line.endsWith('\\') && i + 1 < lines.length) {
      line = line.slice(0, -1) + lines[++i].replace(/\s+$/, '');
    }

    const kv = line.match(/^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$/);
    if (!kv || section === null) continue;

    const key = kv[1].toLowerCase();
    let value = (kv[2] ?? 'true').trim();

    // strip trailing inline comment when it is not inside quotes
    if (!value.startsWith('"')) {
      const hash = value.search(/\s[#;]/);
      if (hash !== -1) value = value.slice(0, hash).trim();
    }
    if (value.length > 1 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).replace(/\\(.)/g, '$1');
    } else {
      // Outside quotes git records a tab as a plain space (verified against
      // git 2.43 in the golden table). Keeping the tab produced a value git
      // never reads.
      value = value.replace(/\t/g, ' ');
    }

    entries.push({ section, subsection, key, value, line: lineNumber });
  }

  return entries;
}
