// Prints one version's section from CHANGELOG.md, for the release workflow.
//
// Release notes that are typed into a web form once and never again are how a
// repository ends up with five published versions and one release object. The
// notes already exist - they are the changelog entry - so the release job reads
// them from there rather than asking a person to retype them at the end of an
// otherwise automated pipeline.
//
//   node tools/changelog-section.mjs 0.5.3 [path]

import { readFile } from 'node:fs/promises';

export function sectionFor(changelog, version) {
  const lines = changelog.split('\n');
  const head = lines.findIndex(l => new RegExp(`^##\\s+${version.replace(/\./g, '\\.')}(\\s|$|—|-)`).test(l));
  if (head === -1) return null;
  const rest = lines.slice(head + 1);
  const next = rest.findIndex(l => /^##\s/.test(l));
  return rest.slice(0, next === -1 ? rest.length : next).join('\n').trim();
}

const invokedDirectly = process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop());
if (invokedDirectly) {
  const version = process.argv[2];
  if (!version) { console.error('usage: changelog-section.mjs <version> [changelog path]'); process.exit(2); }
  const text = await readFile(process.argv[3] ?? 'CHANGELOG.md', 'utf-8');
  const section = sectionFor(text, version);
  if (!section) {
    console.error(`changelog-section: no section for ${version} in the changelog`);
    process.exit(1);
  }
  console.log(section);
}
