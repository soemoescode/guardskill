// The release pipeline is a published surface too. It decides what reaches npm,
// what the Marketplace listing shows, and which job holds which permission.
//
// No YAML parser: the same reason the Action test has none. These are a handful
// of structural facts about one file, and a scanner with no dependencies does
// not take one on to read its own workflow.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { sectionFor } from '../tools/changelog-section.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const workflow = async () =>
  (await readFile(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf-8')).replace(/\r\n/g, '\n');

/**
 * The lines of one job, from its key to the next key at the same indent.
 *
 * Line by line rather than by regex over the whole file: the first version
 * searched for the next job header from the start of the block and ran straight
 * past it into the following job, so `publish` appeared to carry the permissions
 * of `release-object`. A test that reads the wrong half of a file is worse than
 * no test, because it is green for the wrong reason exactly as often as it is
 * red for one.
 */
function jobBlock(yml, name) {
  const lines = yml.split('\n');
  const isJobHeader = l => /^ {2}[a-z][a-z0-9-]*:\s*$/.test(l);
  const start = lines.findIndex(l => l === `  ${name}:`);
  if (start === -1) return null;
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (isJobHeader(lines[i])) break;
    // Comments are dropped: the block above release-object explains, in prose,
    // why `contents: write` is not in the publish job - and a test that reads
    // that sentence as a permission would fail on the very comment that says the
    // permission is absent.
    if (lines[i].trim().startsWith('#')) continue;
    out.push(lines[i]);
  }
  return out.join('\n');
}

test('the job that can write to the repository is not the job that publishes', async () => {
  // The tags are what npm's provenance attestations are anchored to. A job that
  // can rewrite them and also holds the OIDC token npm trusts is one mistake
  // away from being able to publish something and then point the tag at it.
  const yml = await workflow();

  const publish = jobBlock(yml, 'publish');
  assert.ok(publish, 'the publish job must exist');
  assert.match(publish, /id-token: write/, 'publish needs OIDC for provenance');
  assert.ok(!/contents: write/.test(publish),
    'publish must not be able to write to the repository');

  const release = jobBlock(yml, 'release-object');
  assert.ok(release, 'the release-object job must exist');
  assert.match(release, /contents: write/, 'creating a release needs write access');
  assert.ok(!/id-token/.test(release),
    'the job that can write to the repository must not hold the publishing token');
  assert.match(release, /needs: publish/,
    'a release object for a version that failed to publish points at nothing');
});

test('the release workflow only ever runs on a version tag', async () => {
  const yml = await workflow();
  assert.match(yml, /on:\n\s+push:\n\s+tags:/, 'tag-only');
  assert.ok(!/pull_request/.test(yml),
    'a pull request from a fork must never reach the publishing job');
  assert.match(yml, /v\[0-9\]\+\.\[0-9\]\+\.\[0-9\]\+/,
    'the pattern must match a release tag and not a release-candidate tag');
});

test('the release notes come from the changelog, and the changelog has a section for this version', async () => {
  // Release notes typed into a web form once are how a repository ends up with
  // five published versions and one release object. This keeps them in the file
  // that is written anyway - and fails here if that file has no entry.
  const yml = await workflow();
  assert.match(yml, /changelog-section\.mjs/, 'the workflow must read the notes from the changelog');

  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf-8'));
  const changelog = await readFile(path.join(ROOT, 'CHANGELOG.md'), 'utf-8');
  const section = sectionFor(changelog, pkg.version);

  assert.ok(section, `CHANGELOG.md has no "## ${pkg.version}" section; the release job would have nothing to publish`);
  assert.ok(section.length > 80, `the section for ${pkg.version} is ${section.length} characters - that is not release notes`);
  assert.ok(!/^##\s/m.test(section), 'the extracted section must stop at the next version heading');
});

test('the changelog extractor takes exactly one section', async () => {
  const sample = [
    '# Changelog', '',
    '## 2.0.0 — 2026-01-02', '', 'Second thing.', '',
    '## 1.0.0 — 2026-01-01', '', 'First thing.', '',
  ].join('\n');

  assert.equal(sectionFor(sample, '2.0.0'), 'Second thing.');
  assert.equal(sectionFor(sample, '1.0.0'), 'First thing.');
  assert.equal(sectionFor(sample, '3.0.0'), null, 'an unknown version must be null, not the whole file');
  assert.equal(sectionFor(sample, '1.0'), null, 'a partial version must not match a longer one');
});
