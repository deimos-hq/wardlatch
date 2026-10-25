#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Deimos AI LLC
// Differential test corpus, part 1: builds realistic machine layouts (servers, developer laptops, CI runners, and bad
// machines that must still be caught) as folders under <outdir>. Each layout has its own fake HOME, its own --paths
// roots and a manifest.json that scripts/corpus/run.mjs reads.
//
//   node scripts/corpus/build.mjs <outdir>
//
// <outdir> must not exist yet, or be empty. Some folders are made unreadable (mode 000) on purpose; to delete a corpus:
//   chmod -R u+rwx <outdir> && rm -rf <outdir>
//
// Reproducible: git runs with no system or global config, a fixed author, committer and dates, so commit ids are the
// same on every build. Nothing here contacts a network host: every git URL is a local path.
// No secret appears in this file: the planted keys are assembled from parts at run time.
import { mkdirSync, writeFileSync, chmodSync, utimesSync, symlinkSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

const out = process.argv[2];
if (!out || process.argv.length > 3) { console.error('usage: node build.mjs <outdir>'); process.exit(2); }
const OUT = resolve(out);
if (existsSync(OUT) && readdirSync(OUT).length) { console.error(`${OUT} is not empty: build into a new folder`); process.exit(2); }
mkdirSync(OUT, { recursive: true });

// ---- helpers -------------------------------------------------------------------------------------------------------

const mk = (p) => { mkdirSync(p, { recursive: true }); return p; };
const write = (p, text) => { mk(dirname(p)); writeFileSync(p, text); return p; };
// before the corpus date (2026-09-01) of the workflows incident and the 18 Oct plugin date of the WordPress one
const OLD = '2026-03-02T10:00:00+00:00';
const NEW = '2026-09-15T12:00:00+00:00';
const OLD_TIME = new Date('2026-01-15T09:00:00Z');

// git with no system or global config, a fixed identity and fixed dates: the same commit ids on every build
const GIT_BASE_ENV = {
  PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C', HOME: mk(join(OUT, '.git-home')),
  GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
  GIT_AUTHOR_NAME: 'Corpus Builder', GIT_AUTHOR_EMAIL: 'builder@corpus.invalid',
  GIT_COMMITTER_NAME: 'Corpus Builder', GIT_COMMITTER_EMAIL: 'builder@corpus.invalid',
};
const GIT_ARGS = ['-c', 'init.defaultBranch=main', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
  '-c', 'protocol.file.allow=always', '-c', 'advice.detachedHead=false'];
const git = (cwd, args, date = OLD) => execFileSync('git', [...GIT_ARGS, ...args], {
  cwd, stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...GIT_BASE_ENV, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
}).toString();

/** A git repository at `dir` with `files` ({ relpath: text }) committed once (or `commits`: [{ files, date, msg }]). */
function repo(dir, files = {}, { date = OLD, commits } = {}) {
  mk(dir);
  git(dir, ['init', '-q']);
  for (const c of commits ?? [{ files, date, msg: 'initial commit' }]) {
    for (const [f, text] of Object.entries(c.files)) write(join(dir, f), text);
    git(dir, ['add', '-A'], c.date);
    git(dir, ['commit', '-q', '--allow-empty', '-m', c.msg ?? 'update'], c.date);
  }
  return dir;
}
const commit = (dir, files, msg, date = OLD, force = []) => {
  for (const [f, text] of Object.entries(files)) write(join(dir, f), text);
  git(dir, ['add', '-A'], date);
  if (force.length) git(dir, ['add', '-f', ...force], date);
  git(dir, ['commit', '-q', '-m', msg], date);
};

// modes applied at the very end, after every git add (git can't read a folder at mode 000 either)
const locks = [];
const lock = (p, mode, layout) => { locks.push({ p, mode }); layout.locked.push({ path: p, mode: mode.toString(8).padStart(3, '0') }); };

const layouts = [];
/** A layout: <OUT>/<name>/ with home/ (its HOME) and whatever else it builds. */
// expect: what a bad layout's incident must find, EXPOSED or REVIEW (run.mjs --gate fails a weaker finding)
function layout(name, { group, cls, catchBy = [], expect, paths = (L) => [], env = {}, notes = '' }, build) {
  const root = mk(join(OUT, name));
  const L = { name, root, home: mk(join(root, 'home')), tmp: mk(join(root, 'tmp')), locked: [] };
  build(L);
  layouts.push({
    name, group, class: cls, catchBy, ...(expect ? { expect } : {}), HOME: L.home, paths: paths(L),
    // TMPDIR: the layout's own temp folder, so the LiteLLM marker check reads it rather than this machine's
    env: { TMPDIR: L.tmp, ...(typeof env === 'function' ? env(L) : env) },
    locked: L.locked, notes,
  });
}

// ---- file contents --------------------------------------------------------------------------------------------------

const compose = (svc) => `services:\n  ${svc}:\n    image: postgres:16\n    restart: unless-stopped\n    volumes:\n      - ./pgdata:/var/lib/postgresql/data\n    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/pg\n`;
const readme = (n) => `# ${n}\n\nInternal project.\n`;
const pkg = (n, extra = {}) => `${JSON.stringify({ name: n, version: '1.0.0', private: true, ...extra }, null, 2)}\n`;
const pyproject = (n) => `[project]\nname = "${n}"\nversion = "0.1.0"\ndependencies = ["requests>=2.32", "certifi"]\n`;
const ciYml = 'name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm test\n';
// assembled at run time, so this file holds no key pattern
const fakeAwsKey = () => 'AKIA' + 'Q'.repeat(16);
const pemHeader = (what) => '-----BEGIN ' + what + '-----';
const pemFooter = (what) => '-----END ' + what + '-----';

/** A WordPress install at `dir` with UpdraftPlus at `updraft` (plugin folders dated before the incident's date). */
function wordpress(dir, updraft) {
  write(join(dir, 'index.php'), "<?php\ndefine('WP_USE_THEMES', true);\nrequire __DIR__ . '/wp-blog-header.php';\n");
  write(join(dir, 'wp-config.php'), "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp');\ndefine('DB_PASSWORD', 'corpus-not-a-secret');\ndefine('DB_HOST', 'localhost');\n$table_prefix = 'wp_';\nrequire_once ABSPATH . 'wp-settings.php';\n");
  write(join(dir, 'wp-includes', 'version.php'), "<?php\n$wp_version = '6.8.3';\n$wp_db_version = 58975;\n");
  write(join(dir, 'wp-content', 'themes', 'twentytwentyfive', 'style.css'), '/*\nTheme Name: Twenty Twenty-Five\nVersion: 1.3\n*/\n');
  write(join(dir, 'wp-content', 'plugins', 'index.php'), '<?php\n// Silence is golden.\n');
  write(join(dir, 'wp-content', 'plugins', 'updraftplus', 'updraftplus.php'),
    `<?php\n/*\nPlugin Name: UpdraftPlus - Backup/Restore\nPlugin URI: https://updraftplus.com\nDescription: Backup and restore.\nAuthor: TeamUpdraft\nVersion: ${updraft}\nLicense: GPLv3 or later\n*/\nif (!defined('ABSPATH')) die('No direct access allowed');\n`);
  write(join(dir, 'wp-content', 'plugins', 'akismet', 'akismet.php'), '<?php\n/*\nPlugin Name: Akismet Anti-spam\nVersion: 5.5\n*/\n');
  write(join(dir, 'wp-content', 'uploads', '2026', '03', '.htaccess'), 'Options -Indexes\n');
  // the WordPress check lists plugin folders created on or after 18 Oct 2026 for review: these were installed long
  // before. On APFS, setting a modification time older than the creation time moves the creation time back too; on a
  // file system that can't (most Linux ones), these folders read REVIEW in both versions, which doesn't change the exit.
  for (const p of ['updraftplus', 'akismet']) utimesSync(join(dir, 'wp-content', 'plugins', p), OLD_TIME, OLD_TIME);
}

/** A Python virtual environment at `dir` (pyvenv.cfg, lib/python3.12/site-packages) with certifi 2026.10.19. */
function venv(dir) {
  write(join(dir, 'pyvenv.cfg'), 'home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.7\n');
  mk(join(dir, 'bin'));
  symlinkSync('/usr/bin/python3', join(dir, 'bin', 'python3'));
  symlinkSync('python3', join(dir, 'bin', 'python'));
  const sp = join(dir, 'lib', 'python3.12', 'site-packages');
  write(join(sp, 'certifi', '__init__.py'), 'from .core import contents, where\n\n__all__ = ["contents", "where"]\n__version__ = "2026.10.19"\n');
  write(join(sp, 'certifi', 'core.py'), 'import os\n\ndef where():\n    return os.path.join(os.path.dirname(__file__), "cacert.pem")\n');
  const cert = (cn) => `\n# Issuer: CN=${cn}\n# Subject: CN=${cn}\n${pemHeader('CERTIFICATE')}\nMIIBszCCAVmgAwIBAgIUcorpusnotarealcertificate0000000000wCgYIKoZIzj0E\nAwIwLzEtMCsGA1UEAwwkY29ycHVzLW5vdC1hLXJlYWwtY2VydGlmaWNhdGUtYXV0aG9y\n${pemFooter('CERTIFICATE')}\n`;
  write(join(sp, 'certifi', 'cacert.pem'), ['Corpus Root CA 1', 'Corpus Root CA 2', 'Corpus Root CA 3'].map(cert).join(''));
  write(join(sp, 'certifi-2026.10.19.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: certifi\nVersion: 2026.10.19\nSummary: Python package for providing Mozilla\'s CA Bundle.\nRequires-Python: >=3.7\n');
  write(join(sp, 'certifi-2026.10.19.dist-info', 'RECORD'), 'certifi/__init__.py,,\ncertifi/cacert.pem,,\ncertifi/core.py,,\n');
  write(join(sp, 'requests', '__init__.py'), '__version__ = "2.32.5"\n');
  write(join(sp, 'requests-2.32.5.dist-info', 'METADATA'), 'Metadata-Version: 2.1\nName: requests\nVersion: 2.32.5\n');
  return sp;
}

/** A clean developer git identity in HOME (the identity-headers check compares header values against it). */
const gitconfigUser = '[user]\n\tname = Ada Lovelace\n\temail = ada.lovelace@analytical-engine.invalid\n[init]\n\tdefaultBranch = main\n';
/** What a Mac home has: Library with Preferences, Application Support and Caches. */
const macHome = (home) => { for (const d of ['Preferences', 'Application Support', 'Caches']) mk(join(home, 'Library', d)); };

// ---- server layouts ---------------------------------------------------------------------------------------------------

for (const variant of ['', '-gitkeep']) {
  layout(`server-compose${variant}`, {
    group: 'server', cls: 'clean',
    paths: (L) => [join(L.root, 'opt'), join(L.root, 'srv', 'www')],
    notes: variant ? 'pgdata/ is gitignored but holds a tracked .gitkeep (force-added), then closed at mode 000' : 'pgdata/ is gitignored and untracked, closed at mode 000',
  }, (L) => {
    write(join(L.home, '.bashrc'), 'export EDITOR=vim\n');
    write(join(L.home, '.gitconfig'), '[user]\n\tname = deploy\n\temail = ops@corpus-host.invalid\n');
    // a docker-compose project in git, its database folders ignored and closed
    const p = repo(join(L.root, 'opt', 'stack'), {
      '.gitignore': 'pgdata/\ndb/\n', 'docker-compose.yml': compose('db'), 'README.md': readme('stack'),
      'nginx/default.conf': 'server {\n  listen 80;\n  location / { proxy_pass http://app:3000; }\n}\n',
    });
    write(join(p, 'pgdata', 'PG_VERSION'), '16\n');
    write(join(p, 'pgdata', 'base', '1', '112'), 'postgres data page\n');
    write(join(p, 'db', 'dump.sql'), '-- nightly dump\n');
    if (variant) commit(p, { 'pgdata/.gitkeep': '' }, 'keep pgdata in the tree', OLD, ['pgdata/.gitkeep']);
    lock(join(p, 'pgdata'), 0o000, L);
    // a compose folder that is not a repository, its database folder closed
    const blog = join(L.root, 'srv', 'www', 'blog');
    write(join(blog, 'docker-compose.yml'), compose('db'));
    write(join(blog, 'db', 'ibdata1'), 'mysql data\n');
    lock(join(blog, 'db'), 0o000, L);
  });
}

for (const mode of [0o700, 0o000]) {
  const m = mode.toString(8).padStart(3, '0');
  layout(`server-certbot-${m}`, {
    group: 'server', cls: 'clean', paths: (L) => [join(L.root, 'srv')],
    notes: `certbot/conf/archive and certbot/conf/keys at mode ${m} (root-owned 700 on a real host, which reads as closed)`,
  }, (L) => {
    write(join(L.home, '.gitconfig'), '[user]\n\tname = deploy\n\temail = ops@corpus-host.invalid\n');
    const p = repo(join(L.root, 'srv', 'proxy'), {
      '.gitignore': 'certbot/\n', 'docker-compose.yml': 'services:\n  certbot:\n    image: certbot/certbot\n    volumes:\n      - ./certbot/conf:/etc/letsencrypt\n',
      'README.md': readme('proxy'),
    });
    const conf = join(p, 'certbot', 'conf');
    const key = `${pemHeader('PRIVATE KEY')}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCcorpusnotakey\n${pemFooter('PRIVATE KEY')}\n`;
    write(join(conf, 'archive', 'example.invalid', 'privkey1.pem'), key);
    write(join(conf, 'archive', 'example.invalid', 'fullchain1.pem'), `${pemHeader('CERTIFICATE')}\nMIIB\n${pemFooter('CERTIFICATE')}\n`);
    write(join(conf, 'keys', '0000_key-certbot.pem'), key);
    write(join(conf, 'renewal', 'example.invalid.conf'), 'version = 2.11.0\narchive_dir = /etc/letsencrypt/archive/example.invalid\n');
    lock(join(conf, 'archive'), mode, L);
    lock(join(conf, 'keys'), mode, L);
  });
}

for (const withOutdated of [false, true]) {
  layout(withOutdated ? 'server-www' : 'server-www-clean', {
    // UpdraftPlus 1.26.12 is older than its fix (1.26.13): EXPOSED
    group: 'server', cls: withOutdated ? 'bad' : 'clean', catchBy: withOutdated ? ['wordpress-plugins-2026-10'] : [], expect: withOutdated ? 'EXPOSED' : undefined,
    paths: (L) => [join(L.root, 'var', 'www')],
    notes: withOutdated ? 'var/www with a clean site (UpdraftPlus 1.26.13) and an outdated one (1.26.12); .ssh at 700'
      : 'var/www with a clean site (UpdraftPlus 1.26.13); .ssh at 700',
  }, (L) => {
    const www = join(L.root, 'var', 'www');
    wordpress(join(www, 'shop.example.invalid'), '1.26.13');
    if (withOutdated) wordpress(join(www, 'blog.example.invalid'), '1.26.12');
    write(join(www, 'html', 'index.html'), '<!doctype html><title>It works</title>\n');
    write(join(www, '.ssh', 'authorized_keys'), 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIcorpusnotarealkey deploy@ci\n');
    lock(join(www, '.ssh'), 0o700, L);
  });
}

layout('server-shared-hosting', {
  group: 'server', cls: 'clean', paths: (L) => [join(L.root, 'home')],
  notes: 'home/site1 at mode 000 stands in for another account\'s folder; home/site2 is a readable clean WordPress site',
}, (L) => {
  // On a real shared host, /home/site1 belongs to another uid (mode 711 or 750, owner site1): to the person running
  // Wardlatch it can't be opened. A corpus can't chown without root, so mode 000 on our own folder stands in for that.
  wordpress(join(L.root, 'home', 'site1', 'public_html'), '1.26.13');
  wordpress(join(L.root, 'home', 'site2', 'public_html'), '1.26.13');
  write(join(L.root, 'home', 'site2', 'logs', 'access.log'), '127.0.0.1 - - [01/Mar/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 512\n');
  lock(join(L.root, 'home', 'site1'), 0o000, L);
});

// ---- developer laptop layouts -----------------------------------------------------------------------------------------

const laptopHome = (L) => { macHome(L.home); write(join(L.home, '.gitconfig'), gitconfigUser); write(join(L.home, '.zshrc'), 'export PATH="$HOME/bin:$PATH"\n'); };

layout('laptop-repos', {
  group: 'laptop', cls: 'clean', paths: () => [],
  notes: 'no --paths: the default folders (~/Development, ~/code; plus this machine\'s own /var/www, /srv/www, /Library/WebServer/Documents if present)',
}, (L) => {
  laptopHome(L);
  repo(join(L.home, 'Development', 'web-app'), { 'package.json': pkg('web-app'), 'src/index.js': 'export const hello = () => "hi";\n', 'README.md': readme('web-app'), '.github/workflows/ci.yml': ciYml });
  repo(join(L.home, 'Development', 'cli-tool'), { 'go.mod': 'module example.invalid/cli\n\ngo 1.23\n', 'main.go': 'package main\n\nfunc main() {}\n' });
  repo(join(L.home, 'code', 'notes'), { 'notes.md': '# notes\n- buy milk\n' });
  repo(join(L.home, 'code', 'site'), {}, {
    commits: [
      { files: { 'index.html': '<!doctype html>\n', '.github/workflows/pages.yml': ciYml }, date: '2026-01-10T09:00:00+00:00', msg: 'site' },
      { files: { 'about.html': '<!doctype html>\n' }, date: '2026-10-01T09:00:00+00:00', msg: 'about page (after the workflow date, no workflow)' },
    ],
  });
});

layout('laptop-submodules', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Development')],
  notes: 'a repository with an old-style submodule (its own .git folder) and an absorbed one (.git file into .git/modules)',
}, (L) => {
  laptopHome(L);
  const up = join(L.root, 'upstream');
  const libA = repo(join(up, 'lib-a'), { 'a.js': 'export const a = 1;\n', 'README.md': readme('lib-a') });
  const libB = repo(join(up, 'lib-b'), { 'b.py': 'B = 2\n', 'README.md': readme('lib-b') });
  const p = repo(join(L.home, 'Development', 'platform'), { 'README.md': readme('platform'), 'package.json': pkg('platform') });
  // absorbed: what `git submodule add` makes today
  git(p, ['submodule', 'add', '-q', libA, 'vendor/lib-a']);
  // old style: a clone made in place first, then added; its .git stays a folder
  git(p, ['clone', '-q', libB, 'vendor/lib-b']);
  git(p, ['submodule', 'add', '-q', libB, 'vendor/lib-b']);
  git(p, ['commit', '-q', '-m', 'add submodules']);
});

layout('laptop-worktree', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Development')],
  notes: 'a git worktree checked out inside its own repository (wt/feature, gitignored)',
}, (L) => {
  laptopHome(L);
  const p = repo(join(L.home, 'Development', 'service'), { '.gitignore': 'wt/\n', 'server.js': 'console.log("up");\n', 'package.json': pkg('service') });
  git(p, ['worktree', 'add', '-q', '-b', 'feature', 'wt/feature']);
  commit(join(p, 'wt', 'feature'), { 'feature.js': 'export const feature = true;\n' }, 'feature work');
});

layout('laptop-nested-ignored', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'code')],
  notes: 'a gitignored repository inside another (tools/upstream-cli)',
}, (L) => {
  laptopHome(L);
  const p = repo(join(L.home, 'code', 'app'), { '.gitignore': 'tools/\n', 'app.py': 'print("app")\n', 'pyproject.toml': pyproject('app') });
  repo(join(p, 'tools', 'upstream-cli'), { 'cli.sh': '#!/bin/sh\necho cli\n', 'README.md': readme('upstream-cli') });
});

layout('laptop-library-repo', {
  group: 'laptop', cls: 'clean', paths: (L) => [L.home],
  notes: '--paths is the home folder, which has a real-looking ~/Library (skipped) and a repository named Library under ~/code',
}, (L) => {
  laptopHome(L);
  write(join(L.home, 'Library', 'Preferences', 'com.apple.finder.plist'), 'bplist00\n');
  repo(join(L.home, 'code', 'Library'), { 'Package.swift': '// swift-tools-version:5.9\nimport PackageDescription\n', 'Sources/Library/Library.swift': 'public struct Library {}\n' });
});

layout('laptop-monorepo', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Development')],
  notes: 'a monorepo with node_modules at the top and in a package (gitignored)',
}, (L) => {
  laptopHome(L);
  const p = repo(join(L.home, 'Development', 'mono'), {
    '.gitignore': 'node_modules/\ndist/\n', 'package.json': pkg('mono', { workspaces: ['packages/*'] }),
    'packages/ui/package.json': pkg('@mono/ui'), 'packages/ui/src/button.tsx': 'export const Button = () => null;\n',
    'packages/api/package.json': pkg('@mono/api'), 'packages/api/src/index.ts': 'export default {};\n',
    '.github/workflows/ci.yml': ciYml,
  });
  for (const [dir, n] of [['node_modules/left-pad', 'left-pad'], ['node_modules/@types/node', '@types/node'], ['packages/ui/node_modules/react', 'react']]) {
    write(join(p, dir, 'package.json'), pkg(n));
    write(join(p, dir, 'index.js'), 'module.exports = {};\n');
  }
  write(join(p, 'node_modules', '.bin', 'tsc'), '#!/usr/bin/env node\n');
  write(join(p, 'node_modules', '.package-lock.json'), '{}\n');
});

layout('laptop-venv-certifi', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Projects')],
  notes: 'a project with a .venv holding certifi 2026.10.19 (cacert.pem and its dist-info METADATA)',
}, (L) => {
  laptopHome(L);
  const p = repo(join(L.home, 'Projects', 'api'), { '.gitignore': '.venv/\n__pycache__/\n', 'pyproject.toml': pyproject('api'), 'api/main.py': 'import requests\n' });
  venv(join(p, '.venv'));
});

layout('laptop-venv-locked-lib', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Projects')],
  notes: 'a project .venv whose lib folder is at mode 000',
}, (L) => {
  laptopHome(L);
  const p = repo(join(L.home, 'Projects', 'worker'), { '.gitignore': '.venv/\n', 'pyproject.toml': pyproject('worker'), 'worker.py': 'print("w")\n' });
  venv(join(p, '.venv'));
  lock(join(p, '.venv', 'lib'), 0o000, L);
});

layout('laptop-big-json', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Development')],
  notes: 'a tracked minified one-line JSON of 9 MB, no keys in it',
}, (L) => {
  laptopHome(L);
  const items = []; let size = 2, i = 0;
  while (size < 9 * 1024 * 1024) {
    const s = JSON.stringify({ id: i, sku: `SKU-${String(i).padStart(7, '0')}`, name: `Item number ${i}`, price: (i % 997) / 10, tags: ['a', 'b', 'c'].slice(0, 1 + (i % 3)), stock: i % 41 });
    items.push(s); size += s.length + 1; i++;
  }
  repo(join(L.home, 'Development', 'catalog'), { 'public/catalog.min.json': `[${items.join(',')}]`, 'index.html': '<!doctype html>\n', 'package.json': pkg('catalog') });
});

layout('laptop-config', {
  group: 'laptop', cls: 'clean', paths: (L) => [join(L.home, 'Development')],
  notes: '.mcp.json with and without headers (no identity in them), ~/.curlrc, ~/.gitconfig with user email and an http.extraHeader that carries no identity',
}, (L) => {
  macHome(L.home);
  write(join(L.home, '.gitconfig'), `${gitconfigUser}[http]\n\textraHeader = X-Build-Host: laptop-07\n[http "https://git.internal.invalid/"]\n\textraHeader = X-Team: platform\n`);
  write(join(L.home, '.curlrc'), '--connect-timeout 10\n--location\n--user-agent "curl-corpus/8.7"\n');
  write(join(L.home, '.npmrc'), 'fund=false\naudit=false\n');
  repo(join(L.home, 'Development', 'agent-with-headers'), {
    '.mcp.json': `${JSON.stringify({ mcpServers: { docs: { type: 'http', url: 'https://mcp.docs.invalid/mcp', headers: { Authorization: 'Bearer ${DOCS_MCP_TOKEN}', 'X-Client': 'corpus' } } } }, null, 2)}\n`,
    'README.md': readme('agent-with-headers'),
  });
  repo(join(L.home, 'Development', 'agent-without-headers'), {
    '.mcp.json': `${JSON.stringify({ mcpServers: { files: { command: 'npx', args: ['-y', '@corpus/files-server', '.'] } } }, null, 2)}\n`,
    'README.md': readme('agent-without-headers'),
  });
});

layout('laptop-dotfiles-home', {
  group: 'laptop', cls: 'clean', paths: (L) => [L.home],
  notes: 'the home folder is itself a git repository (dotfiles); --paths is the home folder; a project repository under ~/Development',
}, (L) => {
  macHome(L.home);
  repo(L.home, { '.gitignore': '*\n!.gitignore\n!.zshrc\n!.gitconfig\n!.config/\n!.config/**\n', '.zshrc': 'export EDITOR=nvim\n', '.gitconfig': gitconfigUser, '.config/nvim/init.lua': 'vim.o.number = true\n' });
  repo(join(L.home, 'Development', 'blog'), { 'hugo.toml': 'title = "blog"\n', 'content/post.md': '# hello\n' });
});

// ---- CI runner layouts ------------------------------------------------------------------------------------------------

layout('ci-no-defaults', {
  group: 'ci', cls: 'clean', paths: () => [],
  notes: 'an empty runner HOME and no --paths: none of the default home folders exist (this machine\'s own /var/www, /srv/www, /Library/WebServer/Documents are still among the defaults)',
}, (L) => { mk(join(L.home, 'work')); });

layout('ci-devnull-config', {
  group: 'ci', cls: 'clean', paths: (L) => [join(L.root, 'work')],
  env: { GIT_CONFIG_GLOBAL: '/dev/null', NPM_CONFIG_USERCONFIG: '/dev/null', CI: 'true', GITHUB_ACTIONS: 'true' },
  notes: 'a checkout under work/, with GIT_CONFIG_GLOBAL and NPM_CONFIG_USERCONFIG at /dev/null',
}, (L) => {
  repo(join(L.root, 'work', 'app', 'app'), { 'package.json': pkg('app'), '.github/workflows/ci.yml': ciYml, 'src/index.js': 'export {};\n' });
});

layout('ci-paths-is-file', {
  group: 'ci', cls: 'clean', paths: (L) => [join(L.root, 'work', 'build.log')],
  env: { CI: 'true' },
  notes: '--paths names a file, not a folder',
}, (L) => {
  write(join(L.root, 'work', 'build.log'), 'build ok\n');
  repo(join(L.root, 'work', 'app'), { 'package.json': pkg('app') });
});

layout('ci-git-dir', {
  group: 'ci', cls: 'clean', paths: (L) => [join(L.root, 'work')],
  env: (L) => ({ GIT_DIR: join(L.root, 'actions', 'checkout-cache', '.git'), CI: 'true' }),
  notes: 'GIT_DIR names a repository outside --paths (as a hook or CI step can leave it); two clean repositories under work/',
}, (L) => {
  repo(join(L.root, 'actions', 'checkout-cache'), { 'action.yml': 'name: cache\nruns:\n  using: node20\n  main: index.js\n' });
  repo(join(L.root, 'work', 'svc-a'), { 'main.py': 'print("a")\n', '.github/workflows/ci.yml': ciYml });
  repo(join(L.root, 'work', 'svc-b'), { 'main.go': 'package main\n' });
});

// ---- bad layouts: each must still be caught -------------------------------------------------------------------------

layout('bad-committed-aws-key', {
  group: 'bad', cls: 'bad', catchBy: ['committed-keys-2026-10'], expect: 'REVIEW', paths: (L) => [join(L.home, 'Development')],
  notes: 'an AWS-format access key id committed in config/aws.js',
}, (L) => {
  laptopHome(L);
  repo(join(L.home, 'Development', 'uploader'), {
    'config/aws.js': `module.exports = {\n  region: 'eu-west-1',\n  accessKeyId: '${fakeAwsKey()}',\n};\n`,
    'package.json': pkg('uploader'),
  });
});

layout('bad-key-in-large-file', {
  group: 'bad', cls: 'bad', catchBy: ['committed-keys-2026-10'], expect: 'REVIEW', paths: (L) => [join(L.home, 'Development')],
  notes: 'an AWS-format key near the end of a 1.5 MB tracked text file',
}, (L) => {
  laptopHome(L);
  const lines = []; let size = 0;
  for (let i = 0; size < 1.5 * 1024 * 1024; i++) { const l = `INSERT INTO events (id, kind, at) VALUES (${i}, 'view', '2026-03-0${1 + (i % 9)}');`; lines.push(l); size += l.length + 1; }
  lines.push(`-- loader credentials: ${fakeAwsKey()}`);
  lines.push('COMMIT;');
  repo(join(L.home, 'Development', 'warehouse'), { 'seed/events.sql': `${lines.join('\n')}\n`, 'README.md': readme('warehouse') });
});

layout('bad-new-workflow', {
  group: 'bad', cls: 'bad', catchBy: ['github-actions-2026-10'], expect: 'REVIEW', paths: (L) => [join(L.home, 'Development')],
  notes: '.github/workflows/new.yml added in a commit dated 2026-09-15, after the incident\'s 2026-09-01',
}, (L) => {
  laptopHome(L);
  repo(join(L.home, 'Development', 'library'), {}, {
    commits: [
      { files: { 'index.js': 'module.exports = 1;\n', '.github/workflows/ci.yml': ciYml }, date: OLD, msg: 'initial commit' },
      { files: { '.github/workflows/new.yml': 'name: release\non: [push]\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./scripts/publish.sh\n' }, date: NEW, msg: 'add release workflow' },
    ],
  });
});

// (the outdated WordPress plugin is server-www above: blog.example.invalid has UpdraftPlus 1.26.12)

// ---- close the folders, write the manifests ---------------------------------------------------------------------------

for (const L of layouts) writeFileSync(join(OUT, L.name, 'manifest.json'), `${JSON.stringify(L, null, 2)}\n`);
writeFileSync(join(OUT, 'corpus.json'), `${JSON.stringify({ built: 'scripts/corpus/build.mjs', layouts: layouts.map((l) => l.name) }, null, 2)}\n`);
// deepest first, so a closed folder never hides one below it that is still to be closed
for (const { p, mode } of locks.sort((a, b) => b.p.length - a.p.length)) chmodSync(p, mode);
console.log(`built ${layouts.length} layouts in ${OUT}`);
for (const L of layouts) console.log(`  ${L.class.padEnd(5)}  ${L.name}${L.catchBy.length ? `  (caught by ${L.catchBy.join(', ')})` : ''}`);
