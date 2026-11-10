// Exercise the shipped CLI and real npm using an isolated loopback registry/cache.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, spawn } from 'node:child_process';
import { createServer } from 'node:http';

const cli = fileURLToPath(new URL('../bin/sca-triage.js', import.meta.url));
const json = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
// No npm settings from an npm that runs these tests ("npm publish --dry-run" exports
// npm_config_dry_run, which would make every install here a no-op).
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^npm_/i.test(k)));

test('F02/F03/F04: real npm preserves declarations and alias identities, leaves two-target overrides alone, overrides only what the direct upgrades leave vulnerable, and holds majors', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'sca-npm-integration-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const cache = join(root, 'cache'), tarballs = new Map();
  const catalog = ['x', 'alpha', 'beta'].flatMap((name) => ['1.0.0', '1.0.1'].map((version) => ({ name, version })));
  catalog.push({ name: 'x', version: '2.0.0' }, { name: 'x', version: '2.0.1' },
    { name: 'parent', version: '1.0.0', dependencies: { x: '1.0.0' } },
    { name: 'parent', version: '2.0.0', dependencies: { x: '2.0.0' } },
    { name: 'left', version: '1.0.0', dependencies: { parent: '1.0.0' } },
    { name: 'right', version: '1.0.0', dependencies: { parent: '2.0.0' } },
    { name: 'lib', version: '1.0.0', dependencies: { dep: '1.0.0' } }, { name: 'lib', version: '1.0.1', dependencies: { dep: '1.0.1' } },
    { name: 'dep', version: '1.0.0' }, { name: 'dep', version: '1.0.1' }, { name: 'big', version: '1.0.0' }, { name: 'big', version: '2.0.0' });
  const ranges = { x: '<1.0.1 || >=2.0.0 <2.0.1', alpha: '<1.0.1', beta: '<1.0.1', lib: '<1.0.1', dep: '<1.0.1', big: '<2.0.0' };
  for (const item of catalog) {
    const { name, version } = item;
    const dir = join(root, `${name}-${version}`); mkdirSync(dir);
    json(join(dir, 'package.json'), { ...item, main: 'index.js' });
    writeFileSync(join(dir, 'index.js'), `module.exports = '${name}@${version}';`);
    const pack = spawnSync(npm, ['pack', '--ignore-scripts', '--json'], {
      cwd: dir, encoding: 'utf8', shell: process.platform === 'win32', env: { ...env, npm_config_cache: cache, npm_config_update_notifier: 'false' },
    });
    assert.equal(pack.status, 0, pack.stderr);
    tarballs.set(`${name}-${version}`, readFileSync(join(dir, JSON.parse(pack.stdout)[0].filename)));
  }
  let url;
  const server = createServer((req, res) => {
    if (req.url.startsWith('/tar/')) { res.end(tarballs.get(req.url.slice(5))); return; }
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST') {
      res.end(JSON.stringify(Object.fromEntries(Object.entries(ranges).map(([n, range]) => [n, [{ severity: 'high', vulnerable_versions: range, title: n }]])))); return;
    }
    const name = req.url.slice(1);
    const versions = catalog.filter((item) => item.name === name);
    res.end(JSON.stringify({ name, 'dist-tags': { latest: versions.at(-1)?.version }, versions: Object.fromEntries(versions.map((item) => [item.version, {
      ...item, dist: { tarball: `${url}/tar/${name}-${item.version}` },
    }])) }));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => server.close(r)));
  url = `http://127.0.0.1:${server.address().port}`;
  const run = (dir) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, 'fix', dir, '--no-tests', '--evidence', join(dir, 'evidence')], {
      env: { ...env, SCA_TRIAGE_REGISTRY: url, npm_config_registry: url, npm_config_cache: cache },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; }); child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject); child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  for (const fields of [['optionalDependencies'], ['peerDependencies'], ['peerDependencies', 'devDependencies'], ['optionalDependencies', 'devDependencies']]) {
    const dir = join(root, fields.join('-')); mkdirSync(dir);
    const pkg = { name: 'integration-app', version: '1.0.0', ...Object.fromEntries(fields.map((field) => [field, { x: '1.0.0' }])) };
    if (fields.includes('peerDependencies')) pkg.peerDependenciesMeta = { x: { optional: true } };
    json(join(dir, 'package.json'), pkg);
    json(join(dir, 'package-lock.json'), { lockfileVersion: 3, packages: { '': pkg,
      'node_modules/x': { version: '1.0.0', resolved: `${url}/tar/x-1.0.0` },
    } });
    const result = await run(dir);
    assert.equal(result.code, 0, JSON.stringify(result));
    const after = JSON.parse(readFileSync(join(dir, 'package.json')));
    for (const field of fields) assert.equal(after[field].x, '1.0.1', field);
    assert.equal(after.dependencies, undefined);
    assert.deepEqual(after.peerDependenciesMeta, pkg.peerDependenciesMeta);
    const lock = JSON.parse(readFileSync(join(dir, 'package-lock.json')));
    assert.equal(lock.packages['node_modules/x'].version, '1.0.1');
    assert.match(result.stdout, /Verified 1 of 1/);
    assert.equal(JSON.parse(readFileSync(join(dir, 'evidence/sbom.cdx.json'))).bomFormat, 'CycloneDX');
  }
  {
    // A project's .npmrc can name the program npm runs as git; fix must not run it.
    const dir = join(root, 'npmrc'); mkdirSync(dir);
    const git = 'git+https://git.invalid/g.git#0123456789abcdef0123456789abcdef01234567';
    const pkg = { name: 'npmrc-app', version: '1.0.0', dependencies: { x: '1.0.0', g: git } };
    json(join(dir, 'package.json'), pkg);
    json(join(dir, 'package-lock.json'), { lockfileVersion: 3, packages: { '': pkg,
      'node_modules/x': { version: '1.0.0', resolved: `${url}/tar/x-1.0.0` }, 'node_modules/g': { version: '1.0.0', resolved: git } } });
    const marker = join(dir, 'ran');
    writeFileSync(join(dir, 'fake-git.sh'), `#!/bin/sh\ntouch "${marker}"\nexit 1\n`, { mode: 0o755 });
    writeFileSync(join(dir, '.npmrc'), 'git=./fake-git.sh\n');
    await run(dir); // the git dependency can't be fetched, so the fix itself fails and rolls back
    assert.ok(!existsSync(marker), 'npm ran the program the project named as git');
  }
  const dir = join(root, 'workspaces'); mkdirSync(dir);
  const pkg = { name: 'alias-workspaces', version: '1.0.0', workspaces: ['packages/*'] };
  const entries = { '': pkg };
  for (const name of ['alpha', 'beta']) {
    const ws = `packages/${name}`; mkdirSync(join(dir, ws), { recursive: true });
    const manifest = { name: `ws-${name}`, version: '1.0.0', dependencies: { foo: `npm:${name}@1.0.0` } };
    json(join(dir, ws, 'package.json'), manifest); entries[ws] = manifest;
    entries[`node_modules/ws-${name}`] = { link: true, resolved: ws };
    entries[`${ws}/node_modules/foo`] = { name, version: '1.0.0', resolved: `${url}/tar/${name}-1.0.0` };
  }
  json(join(dir, 'package.json'), pkg); json(join(dir, 'package-lock.json'), { lockfileVersion: 3, packages: entries });
  const result = await run(dir);
  assert.equal(result.code, 0, JSON.stringify(result));
  for (const name of ['alpha', 'beta']) {
    assert.equal(JSON.parse(readFileSync(join(dir, `packages/${name}/package.json`))).dependencies.foo, `npm:${name}@1.0.1`);
  }
  assert.match(result.stdout, /Verified 2 of 2/);

  const npmInstall = (cwd) => new Promise((resolve, reject) => {
    const child = spawn(npm, ['install', '--ignore-scripts'], { cwd, shell: process.platform === 'win32',
      env: { ...env, npm_config_registry: url, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false' } });
    let output = '';
    child.stdout.on('data', (d) => { output += d; }); child.stderr.on('data', (d) => { output += d; });
    child.on('error', reject); child.on('close', (code) => code === 0 ? resolve() : reject(new Error(output)));
  });
  const scoped = join(root, 'scoped'); mkdirSync(scoped);
  json(join(scoped, 'package.json'), { name: 'scoped-app', version: '1.0.0', dependencies: { left: '1.0.0', right: '1.0.0' } });
  await npmInstall(scoped);
  const manifestBefore = readFileSync(join(scoped, 'package.json'), 'utf8');
  const lockBefore = readFileSync(join(scoped, 'package-lock.json'), 'utf8');
  // x@1.0.0 under parent@1 and x@2.0.0 under parent@2 need different targets. One "parent" key
  // can hold one version, and npm 10 ignores "parent@1.0.0" keys, so both are left for a manual
  // upgrade and nothing is changed.
  const scopedResult = await run(scoped);
  assert.equal(scopedResult.code, 0, JSON.stringify(scopedResult));
  assert.match(scopedResult.stdout, /Needs a manual upgrade[\s\S]*x 1\.0\.0 -> 1\.0\.1: the override "parent" > "x" would need several versions/);
  assert.equal(readFileSync(join(scoped, 'package.json'), 'utf8'), manifestBefore);
  assert.equal(readFileSync(join(scoped, 'package-lock.json'), 'utf8'), lockBefore);
  // lib@1.0.1 brings dep@1.0.1 itself, so the planned "dep" override is not written; big's
  // only fix is a major upgrade, which waits for --allow-major.
  const stages = join(root, 'stages'); mkdirSync(stages);
  json(join(stages, 'package.json'), { name: 'stages-app', version: '1.0.0', dependencies: { lib: '1.0.0', big: '1.0.0' } });
  await npmInstall(stages);
  const staged = await run(stages);
  assert.equal(staged.code, 0, JSON.stringify(staged));
  const stagedPkg = JSON.parse(readFileSync(join(stages, 'package.json')));
  assert.deepEqual(stagedPkg.dependencies, { big: '1.0.0', lib: '1.0.1' });
  assert.equal(stagedPkg.overrides, undefined);
  assert.match(staged.stdout, /Not needed after the direct upgrades, so no override was written: dep/);
  assert.match(staged.stdout, /Major upgrades, not applied without --allow-major[^\n]*\n  big 1\.0\.0 -> 2\.0\.0/);
});
