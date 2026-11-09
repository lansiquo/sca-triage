// Exercise the shipped CLI and real npm using an isolated loopback registry/cache.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { acceptsVersion } from '../src/semver.js';

const cli = fileURLToPath(new URL('../bin/sca-triage.js', import.meta.url));
const json = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';

test('F02/F03/F04: real npm preserves declarations, alias identities and version-scoped overrides', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'sca-npm-integration-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const cache = join(root, 'cache'), tarballs = new Map();
  const catalog = ['x', 'alpha', 'beta'].flatMap((name) => ['1.0.0', '1.0.1'].map((version) => ({ name, version })));
  catalog.push({ name: 'x', version: '2.0.0' }, { name: 'x', version: '2.0.1' },
    { name: 'parent', version: '1.0.0', dependencies: { x: '1.0.0' } },
    { name: 'parent', version: '2.0.0', dependencies: { x: '2.0.0' } },
    { name: 'left', version: '1.0.0', dependencies: { parent: '1.0.0' } },
    { name: 'right', version: '1.0.0', dependencies: { parent: '2.0.0' } });
  for (const item of catalog) {
    const { name, version } = item;
    const dir = join(root, `${name}-${version}`); mkdirSync(dir);
    json(join(dir, 'package.json'), { ...item, main: 'index.js' });
    writeFileSync(join(dir, 'index.js'), `module.exports = '${name}@${version}';`);
    const pack = spawnSync(npm, ['pack', '--ignore-scripts', '--json'], {
      cwd: dir, encoding: 'utf8', shell: process.platform === 'win32', env: { ...process.env, npm_config_cache: cache, npm_config_update_notifier: 'false' },
    });
    assert.equal(pack.status, 0, pack.stderr);
    tarballs.set(`${name}-${version}`, readFileSync(join(dir, JSON.parse(pack.stdout)[0].filename)));
  }
  let url;
  const server = createServer((req, res) => {
    if (req.url.startsWith('/tar/')) { res.end(tarballs.get(req.url.slice(5))); return; }
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST') {
      res.end(JSON.stringify(Object.fromEntries(['x', 'alpha', 'beta'].map((n) => [n, [{ severity: 'high', vulnerable_versions: n === 'x' ? '<1.0.1 || >=2.0.0 <2.0.1' : '<1.0.1', title: n }]])))); return;
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
      env: { ...process.env, SCA_TRIAGE_REGISTRY: url, npm_config_registry: url, npm_config_cache: cache },
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

  const scoped = join(root, 'scoped'); mkdirSync(scoped);
  json(join(scoped, 'package.json'), { name: 'scoped-app', version: '1.0.0', dependencies: { left: '1.0.0', right: '1.0.0' } });
  await new Promise((resolve, reject) => {
    const child = spawn(npm, ['install', '--ignore-scripts'], { cwd: scoped, shell: process.platform === 'win32',
      env: { ...process.env, npm_config_registry: url, npm_config_cache: cache, npm_config_audit: 'false', npm_config_fund: 'false' } });
    let output = '';
    child.stdout.on('data', (d) => { output += d; }); child.stderr.on('data', (d) => { output += d; });
    child.on('error', reject); child.on('close', (code) => code === 0 ? resolve() : reject(new Error(output)));
  });
  const manifestBefore = readFileSync(join(scoped, 'package.json'), 'utf8');
  const lockBefore = readFileSync(join(scoped, 'package-lock.json'), 'utf8');
  const npmVersion = spawnSync(npm, ['--version'], { encoding: 'utf8', shell: process.platform === 'win32' }).stdout.trim();
  const scopedResult = await run(scoped);
  if (!acceptsVersion('>=11.9.0', npmVersion)) {
    assert.equal(scopedResult.code, 2, JSON.stringify(scopedResult));
    assert.match(scopedResult.stderr, /require npm >=11\.9\.0/);
    assert.equal(readFileSync(join(scoped, 'package.json'), 'utf8'), manifestBefore);
    assert.equal(readFileSync(join(scoped, 'package-lock.json'), 'utf8'), lockBefore);
    return;
  }
  assert.equal(scopedResult.code, 0, JSON.stringify(scopedResult));
  assert.deepEqual(JSON.parse(readFileSync(join(scoped, 'package.json'))).overrides, {
    'parent@1.0.0': { x: '1.0.1' }, 'parent@2.0.0': { x: '2.0.1' },
  });
  const finalLock = JSON.parse(readFileSync(join(scoped, 'package-lock.json')));
  const xVersions = Object.entries(finalLock.packages).filter(([path]) => path.endsWith('/node_modules/x') || path === 'node_modules/x').map(([, value]) => value.version).sort();
  assert.deepEqual(xVersions, ['1.0.1', '2.0.1']);
  assert.match(scopedResult.stdout, /Verified 2 of 2/);
});
