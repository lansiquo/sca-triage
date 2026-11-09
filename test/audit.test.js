import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { loadProject } from '../src/lockfile.js';
import { normalizeAdvisories } from '../src/advisories.js';
import { findImports } from '../src/reachability.js';
import { triage } from '../src/triage.js';
import { planFixes, applyOverrides, applyFixes } from '../src/fix.js';

const cli = fileURLToPath(new URL('../bin/sca-triage.js', import.meta.url));
const json = (file, value) => { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(value)); };
function project(t, pkg = { dependencies: { x: '1.0.0' } }, entries = { 'node_modules/x': { version: '1.0.0' } }) {
  const dir = mkdtempSync(join(tmpdir(), 'sca-audit-test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  json(join(dir, 'package.json'), { name: 'audit-fixture', version: '1.0.0', ...pkg });
  json(join(dir, 'package-lock.json'), { lockfileVersion: 3, packages: { '': pkg, ...entries } });
  return dir;
}
const advisory = { ghsa: 'G-test', severity: 'high', vulnerableVersions: '<1.0.1' };
const lookups = { advisoryLookup: async () => ({ x: [advisory] }), versionLookup: async () => ['1.0.1'] };
const finding = (values = {}) => ({ package: 'x', installedAs: 'x', version: '1.0.0', path: 'node_modules/x',
  direct: false, declaredBy: [], requiredBy: [], copiesInstalled: 2, priority: 'P1', fix: { target: '1.0.1' }, ...values });

async function registry(t, response) {
  const server = createServer((req, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(response(req))); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => server.close(r)));
  return `http://127.0.0.1:${server.address().port}`;
}
function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { ...process.env, ...env } });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; }); child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject); child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('F01: missing option values and invalid priorities fail before reading or mutating a project', () => {
  for (const args of [
    ['fix', '/missing', '--min-priority', '--dry-run', '--no-tests'],
    ['fix', '/missing', '--min-priority', 'garbage'], ['plan', '/missing', '--min-priority'],
    ['scan', '/missing', '--markdown', '--json'], ['fix', '/missing', '--evidence', '--no-tests'],
    ['scan', '/missing', '--fail-on', '--json'], ['scan', '/missing', '--apply'],
  ]) {
    const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    assert.equal(r.status, 2); assert.match(r.stderr, /requires a value|must be one of|does not support/);
    assert.doesNotMatch(r.stderr, /no package/);
  }
  assert.throws(() => planFixes({ findings: [] }, { minPriority: 'garbage' }), /must be one of/);
});

test('F03: two versions of one parent that need different targets are left for a manual upgrade', () => {
  // npm 10 does not reliably apply "parent@version" keys, and one "parent" key can hold one version.
  const result = { findings: [
    finding({ path: 'node_modules/a/node_modules/x', requiredEdges: [{ by: 'parent', version: '1.0.0', path: 'node_modules/a', spec: '1.0.0' }] }),
    finding({ version: '2.0.0', path: 'node_modules/b/node_modules/x', requiredEdges: [{ by: 'parent', version: '2.0.0', path: 'node_modules/b', spec: '2.0.0' }], fix: { target: '2.0.1' } }),
  ] };
  const plan = planFixes(result);
  assert.deepEqual(plan.actions, []);
  assert.deepEqual(plan.manual.map((m) => m.reason), Array(2).fill('the override "parent" > "x" would need several versions (1.0.1, 2.0.1)'));
  // Entries that can't be told apart are refused, never last-one-wins.
  assert.throws(() => applyOverrides({}, [{ overrides: [{ scope: 'p', name: 'x', spec: '1.0.1' }] }, { overrides: [{ scope: 'p', name: 'x', spec: '2.0.1' }] }]), /conflicting/);
});

test('F04: identical workspace aliases retain distinct registry identities', () => {
  const plan = planFixes({ findings: ['alpha', 'beta'].map((packageName, i) => finding({
    package: packageName, installedAs: 'foo', path: `packages/${i}/node_modules/foo`, direct: true,
    declaredBy: [{ owner: `packages/${i}`, kind: 'prod' }],
  })) });
  assert.deepEqual(plan.actions.map((a) => [a.spec, a.pins[0].owner, a.overrides]), [
    ['npm:alpha@1.0.1', 'packages/0', []], ['npm:beta@1.0.1', 'packages/1', []],
  ]);
});

test('F05: override updates preserve nested children and prototype-like keys', () => {
  const original = { x: { '.': '1.0.0', y: '2.0.1' }, parent: { x: { '.': '1.0.0', z: '3.0.0' } } };
  const actions = [{ overrides: [{ scope: null, name: 'x', spec: '1.0.1' }, { scope: 'parent', name: 'x', spec: '1.0.1' }, { scope: null, name: '__proto__', spec: '1.0.1' }] }];
  const { overrides } = applyOverrides(original, actions);
  assert.deepEqual(overrides.x, { '.': '1.0.1', y: '2.0.1' });
  assert.deepEqual(overrides.parent.x, { '.': '1.0.1', z: '3.0.0' });
  assert.equal(overrides.__proto__, '1.0.1'); assert.equal(Object.getPrototypeOf(overrides), Object.prototype);
  assert.equal(original.x['.'], '1.0.0');
});

test('F06: malformed and incomplete inventories fail, absent optional dependencies remain valid', (t) => {
  const dir = project(t);
  for (const lock of [
    { lockfileVersion: 3, packages: [] }, { lockfileVersion: 3, packages: { '': {} } },
    { lockfileVersion: 1, packages: { '': {} } }, { lockfileVersion: 3, packages: { '': {}, 'node_modules/x': {} } },
    { lockfileVersion: 3, packages: { '': {}, 'node_modules/x': { version: 123 } } },
    { lockfileVersion: 3, packages: { '': {}, 'node_modules/x': { version: '1.0.0', dependencies: { missing: '*' } } } },
  ]) { json(join(dir, 'package-lock.json'), lock); assert.throws(() => loadProject(dir), /lockfile|lockfile entry/); }
  const optional = project(t, { optionalDependencies: { absent: '*' }, peerDependencies: { peer: '*' }, peerDependenciesMeta: { peer: { optional: true } } }, {});
  assert.equal(loadProject(optional).installs.length, 0);
});

test('lockfiles real npm writes still load: peers left out by legacy-peer-deps, file: folders outside the project', (t) => {
  const peers = project(t, { dependencies: { a: '1.0.0' } }, { 'node_modules/a': { version: '1.0.0', peerDependencies: { p: '^1.0.0' } } });
  assert.equal(loadProject(peers).installs.length, 1);
  const linked = project(t, { dependencies: { shared: 'file:../shared' } }, {
    '../shared': { version: '1.0.0', dependencies: { c: '1.0.0' } }, 'node_modules/shared': { resolved: '../shared', link: true },
  });
  assert.equal(loadProject(linked).installs.length, 0);
});

test('an entry whose name or version is not what its registry tarball contains is rejected', (t) => {
  const tgz = 'https://registry.npmjs.org/x/-/x-1.0.0.tgz';
  for (const entry of [{ version: '1.0.1', resolved: tgz }, { name: 'not-x', version: '1.0.0', resolved: tgz }]) {
    assert.throws(() => loadProject(project(t, { dependencies: { x: '1.0.0' } }, { 'node_modules/x': entry })), /but npm installs/);
  }
  const scoped = { name: '@s/real', version: '2.0.0', resolved: 'https://registry.npmjs.org/@s/real/-/real-2.0.0.tgz' };
  assert.equal(loadProject(project(t, { dependencies: { x: 'npm:@s/real@2.0.0' } }, { 'node_modules/x': scoped })).installs[0].realName, '@s/real');
});

test('F07: missing or unsupported severity is an input error', () => {
  for (const severity of [undefined, null, {}, 3, 'urgent', 'HIGH']) {
    assert.throws(() => normalizeAdvisories({ x: [{ vulnerable_versions: '*', severity }] }), /severity/);
  }
});

test('F08 and F15: long declarations and dense imports retain evidence within bounded processing time', (t) => {
  const dir = project(t);
  const names = Array.from({ length: 1200 }, (_, i) => `identifier${i}`).join(', ');
  writeFileSync(join(dir, 'long.js'), `import { ${names} } from 'x';\nexport { ${names} } from 'y';`);
  const count = 32_000;
  writeFileSync(join(dir, 'dense.js'), "require('dense');\n".repeat(count));
  const start = performance.now(); const imports = findImports(dir);
  assert.ok(performance.now() - start < 5000, 'dense scanning must not repeatedly scan prior text/evidence');
  assert.deepEqual(imports.get('x').runtime, ['long.js:1']); assert.deepEqual(imports.get('y').runtime, ['long.js:2']);
  assert.equal(imports.get('dense').runtime.length, count);
  assert.equal(imports.get('dense').runtime.at(-1), `dense.js:${count}`);
});

test('F09: a large JSON scan drains completely through a pipe', async (t) => {
  const count = 1200, entries = {};
  for (let i = 0; i < count; i++) entries[`node_modules/holder${i}/node_modules/x`] = { version: '1.0.0' };
  const dir = project(t, {}, entries);
  const url = await registry(t, (req) => req.method === 'POST' ? { x: [{ severity: 'high', vulnerable_versions: '<1.0.1', title: 'x'.repeat(300) }] } : { versions: { '1.0.1': {} } });
  const r = await run(['scan', dir, '--json', '--fail-on', 'none'], { SCA_TRIAGE_REGISTRY: url });
  assert.equal(r.code, 0, r.stderr); assert.ok(r.stdout.length > 500_000);
  assert.equal(JSON.parse(r.stdout).findings.length, count);
});

test('F10: post-install rescan failure preserves changes and complete recovery evidence', async (t) => {
  const dir = project(t), evidence = join(dir, 'evidence');
  let queries = 0;
  const failing = { ...lookups, advisoryLookup: async () => { if (++queries > 2) throw new Error('registry unavailable'); return { x: [advisory] }; } };
  const exec = (_cmd, args) => {
    if (args[0] === 'install') {
      for (const file of ['package.json', 'package-lock.json']) writeFileSync(join(dir, file), readFileSync(join(dir, file), 'utf8').replaceAll('1.0.0', '1.0.1'));
    }
    return { code: 0, output: 'installed' };
  };
  await assert.rejects(applyFixes(dir, { lookups: failing, exec, evidenceDir: evidence, runTests: false }), /Applied changes were preserved/);
  assert.equal(JSON.parse(readFileSync(join(dir, 'package.json'))).dependencies.x, '1.0.1');
  assert.equal(JSON.parse(readFileSync(join(evidence, 'before/package.json'))).dependencies.x, '1.0.0');
  assert.equal(JSON.parse(readFileSync(join(evidence, 'after/package.json'))).dependencies.x, '1.0.1');
  assert.match(readFileSync(join(evidence, 'REPORT.md'), 'utf8'), /Verification FAILED: applied changes preserved/);
  assert.match(readFileSync(join(evidence, 'commands.txt'), 'utf8'), /installed/);
  assert.equal(existsSync(join(evidence, 'after.json')), false);
});

test('F11: successful tests producing more than 1 MiB are not terminated by output capture', async (t) => {
  const dir = project(t, { scripts: { test: 'node noisy.cjs' } }, {}), evidence = join(dir, 'evidence');
  writeFileSync(join(dir, 'noisy.cjs'), "process.stdout.write('A'.repeat(2 * 1024 * 1024)); process.stderr.write('diagnostic');");
  const r = await applyFixes(dir, { evidenceDir: evidence, lookups: { advisoryLookup: async () => ({}) } });
  assert.equal(r.tests.passed, true); assert.equal(r.testsBefore.passed, true);
  assert.ok(readFileSync(join(evidence, 'tests.after.txt')).length > 2 * 1024 * 1024);
});

test('F12: SBOM JSON excludes stderr; invalid JSON is reported instead of saved', async (t) => {
  for (const valid of [true, false]) {
    const dir = project(t, {}, {}), evidence = join(dir, 'evidence');
    const stdout = valid ? '{"bomFormat":"CycloneDX"}' : '{broken';
    const r = await applyFixes(dir, { runTests: false, evidenceDir: evidence, lookups: { advisoryLookup: async () => ({}) },
      exec: () => ({ code: 0, stdout, stderr: 'npm WARN diagnostic', output: stdout + 'npm WARN diagnostic' }) });
    const file = join(evidence, 'sbom.cdx.json');
    assert.equal(existsSync(file), valid);
    assert.equal(readFileSync(join(evidence, 'sbom.stderr.txt'), 'utf8'), 'npm WARN diagnostic');
    if (valid) assert.equal(JSON.parse(readFileSync(file)).bomFormat, 'CycloneDX');
    else assert.match(r.verificationWarnings.join(), /SBOM unavailable/);
  }
});

test('F13: importing a hoisted transitive package reaches its descendants', async (t) => {
  const dir = project(t, { dependencies: { outer: '1.0.0' } }, {
    'node_modules/outer': { version: '1.0.0', dependencies: { inner: '1.0.0' } },
    'node_modules/inner': { version: '1.0.0', dependencies: { x: '1.0.0' } }, 'node_modules/x': { version: '1.0.0' },
  });
  writeFileSync(join(dir, 'index.js'), "require('inner');");
  const r = await triage(dir, lookups);
  assert.equal(r.findings[0].priority, 'P1'); assert.equal(r.findings[0].reachability, 'via-imported');
  assert.match(r.findings[0].evidence[0], /via inner/);
});

test('F14: one workspace cannot lend import evidence to another installed copy', async (t) => {
  const dir = project(t, { workspaces: ['packages/*'] }, {
    'packages/a': { name: 'a', dependencies: { x: '1.0.1' } }, 'packages/b': { name: 'b', dependencies: { x: '1.0.0' } },
    'node_modules/a': { link: true, resolved: 'packages/a' }, 'node_modules/b': { link: true, resolved: 'packages/b' },
    'packages/a/node_modules/x': { version: '1.0.1' }, 'packages/b/node_modules/x': { version: '1.0.0' },
  });
  for (const name of ['a', 'b']) json(join(dir, `packages/${name}/package.json`), { name, dependencies: { x: name === 'a' ? '1.0.1' : '1.0.0' } });
  mkdirSync(join(dir, 'packages/a/src'), { recursive: true }); writeFileSync(join(dir, 'packages/a/src/index.js'), "require('x');");
  const r = await triage(dir, lookups);
  assert.equal(r.findings[0].priority, 'P2'); assert.equal(r.findings[0].reachability, 'not-imported');
  assert.deepEqual(r.findings[0].evidence, []);
});

test('F16: registry error text cannot inject terminal controls', async (t) => {
  const dir = project(t);
  const url = await registry(t, () => ({ '\u001b[2Jpoison': {} }));
  const r = await run(['scan', dir], { SCA_TRIAGE_REGISTRY: url });
  assert.equal(r.code, 2); assert.doesNotMatch(r.stderr, /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/);
  assert.match(r.stderr, /advisory response/);
});

test('override coverage rejects an unrelated safe copy on a different release line', () => {
  const selected = finding({ copiesInstalled: 2, requiredEdges: [{ by: 'parent', version: '1.0.0', path: 'node_modules/parent', spec: '1.0.0' }] });
  const inventory = [
    { name: 'parent', realName: 'parent', version: '1.0.0', path: 'node_modules/parent', dependencyPaths: ['node_modules/x', 'node_modules/helper'] },
    { name: 'helper', realName: 'helper', version: '1.0.0', path: 'node_modules/helper', dependencyPaths: ['node_modules/helper/node_modules/x'] },
    { name: 'x', realName: 'x', version: '1.0.0', path: 'node_modules/x', dependencyPaths: [] },
    { name: 'x', realName: 'x', version: '2.0.1', path: 'node_modules/helper/node_modules/x', dependencyPaths: [] },
  ];
  const plan = planFixes({ findings: [selected], inventory });
  assert.deepEqual(plan.actions, []);
  assert.match(plan.manual[0].reason, /"parent" > "x" would also change x@2\.0\.1 at node_modules\/helper\/node_modules\/x/);
});
