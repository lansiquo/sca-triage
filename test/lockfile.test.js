import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadProject } from '../src/lockfile.js';
import { triage } from '../src/triage.js';
import { normalizeAdvisories } from '../src/advisories.js';

const fixture = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));
const advisory = (severity, vulnerableVersions) => ({ ghsa: `GHSA-${vulnerableVersions}`, title: 't', severity, vulnerableVersions, url: 'x', cwe: [], cvss: null });
const lookups = (advisories, versions = {}) => ({
  advisoryLookup: async () => advisories,
  versionLookup: async (name) => versions[name] || [],
});
const summarize = (r) => r.findings.map((f) => `${f.priority} ${f.installedAs}=${f.package}@${f.version} ${f.reachability}`);

test('an aliased package keeps its installed name for reachability and its real name for advisories', async () => {
  const p = loadProject(fixture('alias'));
  const foo = p.installs.find((i) => i.path === 'node_modules/foo');
  assert.equal(foo.name, 'foo');
  assert.equal(foo.realName, 'lodash');
  assert.equal(foo.direct, true);
  assert.deepEqual(p.installs.find((i) => i.name === 'helper').via, ['foo']);

  let asked;
  const r = await triage(fixture('alias'), {
    advisoryLookup: async (installs) => {
      asked = installs.map((i) => i.name).sort();
      return { lodash: [advisory('critical', '<4.17.21')], helper: [advisory('high', '<1.0.1')] };
    },
    versionLookup: async (name) => ({ lodash: ['4.17.21'], helper: ['1.0.1'] })[name] || [],
  });
  assert.deepEqual(asked, ['helper', 'lodash']); // advisories are looked up by registry name
  assert.deepEqual(summarize(r), ['P1 foo=lodash@4.17.20 imported', 'P1 helper=helper@1.0.0 via-imported']);
});

test('dependencies of workspace packages are traced like root dependencies', async () => {
  const p = loadProject(fixture('workspaces'));
  assert.deepEqual(p.workspaces.sort(), ['packages/app', 'packages/tools']);
  const qs = p.installs.find((i) => i.path === 'node_modules/qs');
  assert.deepEqual(qs.via, ['express']);
  assert.deepEqual(qs.requiredBy, ['express']);
  const nested = p.installs.find((i) => i.path === 'packages/tools/node_modules/qs');
  assert.equal(nested.direct, true);
  assert.deepEqual(nested.declaredBy, [{ owner: 'packages/tools', kind: 'prod' }]);

  const r = await triage(fixture('workspaces'), lookups({ qs: [advisory('high', '<5.0.1 || >=6.0.0 <6.1.0')], 'test-lib': [advisory('critical', '<3.1.0')] }, { qs: ['5.0.1', '6.1.0'] }));
  assert.deepEqual(summarize(r), [
    'P1 qs=qs@6.0.0 via-imported', // express is imported by packages/app
    'P2 test-lib=test-lib@3.0.0 test-only', // only packages/app/test loads it
    'P2 qs=qs@5.0.0 not-imported',
  ]);
});

test('peer dependencies are part of the dependency graph', async () => {
  const p = loadProject(fixture('peers'));
  assert.deepEqual(p.installs.find((i) => i.name === 'plugin').dependsOn, ['core']);
  const r = await triage(fixture('peers'), lookups({ core: [advisory('critical', '<1.0.1')] }, { core: ['1.0.1'] }));
  assert.deepEqual(summarize(r), ['P1 core=core@1.0.0 via-imported']);
});

test('package names that are Object.prototype properties do not break the scan', async () => {
  // The fixture has node_modules/constructor; advisories come back as a null-prototype object.
  const r = await triage(fixture('peers'), lookups(normalizeAdvisories({})));
  assert.equal(r.findings.length, 0);
  assert.equal(r.packagesScanned, 3);
  const withHit = await triage(fixture('peers'), lookups(normalizeAdvisories({ constructor: [{ vulnerable_versions: '<2.0.0', severity: 'low', title: 't', url: 'u/GHSA-c' }] }), { constructor: ['2.0.0'] }));
  assert.deepEqual(summarize(withHit), ['P3 constructor=constructor@1.0.0 not-imported']);
});

test('each copy records the spec every package that requires it asks for', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sca-triage-specs-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', dependencies: { a: '1.0.0', b: '^1.0.0' } }));
    writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
      '': { name: 'app', dependencies: { a: '1.0.0', b: '^1.0.0' } },
      'node_modules/a': { version: '1.0.0', dependencies: { b: '1.0.0' }, peerDependencies: { c: '^2.0.0' } },
      'node_modules/b': { version: '1.0.0' },
      'node_modules/c': { version: '2.1.0' },
    } }));
    const b = loadProject(dir).installs.find((i) => i.path === 'node_modules/b');
    assert.deepEqual(b.requiredSpecs, [{ by: 'a', spec: '1.0.0' }]);
    const c = loadProject(dir).installs.find((i) => i.path === 'node_modules/c');
    assert.deepEqual(c.requiredSpecs, [{ by: 'a', spec: '^2.0.0' }]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
