import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { planFixes, applyOverrides } from '../src/fix.js';
import { triage } from '../src/triage.js';

const fixture = (name) => fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url));

// A minimal finding, as triage() produces it.
function finding(overrides) {
  return {
    package: 'x',
    installedAs: 'x',
    version: '1.0.0',
    path: 'node_modules/x',
    direct: false,
    devOnly: false,
    declaredBy: [],
    requiredBy: [],
    copiesInstalled: 1,
    priority: 'P1',
    ...overrides,
    fix: { crossesMajor: false, ...overrides.fix },
  };
}

test('copies on different major lines get their own target, scoped to their parents', () => {
  const plan = planFixes({
    findings: [
      finding({ version: '1.2.0', path: 'node_modules/a/node_modules/x', requiredBy: ['a'], copiesInstalled: 2, fix: { target: '1.2.5' } }),
      finding({ version: '2.0.0', path: 'node_modules/x', requiredBy: ['b'], copiesInstalled: 2, fix: { target: '2.0.3' } }),
    ],
  });
  const byTarget = Object.fromEntries(plan.actions.map((a) => [a.target, a]));
  assert.deepEqual(Object.keys(byTarget).sort(), ['1.2.5', '2.0.3']);
  assert.equal(byTarget['1.2.5'].crossesMajor, false);
  assert.deepEqual(byTarget['1.2.5'].overrides, [{ scope: 'a', name: 'x', spec: '1.2.5' }]);
  assert.deepEqual(byTarget['2.0.3'].overrides, [{ scope: 'b', name: 'x', spec: '2.0.3' }]);
});

test('crossesMajor is computed for every copy that shares a target', () => {
  const plan = planFixes({
    findings: [
      finding({ version: '1.9.0', path: 'node_modules/x', copiesInstalled: 2, fix: { target: '2.0.3', crossesMajor: true } }),
      finding({ version: '2.0.0', path: 'node_modules/a/node_modules/x', copiesInstalled: 2, fix: { target: '2.0.3' } }),
    ],
  });
  assert.equal(plan.actions.length, 1);
  assert.equal(plan.actions[0].crossesMajor, true);
  assert.deepEqual(plan.actions[0].overrides, [{ scope: null, name: 'x', spec: '2.0.3' }]); // all copies, one target: global
});

test('a direct dependency with nested vulnerable copies gets a pin and scoped overrides', () => {
  const plan = planFixes({
    findings: [
      finding({ direct: true, declaredBy: [{ owner: '', kind: 'prod' }], copiesInstalled: 2, fix: { target: '1.0.5' } }),
      finding({ path: 'node_modules/a/node_modules/x', requiredBy: ['a'], copiesInstalled: 2, fix: { target: '1.0.5' } }),
    ],
  });
  assert.equal(plan.actions.length, 1);
  const [a] = plan.actions;
  assert.deepEqual(a.pins, [{ owner: '', dev: false }]);
  // Never a global "x" override: npm rejects one that conflicts with a direct dependency.
  assert.deepEqual(a.overrides, [{ scope: 'a', name: 'x', spec: '1.0.5' }]);
});

test('a global override is not used when a safe copy would be rewritten too', () => {
  const plan = planFixes({ findings: [finding({ path: 'node_modules/x', requiredBy: ['a'], copiesInstalled: 2, fix: { target: '1.0.5' } })] });
  assert.deepEqual(plan.actions[0].overrides, [{ scope: 'a', name: 'x', spec: '1.0.5' }]);
});

test('aliased packages are pinned and overridden with an npm: spec under their installed name', async () => {
  const r = await triage(fixture('alias'), {
    advisoryLookup: async () => ({ lodash: [{ ghsa: 'G1', severity: 'critical', vulnerableVersions: '<4.17.21' }] }),
    versionLookup: async () => ['4.17.21'],
  });
  const [a] = planFixes(r).actions;
  assert.equal(a.name, 'foo');
  assert.equal(a.package, 'lodash');
  assert.equal(a.spec, 'npm:lodash@4.17.21');
  assert.deepEqual(a.pins, [{ owner: '', dev: false }]);
});

test('workspace dependencies are pinned in their workspace', async () => {
  const r = await triage(fixture('workspaces'), {
    advisoryLookup: async () => ({ qs: [{ ghsa: 'G1', severity: 'high', vulnerableVersions: '<5.0.1 || >=6.0.0 <6.1.0' }] }),
    versionLookup: async () => ['5.0.1', '6.1.0'],
  });
  const byTarget = Object.fromEntries(planFixes(r).actions.map((a) => [a.target, a]));
  assert.deepEqual(byTarget['5.0.1'].pins, [{ owner: 'packages/tools', dev: false }]);
  assert.deepEqual(byTarget['5.0.1'].overrides, []);
  assert.deepEqual(byTarget['6.1.0'].overrides, [{ scope: 'express', name: 'qs', spec: '6.1.0' }]);
});

test('overrides merge into npm syntax without losing existing entries', () => {
  const actions = [
    { overrides: [{ scope: null, name: 'x', spec: '1.0.5' }] },
    { overrides: [{ scope: 'a', name: 'y', spec: '2.0.1' }, { scope: 'b', name: 'y', spec: '2.0.1' }] },
  ];
  const { overrides, changes } = applyOverrides({ a: '3.0.0', b: { z: '1.0.0' } }, actions);
  assert.deepEqual(overrides, { x: '1.0.5', a: { '.': '3.0.0', y: '2.0.1' }, b: { z: '1.0.0', y: '2.0.1' } });
  assert.equal(changes.length, 3);
});
