import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { cpSync, mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { planFixes, applyOverrides, applyFixes, pinCommands } from '../src/fix.js';
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

test('pins are grouped into one npm install per manifest and dependency type', () => {
  const cmds = pinCommands([
    { name: 'a', spec: '1.0.1', pins: [{ owner: '', dev: false }, { owner: 'packages/web', dev: false }] },
    { name: 'b', spec: '2.0.1', pins: [{ owner: '', dev: false }] },
    { name: 'c', spec: '3.1.0', pins: [{ owner: '', dev: true }] },
    { name: 'foo', spec: 'npm:lodash@4.17.21', pins: [{ owner: 'packages/web', dev: false }] },
    { name: 'd', spec: '1.0.0', pins: [] },
  ]);
  assert.deepEqual(
    cmds.map((c) => c.args.join(' ')),
    [
      'install a@1.0.1 b@2.0.1 --save-exact --ignore-scripts --save-prod',
      'install a@1.0.1 foo@npm:lodash@4.17.21 --save-exact --ignore-scripts --save-prod --workspace packages/web',
      'install c@3.1.0 --save-exact --ignore-scripts --save-dev',
    ],
  );
  assert.deepEqual(cmds.map((c) => c.owner), ['', 'packages/web', '']);
});

// applyFixes against a temporary copy of the fixture project, with npm replaced by a fake.
const LOOKUPS = {
  advisoryLookup: async () => ({
    'web-lib': [{ ghsa: 'G-web', severity: 'high', vulnerableVersions: '<2.0.1' }],
    'unused-lib': [{ ghsa: 'G-unused', severity: 'moderate', vulnerableVersions: '<1.0.1' }],
    'test-lib': [{ ghsa: 'G-test', severity: 'critical', vulnerableVersions: '<3.1.0' }],
    parser: [{ ghsa: 'G-parser', severity: 'high', vulnerableVersions: '<1.0.3' }],
  }),
  versionLookup: async (name) => ({ 'web-lib': ['2.0.1'], 'unused-lib': ['1.0.1'], 'test-lib': ['3.1.0'], parser: ['1.0.3'] })[name] || [],
};

function tempProject(t, { testScript = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sca-triage-fix-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const app = join(dir, 'app');
  cpSync(fixture('project'), app, { recursive: true });
  if (testScript) {
    const pkg = JSON.parse(readFileSync(join(app, 'package.json'), 'utf8'));
    pkg.scripts = { test: 'node --test' };
    writeFileSync(join(app, 'package.json'), JSON.stringify(pkg, null, 2) + '\n');
  }
  return { app, evidence: join(dir, 'evidence') };
}

// Records npm calls; every install changes the lockfile, as npm would.
function fakeNpm(app, respond = () => 0) {
  const calls = [];
  const exec = (cmd, args) => {
    calls.push(args.join(' '));
    if (args[0] === 'install') {
      const lock = JSON.parse(readFileSync(join(app, 'package-lock.json'), 'utf8'));
      writeFileSync(join(app, 'package-lock.json'), JSON.stringify({ ...lock, changedByFakeNpm: true }));
    }
    const code = respond(args, calls);
    return { code, output: code ? 'npm ERR! simulated failure' : args[0] === 'sbom' ? '{}' : 'ok' };
  };
  return { exec, calls };
}

test('fix runs one install per manifest group plus one for overrides', async (t) => {
  const { app, evidence } = tempProject(t);
  const npm = fakeNpm(app);
  const r = await applyFixes(app, { lookups: LOOKUPS, evidenceDir: evidence, exec: npm.exec });
  assert.deepEqual(npm.calls.filter((c) => c.startsWith('install')), [
    'install web-lib@2.0.1 unused-lib@1.0.1 --save-exact --ignore-scripts --save-prod',
    'install test-lib@3.1.0 --save-exact --ignore-scripts --save-dev',
    'install --ignore-scripts',
  ]);
  // The report lists the commands that ran.
  assert.ok(r.changes.includes('npm install web-lib@2.0.1 unused-lib@1.0.1 --save-exact --ignore-scripts --save-prod'));
  assert.ok(r.changes.includes('npm install test-lib@3.1.0 --save-exact --ignore-scripts --save-dev'));
  assert.ok(r.changes.includes('package.json overrides: "parser": "1.0.3"'));
});

test('a failed install restores package.json and the lockfile and writes a failure report', async (t) => {
  const { app, evidence } = tempProject(t);
  const pkgBefore = readFileSync(join(app, 'package.json'), 'utf8');
  const lockBefore = readFileSync(join(app, 'package-lock.json'), 'utf8');
  // The pins succeed; the overrides install fails after package.json has been rewritten.
  const npm = fakeNpm(app, (args) => (args.join(' ') === 'install --ignore-scripts' ? 1 : 0));
  await assert.rejects(applyFixes(app, { lookups: LOOKUPS, evidenceDir: evidence, exec: npm.exec }), (err) => {
    assert.match(err.message, /npm install \(overrides\) failed/);
    assert.match(err.message, /Fix rolled back: package\.json and package-lock\.json were restored/);
    assert.match(err.message, /npm ci/);
    return true;
  });
  assert.equal(readFileSync(join(app, 'package.json'), 'utf8'), pkgBefore);
  assert.equal(readFileSync(join(app, 'package-lock.json'), 'utf8'), lockBefore);
  assert.ok(existsSync(join(evidence, 'before.json')));
  assert.equal(readFileSync(join(evidence, 'install-failure.txt'), 'utf8'), 'npm ERR! simulated failure');
  const md = readFileSync(join(evidence, 'REPORT.md'), 'utf8');
  assert.match(md, /## Fix FAILED: changes rolled back/);
  assert.match(md, /Failed step: `npm install --ignore-scripts`/);
  assert.match(md, /\*\*restored\*\*/);
  assert.match(md, /npm ci/);
  assert.doesNotMatch(md, /## Changes applied/);
});

test('a failed fix also restores the workspace manifests its pins changed', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sca-triage-ws-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const app = join(dir, 'app');
  cpSync(fixture('workspaces'), app, { recursive: true });
  const tools = join(app, 'packages', 'tools', 'package.json');
  const toolsBefore = readFileSync(tools, 'utf8');
  const calls = [];
  // The workspace pin rewrites packages/tools/package.json, as npm would; the overrides install fails.
  const exec = (cmd, args) => {
    calls.push(args.join(' '));
    if (args.includes('--workspace')) writeFileSync(tools, toolsBefore.replace('}', ', "changedByFakeNpm": true }'));
    return { code: args.join(' ') === 'install --ignore-scripts' ? 1 : 0, output: 'npm ERR! simulated failure' };
  };
  const lookups = {
    advisoryLookup: async () => ({ qs: [{ ghsa: 'G1', severity: 'high', vulnerableVersions: '<5.0.1 || >=6.0.0 <6.1.0' }] }),
    versionLookup: async () => ['5.0.1', '6.1.0'],
  };
  await assert.rejects(applyFixes(app, { lookups, exec }),
    /Fix rolled back: package\.json, packages\/tools\/package\.json and package-lock\.json were restored/);
  assert.ok(calls.some((c) => c.endsWith('--workspace packages/tools')));
  assert.equal(readFileSync(tools, 'utf8'), toolsBefore);
});

test('an error thrown mid-way also rolls back the earlier installs', async (t) => {
  const { app } = tempProject(t);
  const lockBefore = readFileSync(join(app, 'package-lock.json'), 'utf8');
  const npm = fakeNpm(app);
  let installs = 0;
  const exec = (cmd, args, cwd) => {
    if (args[0] === 'install' && ++installs === 2) throw new Error('spawn npm ENOENT');
    return npm.exec(cmd, args, cwd);
  };
  await assert.rejects(applyFixes(app, { lookups: LOOKUPS, exec }), /spawn npm ENOENT\nFix rolled back/);
  assert.equal(npm.calls.length, 1); // the first pin group ran and changed the lockfile
  assert.equal(readFileSync(join(app, 'package-lock.json'), 'utf8'), lockBefore);
});

test('tests failing after a successful upgrade keep the changes (no rollback)', async (t) => {
  const { app, evidence } = tempProject(t, { testScript: true });
  // Baseline passes, the run after the upgrade fails.
  const npm = fakeNpm(app, (args, calls) => (args[0] === 'test' && calls.filter((c) => c === 'test').length === 2 ? 1 : 0));
  const r = await applyFixes(app, { lookups: LOOKUPS, evidenceDir: evidence, exec: npm.exec });
  assert.equal(r.testsBefore.passed, true);
  assert.equal(r.tests.passed, false);
  assert.equal(JSON.parse(readFileSync(join(app, 'package-lock.json'), 'utf8')).changedByFakeNpm, true);
  assert.match(JSON.parse(readFileSync(join(app, 'package.json'), 'utf8')).overrides.parser, /1\.0\.3/);
  assert.doesNotMatch(readFileSync(join(evidence, 'REPORT.md'), 'utf8'), /Fix FAILED/);
});

test('every grouped npm argument is still checked, and a refusal rolls back', async (t) => {
  const { app } = tempProject(t);
  // A crafted lockfile and manifest: a "package" whose name carries a shell metacharacter.
  for (const file of ['package.json', 'package-lock.json']) {
    const p = join(app, file);
    writeFileSync(p, readFileSync(p, 'utf8').replaceAll('web-lib', 'web-lib;x'));
  }
  const pkgBefore = readFileSync(join(app, 'package.json'), 'utf8');
  const npm = fakeNpm(app);
  const lookups = { ...LOOKUPS, advisoryLookup: async () => ({ 'web-lib;x': [{ ghsa: 'G', severity: 'high', vulnerableVersions: '<2.0.1' }] }), versionLookup: async () => ['2.0.1'] };
  await assert.rejects(applyFixes(app, { lookups, exec: npm.exec }), /refusing to run npm with unexpected argument "web-lib;x@2\.0\.1"[\s\S]*Fix rolled back/);
  assert.deepEqual(npm.calls, []);
  assert.equal(readFileSync(join(app, 'package.json'), 'utf8'), pkgBefore);
});

test('a pinned direct dependency also gets an override for parents whose range excludes the target', () => {
  const plan = planFixes({ findings: [finding({
    direct: true, declaredBy: [{ owner: '', kind: 'prod' }], requiredBy: ['express', 'other', 'tool'],
    requiredSpecs: [{ by: 'express', spec: '1.0.0' }, { by: 'other', spec: '^1.0.0' }, { by: 'tool', spec: 'github:o/r' }],
    fix: { target: '1.0.5' },
  })] });
  const [a] = plan.actions;
  assert.deepEqual(a.pins, [{ owner: '', dev: false }]);
  // express pins 1.0.0 exactly; "other" accepts 1.0.5; an unreadable spec is left alone.
  assert.deepEqual(a.overrides, [{ scope: 'express', name: 'x', spec: '1.0.5' }]);
});

// A project where the vulnerable x@1.0.0 is nested under a (which requires it exactly),
// next to a safe top-level x@1.0.5: npm keeps the nested copy unless its lock entry goes.
function nestedProject(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sca-triage-nested-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'app', version: '1.0.0', dependencies: { a: '1.0.0', x: '1.0.5' }, devDependencies: { b: '1.0.0' } }, null, 2) + '\n');
  writeFileSync(join(dir, 'index.js'), "require('a');\n");
  writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ name: 'app', lockfileVersion: 3, packages: {
    '': { name: 'app', version: '1.0.0', dependencies: { a: '1.0.0', x: '1.0.5' }, devDependencies: { b: '1.0.0' } },
    'node_modules/a': { version: '1.0.0', dependencies: { x: '1.0.0' } },
    'node_modules/a/node_modules/x': { version: '1.0.0', dependencies: { y: '1.0.0' } },
    'node_modules/a/node_modules/x/node_modules/y': { version: '1.0.0' },
    'node_modules/x': { version: '1.0.5' },
    // A dev-only copy: P2, so outside a P1 plan, but the "a" > "x" override covers it too.
    'node_modules/b': { version: '1.0.0', dev: true, dependencies: { a: '1.0.0' } },
    'node_modules/b/node_modules/a': { version: '1.0.0', dev: true, dependencies: { x: '1.0.1' } },
    'node_modules/b/node_modules/a/node_modules/x': { version: '1.0.1', dev: true },
    // Bundled in b's tarball: npm restores it from the bundle, so it is left alone.
    'node_modules/b/node_modules/a/node_modules/c': { version: '1.0.0', dev: true, inBundle: true, dependencies: { x: '1.0.0' } },
    'node_modules/b/node_modules/a/node_modules/c/node_modules/x': { version: '1.0.0', dev: true, inBundle: true },
  } }, null, 2) + '\n');
  return dir;
}
const NESTED_LOOKUPS = {
  advisoryLookup: async () => ({ x: [{ ghsa: 'G-x', severity: 'high', vulnerableVersions: '<1.0.5' }] }),
  versionLookup: async () => ['1.0.0', '1.0.5'],
};

test('fix drops the lock entries of nested copies an override targets, so npm resolves them again', async (t) => {
  const dir = nestedProject(t);
  const lockAtInstall = [];
  const exec = (cmd, args) => {
    if (args.join(' ') === 'install --ignore-scripts') lockAtInstall.push(Object.keys(JSON.parse(readFileSync(join(dir, 'package-lock.json'), 'utf8')).packages));
    return { code: 0, output: args[0] === 'sbom' ? '{}' : 'ok' };
  };
  const r = await applyFixes(dir, { lookups: NESTED_LOOKUPS, minPriority: 'P1', runTests: false, exec });
  assert.deepEqual(r.plan.actions.map((a) => a.from), [['1.0.0']]);   // the dev copy is not in the plan
  assert.deepEqual(lockAtInstall, [['', 'node_modules/a', 'node_modules/x', 'node_modules/b', 'node_modules/b/node_modules/a',
    'node_modules/b/node_modules/a/node_modules/c', 'node_modules/b/node_modules/a/node_modules/c/node_modules/x']]);
  assert.ok(r.changes.includes('package.json overrides: "a" > "x": "1.0.5"'));
  assert.ok(r.changes.includes('package-lock.json: re-resolve x@1.0.0 at node_modules/a/node_modules/x'));
  assert.ok(r.changes.includes('package-lock.json: re-resolve x@1.0.1 at node_modules/b/node_modules/a/node_modules/x'));
});

test('a failed install after dropping lock entries restores the original lockfile', async (t) => {
  const dir = nestedProject(t);
  const lockBefore = readFileSync(join(dir, 'package-lock.json'), 'utf8');
  const exec = (cmd, args) => ({ code: args.join(' ') === 'install --ignore-scripts' ? 1 : 0, output: 'npm ERR! simulated failure' });
  await assert.rejects(applyFixes(dir, { lookups: NESTED_LOOKUPS, runTests: false, exec }), /Fix rolled back/);
  assert.equal(readFileSync(join(dir, 'package-lock.json'), 'utf8'), lockBefore);
});

test('bundled copies are listed for a parent upgrade, never planned as overrides', () => {
  const bundledIn = { name: 'tool', version: '2.0.0', path: 'node_modules/tool' };
  const plan = planFixes({ findings: [
    finding({ path: 'node_modules/tool/node_modules/x', requiredBy: ['tool'], copiesInstalled: 2, bundledIn, fix: { target: '1.0.5' } }),
    finding({ path: 'node_modules/other/node_modules/x', requiredBy: ['other'], copiesInstalled: 2, fix: { target: '1.0.5' } }),
  ] });
  assert.deepEqual(plan.bundled.map((f) => f.path), ['node_modules/tool/node_modules/x']);
  assert.deepEqual(plan.actions.flatMap((a) => a.overrides), [{ scope: 'other', name: 'x', spec: '1.0.5' }]);
  assert.deepEqual(plan.unfixable, []);
});
