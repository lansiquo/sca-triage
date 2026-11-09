import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { loadProject } from '../src/lockfile.js';
import { findImports, classify, packageNameFromSpecifier } from '../src/reachability.js';
import { triage, pickSafeVersion, priorityFor, gateFails, affects, MAX_TARGET_CHECKS, mapLimit } from '../src/triage.js';
import { planFixes, applyFixes } from '../src/fix.js';
import { formatMarkdown } from '../src/report.js';

const FIXTURE = fileURLToPath(new URL('./fixtures/project', import.meta.url));

// Offline stand-ins for the npm registry.
const ADVISORIES = {
  parser: [
    { ghsa: 'GHSA-test-0001', title: 'Parser prototype pollution', severity: 'high', vulnerableVersions: '<1.0.3', url: 'x', cwe: [], cvss: 7.5 },
  ],
  'test-lib': [
    { ghsa: 'GHSA-test-0002', title: 'Test lib ReDoS', severity: 'critical', vulnerableVersions: '<3.1.0', url: 'x', cwe: [], cvss: 9.1 },
  ],
  'unused-lib': [
    { ghsa: 'GHSA-test-0003', title: 'Unused lib issue', severity: 'moderate', vulnerableVersions: '<1.0.1', url: 'x', cwe: [], cvss: 5 },
  ],
};
const VERSIONS = {
  parser: ['0.9.1', '1.0.0', '1.0.1', '1.0.3', '1.1.0', '2.0.0-beta.1', '2.0.0'],
  'test-lib': ['3.0.0', '3.1.0', '4.0.0'],
  'unused-lib': ['1.0.0', '1.0.1'],
  'web-lib': ['2.0.0'],
};
const lookups = {
  advisoryLookup: async () => ADVISORIES,
  versionLookup: async (name) => VERSIONS[name] || [],
};

test('extracts package names from import specifiers', () => {
  assert.equal(packageNameFromSpecifier('lodash/merge'), 'lodash');
  assert.equal(packageNameFromSpecifier('@scope/pkg/sub'), '@scope/pkg');
  assert.equal(packageNameFromSpecifier('./local'), null);
  assert.equal(packageNameFromSpecifier('node:fs'), null);
});

test('builds the dependency graph from the lockfile', () => {
  const p = loadProject(FIXTURE);
  const hoisted = p.installs.find((i) => i.path === 'node_modules/parser');
  const nested = p.installs.find((i) => i.path === 'node_modules/unused-lib/node_modules/parser');
  assert.deepEqual(hoisted.via, ['web-lib']);
  assert.deepEqual(nested.via, ['unused-lib']);
  assert.equal(hoisted.direct, false);
});

test('classifies reachability from real import statements', () => {
  const p = loadProject(FIXTURE);
  const imports = findImports(FIXTURE);
  const level = (path) => classify(p.installs.find((i) => i.path === path), imports).level;
  assert.equal(level('node_modules/web-lib'), 'imported');
  assert.equal(level('node_modules/parser'), 'via-imported');
  assert.equal(level('node_modules/unused-lib'), 'not-imported');
  assert.equal(level('node_modules/unused-lib/node_modules/parser'), 'not-imported');
  assert.equal(level('node_modules/test-lib'), 'test-only');
});

test('priority combines severity with reachability', () => {
  assert.equal(priorityFor('critical', 'imported'), 'P1');
  assert.equal(priorityFor('high', 'via-imported'), 'P1');
  assert.equal(priorityFor('critical', 'not-imported'), 'P2');
  assert.equal(priorityFor('moderate', 'imported'), 'P2');
  assert.equal(priorityFor('moderate', 'test-only'), 'P3');
});

test('picks the smallest safe version, preferring the same major', () => {
  const adv = [{ vulnerableVersions: '<1.0.3' }];
  assert.deepEqual(pickSafeVersion('1.0.0', VERSIONS.parser, adv), { target: '1.0.3', crossesMajor: false });
  // Skips prereleases, and crosses a major only when it has to.
  assert.deepEqual(pickSafeVersion('1.0.0', ['1.0.1', '2.0.0-rc.1', '2.0.0'], [{ vulnerableVersions: '<2.0.0' }]), { target: '2.0.0', crossesMajor: true });
  // A newer version that a *different* advisory covers is not "safe".
  assert.deepEqual(
    pickSafeVersion('1.0.0', ['1.0.1', '1.0.2'], [{ vulnerableVersions: '<1.0.1' }, { vulnerableVersions: '=1.0.1' }]),
    { target: '1.0.2', crossesMajor: false },
  );
  assert.deepEqual(pickSafeVersion('1.0.0', ['1.0.0'], adv), { target: null, crossesMajor: false });
});

test('triage ranks findings and the gate fails only on P1 by default', async () => {
  const r = await triage(FIXTURE, lookups);
  const summary = r.findings.map((f) => `${f.priority} ${f.package}@${f.version} ${f.reachability}`);
  assert.deepEqual(summary, [
    'P1 parser@1.0.0 via-imported',
    'P2 test-lib@3.0.0 test-only', // critical, but never loaded at runtime
    'P2 parser@0.9.1 not-imported', // high, in a copy nothing loads
    'P3 unused-lib@1.0.0 not-imported',
  ]);
  assert.equal(gateFails(r, 'P1'), true);
  assert.equal(gateFails({ findings: r.findings.filter((f) => f.priority !== 'P1') }, 'P1'), false);
  assert.equal(gateFails(r, 'none'), false);
});

test('fix plan pins direct deps and overrides transitive ones with one target', async () => {
  const r = await triage(FIXTURE, lookups);
  const plan = planFixes(r);
  const byName = Object.fromEntries(plan.actions.map((a) => [a.package, a]));
  assert.equal(byName.parser.direct, false); // transitive -> npm overrides
  assert.equal(byName.parser.target, '1.0.3'); // highest target across both copies
  assert.equal(byName['test-lib'].direct, true);
  assert.equal(byName['test-lib'].dev, true);
  assert.equal(byName['test-lib'].target, '3.1.0');
  assert.deepEqual(planFixes(r, { minPriority: 'P1' }).actions.map((a) => a.package), ['parser']);
});

test('fix records why the project tests did not run', async () => {
  // No advisories means nothing to upgrade, and no evidenceDir means nothing is written,
  // so applyFixes runs no npm commands here. The fixture has no "test" script.
  const nothingToFix = { advisoryLookup: async () => ({}), versionLookup: async () => [] };
  const r = await applyFixes(FIXTURE, { lookups: nothingToFix });
  assert.equal(r.tests, null);
  assert.equal(r.testsSkipped, 'no "test" script in package.json');
  const noTests = await applyFixes(FIXTURE, { lookups: nothingToFix, runTests: false });
  assert.equal(noTests.testsSkipped, 'disabled with --no-tests');
});

test('fix report says the changes are unverified when tests did not run', async () => {
  const r = await triage(FIXTURE, lookups);
  const md = formatMarkdown(r, r, { changes: ['npm install test-lib@3.1.0'], tests: null, testsSkipped: 'disabled with --no-tests' });
  assert.match(md, /## Project tests/);
  assert.match(md, /Not run — changes applied but UNVERIFIED\*\* \(disabled with --no-tests\)/);
  // A scan report (no "after") has no tests section.
  assert.doesNotMatch(formatMarkdown(r, null), /## Project tests/);
});

test('0.x minor bumps count as crossing a major', () => {
  assert.deepEqual(pickSafeVersion('0.9.1', ['0.9.2', '0.10.0'], [{ vulnerableVersions: '<0.9.2' }]), { target: '0.9.2', crossesMajor: false });
  assert.deepEqual(pickSafeVersion('0.9.1', ['0.10.0', '1.0.0'], [{ vulnerableVersions: '<0.10.0' }]), { target: '0.10.0', crossesMajor: true });
  assert.deepEqual(pickSafeVersion('garbage', ['1.0.0'], []), { target: null, crossesMajor: false });
});

test('an advisory range the parser cannot read counts as vulnerable, with a warning', async () => {
  const warnings = [];
  assert.equal(affects('1.0.0', '1.0.0 - 1.2.0', warnings, 'G1'), true);
  assert.match(warnings[0], /G1: unsupported range comparator: "-"; treating it as vulnerable/);
  const r = await triage(FIXTURE, {
    advisoryLookup: async () => ({ parser: [{ ghsa: 'G2', severity: 'high', vulnerableVersions: '>=1.0.0, <1.0.3' }] }),
    versionLookup: async () => ['1.0.3'],
  });
  assert.deepEqual(r.findings.map((f) => `${f.package}@${f.version}`), ['parser@1.0.0', 'parser@0.9.1']);
  assert.ok(r.warnings.some((w) => w.includes('G2')));
  // No version can be proven safe from an unreadable range.
  assert.equal(r.findings[0].fix.target, null);
});

// A stand-in for the registry's bulk endpoint: like the real one, it returns only the
// advisories that affect at least one of the versions asked about.
function bulkRegistry(db, calls = []) {
  return async (installs) => {
    calls.push(installs.map((i) => `${i.name}@${i.version}`));
    const out = {};
    for (const { name, version } of installs) {
      for (const a of db[name] || []) {
        if (!affects(version, a.vulnerableVersions)) continue;
        out[name] ||= [];
        if (!out[name].includes(a)) out[name].push(a);
      }
    }
    return out;
  };
}

// The real moment advisories and published versions around 2.29.x.
const MOMENT = {
  moment: [
    { ghsa: 'GHSA-8hfj-j24r-96c4', severity: 'high', vulnerableVersions: '<2.29.2' },
    { ghsa: 'GHSA-wc69-rhjr-hc9g', severity: 'high', vulnerableVersions: '>=2.18.0 <2.29.4' },
    { ghsa: 'GHSA-4p3w-j4w9-5jqw', severity: 'moderate', vulnerableVersions: '>=2.29.2 <2.31.0' },
  ],
};
const MOMENT_VERSIONS = ['2.29.0', '2.29.1', '2.29.2', '2.29.3', '2.29.4', '2.30.0', '2.30.1', '2.31.0'];

test('the upgrade target is checked against advisories that only affect newer versions', async () => {
  const calls = [];
  const r = await triage(fileURLToPath(new URL('./fixtures/moment', import.meta.url)), {
    advisoryLookup: bulkRegistry(MOMENT, calls),
    versionLookup: async () => MOMENT_VERSIONS,
  });
  const [f] = r.findings;
  // The installed version is hit by two advisories; 2.29.4 clears those two but not
  // GHSA-4p3w-j4w9-5jqw, which only shows up when 2.29.4 itself is looked up.
  assert.deepEqual(f.advisories.map((a) => a.ghsa).sort(), ['GHSA-8hfj-j24r-96c4', 'GHSA-wc69-rhjr-hc9g']);
  assert.deepEqual(f.fix, { target: '2.31.0', crossesMajor: false });
  assert.deepEqual(calls, [['moment@2.29.1'], ['moment@2.29.4'], ['moment@2.31.0']]);
  assert.deepEqual(r.warnings, []);
});

test('candidate targets for many packages are checked in one lookup per round', async () => {
  const calls = [];
  await triage(FIXTURE, { advisoryLookup: bulkRegistry(ADVISORIES, calls), versionLookup: async (name) => VERSIONS[name] || [] });
  assert.equal(calls.length, 2); // the installed versions, then every target at once
  assert.deepEqual(calls[1].sort(), ['parser@1.0.3', 'test-lib@3.1.0', 'unused-lib@1.0.1']);
});

test('a target still unconfirmed after the lookup limit is kept, with a warning', async () => {
  // Every published version has its own advisory, so each check turns up a new one.
  const versions = ['2.29.1', '2.29.2', '2.29.3', '2.29.4', '2.29.5', '2.29.6', '2.29.7', '2.29.8'];
  const db = { moment: versions.map((v) => ({ ghsa: `G-${v}`, severity: 'high', vulnerableVersions: `=${v}` })) };
  const calls = [];
  const r = await triage(fileURLToPath(new URL('./fixtures/moment', import.meta.url)), {
    advisoryLookup: bulkRegistry(db, calls),
    versionLookup: async () => versions,
  });
  assert.equal(calls.length, 1 + MAX_TARGET_CHECKS);
  assert.equal(r.findings[0].fix.target, '2.29.7'); // 2.29.2 to 2.29.6 were checked and ruled out
  assert.deepEqual(r.warnings, [
    'moment@2.29.1: upgrade target 2.29.7 was not checked against the registry after 5 lookups; it may still be vulnerable',
  ]);
});

test('a failed lookup for a candidate target fails the scan', async () => {
  let n = 0;
  await assert.rejects(
    triage(fileURLToPath(new URL('./fixtures/moment', import.meta.url)), {
      advisoryLookup: async (installs) => {
        if (n++) throw new Error('HTTP 503');
        return bulkRegistry(MOMENT)(installs);
      },
      versionLookup: async () => MOMENT_VERSIONS,
    }),
    /HTTP 503/,
  );
});

test('mapLimit keeps input order and never runs more than the limit at once', async () => {
  let active = 0;
  let peak = 0;
  const items = Array.from({ length: 20 }, (_, i) => i);
  const out = await mapLimit(items, 8, async (n) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, (20 - n) % 5));
    active -= 1;
    return n * 2;
  });
  assert.deepEqual(out, items.map((n) => n * 2));
  assert.equal(peak, 8);
  assert.deepEqual(await mapLimit([], 8, async () => 1), []);
  await assert.rejects(mapLimit([1, 2, 3], 2, async (n) => { if (n === 2) throw new Error('boom'); return n; }), /boom/);
});

test('versions are looked up once per vulnerable package, concurrently, with the same result', async () => {
  const calls = [];
  let active = 0;
  let peak = 0;
  const concurrent = {
    advisoryLookup: lookups.advisoryLookup,
    versionLookup: async (name) => {
      calls.push(name);
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active -= 1;
      return VERSIONS[name] || [];
    },
  };
  const parallel = await triage(FIXTURE, concurrent);
  const serial = await triage(FIXTURE, lookups);
  assert.deepEqual(calls.sort(), [...new Set(calls)].sort(), 'each name once');
  assert.deepEqual(calls.sort(), [...new Set(parallel.findings.map((f) => f.package))].sort(), 'only vulnerable packages');
  assert.ok(peak > 1, 'lookups overlap');
  const strip = (r) => ({ ...r, scannedAt: null });
  assert.deepEqual(strip(parallel), strip(serial));
});
