import test from 'node:test';
import assert from 'node:assert/strict';
import { formatMarkdown, formatTable, formatTestsLine, escapeMarkdown, codeSpan, upgradeText, formatBundled } from '../src/report.js';

const finding = (overrides = {}) => ({
  priority: 'P1',
  package: 'lodash',
  installedAs: 'lodash',
  version: '4.17.20',
  severity: 'critical',
  advisories: [{ ghsa: 'GHSA-1', severity: 'critical', title: 'Prototype pollution' }],
  reachability: 'imported',
  evidence: ['src/index.js:1'],
  direct: true,
  via: [],
  fix: { target: '4.17.21', crossesMajor: false },
  ...overrides,
});
const result = (findings, project = 'demo') => ({
  project,
  packagesScanned: 3,
  summary: { P1: findings.length, P2: 0, P3: 0 },
  findings,
  warnings: [],
});

test('escapes project-controlled text in the Markdown report', () => {
  const md = formatMarkdown(result([finding({ installedAs: 'x`|<img src=y>', version: '1.0.0<b>' })], 'evil\n\n<img src=https://attacker/p>[click](https://attacker)'), null);
  assert.doesNotMatch(md, /<img/);
  assert.doesNotMatch(md, /<b>/);
  assert.doesNotMatch(md, /\[click\]\(/);
  assert.match(md, /^# Remediation evidence: evil {2}&lt;img/m); // newlines can't start a new block
  // Each table row still has exactly 7 unescaped pipes (6 cells).
  const row = md.split('\n').find((l) => l.startsWith('| P1'));
  assert.equal(row.replace(/\\\|/g, '').split('|').length - 1, 7);
});

test('shows aliased packages with both names', () => {
  const f = finding({ installedAs: 'foo' });
  assert.match(formatMarkdown(result([f]), null), /`foo \(npm:lodash\)@4\.17\.20`/);
  assert.match(formatTable(result([f])), /\[P1\] foo \(npm:lodash\)@4\.17\.20/);
});

test('strips terminal control characters from the table', () => {
  const out = formatTable(result([finding({ installedAs: 'a\u001b[2Jb' })]));
  assert.doesNotMatch(out, /\u001b/);
});

test('lists scan warnings in both formats', () => {
  const r = { ...result([]), warnings: ['GHSA-9: unsupported range comparator: "-"; treating it as vulnerable'] };
  assert.match(formatTable(r), /warning: GHSA-9/);
  assert.match(formatMarkdown(r, null), /## Warnings\n\n- GHSA-9/);
});

test('code spans fall back to escaping when they could break out', () => {
  assert.equal(codeSpan('npm install x@1.0.0'), '`npm install x@1.0.0`');
  assert.equal(codeSpan('a`b'), 'a\\`b');
  assert.equal(escapeMarkdown('<a>&[b]'), '&lt;a&gt;&amp;\\[b\\]');
});

test('the fix output says when the tests already failed before the upgrade', () => {
  const pass = { passed: true, code: 0 };
  const fail = { passed: false, code: 1 };
  assert.equal(formatTestsLine({ tests: pass, testsBefore: fail }), 'Tests (npm test): passed');
  assert.equal(formatTestsLine({ tests: fail, testsBefore: pass }), 'Tests (npm test): FAILED');
  assert.equal(
    formatTestsLine({ tests: fail, testsBefore: fail }),
    'Tests (npm test): FAILED (also failed before the upgrade, so this failure may not be caused by it)',
  );
  assert.equal(formatTestsLine({ tests: null, testsSkipped: 'disabled with --no-tests' }), 'Tests: not run — changes applied but UNVERIFIED (disabled with --no-tests)');
});

test('a bundled finding names the package to upgrade instead of an override', () => {
  const f = { version: '1.0.0', direct: false, fix: { target: '1.0.5', crossesMajor: false }, bundledIn: { name: 'tool', version: '2.0.0', path: 'node_modules/tool' } };
  assert.equal(upgradeText(f), 'bundled in tool@2.0.0: upgrade tool');
  assert.equal(upgradeText({ ...f, bundledIn: null }), '1.0.0 -> 1.0.5 (override)');
  assert.equal(upgradeText({ ...f, bundledIn: { name: 'a|b', version: '1.0.0' } }, escapeMarkdown), `bundled in ${escapeMarkdown('a|b@1.0.0')}: upgrade ${escapeMarkdown('a|b')}`);
});

test('bundled copies are grouped by the package that ships them', () => {
  const b = (name, version, owner) => ({ package: name, installedAs: name, version, bundledIn: { name: owner, version: '1.0.0' } });
  assert.deepEqual(formatBundled([b('x', '1.0.0', 'tool'), b('a', '2.0.0', 'tool'), b('x', '1.0.0', 'tool'), b('y', '3.0.0', 'cli')]), [
    "Bundled inside other packages (npm overrides can't change these; upgrade the package that bundles them):",
    '  cli@1.0.0: y@3.0.0',
    '  tool@1.0.0: a@2.0.0, x@1.0.0',
  ]);
  assert.deepEqual(formatBundled([]), []);
});
