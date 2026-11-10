import test from 'node:test';
import assert from 'node:assert/strict';
import { acceptsVersion, compare, satisfies, sortVersions } from '../src/semver.js';

test('compares versions, including prereleases', () => {
  assert.equal(compare('1.2.10', '1.2.9'), 1);
  assert.equal(compare('1.2.0', '1.2.0'), 0);
  assert.equal(compare('2.0.0-beta.2', '2.0.0-beta.10'), -1);
  assert.equal(compare('2.0.0-rc.1', '2.0.0'), -1);
});

test('matches the range syntax npm advisories use', () => {
  assert.ok(satisfies('1.2.5', '>=1.0.0 <1.2.6'));
  assert.ok(!satisfies('1.2.6', '>=1.0.0 <1.2.6'));
  assert.ok(satisfies('7.5.2', '<=7.5.2'));
  assert.ok(satisfies('0.4.0', '<0.5.0 || >=1.0.0 <1.1.0'));
  assert.ok(satisfies('1.0.5', '<0.5.0 || >=1.0.0 <1.1.0'));
  assert.ok(!satisfies('0.7.0', '<0.5.0 || >=1.0.0 <1.1.0'));
  assert.ok(satisfies('3.0.0', '>= 2.0.0 < 4.0.0'));
  assert.ok(satisfies('9.9.9', '*'));
});

test('rejects range syntax it does not understand instead of guessing', () => {
  assert.throws(() => satisfies('1.0.0', '~>1.0.0'), /unsupported range/);
});

test('reads the partial versions and hyphen ranges real advisories use', () => {
  // next GHSA-3h52-269p-cp9r and tinymce GHSA-vg35-5wq7-3x7w: unreadable before, so no upgrade was ever safe.
  for (const [version, range, inside] of [
    ['14.2.29', '>=13.0 <14.2.30', true], ['13.0.0', '>=13.0 <14.2.30', true], ['15.5.28', '>=13.0 <14.2.30', false],
    ['5.10.9', '>0 <=5.10.9', true], ['0.9.0', '>0 <=5.10.9', false], ['8.9.3', '>0 <=5.10.9', false],
    ['1.1.0', '1.0.0 - 1.2.0', true], ['1.3.0', '1.0.0 - 1.2.0', false],
    // npm audit's rule (semver with includePrerelease): a partial lower bound covers the
    // prereleases of that version, and a partial upper bound stops before the next one's.
    ['1.0.0-alpha.4', '>0 <=5.10.9', true], ['0.0.0-experimental', '>=0', true], ['1.0.0-rc.1', '1.0.0 - 1.2.0', true],
    ['2.0.0-beta.1', '<2', false], ['2.0.0-beta.1', '1.x', false], ['1.0.0-rc.1', '>=1.0.0', false],
  ]) assert.equal(satisfies(version, range), inside, `${version} in ${range}`);
});

test('sorts and drops invalid versions', () => {
  assert.deepEqual(sortVersions(['1.10.0', 'garbage', '1.2.0', '1.9.3', '\r\n 2.0.0\n']), ['1.2.0', '1.9.3', '1.10.0', '2.0.0']);
});

test('release lines follow npm caret rules below 1.0.0', async () => {
  const { releaseLine } = await import('../src/semver.js');
  assert.equal(releaseLine('2.3.4'), '2');
  assert.equal(releaseLine('0.9.1'), '0.9');
  assert.equal(releaseLine('0.0.4'), '0.0.4');
  assert.equal(releaseLine('garbage'), null);
});

test('acceptsVersion reads npm dependency specs and returns null for ones it cannot', () => {
  const cases = [
    ['1.18.3', '1.20.9', false], ['=1.18.3', '1.18.3', true], ['~2.2.0', '2.6.9', false], ['~2.2.0', '2.2.9', true],
    ['^1.18.3', '1.20.9', true], ['^1.18.3', '2.0.0', false], ['^0.2.1', '0.3.0', false], ['^0.0.3', '0.0.4', false],
    ['1.x', '1.9.0', true], ['2.2', '2.2.9', true], ['~1', '1.9.9', true], ['<2.2', '2.2.0', false],
    ['>=1.0.0 <2', '2.0.0', false], ['1.2.3 - 2.0.0', '2.0.0', true], ['1.0.0 || ^2.0.0', '2.5.0', true], ['*', '9.9.9', true],
    ['npm:lodash@^4', '4.17.21', null], ['github:a/b', '1.0.0', null], ['latest', '1.0.0', null], ['file:../x', '1.0.0', null],
  ];
  for (const [spec, version, expected] of cases) assert.equal(acceptsVersion(spec, version), expected, `${spec} ${version}`);
});
