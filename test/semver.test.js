import test from 'node:test';
import assert from 'node:assert/strict';
import { compare, satisfies, sortVersions } from '../src/semver.js';

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
  assert.throws(() => satisfies('1.0.0', '^1.0.0'), /unsupported range/);
});

test('sorts and drops invalid versions', () => {
  assert.deepEqual(sortVersions(['1.10.0', 'garbage', '1.2.0', '1.9.3']), ['1.2.0', '1.9.3', '1.10.0']);
});

test('release lines follow npm caret rules below 1.0.0', async () => {
  const { releaseLine } = await import('../src/semver.js');
  assert.equal(releaseLine('2.3.4'), '2');
  assert.equal(releaseLine('0.9.1'), '0.9');
  assert.equal(releaseLine('0.0.4'), '0.0.4');
  assert.equal(releaseLine('garbage'), null);
});
