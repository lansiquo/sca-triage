import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAdvisories, registryUrl, severityRank } from '../src/advisories.js';

test('rejects advisory responses that are not the documented shape', () => {
  for (const raw of [null, [], 'ok', { lodash: 'nope' }, { lodash: [{ severity: 'high' }] }, { lodash: [null] }]) {
    assert.throws(() => normalizeAdvisories(raw), /advisory response/, JSON.stringify(raw));
  }
  const out = normalizeAdvisories({ lodash: [{ url: 'https://github.com/advisories/GHSA-1', vulnerable_versions: '<4.17.21', severity: 'high' }] });
  assert.equal(out.lodash[0].ghsa, 'GHSA-1');
  assert.equal(Object.getPrototypeOf(out), null);
});

test('requires https for the registry, except on localhost', () => {
  assert.equal(registryUrl(undefined), 'https://registry.npmjs.org');
  assert.equal(registryUrl('https://npm.example.com/'), 'https://npm.example.com');
  assert.equal(registryUrl('http://localhost:4873'), 'http://localhost:4873');
  assert.equal(registryUrl('http://127.0.0.1:4873'), 'http://127.0.0.1:4873');
  assert.throws(() => registryUrl('http://npm.example.com'), /must use https/);
  assert.throws(() => registryUrl('file:///etc/passwd'), /must use https/);
  assert.throws(() => registryUrl('not a url'), /not a valid URL/);
  assert.throws(() => registryUrl('https://user:pw@npm.example.com'), /credentials/);
});

test('severity lookup ignores Object.prototype names', () => {
  assert.equal(severityRank('critical'), 4);
  assert.equal(severityRank('constructor'), 0);
  assert.equal(severityRank('__proto__'), 0);
});
