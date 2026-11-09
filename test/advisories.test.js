import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { normalizeAdvisories, registryUrl, severityRank, fetchJson, retryDelay } from '../src/advisories.js';

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

// A local server that answers each request with the next scripted response.
async function withServer(responses, fn) {
  let hits = 0;
  const server = createServer((req, res) => {
    const r = responses[Math.min(hits, responses.length - 1)];
    hits += 1;
    if (r === 'drop') return req.socket.destroy();
    res.writeHead(r.status, { 'content-type': 'application/json', ...r.headers });
    res.end(r.body ?? '{}');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}/x`, () => hits);
  } finally {
    server.close();
  }
}

const ok = { status: 200, body: '{"ok":true}' };

test('retries 429, 5xx and dropped connections, honouring Retry-After', async () => {
  const waits = [];
  const wait = async (ms) => { waits.push(ms); };
  await withServer([{ status: 503 }, { status: 429, headers: { 'retry-after': '2' } }, ok], async (url, hits) => {
    assert.deepEqual(await fetchJson(url, undefined, { wait }), { ok: true });
    assert.equal(hits(), 3);
  });
  assert.deepEqual(waits, [500, 2000]);
  waits.length = 0;
  await withServer(['drop', ok], async (url, hits) => {
    assert.deepEqual(await fetchJson(url, undefined, { wait }), { ok: true });
    assert.equal(hits(), 2);
  });
  assert.deepEqual(waits, [500]);
});

test('gives up after 3 attempts and does not retry other 4xx errors', async () => {
  const wait = async () => {};
  await withServer([{ status: 502 }], async (url, hits) => {
    await assert.rejects(fetchJson(url, { method: 'POST' }, { wait }), /POST .* -> HTTP 502 \(after 3 attempts\)/);
    assert.equal(hits(), 3);
  });
  for (const status of [400, 404, 401]) {
    await withServer([{ status }], async (url, hits) => {
      await assert.rejects(fetchJson(url, undefined, { wait }), new RegExp(`HTTP ${status}$`));
      assert.equal(hits(), 1);
    });
  }
  await withServer([{ status: 200, body: 'nope' }], async (url, hits) => {
    await assert.rejects(fetchJson(url, undefined, { wait }), /not JSON/);
    assert.equal(hits(), 1);
  });
});

test('retry delays back off and are capped', () => {
  assert.equal(retryDelay(0), 500);
  assert.equal(retryDelay(1), 1500);
  assert.equal(retryDelay(0, '3'), 3000);
  assert.equal(retryDelay(0, '0'), 0);
  assert.equal(retryDelay(0, '120'), 10_000);
  assert.equal(retryDelay(1, 'Wed, 21 Oct 2015 07:28:00 GMT'), 1500); // dates fall back to backoff
});
