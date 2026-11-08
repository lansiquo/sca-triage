import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/sca-triage.js', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });

test('--help prints help and exits 0, with or without a command', () => {
  for (const args of [['--help'], ['-h'], ['scan', '--help']]) {
    const r = run(...args);
    assert.equal(r.status, 0, args.join(' '));
    assert.match(r.stdout, /sca-triage/);
  }
});

test('no command prints help and exits 2 (usage error)', () => {
  const r = run();
  assert.equal(r.status, 2);
  assert.match(r.stdout, /sca-triage/);
});

// plan / fix --dry-run against a local fake registry: they must print the plan and change nothing.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { cpSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const fixture = fileURLToPath(new URL('./fixtures/project', import.meta.url));

function runAsync(args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

async function withRegistry(fn) {
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST') {
      res.end(JSON.stringify({
        'web-lib': [{ id: 1, url: 'https://github.com/advisories/GHSA-test-0001', title: 'test', severity: 'high', vulnerable_versions: '<2.0.1' }],
      }));
    } else {
      res.end(JSON.stringify({ versions: { '2.0.0': {}, '2.0.1': {}, '3.0.0': {} } }));
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`);
  } finally {
    server.close();
  }
}

for (const args of [['plan'], ['fix', '--dry-run']]) {
  test(`${args.join(' ')} shows the upgrade and changes nothing`, async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sca-plan-'));
    try {
      cpSync(fixture, dir, { recursive: true });
      const before = readFileSync(join(dir, 'package.json'), 'utf8') + readFileSync(join(dir, 'package-lock.json'), 'utf8');
      const r = await withRegistry((url) => runAsync([args[0], dir, ...args.slice(1)], { SCA_TRIAGE_REGISTRY: url }));
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /web-lib: 2\.0\.0 -> 2\.0\.1/);
      assert.match(r.stdout, /Dry run: nothing was changed/);
      const after = readFileSync(join(dir, 'package.json'), 'utf8') + readFileSync(join(dir, 'package-lock.json'), 'utf8');
      assert.equal(after, before);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('plan rejects fix-only options (usage error, exit 2)', () => {
  for (const extra of [['--apply'], ['--evidence', '/tmp/x'], ['--no-tests']]) {
    const r = run('plan', fixture, ...extra);
    assert.equal(r.status, 2, extra.join(' '));
    assert.match(r.stderr, /use "sca-triage fix" to apply/);
  }
});

test('fix rejects --dry-run combined with --apply', () => {
  const r = run('fix', fixture, '--dry-run', '--apply');
  assert.equal(r.status, 2);
});
