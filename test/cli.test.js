import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../bin/sca-triage.js', import.meta.url));
const run = (...args) => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });

test('--help prints help and exits 0; no command prints it and exits 2', () => {
  for (const args of [['--help'], ['-h'], ['scan', '--help']]) {
    const r = run(...args);
    assert.equal(r.status, 0, args.join(' '));
    assert.match(r.stdout, /sca-triage/);
  }
  const none = run();
  assert.equal(none.status, 2);
  assert.match(none.stdout, /sca-triage/);
});

test('--version prints the package version', () => {
  const r = run('--version');
  assert.equal(r.status, 0);
  assert.equal(r.stdout.trim(), JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version);
});

// plan / fix --dry-run against a local fake registry: they must print the plan and change nothing.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
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

const WEB_LIB_ADVISORY = {
  'web-lib': [{ id: 1, url: 'https://github.com/advisories/GHSA-test-0001', title: 'test', severity: 'high', vulnerable_versions: '<2.0.1' }],
};

async function withRegistry(fn, advisories = WEB_LIB_ADVISORY) {
  const server = createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.method === 'POST') {
      res.end(JSON.stringify(advisories));
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

test('fix refuses a default evidence folder that is a symbolic link', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'sca-evlink-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  cpSync(fixture, join(dir, 'app'), { recursive: true });
  rmSync(join(dir, 'app', 'evidence'), { recursive: true, force: true });
  mkdirSync(join(dir, 'elsewhere'));
  symlinkSync(join(dir, 'elsewhere'), join(dir, 'app', 'evidence'), 'dir');
  const r = run('fix', join(dir, 'app'), '--no-tests');
  assert.equal(r.status, 2);
  assert.match(r.stderr, /is a symbolic link; pass --evidence/);
});

// The exit code is the CI gate (the GitHub Action fails the build on 1).
test('scan exits 1 when a finding meets --fail-on and 0 when none does, with --json and --markdown output', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sca-scan-'));
  try {
    cpSync(fixture, dir, { recursive: true });
    await withRegistry(async (url) => {
      const env = { SCA_TRIAGE_REGISTRY: url };
      const gate = await runAsync(['scan', dir, '--markdown', join(dir, 'findings.md')], env);
      assert.equal(gate.status, 1, gate.stderr);
      assert.match(gate.stdout, /\[P1\] web-lib@2\.0\.0/);
      assert.match(gate.stdout, /Gate \(--fail-on P1\): FAIL/);
      assert.match(readFileSync(join(dir, 'findings.md'), 'utf8'), /\| P1 \| `web-lib@2\.0\.0` \|/);
      const none = await runAsync(['scan', dir, '--fail-on', 'none'], env);
      assert.equal(none.status, 0, none.stderr);
      assert.match(none.stdout, /Gate \(--fail-on none\): pass/);
      const json = await runAsync(['scan', dir, '--json'], env);
      assert.equal(json.status, 1);
      assert.deepEqual(JSON.parse(json.stdout).findings.map((f) => `${f.package}@${f.version} ${f.priority}`), ['web-lib@2.0.0 P1']);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Bad input must stop before any project is read or changed: /missing doesn't exist, and
// each error is about the option, never about a missing package.json.
test('usage errors exit 2 before anything is read or changed', () => {
  const missing = '/missing';
  for (const [args, message] of [
    [['audit', missing], /unknown command "audit"/],
    [['scan', missing, '--fail-on', 'P9'], /--fail-on must be one of/],
    [['scan', missing, '--fail-on', '--json'], /--fail-on requires a value/],
    [['scan', missing, '--markdown', '--json'], /--markdown requires a value/],
    [['scan', missing, '--apply'], /scan does not support option/],
    [['scan', missing, '--allow-major'], /scan does not support option/],
    [['plan', missing, '--min-priority'], /--min-priority requires a value/],
    ...[['--apply'], ['--evidence', '/tmp/x'], ['--no-tests']].map((extra) => [['plan', missing, ...extra], /plan does not support option/]),
    // "--min-priority --dry-run" used to take --dry-run as the priority and apply the upgrades.
    [['fix', missing, '--min-priority', '--dry-run', '--no-tests'], /--min-priority requires a value/],
    [['fix', missing, '--min-priority', 'garbage'], /--min-priority must be one of P1, P2, P3/],
    [['fix', missing, '--evidence', '--no-tests'], /--evidence requires a value/],
    [['fix', missing, '--dry-run', '--apply'], /--dry-run and --apply cannot be combined/],
    ...['scan', 'plan', 'fix'].map((cmd) => [[cmd, missing, '/tmp/another-dir'], /takes one directory, got 2/]),
  ]) {
    const r = run(...args);
    assert.equal(r.status, 2, args.join(' '));
    assert.match(r.stderr, message, args.join(' '));
  }
});

test('fix with nothing to upgrade changes no files, exits 0 and still writes the evidence', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sca-fix-clean-'));
  try {
    cpSync(fixture, dir, { recursive: true });
    const before = readFileSync(join(dir, 'package.json'), 'utf8') + readFileSync(join(dir, 'package-lock.json'), 'utf8');
    const evidence = join(dir, 'ev');
    const r = await withRegistry((url) => runAsync(['fix', dir, '--no-tests', '--evidence', evidence], { SCA_TRIAGE_REGISTRY: url }), {});
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Verified 0 of 0 upgrade target\(s\)/);
    assert.match(r.stdout, /After: 0 vulnerable packages/);
    assert.equal(readFileSync(join(dir, 'package.json'), 'utf8') + readFileSync(join(dir, 'package-lock.json'), 'utf8'), before);
    assert.ok(existsSync(join(evidence, 'REPORT.md')));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
