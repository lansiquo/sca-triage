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
