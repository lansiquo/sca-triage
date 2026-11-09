#!/usr/bin/env node
// Runs the whole sca-triage lab in one go: install, scan, plan, fix a copy, rescan, show the report.
// lab/vulnerable-app is never changed; each run works in its own new temporary folder.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const lab = join(root, 'lab', 'vulnerable-app');
const cli = join(root, 'bin', 'sca-triage.js');
const run = mkdtempSync(join(tmpdir(), 'sca-triage-lab-'));
const app = join(run, 'app');
const evidence = join(run, 'evidence');

let n = 0;
function step(title, cmd, args, expect) {
  n += 1;
  process.stdout.write(`\n== ${n}. ${title}\n$ ${[cmd, ...args].join(' ')}\n\n`);
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', shell: process.platform === 'win32' && cmd === 'npm' });
  if (r.status !== expect) {
    process.stderr.write(`\nLab stopped: step ${n} exited with ${r.status}, expected ${expect}.\n`);
    process.exit(1);
  }
}

step('Install the intentionally vulnerable app (no install scripts)', 'npm', ['ci', '--prefix', 'lab/vulnerable-app', '--ignore-scripts', '--no-audit', '--no-fund'], 0);
step('Scan it: the P1 gate is expected to FAIL (exit 1)', process.execPath, [cli, 'scan', 'lab/vulnerable-app'], 1);
step('Plan the upgrades (dry run, changes nothing)', process.execPath, [cli, 'plan', 'lab/vulnerable-app'], 0);

n += 1;
cpSync(lab, app, { recursive: true });
process.stdout.write(`\n== ${n}. Copy the app to a new temporary folder\n${app}\n`);

step('Fix the copy: upgrade, run its tests, rescan, save evidence', process.execPath, [cli, 'fix', app, '--evidence', evidence], 0);
step('Scan the fixed copy: the P1 gate should pass', process.execPath, [cli, 'scan', app], 0);

n += 1;
process.stdout.write(`\n== ${n}. Evidence report (${join(evidence, 'REPORT.md')})\n\n`);
process.stdout.write(readFileSync(join(evidence, 'REPORT.md'), 'utf8'));
process.stdout.write(`\nLab complete. Fixed copy: ${app}\nEvidence: ${evidence}\n`);
