#!/usr/bin/env node
// sca-triage: rank npm dependency vulnerabilities by whether your code loads them,
// then apply the smallest safe upgrades and prove them with your tests.

import { resolve, join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { triage, gateFails } from '../src/triage.js';
import { planFixes, applyFixes } from '../src/fix.js';
import { formatTable, formatMarkdown, displayName, plain } from '../src/report.js';

const HELP = `Usage:
  sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
  sca-triage fix  [dir] [--apply] [--min-priority P1|P2|P3] [--evidence <dir>] [--no-tests]

scan   Find known vulnerabilities in the dependency tree locked in
       package-lock.json (v2/v3), ranked by severity and whether your code loads
       the package. Exit code 1 when a finding meets --fail-on (default P1), so
       it works as a CI gate. --json prints the full result; --markdown writes
       the findings table to a file.
fix    Show the smallest safe upgrade for each finding (all priorities unless
       --min-priority is set). With --apply, make the changes, run "npm test",
       rescan, and write an evidence folder. Exit code 1 when the tests fail
       after the upgrade.

Priorities:
  P1  high/critical, and your code loads the package (directly or through a dependency)
  P2  high/critical but not loaded at runtime, or moderate and loaded
  P3  everything else

Exit code 2 means a usage or input error (bad option, missing lockfile, registry error).
Advisories come from registry.npmjs.org; set SCA_TRIAGE_REGISTRY to use an https:// mirror.
`;

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json' || a === '--apply' || a === '--help' || a === '-h') opts[a.replace(/^-+/, '')] = true;
    else if (a === '--no-tests') opts.noTests = true;
    else if (['--fail-on', '--min-priority', '--evidence', '--markdown'].includes(a)) opts[a.slice(2)] = argv[++i];
    else if (a.startsWith('--')) throw new Error(`unknown option ${a}`);
    else opts._.push(a);
  }
  return opts;
}

const VALID = new Set(['P1', 'P2', 'P3', 'none']);

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const [command, dirArg] = opts._;
  if (opts.help || opts.h || !command) {
    process.stdout.write(HELP);
    return command ? 0 : 2;
  }
  const dir = resolve(dirArg || '.');

  if (command === 'scan') {
    const failOn = opts['fail-on'] || 'P1';
    if (!VALID.has(failOn)) throw new Error(`--fail-on must be one of ${[...VALID].join(', ')}`);
    const result = await triage(dir);
    if (opts.markdown) writeFileSync(opts.markdown, formatMarkdown(result, null));
    process.stdout.write((opts.json ? JSON.stringify(result, null, 2) : formatTable(result)) + '\n');
    const fails = gateFails(result, failOn);
    if (!opts.json) process.stdout.write(`\nGate (--fail-on ${failOn}): ${fails ? 'FAIL' : 'pass'}\n`);
    return fails ? 1 : 0;
  }

  if (command === 'fix') {
    const minPriority = opts['min-priority'] || 'P3';
    if (!opts.apply) {
      const result = await triage(dir);
      const plan = planFixes(result, { minPriority });
      if (!plan.actions.length) process.stdout.write('Nothing to upgrade.\n');
      for (const a of plan.actions) {
        const how = [
          ...a.pins.map((p) => `npm install ${a.name}@${a.spec} --save-exact${p.dev ? ' --save-dev' : ''}${p.owner ? ` --workspace ${p.owner}` : ''}`),
          ...a.overrides.map((o) => (o.scope === null ? `overrides: "${o.name}": "${o.spec}"` : `overrides: "${o.scope}" > "${o.name}": "${o.spec}"`)),
        ];
        const label = displayName({ package: a.package, installedAs: a.name });
        process.stdout.write(
          `${plain(`${label}: ${[...new Set(a.from)].join(', ')} -> ${a.target}`)}${a.crossesMajor ? '  (major upgrade: review release notes)' : ''}\n${how.map((h) => `    ${plain(h)}\n`).join('')}`,
        );
      }
      for (const f of plan.unfixable) process.stdout.write(plain(`${displayName(f)}@${f.version}: no fixed version published yet`) + '\n');
      for (const w of result.warnings || []) process.stderr.write(`warning: ${plain(w)}\n`);
      process.stdout.write('\nDry run. Re-run with --apply to make these changes.\n');
      return 0;
    }
    const evidenceDir = opts.evidence ? resolve(opts.evidence) : join(dir, 'evidence', new Date().toISOString().replace(/[:.]/g, '-'));
    const r = await applyFixes(dir, { minPriority, evidenceDir, runTests: !opts.noTests });
    process.stdout.write(`Applied ${r.changes.length} change(s):\n${r.changes.map((c) => `  ${plain(c)}`).join('\n')}\n`);
    for (const w of r.after.warnings || []) process.stderr.write(`warning: ${plain(w)}\n`);
    if (r.tests) process.stdout.write(`Tests (npm test): ${r.tests.passed ? 'passed' : 'FAILED'}\n`);
    else process.stdout.write(`Tests: not run — changes applied but UNVERIFIED (${r.testsSkipped})\n`);
    process.stdout.write(`After: ${r.after.findings.length} vulnerable packages (P1: ${r.after.summary.P1}, P2: ${r.after.summary.P2}, P3: ${r.after.summary.P3})\n`);
    process.stdout.write(`Evidence: ${evidenceDir}\n`);
    return r.tests && !r.tests.passed ? 1 : 0;
  }

  throw new Error(`unknown command "${command}" (try --help)`);
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`sca-triage: ${err.message}\n`);
    process.exit(2);
  },
);
