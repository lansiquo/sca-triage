#!/usr/bin/env node
// sca-triage: rank npm dependency vulnerabilities by whether your code loads them,
// then apply the smallest safe upgrades and prove them with your tests.

import { resolve, join } from 'node:path';
import { writeFileSync } from 'node:fs';
import { triage, gateFails } from '../src/triage.js';
import { planFixes, applyFixes } from '../src/fix.js';
import { formatTable, formatMarkdown, formatTestsLine, displayName, plain, formatBundled } from '../src/report.js';

const HELP = `Usage:
  sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
  sca-triage plan [dir] [--min-priority P1|P2|P3]
  sca-triage fix  [dir] [--min-priority P1|P2|P3] [--evidence <dir>] [--no-tests]

scan   Find known vulnerabilities in the dependency tree locked in
       package-lock.json (v2/v3), ranked by severity and whether your code loads
       the package. Exit code 1 when a finding meets --fail-on (default P1), so
       it works as a CI gate. --json prints the full result; --markdown writes
       the findings table to a file.
plan   Dry run: show the smallest safe upgrade for each finding (all
       priorities unless --min-priority is set). Changes nothing.
fix    Apply those upgrades, run "npm test", rescan, and write an evidence
       folder. Exit code 1 when the tests fail after the upgrade. If an install
       fails, the manifests and package-lock.json are restored (exit code 2).
       "fix --dry-run" is the same as "plan".

Priorities:
  P1  high/critical, and your code loads the package (directly or through a dependency)
  P2  high/critical but not loaded at runtime, or moderate and loaded
  P3  everything else

Exit code 2 means a usage or input error (bad option, more than one directory, missing
lockfile, registry error).
Advisories come from registry.npmjs.org; set SCA_TRIAGE_REGISTRY to use an https:// mirror.
`;

function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json' || a === '--help' || a === '-h') opts[a.replace(/^-+/, '')] = true;
    else if (a === '--apply') opts.apply = true; // accepted for compatibility: fix always applies
    else if (a === '--dry-run') opts.dryRun = true;
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
    return opts.help || opts.h ? 0 : 2; // asking for help succeeds; a missing command is a usage error
  }
  if (opts._.length > 2) {
    throw new Error(`${command} takes one directory, got ${opts._.length - 1}: ${opts._.slice(1).join(' ')}`);
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

  if (command === 'plan' || command === 'fix') {
    const dryRun = command === 'plan' || opts.dryRun;
    if (command === 'plan' && (opts.apply || opts.evidence || opts.noTests)) {
      throw new Error('plan only shows upgrades; use "sca-triage fix" to apply them');
    }
    if (opts.dryRun && opts.apply) throw new Error('--dry-run and --apply cannot be combined');
    const minPriority = opts['min-priority'] || 'P3';
    if (dryRun) {
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
      for (const line of formatBundled(plan.bundled)) process.stdout.write(line + '\n');
      for (const w of result.warnings || []) process.stderr.write(`warning: ${plain(w)}\n`);
      process.stdout.write('\nDry run: nothing was changed. Run "sca-triage fix" to apply these upgrades.\n');
      return 0;
    }
    const evidenceDir = opts.evidence ? resolve(opts.evidence) : join(dir, 'evidence', new Date().toISOString().replace(/[:.]/g, '-'));
    const r = await applyFixes(dir, { minPriority, evidenceDir, runTests: !opts.noTests });
    process.stdout.write(`Upgraded ${r.plan.actions.length} package(s):\n${r.changes.map((c) => `  ${plain(c)}`).join('\n')}\n`);
    for (const line of formatBundled(r.plan.bundled)) process.stdout.write(line + '\n');
    for (const w of new Set([...(r.before.warnings || []), ...(r.after.warnings || [])])) process.stderr.write(`warning: ${plain(w)}\n`);
    process.stdout.write(`${formatTestsLine(r)}\n`);
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
