// Human-readable output: a terminal table and a Markdown report.

const LEVEL_LABEL = {
  imported: 'imported by your code',
  'via-imported': 'pulled in by an imported dependency',
  'test-only': 'test code only',
  'not-imported': 'not imported',
};

// Lockfile paths, package.json names and test output come from the scanned project,
// so they are escaped before they reach Markdown (a PR comment or job summary) or a terminal.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;

export function escapeMarkdown(value) {
  return String(value)
    .replace(CONTROL, ' ')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/[\\`*_[\]!|~]/g, '\\$&');
}

// Inline code renders its content literally (no HTML, no links), so it is used as-is
// when it can't break out of the span or the table cell; otherwise fall back to escaping.
export function codeSpan(value) {
  const s = String(value).replace(CONTROL, ' ');
  return /[`|]/.test(s) ? escapeMarkdown(s) : `\`${s}\``;
}

// One line of terminal text: control characters (escape sequences, newlines) become spaces.
export function plain(value) {
  return String(value).replace(CONTROL, ' ');
}

// "foo (npm:lodash)" for an aliased install, "lodash" otherwise.
export function displayName(f) {
  return f.installedAs && f.installedAs !== f.package ? `${f.installedAs} (npm:${f.package})` : f.package;
}

// Plan and fix output: vulnerable copies that ship inside another package's tarball,
// grouped by that package, since upgrading it is the only way to change them.
export function formatBundled(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.bundledIn.name}@${f.bundledIn.version}`;
    if (!groups.has(key)) groups.set(key, new Set());
    groups.get(key).add(`${displayName(f)}@${f.version}`);
  }
  if (!groups.size) return [];
  return [
    "Bundled inside other packages (npm overrides can't change these; upgrade the package that bundles them):",
    ...[...groups].sort(([a], [b]) => a.localeCompare(b)).map(([owner, copies]) => `  ${plain(owner)}: ${plain([...copies].sort().join(', '))}`),
  ];
}

// Plan and fix output: upgrades fix leaves alone because no npm override can change only
// those copies (see planFixes), with the reason.
export function formatManual(manual = []) {
  if (!manual.length) return [];
  return [
    'Needs a manual upgrade (an npm override would change more than these copies):',
    ...manual.map(({ action: a, reason }) => `  ${plain(displayName({ package: a.package, installedAs: a.name }))} ${plain([...new Set(a.from)].join(', '))} -> ${a.target}: ${plain(reason)}`),
  ];
}

export function upgradeText(f, esc = plain) {
  if (f.bundledIn) return `bundled in ${esc(`${f.bundledIn.name}@${f.bundledIn.version}`)}: upgrade ${esc(f.bundledIn.name)}`;
  if (!f.fix.target) return 'no fixed version published';
  return `${esc(f.version)} -> ${f.fix.target}${f.fix.crossesMajor ? ' (major upgrade)' : ''}${f.direct ? '' : ' (override)'}${f.fix.verified === false ? ' (unverified: not auto-applied)' : ''}`;
}

export function formatTable(result) {
  const lines = [];
  const s = result.summary;
  lines.push(`${plain(result.project)}: ${result.packagesScanned} packages scanned, ${result.findings.length} vulnerable (P1: ${s.P1}, P2: ${s.P2}, P3: ${s.P3})`);
  for (const w of result.warnings || []) lines.push(`warning: ${plain(w)}`);
  if (!result.findings.length) {
    lines.push('No known vulnerabilities in the installed versions.');
    return lines.join('\n');
  }
  lines.push('');
  for (const f of result.findings) {
    lines.push(`[${f.priority}] ${plain(displayName(f))}@${plain(f.version)}  ${plain(f.severity).toUpperCase()}, ${f.advisories.length} advisor${f.advisories.length === 1 ? 'y' : 'ies'}`);
    lines.push(`     reachability: ${LEVEL_LABEL[f.reachability]}${f.evidence.length ? ` (${plain(f.evidence.slice(0, 2).join(', '))})` : ''}`);
    if (!f.direct && f.via.length) lines.push(`     dependency of: ${plain(f.via.join(', '))}`);
    lines.push(`     fix: ${upgradeText(f)}`);
    for (const a of f.advisories.slice(0, 3)) lines.push(`       - ${plain(a.ghsa)} ${plain(a.severity)}: ${plain(a.title)}`);
    if (f.advisories.length > 3) lines.push(`       - ...and ${f.advisories.length - 3} more`);
  }
  return lines.join('\n');
}

// node --test / TAP: "# pass 5" and "# fail 1" totals, and the names of failing tests.
function summarizeTap(output = '') {
  const pass = /^# pass (\d+)/m.exec(output);
  const fail = /^# fail (\d+)/m.exec(output);
  return pass && fail ? `, ${pass[1]} passed / ${fail[1]} failed` : '';
}
function failingTests(output = '') {
  return [...output.matchAll(/^not ok \d+ - (.+)$/gm)].map((m) => m[1].trim());
}

// The one-line test result `fix` prints. When the tests also failed before the
// upgrade, say so: the failure may not be the upgrade's fault.
export function formatTestsLine({ tests, testsBefore, testsSkipped } = {}) {
  if (!tests) return `Tests: not run — changes applied but UNVERIFIED (${testsSkipped || 'reason not recorded'})`;
  if (tests.passed) return 'Tests (npm test): passed';
  if (testsBefore && !testsBefore.passed) {
    return 'Tests (npm test): FAILED (also failed before the upgrade, so this failure may not be caused by it)';
  }
  return 'Tests (npm test): FAILED';
}

export function formatMarkdown(before, after, extras = {}) {
  const row = (f) =>
    `| ${f.priority} | ${codeSpan(`${displayName(f)}@${f.version}`)} | ${escapeMarkdown(f.severity)} | ${f.advisories.length} | ${LEVEL_LABEL[f.reachability]} | ${upgradeText(f, escapeMarkdown)} |`;
  const table = (r) =>
    r.findings.length
      ? ['| Priority | Package | Severity | Advisories | Reachability | Fix |', '|---|---|---|---|---|---|', ...r.findings.map(row)].join('\n')
      : '_No known vulnerabilities in the installed versions._';
  const out = [
    `# Remediation evidence: ${escapeMarkdown(before.project)}`,
    '',
    `Generated ${new Date().toISOString()} by sca-triage. Advisory data: GitHub Advisory Database via the npm registry.`,
    '',
    '## Before',
    `${before.findings.length} vulnerable packages (P1: ${before.summary.P1}, P2: ${before.summary.P2}, P3: ${before.summary.P3}).`,
    '',
    table(before),
  ];
  const warnings = [...new Set([...(before.warnings || []), ...(after?.warnings || [])])];
  if (warnings.length) out.push('', '## Warnings', '', ...warnings.map((w) => `- ${escapeMarkdown(w)}`));
  if (extras.failure) {
    const f = extras.failure;
    out.push('', '## Fix FAILED: changes rolled back', '');
    if (f.command) out.push(`Failed step: ${codeSpan(f.command)}`, '');
    out.push(`Error: ${escapeMarkdown(f.message)}${extras.logFile ? ` (npm output: \`${extras.logFile}\`)` : ''}`, '');
    out.push(
      f.restored
        ? `${(f.files || ['package.json', 'package-lock.json']).map((file) => codeSpan(file)).join(', ').replace(/, ([^,]*)$/, ' and $1')} were **restored** to their original contents.`
        : `**Restore failed**: ${escapeMarkdown(f.restoreErrors.join('; '))}`,
    );
    out.push(`\`node_modules\` was not restored and may not match the lockfile: run \`npm ci\` before using the project.`);
    if (f.attempted?.length) out.push('', 'Rolled back:', '', ...f.attempted.map((c) => `- ${codeSpan(c)}`));
  }
  if (extras.changes?.length) {
    out.push('', '## Changes applied', '', ...extras.changes.map((c) => `- ${codeSpan(c)}`));
  }
  if (extras.manual?.length) {
    out.push('', '## Needs a manual upgrade', '', 'An npm override would change more than these copies, so `fix` left them as they are:', '',
      ...extras.manual.map(({ action: a, reason }) => `- ${codeSpan(`${displayName({ package: a.package, installedAs: a.name })}@${[...new Set(a.from)].join(', ')}`)} -> ${escapeMarkdown(a.target)}: ${escapeMarkdown(reason)}`));
  }
  if (extras.verificationError) {
    out.push('', '## Verification FAILED: applied changes preserved', '',
      `**No successful verification was completed.** ${escapeMarkdown(extras.verificationError)}`,
      'Review the before/after manifest and lockfile snapshots and commands.txt before proceeding.');
  }
  if (extras.verificationWarnings?.length) {
    out.push('', '## Verification warnings', '', ...extras.verificationWarnings.map((w) => `- ${escapeMarkdown(w)}`));
  }
  if (extras.tests) {
    const line = (t) => `**${t.passed ? 'passed' : 'FAILED'}** (exit code ${t.code})`;
    out.push('', '## Project tests (`npm test`)', '', '| Run | Result | Output |', '|---|---|---|');
    if (extras.testsBefore) out.push(`| Before upgrade | ${line(extras.testsBefore)}${summarizeTap(extras.testsBefore.output)} | \`tests.before.txt\` |`);
    out.push(`| After upgrade | ${line(extras.tests)}${summarizeTap(extras.tests.output)} | \`tests.after.txt\` |`);
    const failedBefore = failingTests(extras.testsBefore?.output);
    if (failedBefore.length) out.push('', 'Failing before the upgrade:', '', ...failedBefore.map((n) => `- ${escapeMarkdown(n)}`));
  } else if (after) {
    // A fix report always says whether the tests checked the upgrade. Scan reports (no "after") skip this.
    out.push('', '## Project tests (`npm test`)', '', `**Not run — changes applied but UNVERIFIED** (${extras.testsSkipped || 'reason not recorded'}).`);
  }
  if (after) {
    out.push('', '## After', `${after.findings.length} vulnerable packages (P1: ${after.summary.P1}, P2: ${after.summary.P2}, P3: ${after.summary.P3}).`, '', table(after));
  }
  out.push(
    '',
    '## Limits',
    '',
    '- Reachability is import-level: "imported" means the code loads the package, not that the vulnerable function is proven to run.',
    '- Results reflect the advisory database at scan time. Zero findings is not a security certification.',
  );
  return out.join('\n') + '\n';
}
