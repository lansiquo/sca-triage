// Plan and apply the smallest safe upgrades, then prove the result: run the
// project's own tests, rescan, and write an evidence folder.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { releaseLine } from './semver.js';
import { priorityRank, triage } from './triage.js';
import { formatMarkdown } from './report.js';

const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

// Arguments built from lockfile and registry data. Refuse anything outside the
// characters package names, versions and workspace paths use, so a crafted lockfile
// can't smuggle a flag or (with Windows' shell) a command into the npm call.
const SAFE_ARG = /^(?:--[a-z-]+|[A-Za-z0-9@.][A-Za-z0-9@._/:+~^=-]*)$/;

function spawnNpm(cmd, args, cwd) {
  const res = spawnSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    env: { ...process.env, npm_config_fund: 'false', npm_config_audit: 'false', npm_config_update_notifier: 'false' },
  });
  return { code: res.status ?? 1, output: `${res.stdout || ''}${res.stderr || ''}` };
}

// Every npm call goes through the argument check; `exec` is replaceable for tests.
function run(cmd, args, cwd, exec = spawnNpm) {
  const bad = args.find((a) => !SAFE_ARG.test(a));
  if (bad !== undefined) throw new Error(`refusing to run npm with unexpected argument ${JSON.stringify(bad)}`);
  return exec(cmd, args, cwd);
}

// The spec npm should install for a copy: "1.2.5", or "npm:lodash@4.17.21" for an alias.
function installSpec(f, target) {
  return f.installedAs && f.installedAs !== f.package ? `npm:${f.package}@${target}` : target;
}

// Plan the upgrades. Each vulnerable copy gets its own smallest safe target (on its own
// release line when one exists), and copies that share a target are grouped into one
// action. An action carries:
//   pins       - manifests (the root "" or a workspace path) that declare the package
//                directly: `npm install name@target --save-exact [-w workspace]`
//   overrides  - npm "overrides" entries for the copies nothing declares directly.
//                One global entry when that is unambiguous; otherwise entries scoped to
//                the packages that require each copy ({ parent: { name: spec } }), so
//                a global override never pins every copy (and a direct dependency, which
//                npm refuses) to one version.
export function planFixes(result, { minPriority = 'P3' } = {}) {
  const threshold = priorityRank(minPriority);
  const selected = result.findings.filter((f) => priorityRank(f.priority) >= threshold);
  const unfixable = selected.filter((f) => !f.fix.target);
  const fixable = selected.filter((f) => f.fix.target);

  const byName = new Map(); // installed name -> findings
  for (const f of fixable) {
    const name = f.installedAs || f.package;
    if (!byName.has(name)) byName.set(name, []);
    byName.get(name).push(f);
  }

  const actions = [];
  for (const [name, copies] of byName) {
    const targets = new Map(); // target -> copies
    for (const f of copies) {
      if (!targets.has(f.fix.target)) targets.set(f.fix.target, []);
      targets.get(f.fix.target).push(f);
    }
    const anyDirect = copies.some((f) => f.direct);
    // A global override rewrites every copy of the package, so it is used only when every
    // installed copy is in this plan, they all want the same target, and none is a direct
    // dependency (npm rejects an override that conflicts with a direct dependency).
    const installed = Math.max(...copies.map((f) => f.copiesInstalled ?? copies.length));
    const globalOverride = targets.size === 1 && !anyDirect && copies.length >= installed;
    for (const [target, group] of targets) {
      const spec = installSpec(group[0], target);
      const action = {
        package: group[0].package,
        name,
        target,
        spec,
        direct: false,
        dev: true,
        crossesMajor: false,
        from: [],
        pins: [],
        overrides: [],
      };
      for (const f of group) {
        action.from.push(f.version);
        action.crossesMajor ||= releaseLine(f.version) !== releaseLine(target);
        action.dev &&= Boolean(f.devOnly);
        if (f.direct) {
          action.direct = true;
          for (const d of f.declaredBy || [{ owner: '', kind: f.devOnly ? 'dev' : 'prod' }]) {
            if (!action.pins.some((p) => p.owner === d.owner)) action.pins.push({ owner: d.owner, dev: d.kind === 'dev' });
          }
        } else if (globalOverride) {
          if (!action.overrides.length) action.overrides.push({ scope: null, name, spec });
        } else {
          // Scope to the packages that require this copy; fall back to the folder it is nested in.
          let parents = (f.requiredBy || []).filter((p) => p !== name);
          if (!parents.length) {
            const i = f.path.lastIndexOf('/node_modules/');
            if (i !== -1) parents = [f.path.slice(0, i).split('node_modules/').pop()];
          }
          for (const scope of parents) {
            if (!action.overrides.some((o) => o.scope === scope)) action.overrides.push({ scope, name, spec });
          }
        }
      }
      actions.push(action);
    }
  }
  return { actions, unfixable };
}

// Merge planned overrides into a package.json "overrides" object, following npm's
// syntax: { name: spec } globally, or { parent: { name: spec } } scoped to a parent.
// A parent that already has a plain override keeps it under ".".
export function applyOverrides(existing, actions) {
  const overrides = existing && typeof existing === 'object' && !Array.isArray(existing) ? existing : {};
  const changes = [];
  for (const a of actions) {
    for (const o of a.overrides) {
      if (o.scope === null) {
        overrides[o.name] = o.spec;
        changes.push(`package.json overrides: "${o.name}": "${o.spec}"`);
      } else {
        const cur = Object.hasOwn(overrides, o.scope) ? overrides[o.scope] : undefined;
        const scoped = cur && typeof cur === 'object' ? cur : cur === undefined ? {} : { '.': cur };
        scoped[o.name] = o.spec;
        overrides[o.scope] = scoped;
        changes.push(`package.json overrides: "${o.scope}" > "${o.name}": "${o.spec}"`);
      }
    }
  }
  return { overrides, changes };
}

// Group the pins into one `npm install` per manifest and dependency type, so npm resolves
// the tree once per group instead of once per package.
export function pinCommands(actions) {
  const groups = new Map(); // "owner\0dev|prod" -> { owner, dev, specs }
  for (const a of actions) {
    for (const pin of a.pins) {
      const key = `${pin.owner}\0${pin.dev ? 'dev' : 'prod'}`;
      if (!groups.has(key)) groups.set(key, { owner: pin.owner, dev: pin.dev, specs: [] });
      const spec = `${a.name}@${a.spec}`;
      const g = groups.get(key);
      if (!g.specs.includes(spec)) g.specs.push(spec);
    }
  }
  return [...groups.values()].map((g) => {
    const flags = ['--save-exact', '--ignore-scripts', g.dev ? '--save-dev' : '--save-prod'];
    if (g.owner) flags.push('--workspace', g.owner);
    return { owner: g.owner, args: ['install', ...g.specs, ...flags] };
  });
}

const RESTORE_HINT = 'node_modules may still hold the partial install: run "npm ci" to match the restored lockfile';

export async function applyFixes(projectDir, { minPriority = 'P3', evidenceDir, runTests = true, lookups, exec } = {}) {
  const before = await triage(projectDir, lookups);
  const plan = planFixes(before, { minPriority });
  const changes = [];
  const npm = (args) => run(NPM, args, projectDir, exec);

  const pkgPath = join(projectDir, 'package.json');
  const lockPath = join(projectDir, 'package-lock.json');
  const pkgBefore = readFileSync(pkgPath, 'utf8');
  const lockBefore = readFileSync(lockPath, 'utf8');
  const scripts = JSON.parse(pkgBefore).scripts || {};
  const pins = pinCommands(plan.actions);
  // Everything an install step can rewrite, restored if fix fails before the tests:
  // the root manifest, each workspace manifest a pin targets, and the lockfile.
  const snapshots = [['package.json', pkgBefore], ...workspaceManifests(projectDir, pins), ['package-lock.json', lockBefore]];
  // If the tests can't run, record why, so the output can flag the upgrade as unverified.
  const testsSkipped = !runTests ? 'disabled with --no-tests' : !scripts.test ? 'no "test" script in package.json' : null;
  const testsEnabled = !testsSkipped;
  const runProjectTests = () => {
    const r = npm(['test']);
    return { command: 'npm test', code: r.code, passed: r.code === 0, output: r.output };
  };

  let testsBefore = null;
  let step = null; // the command being run, for the failure report
  try {
    // 0) Baseline test run, so the evidence shows what changed.
    testsBefore = testsEnabled ? runProjectTests() : null;

    // 1) Direct dependencies: pin the safe versions, one install per manifest and type.
    for (const cmd of pins) {
      step = { command: `npm ${cmd.args.join(' ')}` };
      const r = npm(cmd.args);
      if (r.code !== 0) throw Object.assign(new Error(`${step.command} failed:\n${r.output}`), { npmOutput: r.output });
      changes.push(step.command);
    }

    // 2) Copies nothing declares directly: npm overrides, then one install to apply them.
    if (plan.actions.some((a) => a.overrides.length)) {
      step = { command: 'write package.json overrides' };
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      const merged = applyOverrides(pkg.overrides, plan.actions);
      pkg.overrides = merged.overrides;
      writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
      changes.push(...merged.changes);
      step = { command: 'npm install --ignore-scripts' };
      const r = npm(['install', '--ignore-scripts']);
      if (r.code !== 0) throw Object.assign(new Error(`npm install (overrides) failed:\n${r.output}`), { npmOutput: r.output });
    }
  } catch (err) {
    throw rollback(err, { projectDir, evidenceDir, before, step, changes, snapshots, testsBefore });
  }

  // 3) The project's own tests decide whether the upgrade is safe to keep. A failure here
  //    keeps the changes (the evidence shows what broke) and the CLI exits 1.
  const tests = testsEnabled ? runProjectTests() : null;

  // 4) Rescan and write evidence.
  const after = await triage(projectDir, lookups);
  if (evidenceDir) {
    mkdirSync(evidenceDir, { recursive: true });
    writeFileSync(join(evidenceDir, 'before.json'), JSON.stringify(before, null, 2));
    writeFileSync(join(evidenceDir, 'after.json'), JSON.stringify(after, null, 2));
    writeFileSync(join(evidenceDir, 'package-lock.before.json'), lockBefore);
    writeFileSync(join(evidenceDir, 'package-lock.after.json'), readFileSync(lockPath, 'utf8'));
    if (testsBefore) writeFileSync(join(evidenceDir, 'tests.before.txt'), testsBefore.output);
    if (tests) writeFileSync(join(evidenceDir, 'tests.after.txt'), tests.output);
    const sbom = npm(['sbom', '--sbom-format', 'cyclonedx']);
    if (sbom.code === 0) writeFileSync(join(evidenceDir, 'sbom.cdx.json'), sbom.output);
    writeFileSync(join(evidenceDir, 'REPORT.md'), formatMarkdown(before, after, { changes, tests, testsBefore, testsSkipped }));
  }

  return { before, after, plan, changes, tests, testsBefore, testsSkipped, evidenceWritten: Boolean(evidenceDir && existsSync(evidenceDir)) };
}

// An install step failed (or something threw) before the tests ran: put package.json and
// package-lock.json back, record the failure in the evidence folder, and return the error
// to throw, with a note on what was restored.
function rollback(err, { projectDir, evidenceDir, before, step, changes, snapshots, testsBefore }) {
  const restoreErrors = [];
  for (const [file, text] of snapshots) {
    try {
      writeFileSync(join(projectDir, file), text);
    } catch (e) {
      restoreErrors.push(`${file}: ${e.message}`);
    }
  }
  const restored = !restoreErrors.length;
  const failure = {
    command: step?.command || null,
    message: err.npmOutput !== undefined ? `${step.command} exited with an error` : err.message,
    restored,
    files: snapshots.map(([file]) => file),
    restoreErrors,
    attempted: changes.slice(),
  };
  let evidenceNote = '';
  if (evidenceDir) {
    try {
      mkdirSync(evidenceDir, { recursive: true });
      writeFileSync(join(evidenceDir, 'before.json'), JSON.stringify(before, null, 2));
      if (testsBefore) writeFileSync(join(evidenceDir, 'tests.before.txt'), testsBefore.output);
      if (err.npmOutput !== undefined) writeFileSync(join(evidenceDir, 'install-failure.txt'), err.npmOutput);
      writeFileSync(join(evidenceDir, 'REPORT.md'), formatMarkdown(before, null, { failure, logFile: err.npmOutput !== undefined ? 'install-failure.txt' : null }));
      evidenceNote = `\nFailure report: ${join(evidenceDir, 'REPORT.md')}`;
    } catch (e) {
      evidenceNote = `\nCould not write the failure report: ${e.message}`;
    }
  }
  const status = restored
    ? `${listFiles(failure.files)} were restored to their original contents; ${RESTORE_HINT}.`
    : `could NOT restore ${restoreErrors.join('; ')}`;
  const out = new Error(`${err.message.trimEnd()}\nFix rolled back: ${status}${evidenceNote}`);
  out.cause = err;
  out.failure = failure;
  return out;
}

// Workspace manifests that a pin group installs into, as [relative path, original text].
// Only files inside the project are read; npm itself rejects unknown workspaces.
function workspaceManifests(projectDir, pins) {
  const root = resolve(projectDir);
  const out = [];
  for (const owner of new Set(pins.map((p) => p.owner).filter(Boolean))) {
    const file = resolve(root, owner, 'package.json');
    if (!file.startsWith(root + sep) || !existsSync(file)) continue;
    out.push([relative(root, file).split(sep).join('/'), readFileSync(file, 'utf8')]);
  }
  return out;
}

export function listFiles(files) {
  return files.length < 2 ? files.join('') : `${files.slice(0, -1).join(', ')} and ${files[files.length - 1]}`;
}
