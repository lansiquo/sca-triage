// Plan and apply the smallest safe upgrades, then prove the result: run the
// project's own tests, rescan, and write an evidence folder.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, mkdtempSync, openSync, closeSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve, sep, dirname } from 'node:path';
import { acceptsVersion, releaseLine, compare } from './semver.js';
import { loadProject } from './lockfile.js';
import { priorityRank, triage } from './triage.js';
import { formatMarkdown } from './report.js';

const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

// Arguments built from lockfile and registry data. Refuse anything outside the
// characters package names, versions and workspace paths use, so a crafted lockfile
// can't smuggle a flag or (with Windows' shell) a command into the npm call.
const SAFE_ARG = /^(?:--[a-z-]+|[A-Za-z0-9@.][A-Za-z0-9@._/:+~^=-]*)$/;

function spawnNpm(cmd, args, cwd) {
  // File-backed capture avoids spawnSync's default 1 MiB pipe buffer terminating
  // otherwise successful test suites. Keep stderr out of machine-readable stdout.
  const temp = mkdtempSync(join(tmpdir(), 'sca-triage-npm-'));
  let out, err;
  try {
    out = openSync(join(temp, 'stdout'), 'w');
    err = openSync(join(temp, 'stderr'), 'w');
    const res = spawnSync(cmd, args, {
      cwd, stdio: ['ignore', out, err], shell: process.platform === 'win32',
      env: { ...process.env, npm_config_fund: 'false', npm_config_audit: 'false', npm_config_update_notifier: 'false' },
    });
    const stdout = readFileSync(join(temp, 'stdout'), 'utf8');
    const stderr = readFileSync(join(temp, 'stderr'), 'utf8');
    const error = res.error?.message || (res.signal ? `terminated by signal ${res.signal}` : null);
    return { code: res.status ?? 2, stdout, stderr, output: stdout + stderr, error };
  } finally {
    if (out !== undefined) closeSync(out);
    if (err !== undefined) closeSync(err);
    rmSync(temp, { recursive: true, force: true });
  }
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
  if (!['P1', 'P2', 'P3'].includes(minPriority)) throw new Error('--min-priority must be one of P1, P2, P3');
  const threshold = priorityRank(minPriority);
  const selected = result.findings.filter((f) => priorityRank(f.priority) >= threshold);
  // Copies bundled inside another package's tarball: npm overrides can't reach them, so
  // they are listed for a manual upgrade of that package instead of planned.
  const bundled = selected.filter((f) => f.bundledIn);
  const unfixable = selected.filter((f) => !f.bundledIn && (!f.fix.target || f.fix.verified === false));
  const fixable = selected.filter((f) => !f.bundledIn && f.fix.target && f.fix.verified !== false);

  const byName = new Map(); // installed name -> findings
  for (const f of fixable) {
    const name = f.installedAs || f.package;
    const key = `${name}\0${f.package}`;
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push(f);
  }

  const actions = [];
  for (const copies of byName.values()) {
    const name = copies[0].installedAs || copies[0].package;
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
        paths: group.map((f) => f.path),
      };
      for (const f of group) {
        action.from.push(f.version);
        action.crossesMajor ||= releaseLine(f.version) !== releaseLine(target);
        action.dev &&= Boolean(f.devOnly);
        if (f.direct) {
          action.direct = true;
          for (const d of f.declaredBy || [{ owner: '', kind: f.devOnly ? 'dev' : 'prod' }]) {
            let pin = action.pins.find((p) => p.owner === d.owner);
            if (!pin) { pin = { owner: d.owner, kinds: [], dev: true }; action.pins.push(pin); }
            if (!pin.kinds.includes(d.kind)) pin.kinds.push(d.kind);
            pin.dev &&= d.kind === 'dev';
          }
          // A package that also uses this copy but whose range excludes the target (express
          // requiring body-parser "1.18.3") would get its own old copy once the pin lands.
          for (const r of f.requiredEdges || f.requiredSpecs || []) {
            if (r.by === name || acceptsVersion(r.spec, target) !== false) continue;
            const scope = r.version ? `${r.by}@${r.version}` : r.by;
            if (!action.overrides.some((o) => o.scope === scope)) action.overrides.push({ scope, name, spec });
          }
        } else if (globalOverride) {
          if (!action.overrides.length) action.overrides.push({ scope: null, name, spec });
        } else {
          // Scope to the packages that require this copy; fall back to the folder it is nested in.
          let parents = f.requiredEdges?.length
            ? f.requiredEdges.map((p) => `${p.by}@${p.version}`)
            : (f.requiredBy || []).filter((p) => p !== name);
          if (!parents.length) {
            const i = f.path.lastIndexOf('/node_modules/');
            if (i !== -1) parents = [f.path.slice(0, i).split('node_modules/').pop()];
          }
          if (!parents.length) throw new Error(`cannot safely scope an override for ${name} at ${f.path}; upgrade its parent manually`);
          for (const scope of parents) {
            if (!action.overrides.some((o) => o.scope === scope)) action.overrides.push({ scope, name, spec });
          }
        }
      }
      actions.push(action);
    }
  }
  validateActions(actions);
  validateCoverage(actions, result.inventory);
  return { actions, unfixable, bundled };
}

// Merge planned overrides into a package.json "overrides" object, following npm's
// syntax: { name: spec } globally, or { parent: { name: spec } } scoped to a parent.
// A parent that already has a plain override keeps it under ".".
// npm selectors apply throughout a parent's subtree. Check every matching copy,
// including safe or lower-priority copies, before allowing an override to rewrite it.
function validateCoverage(actions, inventory) {
  if (!inventory) return;
  const nodes = new Map(inventory.map((item) => [item.path, item]));
  for (const action of actions) for (const override of action.overrides) {
    const roots = override.scope === null ? inventory : inventory.filter((item) => `${item.name}@${item.version}` === override.scope);
    const queue = [...roots], seen = new Set();
    while (queue.length) {
      const item = queue.pop();
      if (seen.has(item.path)) continue;
      seen.add(item.path);
      if (item.name === action.name && !item.bundledIn) {
        if (item.realName !== action.package || (!action.paths.includes(item.path)
          && (releaseLine(item.version) !== releaseLine(action.target) || compare(item.version, action.target) > 0))) {
          throw new Error(`override ${override.scope || '(global)'} > ${action.name} would rewrite an unrelated copy at ${item.path}; upgrade its parents manually`);
        }
      }
      for (const path of item.dependencyPaths) if (nodes.has(path)) queue.push(nodes.get(path));
    }
  }
}

function validateActions(actions) {
  const assignments = new Map();
  const set = (key, value) => {
    if (assignments.has(key) && assignments.get(key) !== value) throw new Error(`conflicting upgrade targets for ${key}; upgrade the parents manually`);
    assignments.set(key, value);
  };
  for (const a of actions) {
    for (const pin of a.pins || []) set(`pin ${pin.owner}:${a.name}`, a.spec);
    for (const o of a.overrides) set(`override ${o.scope || '(global)'}:${o.name}`, o.spec);
  }
  for (const a of actions) for (const o of a.overrides) {
    const global = assignments.get(`override (global):${o.name}`);
    if (global && global !== o.spec) throw new Error(`conflicting global and scoped overrides for ${o.name}`);
  }
}

const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const put = (obj, key, value) => Object.defineProperty(obj, key, { value, writable: true, configurable: true, enumerable: true });
function setOverride(obj, name, spec) {
  const previous = Object.hasOwn(obj, name) ? obj[name] : undefined;
  if (object(previous)) put(previous, '.', spec);
  else put(obj, name, spec);
}

export function applyOverrides(existing, actions) {
  validateActions(actions);
  if (existing !== undefined && !object(existing)) throw new Error('package.json overrides must be an object');
  const overrides = structuredClone(existing || {});
  const changes = [];
  for (const a of actions) {
    for (const o of a.overrides) {
      if (o.scope === null) {
        setOverride(overrides, o.name, o.spec);
        changes.push(`package.json overrides: "${o.name}": "${o.spec}"`);
      } else {
        const parent = o.scope.slice(0, o.scope.lastIndexOf('@'));
        // A broader existing selector may take precedence in npm. Do not silently
        // shadow it or erase its descendants to force the new selector to win.
        if (parent && Object.hasOwn(overrides, parent) && object(overrides[parent]) && Object.hasOwn(overrides[parent], o.name)) {
          throw new Error(`existing override ${parent} > ${o.name} overlaps ${o.scope}; reconcile it manually`);
        }
        const cur = Object.hasOwn(overrides, o.scope) ? overrides[o.scope] : undefined;
        const scoped = object(cur) ? cur : cur === undefined ? {} : { '.': cur };
        setOverride(scoped, o.name, o.spec);
        put(overrides, o.scope, scoped);
        changes.push(`package.json overrides: "${o.scope}" > "${o.name}": "${o.spec}"`);
      }
    }
  }
  return { overrides, changes };
}

const KIND_FIELDS = { prod: 'dependencies', dev: 'devDependencies', optional: 'optionalDependencies', peer: 'peerDependencies' };

// Keep npm's normal save flags for a single declaration. Packages declared in more
// than one field are edited in place before install so npm cannot migrate their type.
export function pinCommands(actions) {
  const groups = new Map();
  for (const a of actions) {
    for (const pin of a.pins) {
      const kinds = pin.kinds || [pin.dev ? 'dev' : 'prod'];
      if (kinds.some((k) => !Object.hasOwn(KIND_FIELDS, k))) throw new Error('unknown dependency kind');
      const key = `${pin.owner}\0${kinds.slice().sort().join(',')}`;
      if (!groups.has(key)) groups.set(key, { owner: pin.owner, kinds, specs: [], edits: [] });
      const group = groups.get(key);
      const spec = `${a.name}@${a.spec}`;
      if (!group.specs.includes(spec)) group.specs.push(spec);
      group.edits.push({ name: a.name, spec: a.spec, kinds });
    }
  }
  return [...groups.values()].map((g) => {
    const args = g.kinds.length > 1 ? ['install', '--ignore-scripts']
      : ['install', ...g.specs, '--save-exact', '--ignore-scripts', `--save-${g.kinds[0]}`];
    if (g.owner) args.push('--workspace', g.owner);
    return { owner: g.owner, args, edits: g.kinds.length > 1 ? g.edits : [] };
  });
}

function editPins(projectDir, command) {
  if (!command.edits.length) return;
  const file = join(projectDir, command.owner, 'package.json');
  const pkg = JSON.parse(readFileSync(file, 'utf8'));
  for (const edit of command.edits) for (const kind of edit.kinds) {
    const field = KIND_FIELDS[kind];
    if (!Object.hasOwn(pkg[field] || {}, edit.name)) throw new Error(`declaration changed during fix: ${field}.${edit.name}`);
    put(pkg[field], edit.name, edit.spec);
  }
  writeFileSync(file, JSON.stringify(pkg, null, 2) + '\n');
}

const RESTORE_HINT = 'node_modules may still hold the partial install: run "npm ci" to match the restored lockfile';

export async function applyFixes(projectDir, { minPriority = 'P3', evidenceDir, runTests = true, lookups, exec } = {}) {
  const before = await triage(projectDir, lookups);
  const plan = planFixes(before, { minPriority });
  const changes = [];
  const commandLogs = [];
  const npm = (args) => {
    const r = run(NPM, args, projectDir, exec);
    commandLogs.push(`$ npm ${args.join(' ')}\n${r.output || ''}\nExit: ${r.code}${r.error ? `; execution error: ${r.error}` : ''}\n`);
    if (evidenceDir) writeFileSync(join(evidenceDir, 'commands.txt'), commandLogs.join('\n'));
    if (r.error) throw Object.assign(new Error(`could not execute npm ${args[0]}: ${r.error}`), { npmOutput: r.output });
    return r;
  };

  const pkgPath = join(projectDir, 'package.json');
  const lockPath = join(projectDir, 'package-lock.json');
  const pkgBefore = readFileSync(pkgPath, 'utf8');
  const lockBefore = readFileSync(lockPath, 'utf8');
  const scripts = JSON.parse(pkgBefore).scripts || {};
  const pins = pinCommands(plan.actions);
  // Validate override merges before any npm command can mutate the project.
  applyOverrides(JSON.parse(pkgBefore).overrides, plan.actions);
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

  if (evidenceDir) {
    mkdirSync(evidenceDir, { recursive: true });
    writeFileSync(join(evidenceDir, 'before.json'), JSON.stringify(before, null, 2));
    writeFileSync(join(evidenceDir, 'package-lock.before.json'), lockBefore);
    saveSnapshots(evidenceDir, 'before', snapshots);
    writeFileSync(join(evidenceDir, 'REPORT.md'), formatMarkdown(before, null) + '\n## Verification pending\n\nFix started. Consult commands.txt and the snapshots if the process is interrupted.\n');
  }

  let testsBefore = null;
  let step = null; // the command being run, for the failure report
  try {
    // npm 10 can collapse differently scoped targets to one hoisted version. The
    // real-npm integration verifies this path with npm 11.9; refuse older clients
    // before mutation instead of letting a clean rescan hide a wrong major version.
    const scopedTargets = new Map();
    for (const action of plan.actions) for (const override of action.overrides) {
      if (override.scope === null) continue;
      if (!scopedTargets.has(override.name)) scopedTargets.set(override.name, new Set());
      scopedTargets.get(override.name).add(override.spec);
    }
    if ([...scopedTargets.values()].some((targets) => targets.size > 1)) {
      step = { command: 'npm --version' };
      const versionResult = npm(['--version']);
      const version = (versionResult.stdout ?? versionResult.output).trim();
      if (versionResult.code !== 0 || acceptsVersion('>=11.9.0', version) !== true) {
        throw new Error(`Multiple override targets for the same package require npm >=11.9.0 (found ${version}); update npm or upgrade the parents manually`);
      }
    }
    // 0) Baseline test run, so the evidence shows what changed.
    testsBefore = testsEnabled ? runProjectTests() : null;
    if (evidenceDir && testsBefore) writeFileSync(join(evidenceDir, 'tests.before.txt'), testsBefore.output);

    // 1) Direct dependencies: pin the safe versions, one install per manifest and type.
    for (const cmd of pins) {
      step = { command: `npm ${cmd.args.join(' ')}` };
      editPins(projectDir, cmd);
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
      // npm keeps a locked copy that an override now rejects (it lists it as "invalid"), so
      // remove those lockfile entries and let the install resolve them under the overrides.
      step = { command: 'update package-lock.json' };
      for (const c of dropStaleCopies(projectDir, lockPath, plan.actions)) {
        changes.push(`package-lock.json: re-resolve ${c.name}@${c.version} at ${c.path}`);
      }
      step = { command: 'npm install --ignore-scripts' };
      const r = npm(['install', '--ignore-scripts']);
      if (r.code !== 0) throw Object.assign(new Error(`npm install (overrides) failed:\n${r.output}`), { npmOutput: r.output });
    }
  } catch (err) {
    throw rollback(err, { projectDir, evidenceDir, before, step, changes, snapshots, testsBefore });
  }

  // From this point onward, verification failures preserve applied changes and
  // always record their state. A registry outage is not a successful rescan.
  let tests = null, after = null;
  let verification;
  try {
    tests = testsEnabled ? runProjectTests() : null;
    if (evidenceDir && tests) writeFileSync(join(evidenceDir, 'tests.after.txt'), tests.output);
    after = await triage(projectDir, lookups);
    verification = verifyTargets(projectDir, before, plan);
  } catch (err) {
    let note = '';
    if (evidenceDir) {
      try {
        saveSnapshots(evidenceDir, 'after', snapshots.map(([file]) => [file, readFileSync(join(projectDir, file), 'utf8')]));
        writeFileSync(join(evidenceDir, 'package-lock.after.json'), readFileSync(lockPath, 'utf8'));
        writeFileSync(join(evidenceDir, 'verification-error.txt'), String(err.stack || err));
        writeFileSync(join(evidenceDir, 'REPORT.md'), formatMarkdown(before, after, { changes, tests, testsBefore, testsSkipped, verificationError: err.message }));
        note = `\nEvidence: ${evidenceDir}`;
      } catch (e) { note = `\nCould not finish writing evidence: ${e.message}`; }
    }
    throw new Error(`Post-install verification failed: ${err.message}\nApplied changes were preserved; review the before/after snapshots before proceeding.${note}`, { cause: err });
  }
  const verificationWarnings = verification.unresolved.map((name) => `upgrade target not confirmed for ${name}; inspect the lockfile and install log`);
  if (evidenceDir) {
    writeFileSync(join(evidenceDir, 'after.json'), JSON.stringify(after, null, 2));
    saveSnapshots(evidenceDir, 'after', snapshots.map(([file]) => [file, readFileSync(join(projectDir, file), 'utf8')]));
    writeFileSync(join(evidenceDir, 'package-lock.after.json'), readFileSync(lockPath, 'utf8'));
    // SBOM diagnostics are useful evidence, but are never appended to the JSON file.
    const sbomFile = join(evidenceDir, 'sbom.cdx.json');
    rmSync(sbomFile, { force: true });
    try {
      const sbom = npm(['sbom', '--sbom-format', 'cyclonedx']);
      writeFileSync(join(evidenceDir, 'sbom.stderr.txt'), sbom.stderr || '');
      if (sbom.code !== 0) throw new Error(`npm sbom exited ${sbom.code}`);
      const stdout = sbom.stdout ?? sbom.output;
      const parsed = JSON.parse(stdout);
      if (!object(parsed)) throw new Error('npm sbom did not return a JSON object');
      writeFileSync(sbomFile, stdout);
    } catch (err) {
      verificationWarnings.push(`SBOM unavailable: ${err.message}`);
      writeFileSync(join(evidenceDir, 'sbom-error.txt'), String(err.message));
    }
    writeFileSync(join(evidenceDir, 'REPORT.md'), formatMarkdown(before, after, { changes, tests, testsBefore, testsSkipped, verificationWarnings }));
  }
  return { before, after, plan, changes, tests, testsBefore, testsSkipped, verification, verificationWarnings,
    evidenceWritten: Boolean(evidenceDir && existsSync(evidenceDir)) };
}

function saveSnapshots(evidenceDir, stage, snapshots) {
  for (const [file, text] of snapshots) {
    const destination = join(evidenceDir, stage, file);
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, text);
  }
}

function verifyTargets(projectDir, before, plan) {
  const project = loadProject(projectDir);
  const unresolved = [], confirmed = [];
  for (const action of plan.actions) {
    const sources = before.findings.filter((f) => action.paths.includes(f.path));
    const ok = sources.every((f) => {
      const origins = f.direct ? f.declaredBy.map((d) => d.owner)
        : f.requiredEdges?.length ? f.requiredEdges.flatMap((r) => {
          // npm may rehoist the parent while applying overrides. Follow its identity
          // and version to the new location instead of resolving from a stale path.
          const parents = project.installs.filter((i) => i.name === r.by && i.version === r.version);
          return parents.length ? parents.map((i) => i.path) : [null];
        }) : [f.path.slice(0, Math.max(0, f.path.lastIndexOf('node_modules/'))).replace(/\/$/, '')];
      return origins.every((origin) => {
        if (origin === null) return false;
        const installed = project.resolveDependency(origin, action.name);
        return installed?.realName === action.package && installed.version === action.target;
      });
    });
    (ok ? confirmed : unresolved).push(`${action.name}@${action.target}`);
  }
  return { confirmed, unresolved };
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

// Lockfile entries for nested copies that an override covers but that are not at the
// override's version (npm lists them as "invalid" and keeps them). Removing them, with
// anything nested under them, makes npm resolve them again, so the lockfile matches the
// overrides. That includes lower-priority copies the override also covers.
function dropStaleCopies(projectDir, lockPath, actions) {
  const { installs } = loadProject(projectDir);
  const stale = [];
  for (const a of actions) {
    if (!a.overrides.length) continue;
    for (const install of installs) {
      // Top-level copies are updated by npm itself; the nested ones are what it leaves behind.
      // Bundled copies ship inside their parent's tarball, so neither overrides nor this reach them.
      if (install.name !== a.name || install.version === a.target || install.direct || install.topLevel || install.inBundle) continue;
      const targeted = a.overrides.some((o) => o.scope === null || install.requiredEdges.some((r) => `${r.by}@${r.version}` === o.scope) || install.requiredBy.includes(o.scope)
        || install.path.includes(`node_modules/${o.scope}/node_modules/`));
      if (targeted && !stale.some((s) => s.path === install.path)) stale.push(install);
    }
  }
  if (!stale.length) return [];
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  for (const key of Object.keys(lock.packages)) {
    if (stale.some((s) => key === s.path || key.startsWith(`${s.path}/node_modules/`))) delete lock.packages[key];
  }
  writeFileSync(lockPath, JSON.stringify(lock, null, 2) + '\n');
  return stale.sort((x, y) => x.path.localeCompare(y.path));
}
