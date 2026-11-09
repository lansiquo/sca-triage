// Turn an inventory + advisories + import evidence into ranked findings, each with
// the smallest upgrade that clears every known advisory for that package, including
// advisories that only affect versions newer than the installed one.

import { loadProject } from './lockfile.js';
import { fetchAdvisories, fetchVersions, severityRank } from './advisories.js';
import { findImports, classify, REACHABILITY_RANK } from './reachability.js';
import { satisfies, compare, parse, isPrerelease, sortVersions, releaseLine } from './semver.js';

// satisfies(), but a range or version this tool can't parse counts as a match, with a
// warning: an advisory we can't read must not turn into "not vulnerable".
export function affects(version, range, warnings, context = '') {
  try {
    return satisfies(version, range);
  } catch (err) {
    const msg = `${context ? `${context}: ` : ''}${err.message}; treating it as vulnerable`;
    if (warnings && !warnings.includes(msg)) warnings.push(msg);
    return true;
  }
}

// P1: high/critical and the code loads it. Fix now.
// P2: high/critical but not loaded at runtime, or moderate and loaded. Schedule it.
// P3: everything else. Batch with routine upgrades.
export function priorityFor(severity, reachability) {
  const sev = severityRank(severity);
  const reach = REACHABILITY_RANK[reachability];
  const loaded = reach >= REACHABILITY_RANK['via-imported'];
  if (sev >= 3 && loaded) return 'P1';
  if (sev >= 3 || (sev === 2 && loaded)) return 'P2';
  return 'P3';
}

const PRIORITY_RANK = { P1: 3, P2: 2, P3: 1 };
export function priorityRank(p) {
  return PRIORITY_RANK[p] || 0;
}

// Smallest published, non-prerelease version above `current` that none of `advisories`
// covers. triage() keeps adding the advisories it finds for candidate targets and calls
// this again, so the result is clean under every advisory it has seen.
// Prefers staying on the same release line (same major, or same 0.minor below 1.0.0),
// since that is least likely to break callers. `crossesMajor` means the target is on
// another line: a breaking upgrade under npm's caret rules.
export function pickSafeVersion(current, versions, advisories, warnings) {
  const cur = parse(current);
  if (!cur) return { target: null, crossesMajor: false };
  const candidates = sortVersions(versions).filter(
    (v) => !isPrerelease(v) && compare(v, cur) > 0 && !advisories.some((a) => affects(v, a.vulnerableVersions, warnings, a.ghsa)),
  );
  if (!candidates.length) return { target: null, crossesMajor: false };
  const line = releaseLine(cur);
  const sameLine = candidates.find((v) => releaseLine(v) === line);
  const target = sameLine || candidates[0];
  return { target, crossesMajor: releaseLine(target) !== line };
}

// How many extra advisory lookups triage makes to check candidate upgrade targets.
export const MAX_TARGET_CHECKS = 5;

function advisoryKey(a) {
  return `${a.ghsa}\u0000${a.vulnerableVersions}`;
}

export async function triage(projectDir, { advisoryLookup = fetchAdvisories, versionLookup = fetchVersions } = {}) {
  const project = loadProject(projectDir);
  const imports = findImports(projectDir, { workspaces: project.workspaces });
  // Advisories and versions are looked up by the real package name ("lodash" for
  // "foo": "npm:lodash@..."); reachability uses the installed name.
  const lookup = async (installs) => {
    const res = await advisoryLookup(installs);
    return (name) =>
      res instanceof Map ? res.get(name) || [] : (res && Object.hasOwn(res, name) && res[name]) || [];
  };
  const advisoriesFor = await lookup(project.installs.map((i) => ({ name: i.realName, version: i.version })));

  // Every advisory seen for a package, from the installed versions and from any
  // candidate target checked below. A target must be clear of all of them.
  const known = new Map(); // realName -> Map(key -> advisory)
  const addKnown = (name, list) => {
    if (!known.has(name)) known.set(name, new Map());
    const seen = known.get(name);
    let added = 0;
    for (const a of list) {
      if (!seen.has(advisoryKey(a))) {
        seen.set(advisoryKey(a), a);
        added++;
      }
    }
    return added;
  };
  const knownFor = (name) => [...(known.get(name)?.values() || [])];

  const copiesByName = new Map();
  for (const i of project.installs) copiesByName.set(i.name, (copiesByName.get(i.name) || 0) + 1);

  const warnings = [];
  const findings = [];
  const versionCache = new Map();
  for (const install of project.installs) {
    const all = advisoriesFor(install.realName);
    addKnown(install.realName, all);
    const affecting = all.filter((a) => affects(install.version, a.vulnerableVersions, warnings, `${a.ghsa} (${install.realName}@${install.version})`));
    if (!affecting.length) continue;

    const reach = classify(install, imports);
    const maxSeverity = affecting.reduce((s, a) => (severityRank(a.severity) > severityRank(s) ? a.severity : s), 'info');
    if (!versionCache.has(install.realName)) versionCache.set(install.realName, await versionLookup(install.realName));

    findings.push({
      package: install.realName,
      installedAs: install.name,
      version: install.version,
      path: install.path,
      direct: install.direct,
      declaredBy: install.declaredBy,
      requiredBy: install.requiredBy,
      copiesInstalled: copiesByName.get(install.name),
      devOnly: install.dev,
      via: install.via,
      reachability: reach.level,
      evidence: reach.evidence,
      severity: maxSeverity,
      priority: priorityFor(maxSeverity, reach.level),
      advisories: affecting.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
      fix: null,
    });
  }

  // The registry returns only the advisories that affect the versions it is asked
  // about, so an advisory that starts above the installed version (say >=2.29.2 <2.31.0
  // for an install at 2.29.1) is invisible until a candidate target is queried. Pick a
  // target, ask the registry about every new target in one batched lookup, and pick
  // again with whatever turned up, until no target changes.
  const pick = () => {
    for (const f of findings) f.fix = pickSafeVersion(f.version, versionCache.get(f.package), knownFor(f.package), warnings);
  };
  pick();
  const checked = new Set(); // "name@target" pairs already sent to the registry
  const pairKey = (f) => `${f.package}@${f.fix.target}`;
  for (let round = 0; round < MAX_TARGET_CHECKS; round++) {
    const query = [];
    for (const f of findings) {
      if (!f.fix.target || checked.has(pairKey(f))) continue;
      checked.add(pairKey(f));
      query.push({ name: f.package, version: f.fix.target });
    }
    if (!query.length) break;
    const found = await lookup(query);
    let added = 0;
    for (const name of new Set(query.map((q) => q.name))) added += addKnown(name, found(name));
    if (!added) break;
    pick();
  }
  for (const f of findings) {
    if (f.fix.target && !checked.has(pairKey(f))) {
      warnings.push(
        `${f.package}@${f.version}: upgrade target ${f.fix.target} was not checked against the registry after ${MAX_TARGET_CHECKS} lookups; it may still be vulnerable`,
      );
    }
  }

  findings.sort(
    (a, b) =>
      priorityRank(b.priority) - priorityRank(a.priority) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      a.package.localeCompare(b.package) ||
      a.path.localeCompare(b.path),
  );

  return {
    project: project.name,
    scannedAt: new Date().toISOString(),
    packagesScanned: project.installs.length,
    summary: {
      P1: findings.filter((f) => f.priority === 'P1').length,
      P2: findings.filter((f) => f.priority === 'P2').length,
      P3: findings.filter((f) => f.priority === 'P3').length,
      advisories: findings.reduce((n, f) => n + f.advisories.length, 0),
    },
    findings,
    warnings,
  };
}

// Does this result fail the gate? failOn is "P1", "P2", "P3" or "none".
export function gateFails(result, failOn = 'P1') {
  if (failOn === 'none') return false;
  const threshold = priorityRank(failOn);
  return result.findings.some((f) => priorityRank(f.priority) >= threshold);
}
