// Read an npm project's package.json + package-lock.json (lockfile v2/v3) into a
// dependency inventory with the dependency graph, so findings can be traced back
// to the direct dependency that pulls them in.
//
// Every install has two names:
//   name      - the folder it is installed under, which is what `require()` uses
//               ("foo" for "foo": "npm:lodash@4.17.21")
//   realName  - the registry package it really is ("lodash"), which is what
//               advisories and published versions are keyed by
// For an ordinary dependency they are the same.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const MANIFEST_FIELDS = [
  ['dependencies', 'prod'],
  ['optionalDependencies', 'optional'],
  ['peerDependencies', 'peer'],
  ['devDependencies', 'dev'],
];

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function ownKeys(obj) {
  return obj && typeof obj === 'object' && !Array.isArray(obj) ? Object.keys(obj) : [];
}

// "node_modules/a/node_modules/b" -> "b"; "node_modules/@scope/x" -> "@scope/x"
function nameFromPath(path) {
  const i = path.lastIndexOf('node_modules/');
  return path.slice(i + 'node_modules/'.length);
}

// The folder that owns node_modules/: "" for the project root, "packages/app" for a
// workspace, "node_modules/a" for a nested install.
function ownerOf(path) {
  const i = path.lastIndexOf('node_modules/');
  return i === 0 ? '' : path.slice(0, i - 1);
}

// Direct dependencies declared by one manifest: Map(name -> "prod"|"optional"|"peer"|"dev").
// A name listed in several fields keeps the first (runtime) kind.
function declaredDeps(manifest) {
  const out = new Map();
  for (const [field, kind] of MANIFEST_FIELDS) {
    for (const name of ownKeys(manifest?.[field])) if (!out.has(name)) out.set(name, kind);
  }
  return out;
}

export function loadProject(dir) {
  const pkgPath = join(dir, 'package.json');
  const lockPath = join(dir, 'package-lock.json');
  if (!existsSync(pkgPath)) throw new Error(`no package.json in ${dir}`);
  if (!existsSync(lockPath)) {
    throw new Error(`no package-lock.json in ${dir} (run "npm install --package-lock-only" first)`);
  }
  const pkg = readJson(pkgPath);
  const lock = readJson(lockPath);
  if (!lock.packages || typeof lock.packages !== 'object') {
    throw new Error('package-lock.json v1 is not supported; regenerate it with npm 7 or newer');
  }

  // Manifests that declare direct dependencies: the root package.json and every
  // workspace package (lockfile entries outside node_modules, like "packages/app").
  const manifests = new Map([['', declaredDeps(pkg)]]); // owner path -> declared deps
  const workspaces = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || path.includes('node_modules/') || !entry || typeof entry !== 'object') continue;
    workspaces.push(path);
    manifests.set(path, declaredDeps(entry));
  }

  // Root-level direct dependencies, kept for callers: name -> kind.
  const direct = manifests.get('');

  // Every installed copy of every package. The same name can appear at several versions.
  const installs = [];
  const byPath = new Map();
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || !path.includes('node_modules/') || !entry || typeof entry !== 'object' || entry.link) continue;
    if (!entry.version) continue;
    const name = nameFromPath(path);
    const item = {
      name,
      realName: typeof entry.name === 'string' && entry.name ? entry.name : name,
      version: String(entry.version),
      path,
      owner: ownerOf(path),
      dev: Boolean(entry.dev),
      optional: Boolean(entry.optional),
      inBundle: Boolean(entry.inBundle),
      dependsOn: [...new Set(DEP_FIELDS.flatMap((f) => ownKeys(entry[f])))],
      requires: Object.fromEntries(DEP_FIELDS.slice().reverse().flatMap((f) => ownKeys(entry[f]).map((n) => [n, String(entry[f][n])]))),
      requiredBy: [],
      requiredSpecs: [],
      declaredBy: [],
    };
    item.aliased = item.realName !== item.name;
    // What project or workspace code gets from require(name): the copy directly in its node_modules.
    item.topLevel = manifests.has(item.owner);
    installs.push(item);
    byPath.set(path, item);
  }

  // npm resolves a dependency by walking up node_modules folders from the requiring package.
  function resolve(fromPath, depName) {
    let base = fromPath;
    for (;;) {
      const candidate = `${base ? base + '/' : ''}node_modules/${depName}`;
      if (byPath.has(candidate)) return byPath.get(candidate);
      if (!base) return null;
      const i = base.lastIndexOf('/node_modules/');
      base = i === -1 ? '' : base.slice(0, i);
    }
  }

  // Which installed packages require each copy (used to scope npm overrides).
  for (const item of installs) {
    for (const d of item.dependsOn) {
      const next = resolve(item.path, d);
      if (next && next !== item && !next.requiredBy.includes(item.name)) {
        next.requiredBy.push(item.name);
        next.requiredSpecs.push({ by: item.name, spec: item.requires[d] });
      }
    }
  }

  // Roots: what each manifest's declared dependencies resolve to. A workspace's
  // dependencies are roots too, so their subtrees are traced like the root's.
  const roots = [];
  for (const [owner, deps] of manifests) {
    for (const [name, kind] of deps) {
      const hit = resolve(owner, name);
      if (!hit) continue;
      hit.declaredBy.push({ owner, kind });
      roots.push(hit);
    }
  }

  // For each install, which direct dependencies lead to it (the "via" chains),
  // named by the installed (require-able) name.
  const reachedBy = new Map(); // path -> Set(direct dependency names)
  const tracedRoots = new Set();
  for (const root of roots) {
    if (tracedRoots.has(root.path)) continue;
    tracedRoots.add(root.path);
    const stack = [root];
    const seen = new Set();
    while (stack.length) {
      const cur = stack.pop();
      if (seen.has(cur.path)) continue;
      seen.add(cur.path);
      if (!reachedBy.has(cur.path)) reachedBy.set(cur.path, new Set());
      reachedBy.get(cur.path).add(root.name);
      for (const d of cur.dependsOn) {
        const next = resolve(cur.path, d);
        if (next) stack.push(next);
      }
    }
  }

  for (const item of installs) {
    item.direct = item.declaredBy.length > 0;
    item.via = [...(reachedBy.get(item.path) || [])].sort();
  }

  return { dir, name: pkg.name || '(unnamed)', pkg, direct, workspaces, installs };
}
