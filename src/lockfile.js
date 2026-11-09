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
import { join, posix } from 'node:path';
import { parse } from './semver.js';

const DEP_FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const MANIFEST_FIELDS = [
  ['optionalDependencies', 'optional'],
  ['dependencies', 'prod'],
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
// Optional declarations take precedence over duplicate production declarations.
function declaredDeps(manifest) {
  const out = new Map();
  for (const [field, kind] of MANIFEST_FIELDS) {
    for (const name of ownKeys(manifest?.[field])) if (!out.has(name)) out.set(name, kind);
  }
  return out;
}

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
function validateManifest(value, label) {
  if (!object(value)) throw new Error(`${label} must be an object`);
  for (const [field] of MANIFEST_FIELDS) {
    if (value[field] === undefined) continue;
    if (!object(value[field]) || Object.values(value[field]).some((v) => typeof v !== 'string' || !v)) {
      throw new Error(`${label}.${field} must contain dependency specifications`);
    }
  }
}
// Lockfile keys are relative POSIX paths. npm writes "../shared" for a file: dependency outside
// the project, so leading ".." segments are allowed; nothing else may climb, or repeat a slash.
function safePath(path) {
  if (path === '') return true;
  if (path.startsWith('/') || path.includes('\\')) return false;
  const segs = path.split('/');
  let i = 0;
  while (segs[i] === '..') i++;
  return i < segs.length && segs.slice(i).every((p) => p && p !== '.' && p !== '..');
}
const outside = (path) => path === '..' || path.startsWith('../');

// A registry tarball URL names the package and version inside it (".../@s/x/-/x-1.2.3.tgz").
// An entry that claims another name or version would make the scan check the wrong package
// while npm installs the tarball.
const TARBALL = /\/((?:@[^/]+\/)?[^/]+)\/-\/([^/?#]+)\.tgz(?:[?#].*)?$/;
function tarballMismatch(entry, realName) {
  if (typeof entry.resolved !== 'string') return false;
  const m = TARBALL.exec(entry.resolved);
  if (!m) return false;
  let name;
  try {
    name = decodeURIComponent(m[1]);
  } catch {
    return true;
  }
  return name !== realName || m[2] !== `${name.split('/').pop()}-${entry.version}`;
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
  validateManifest(pkg, 'package.json');
  if (!object(lock) || ![2, 3].includes(lock.lockfileVersion) || !object(lock.packages) || !object(lock.packages[''])) {
    throw new Error('package-lock.json must be a v2/v3 lockfile with a packages object and root entry; regenerate it with npm install --package-lock-only');
  }
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!safePath(path)) throw new Error(`unsupported lockfile path ${path}`);
    validateManifest(entry, `lockfile entry ${path || '(root)'}`);
    if (path.includes('node_modules/') && !entry.link && (typeof entry.version !== 'string' || !parse(entry.version))) {
      throw new Error(`lockfile entry ${path} has an invalid or missing version`);
    }
    if (entry.link && (typeof entry.resolved !== 'string' || !safePath(entry.resolved) || !object(lock.packages[entry.resolved]) || lock.packages[entry.resolved].link)) {
      throw new Error(`lockfile link ${path} has an unsupported or missing target`);
    }
  }

  // Manifests that declare direct dependencies: the root package.json and every
  // workspace package (lockfile entries outside node_modules, like "packages/app").
  const manifests = new Map([['', declaredDeps(pkg)]]); // owner path -> declared deps
  const manifestData = new Map([['', pkg]]);
  const workspaces = [];
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || path.includes('node_modules/') || !entry || typeof entry !== 'object') continue;
    // A file: dependency outside the project: its lockfile entry describes it, and it is not
    // a workspace (nothing is pinned in its manifest, and it isn't read from disk).
    if (outside(path)) {
      manifestData.set(path, entry);
      continue;
    }
    workspaces.push(path);
    const file = join(dir, path, 'package.json');
    if (!existsSync(file)) throw new Error(`missing local package manifest ${path}/package.json`);
    const manifest = readJson(file);
    validateManifest(manifest, file);
    manifestData.set(path, manifest);
    manifests.set(path, declaredDeps(manifest));
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
      requiredEdges: [],
      dependencyPaths: [],
      declaredBy: [],
    };
    item.aliased = item.realName !== item.name;
    if (tarballMismatch(entry, item.realName)) {
      throw new Error(`lockfile entry ${path} says ${item.realName}@${item.version}, but npm installs ${entry.resolved}`);
    }
    // What project or workspace code gets from require(name): the copy directly in its node_modules.
    item.topLevel = manifests.has(item.owner);
    installs.push(item);
    byPath.set(path, item);
  }

  // Local/workspace nodes participate in traversal without being registry packages.
  for (const [path, manifest] of manifestData) {
    if (!path) continue;
    byPath.set(path, { path, name: manifest.name || path, version: manifest.version,
      dependsOn: [...declaredDeps(manifest).keys()], requires: {}, requiredBy: [], requiredSpecs: [], requiredEdges: [], declaredBy: [], dependencyPaths: [] });
  }
  const links = new Map(Object.entries(lock.packages).filter(([, e]) => e.link).map(([path, e]) => [path, e.resolved]));

  // Resolve from an importing directory, including ordinary source subdirectories.
  function resolve(fromPath, depName) {
    let base = fromPath;
    for (;;) {
      if (posix.basename(base) !== 'node_modules') {
        const candidate = `${base ? base + '/' : ''}node_modules/${depName}`;
        const hit = byPath.get(links.get(candidate) || candidate);
        if (hit) return hit;
      }
      if (!base || base === '.') return null;
      const parent = posix.dirname(base);
      base = parent === '.' ? '' : parent;
    }
  }

  // Optional dependencies may be absent, and so may peers: npm doesn't install them with
  // legacy-peer-deps. A file: dependency outside the project gets no installs of its own.
  const missingAllowed = (entry, name) => Object.hasOwn(entry.optionalDependencies || {}, name)
    || Object.hasOwn(entry.peerDependencies || {}, name);
  for (const [path, item] of byPath) {
    const entry = manifestData.get(path) || lock.packages[path];
    for (const name of item.dependsOn) {
      const next = resolve(path, name);
      if (!next && !outside(path) && !missingAllowed(entry, name)) throw new Error(`incomplete lockfile: ${path || '(root)'} requires missing dependency ${name}`);
      if (next) item.dependencyPaths.push(next.path);
    }
  }

  // A bundled copy ships inside the tarball of the nearest package above it that is not
  // bundled itself. npm overrides cannot change it; only a new version of that package can.
  // A copy bundled by the project (or a workspace) itself has no such package.
  for (const item of installs) {
    item.bundledIn = null;
    if (!item.inBundle) continue;
    let base = item.path;
    for (;;) {
      const i = base.lastIndexOf('/node_modules/');
      if (i === -1) break;
      base = base.slice(0, i);
      const parent = byPath.get(base);
      if (!parent) break;
      if (!parent.inBundle) {
        item.bundledIn = { name: parent.name, version: parent.version, path: parent.path };
        break;
      }
    }
  }

  // Which installed packages require each copy (used to scope npm overrides).
  for (const item of installs) {
    for (const d of item.dependsOn) {
      const next = resolve(item.path, d);
      if (next && next !== item) {
        if (!next.requiredBy.includes(item.name)) next.requiredBy.push(item.name);
        next.requiredSpecs.push({ by: item.name, spec: item.requires[d] });
        next.requiredEdges.push({ by: item.name, version: item.version, path: item.path, spec: item.requires[d] });
      }
    }
  }

  // Roots: what each manifest's declared dependencies resolve to. A workspace's
  // dependencies are roots too, so their subtrees are traced like the root's.
  const roots = [];
  for (const [owner, deps] of manifests) {
    for (const [name, kind] of deps) {
      const hit = resolve(owner, name);
      const manifest = manifestData.get(owner);
      if (!hit) {
        if (!missingAllowed(manifest, name)) throw new Error(`incomplete lockfile: ${owner || '(root)'} requires missing dependency ${name}`);
        continue;
      }
      for (const [field, declaredKind] of MANIFEST_FIELDS) {
        if (!Object.hasOwn(manifest[field] || {}, name)) continue;
        if (declaredKind === 'prod' && kind === 'optional') continue;
        hit.declaredBy.push({ owner, kind: declaredKind });
      }
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

  return { dir, name: pkg.name || '(unnamed)', pkg, direct, workspaces, installs, byPath, resolveDependency: resolve };
}
