// Import-level reachability: which packages does the project's own code actually load?
// This is deliberately simple and honest about it. It finds require(), import,
// export ... from, dynamic import() and createRequire() calls with package names in
// the project's source files. It does not build a call graph, so "imported" means
// "the code loads it", not "the vulnerable function is proven to run".
//
// When in doubt it errs toward "loaded": a false "imported" costs a reviewer a look,
// a false "not imported" hides a reachable vulnerability below the CI gate.

import { readdirSync, readFileSync, lstatSync, statSync, realpathSync, openSync, readSync, closeSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

const SOURCE_EXT = /\.(?:(?:c|m)?(?:j|t)sx?|vue|svelte|astro)$/;
const MAX_FILE_BYTES = 2_000_000;
// Never source code, wherever they appear.
const SKIP_ANYWHERE = new Set(['node_modules', '.git']);
// Build output and tool output, skipped only at the top of the project or a workspace,
// so a source folder that happens to be called "build" is still scanned.
const SKIP_AT_ROOT = new Set(['dist', 'build', 'coverage', 'evidence', '.next']);
// Test folders count as test code only at the top of the project or a workspace
// ("test/", "spec/"); "__tests__" is a test folder anywhere. Files named
// *.test.js / *.spec.js are tests anywhere.
const TEST_DIRS_AT_ROOT = new Set(['test', 'tests', '__tests__', 'spec']);
const TEST_FILE = /\.(?:test|spec)\.(?:c|m)?(?:j|t)sx?$/;

// The gaps these patterns allow are bounded, so a hostile file can't make them backtrack
// quadratically (each match attempt does at most a few thousand steps).
const Q = `(['"])`; // opening quote, closed with \\1 / \\2
const SPEC = `([^'"\`\\s]{1,500})`; // a package specifier, maybe with a subpath
// Whitespace and up to 8 comments, e.g. import(/* webpackChunkName: "x" */ 'x').
const COMMENTS = `\\s*(?:(?:\\/\\*(?:[^*]|\\*(?!\\/)){0,400}\\*\\/|\\/\\/[^\\n]{0,400}\\n)\\s*){0,8}`;
const PATTERNS = [
  // require('x'), require.resolve('x'), require( /* c */ "x" )
  new RegExp(`\\brequire(?:\\s*\\.\\s*resolve)?\\s*\\(${COMMENTS}${Q}${SPEC}\\1`, 'g'),
  // import x from 'x', import {a} from"x", import 'x', import type T from 'x'
  new RegExp(`\\bimport\\b(?:[^'"\`;()]{0,1000}?\\bfrom)?\\s*${Q}${SPEC}\\1`, 'g'),
  // import('x'), import(/* webpackChunkName: "x" */ 'x')
  new RegExp(`\\bimport\\s*\\(${COMMENTS}${Q}${SPEC}\\1`, 'g'),
  // export { x } from 'x', export * from"x"
  new RegExp(`\\bexport\\b[^'"\`;()]{0,1000}?\\bfrom\\s*${Q}${SPEC}\\1`, 'g'),
];
// require(`x`) / import(`x/${sub}`): the static text before any ${...}.
const TEMPLATE_PATTERN = new RegExp(`\\b(?:require(?:\\s*\\.\\s*resolve)?|import)\\s*\\(${COMMENTS}\`([^\`$]{1,500})(\\$\\{|\`)`, 'g');
// const req = createRequire(import.meta.url) / module.createRequire(...)
const CREATE_REQUIRE = /\b([A-Za-z_$][\w$]{0,100})\s*=\s*(?:[A-Za-z_$][\w$]{0,100}\s*\.\s*)?createRequire\s*\(/g;

// 'lodash/merge' -> 'lodash', '@scope/pkg/sub' -> '@scope/pkg', './local' -> null
export function packageNameFromSpecifier(spec) {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || /^[a-z][a-z0-9+.-]*:/i.test(spec) || spec.startsWith('#')) return null;
  const parts = spec.split('/');
  if (spec.startsWith('@')) return parts.length >= 2 && parts[1] ? parts.slice(0, 2).join('/') : null;
  return parts[0] || null;
}

// The static prefix of a template literal names a package only if it is complete:
// `lodash/${x}` -> lodash, `@scope/pkg/${x}` -> @scope/pkg, `lod${x}` -> null.
function packageFromTemplate(text, complete) {
  if (complete) return packageNameFromSpecifier(text);
  const parts = text.split('/');
  const needed = text.startsWith('@') ? 3 : 2; // the name, then a "/"
  return parts.length >= needed ? packageNameFromSpecifier(text) : null;
}

function hasNodeShebang(file) {
  let fd;
  try {
    fd = openSync(file, 'r');
    const buf = Buffer.alloc(128);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const first = buf.toString('utf8', 0, n).split('\n')[0];
    return /^#!.*\b(?:node|nodejs|bun|deno|tsx|ts-node)\b/.test(first);
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

// Collect source files under `dir`. Symlinks are followed only when they point back
// inside the project, and each real directory is visited once, so a link to "/" or a
// link loop can't escape the project or recurse forever.
function walk(dir, ctx, out) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch {
    return out;
  }
  const atRoot = ctx.roots.has(dir);
  for (const entry of entries) {
    if (SKIP_ANYWHERE.has(entry) || (atRoot && SKIP_AT_ROOT.has(entry))) continue;
    const full = join(dir, entry);
    let st;
    try {
      st = lstatSync(full);
      if (st.isSymbolicLink()) {
        const real = realpathSync(full);
        if (real !== ctx.realRoot && !real.startsWith(ctx.realRoot + sep)) continue;
        st = statSync(full);
        if (st.isDirectory()) {
          if (ctx.seen.has(real)) continue;
          ctx.seen.add(real);
        }
      } else if (st.isDirectory()) {
        const real = realpathSync(full);
        if (ctx.seen.has(real)) continue;
        ctx.seen.add(real);
      }
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, ctx, out);
    else if (st.isFile() && st.size < MAX_FILE_BYTES && (SOURCE_EXT.test(entry) || (!entry.includes('.') && hasNodeShebang(full)))) {
      out.push(full);
    }
  }
  return out;
}

function isTestPath(rel, workspaceRoots) {
  const segs = rel.split('/');
  if (TEST_FILE.test(segs[segs.length - 1])) return true;
  if (segs.slice(0, -1).includes('__tests__')) return true;
  // First folder below the project root or below a workspace root.
  for (const ws of workspaceRoots) {
    const prefix = ws ? ws.split('/') : [];
    if (prefix.every((p, i) => segs[i] === p) && segs.length > prefix.length + 1 && TEST_DIRS_AT_ROOT.has(segs[prefix.length])) {
      return true;
    }
  }
  return false;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function* specifiers(text) {
  for (const re of PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) yield { name: packageNameFromSpecifier(m[2]), index: m.index };
  }
  TEMPLATE_PATTERN.lastIndex = 0;
  let m;
  while ((m = TEMPLATE_PATTERN.exec(text))) yield { name: packageFromTemplate(m[1], m[2] === '`'), index: m.index };
  // Functions made by createRequire() load packages just like require().
  CREATE_REQUIRE.lastIndex = 0;
  const aliases = new Set();
  while ((m = CREATE_REQUIRE.exec(text))) if (m[1] !== 'require') aliases.add(m[1]);
  for (const alias of aliases) {
    const re = new RegExp(`(?<![\\w$.])${escapeRe(alias)}(?:\\s*\\.\\s*resolve)?\\s*\\(${COMMENTS}${Q}${SPEC}\\1`, 'g');
    while ((m = re.exec(text))) yield { name: packageNameFromSpecifier(m[2]), index: m.index };
  }
}

// Returns Map(packageName -> { runtime: [file:line], test: [file:line] }).
// `workspaces` are workspace folders relative to projectDir ("packages/app"); each one's
// top-level build and test folders are treated like the project root's.
export function findImports(projectDirArg, { workspaces = [] } = {}) {
  const projectDir = resolve(projectDirArg);
  const found = new Map();
  const workspaceRoots = ['', ...workspaces];
  const ctx = {
    realRoot: realpathSync(projectDir),
    roots: new Set(workspaceRoots.map((w) => (w ? join(projectDir, ...w.split('/')) : projectDir))),
    seen: new Set([realpathSync(projectDir)]),
  };
  for (const file of walk(projectDir, ctx, [])) {
    const rel = relative(projectDir, file).split(sep).join('/');
    const kind = isTestPath(rel, workspaceRoots) ? 'test' : 'runtime';
    const text = readFileSync(file, 'utf8');
    for (const { name, index } of specifiers(text)) {
      if (!name) continue;
      const line = text.slice(0, index).split('\n').length;
      if (!found.has(name)) found.set(name, { runtime: [], test: [] });
      const where = found.get(name)[kind];
      const loc = `${rel}:${line}`;
      if (!where.includes(loc)) where.push(loc);
    }
  }
  return found;
}

// Classify one installed package.
//   imported            - the project's runtime code loads it directly
//   via-imported        - a dependency the runtime code loads pulls it in
//   test-only           - only test code loads it (directly or through a dependency)
//   not-imported        - installed, but nothing in the project loads it or its parents
// Names here are installed names: for "foo": "npm:lodash@...", code says require('foo').
export function classify(install, imports) {
  // Only the copy at the top of the project (or a workspace) is what `require(name)`
  // from project code resolves to.
  const topLevel = install.topLevel ?? install.path === `node_modules/${install.name}`;
  const hit = topLevel ? imports.get(install.name) : undefined;
  if (hit?.runtime.length) {
    return { level: 'imported', evidence: hit.runtime };
  }
  // Direct dependencies that lead here, other than this package itself.
  const parents = install.via.filter((d) => d !== install.name);
  const runtimeParents = parents.filter((d) => imports.get(d)?.runtime.length);
  if (runtimeParents.length) {
    return { level: 'via-imported', evidence: runtimeParents.map((d) => `via ${d} (${imports.get(d).runtime[0]})`) };
  }
  if (hit?.test.length) {
    return { level: 'test-only', evidence: hit.test };
  }
  const testParents = parents.filter((d) => imports.get(d)?.test.length);
  if (testParents.length) {
    return { level: 'test-only', evidence: testParents.map((d) => `via ${d} (${imports.get(d).test[0]})`) };
  }
  return { level: 'not-imported', evidence: [] };
}

export const REACHABILITY_RANK = { 'not-imported': 0, 'test-only': 1, 'via-imported': 2, imported: 3 };
