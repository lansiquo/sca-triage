// Import-level reachability: which packages does the project's own code actually load?
// This is deliberately simple and honest about it. It finds require(), import,
// export ... from, dynamic import() and createRequire() calls with package names in
// the project's source files. It does not build a call graph, so "imported" means
// "the code loads it", not "the vulnerable function is proven to run".
//
// When in doubt it errs toward "loaded": a false "imported" costs a reviewer a look,
// a false "not imported" hides a reachable vulnerability below the CI gate.

import { readdirSync, readFileSync, lstatSync, statSync, realpathSync, openSync, readSync, closeSync } from 'node:fs';
import { join, relative, resolve, sep, posix } from 'node:path';

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

// A single lexical pass avoids both declaration-length limits and regex backtracking.
// This is an import inventory, not a JavaScript parser: conservative matches are OK.
function tokens(text) {
  const out = [];
  let line = 1, braceDepth = 0;
  const templates = [];
  for (let i = 0; i < text.length;) {
    const c = text[i];
    if (/\s/.test(c)) { if (c === '\n') line++; i++; continue; }
    if (text.startsWith('//', i)) { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (text.startsWith('/*', i)) {
      i += 2;
      while (i < text.length && !text.startsWith('*/', i)) { if (text[i++] === '\n') line++; }
      i += 2;
      continue;
    }
    const startLine = line;
    const continuation = c === '}' && templates.at(-1) === braceDepth;
    if (c === '"' || c === "'" || c === '`' || continuation) {
      if (continuation) { templates.pop(); braceDepth--; }
      const quote = continuation ? '`' : c;
      let value = '', complete = true;
      i++;
      while (i < text.length && text[i] !== quote) {
        if (text[i] === '\n') line++;
        if (quote === '`' && text.startsWith('${', i)) { complete = false; break; }
        if (text[i] === '\\' && i + 1 < text.length) {
          i++;
          const escape = text[i];
          const width = escape === 'u' ? 4 : escape === 'x' ? 2 : 0;
          const hex = width ? text.slice(i + 1, i + 1 + width) : '';
          if (width && hex.length === width && /^[\da-f]+$/i.test(hex)) {
            value += String.fromCharCode(parseInt(hex, 16)); i += width + 1; continue;
          }
          if (escape === '\n') { line++; i++; continue; }
          value += ({ n: '\n', r: '\r', t: '\t' })[escape] ?? escape;
          i++; continue;
        }
        value += text[i++];
      }
      if (!continuation) out.push({ value, literal: true, template: quote === '`', complete, line: startLine });
      if (!complete) {
        templates.push(++braceDepth);
        i += 2; // Continue lexing the expression inside ${...}.
      } else i++;
      continue;
    }
    if (/[\w$]/.test(c)) {
      const start = i++;
      while (i < text.length && /[\w$]/.test(text[i])) i++;
      out.push({ value: text.slice(start, i), line });
    } else {
      if (c === '{') braceDepth++;
      if (c === '}') braceDepth--;
      out.push({ value: c, line }); i++;
    }
  }
  return out;
}

function* specifiers(text) {
  const ts = tokens(text);
  const aliases = new Set(['require']);
  for (let i = 0; i < ts.length; i++) {
    if (ts[i + 1]?.value !== '=') continue;
    let j = i + 2;
    if (ts[j + 1]?.value === '.') j += 2;
    if (ts[j]?.value === 'createRequire' && ts[j + 1]?.value === '(') aliases.add(ts[i].value);
  }
  const nameOf = (t) => t.template ? packageFromTemplate(t.value, t.complete) : packageNameFromSpecifier(t.value);
  for (let i = 0; i < ts.length; i++) {
    const t = ts[i];
    if (t.literal) continue;
    if (aliases.has(t.value) || t.value === 'import') {
      let j = i + 1;
      if (ts[j]?.value === '.' && ts[j + 1]?.value === 'resolve') j += 2;
      if (ts[j]?.value === '(' && ts[j + 1]?.literal) {
        yield { name: nameOf(ts[j + 1]), line: t.line };
        continue;
      }
    }
    if (t.value !== 'import' && t.value !== 'export') continue;
    if (ts[i + 1]?.value === '(' || ts[i + 1]?.value === '.') continue;
    let j = i + 1;
    if (t.value === 'import' && ts[j]?.literal) {
      yield { name: nameOf(ts[j]), line: t.line };
      i = j; continue;
    }
    for (; j < ts.length; j++) {
      const v = ts[j].value;
      if (v === ';' || v === 'import' || v === 'export' || v === '(' || ts[j].literal) break;
      if (v === 'from' && ts[j + 1]?.literal) {
        yield { name: nameOf(ts[j + 1]), line: t.line };
        j += 2; break;
      }
    }
    // Each token is visited a bounded number of times, even for malformed declarations.
    i = Math.max(i, j - 1);
  }
}

// Returns Map(packageName -> { runtime: [file:line], test: [file:line] }).
// `workspaces` are workspace folders relative to projectDir ("packages/app"); each one's
// top-level build and test folders are treated like the project root's.
export function findImports(projectDirArg, { workspaces = [] } = {}) {
  const projectDir = resolve(projectDirArg);
  const found = new Map();
  found.records = [];
  const locations = new Map();
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
    for (const { name, line } of specifiers(text)) {
      if (!name) continue;
      if (!found.has(name)) found.set(name, { runtime: [], test: [] });
      const where = found.get(name)[kind];
      const loc = `${rel}:${line}`;
      const key = `${name}\0${kind}`;
      if (!locations.has(key)) locations.set(key, new Set());
      if (!locations.get(key).has(loc)) {
        locations.get(key).add(loc);
        where.push(loc);
        found.records.push({ name, file: rel, kind, loc });
      }
    }
  }
  return found;
}

// Bind source imports to installed paths before tracing their dependencies. The same
// name in another workspace must not borrow this source file's evidence.
export function resolveImports(project, imports) {
  const reached = new Map();
  const roots = new Map();
  for (const record of imports.records) {
    const dirname = posix.dirname(record.file);
    const root = project.resolveDependency(dirname === '.' ? '' : dirname, record.name);
    if (!root) continue;
    const key = `${root.path}\0${record.kind}`;
    if (!roots.has(key)) roots.set(key, { root, kind: record.kind, evidence: new Set() });
    roots.get(key).evidence.add(record.loc);
  }
  for (const { root, kind, evidence } of roots.values()) {
    const rootEvidence = [...evidence];
    const stack = [root], seen = new Set();
    while (stack.length) {
      const node = stack.pop();
      if (seen.has(node.path)) continue;
      seen.add(node.path);
      const level = kind === 'test' ? 'test-only' : node === root ? 'imported' : 'via-imported';
      const previous = reached.get(node.path);
      if (!previous || REACHABILITY_RANK[level] >= REACHABILITY_RANK[previous.level]) {
        const locations = node === root ? rootEvidence : [`via ${root.name} (${rootEvidence[0]})`];
        reached.set(node.path, { level, evidence: previous?.level === level ? [...new Set([...previous.evidence, ...locations])] : locations });
      }
      for (const path of node.dependencyPaths) stack.push(project.byPath.get(path));
    }
  }
  return reached;
}

export function classify(install, imports) {
  return imports.get(install.path) || { level: 'not-imported', evidence: [] };
}

export const REACHABILITY_RANK = { 'not-imported': 0, 'test-only': 1, 'via-imported': 2, imported: 3 };
