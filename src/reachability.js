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
export const MAX_FILE_BYTES = 2_000_000;
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
// Tool configuration such as vite.config.js or jest.config.ts. A development-only package
// that only these files load is build tooling, not something the app runs (see resolveImports).
const CONFIG_FILE = /\.config\.(?:c|m)?(?:j|t)s$/;

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
    else if (st.isFile() && (SOURCE_EXT.test(entry) || (!entry.includes('.') && hasNodeShebang(full)))) {
      // Each file once, by its real path: that is where Node resolves its imports from, and
      // it decides runtime vs test code (a test folder that links to src/ doesn't make src/ tests).
      let real;
      try {
        real = realpathSync(full);
      } catch {
        continue;
      }
      if (ctx.seen.has(real)) continue;
      ctx.seen.add(real);
      if (st.size < MAX_FILE_BYTES) out.push(real);
      else ctx.skipped.push(real);
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

// Fallback patterns for text the tokenizer below can't read reliably. They over-match on
// purpose (code in a comment counts): when unsure, a package counts as loaded. The gaps
// they allow are bounded, so a hostile file can't make them backtrack quadratically.
const Q = `(['"])`; // opening quote, closed with \\1
const SPEC = `([^'"\`\\s]{1,500})`; // a package specifier, maybe with a subpath
const COMMENTS = `\\s*(?:(?:\\/\\*(?:[^*]|\\*(?!\\/)){0,400}\\*\\/|\\/\\/[^\\n]{0,400}\\n)\\s*){0,8}`;
// require('x'), require.resolve('x'), import('x')
const CALL_PATTERNS = [
  new RegExp(`\\brequire(?:\\s*\\.\\s*resolve)?\\s*\\(${COMMENTS}${Q}${SPEC}\\1`, 'g'),
  new RegExp(`\\bimport\\s*\\(${COMMENTS}${Q}${SPEC}\\1`, 'g'),
];
// ... plus import 'x' and the source of import/export ... from 'x'
const FALLBACK_PATTERNS = [
  ...CALL_PATTERNS,
  new RegExp(`\\bimport${COMMENTS}${Q}${SPEC}\\1`, 'g'),
  new RegExp(`\\bfrom${COMMENTS}${Q}${SPEC}\\1`, 'g'),
];

function patternHits(text, offset, patterns) {
  const hits = [];
  for (const re of patterns) for (const m of text.matchAll(re)) hits.push({ spec: m[2], index: offset + m.index });
  return hits;
}

// Words and punctuation after which "/" starts a regular expression rather than a division.
// Not after ")", "]", "}" or "<": that is division, or a JSX closing tag.
const REGEX_AFTER_WORD = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);
const REGEX_AFTER_PUNCT = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', ';', '+', '-', '*', '%', '~', '^', '>']);

function regexCanStart(prev, next) {
  if (next === '>') return false; // "/>" closes a JSX tag
  if (!prev) return true;
  if (prev.literal || prev.regex) return false;
  return /^[\w$]/.test(prev.value) ? REGEX_AFTER_WORD.has(prev.value) : REGEX_AFTER_PUNCT.has(prev.value);
}

// The offset just past the regular expression that starts at text[i], or -1 if it doesn't
// end on its line. "/" inside a character class ([/]) doesn't end it.
function regexEnd(text, i) {
  let inClass = false;
  for (let k = i + 1; k < text.length; k++) {
    const ch = text[k];
    if (ch === '\n') return -1;
    if (ch === '\\') {
      if (text[k + 1] === '\n') return -1;
      k++;
    } else if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (ch === '/' && !inClass) {
      k++;
      while (k < text.length && /[a-z]/i.test(text[k])) k++;
      return k;
    }
  }
  return -1;
}

// A single lexical pass avoids both declaration-length limits and regex backtracking.
// This is an import inventory, not a JavaScript parser. Whatever it can't read reliably is
// returned in `unsure` as { start, end } ranges for the fallback patterns:
//   - a line with a quote that has no partner on it, or a "/" that looks like the start of a
//     regular expression but never ends (an apostrophe in JSX text, unusual syntax);
//   - everything after a comment or template literal that is never closed;
//   - everything after a comment that might be JSX text (see mayBeJsxText).
function tokens(text) {
  const out = [];
  const unsure = [];
  let line = 1, braceDepth = 0;
  let oddLine = 0; // a line already handed to the fallback: its quotes and slashes stay punctuation
  const templates = [];
  const lineEnd = (i) => {
    const n = text.indexOf('\n', i);
    return n === -1 ? text.length : n;
  };
  const giveUpOnLine = (i) => {
    oddLine = line;
    unsure.push({ start: text.lastIndexOf('\n', i - 1) + 1, end: lineEnd(i) });
  };
  // "/*" and "//" in JSX text (<code>src/*.js</code>, <p>http://x</p>) are text. JSX text
  // contains none of { } < >, so it can only start after a ">" or "}", and it can only hide
  // code if the "comment" runs past its end, a "<" or "{". Such a comment is read as one, and
  // the rest of the file also goes to the fallback, since the tokenizer may resume inside a
  // string or template literal. The last { } < > is tracked in one forward pass.
  let mark = '', markPos = 0, restUnsure = false;
  const mayBeJsxText = (start, end) => {
    if (restUnsure) return;
    for (; markPos < start; markPos++) if ('{}<>'.includes(text[markPos])) mark = text[markPos];
    if ((mark !== '>' && mark !== '}') || !/[<{]/.test(text.slice(start, end))) return;
    restUnsure = true;
    unsure.push({ start, end: text.length });
  };
  for (let i = 0; i < text.length;) {
    const c = text[i];
    if (/\s/.test(c)) { if (c === '\n') line++; i++; continue; }
    if (text.startsWith('//', i)) { const end = lineEnd(i); mayBeJsxText(i, end); i = end; continue; }
    if (text.startsWith('/*', i)) {
      const close = text.indexOf('*/', i + 2);
      if (close === -1) { unsure.push({ start: i, end: text.length }); break; }
      mayBeJsxText(i, close);
      for (let k = i; k < close; k++) if (text[k] === '\n') line++;
      i = close + 2;
      continue;
    }
    if (c === '/' && oddLine !== line && regexCanStart(out.at(-1), text[i + 1])) {
      const close = regexEnd(text, i);
      if (close !== -1) { out.push({ value: '/regex/', regex: true, line }); i = close; continue; }
      giveUpOnLine(i);
    }
    const startLine = line;
    const continuation = c === '}' && templates.at(-1) === braceDepth;
    if (c === '`' || continuation || ((c === '"' || c === "'") && oddLine !== line)) {
      const start = i;
      const quote = continuation ? '`' : c;
      let value = '', complete = true, closed = false;
      i++;
      while (i < text.length) {
        if (text[i] === quote) { closed = true; break; }
        if (text[i] === '\n') {
          if (quote !== '`') break; // only template literals span lines
          line++;
        }
        if (quote === '`' && text.startsWith('${', i)) { complete = false; closed = true; break; }
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
      if (!closed) {
        if (quote === '`') { unsure.push({ start, end: text.length }); break; }
        // No partner on this line: not a string. Keep the quote as punctuation and read on.
        line = startLine;
        giveUpOnLine(start);
        out.push({ value: c, line });
        i = start + 1;
        continue;
      }
      if (continuation) { templates.pop(); braceDepth--; }
      else out.push({ value, literal: true, template: quote === '`', complete, line: startLine });
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
  return { tokens: out, unsure };
}

// In .vue, .svelte and .astro files only <script> blocks, and Astro's leading "---" block,
// are JavaScript; the rest is HTML, where an apostrophe is just text.
const SFC_EXT = /\.(?:vue|svelte|astro)$/;

function scriptRanges(text, file) {
  const ranges = [];
  let pos = 0;
  const front = file.endsWith('.astro') ? /^﻿?---\r?\n/.exec(text) : null;
  if (front) {
    const close = text.indexOf('\n---', front[0].length - 1);
    pos = close === -1 ? text.length : close;
    ranges.push([front[0].length, pos]);
  }
  const lower = text.toLowerCase();
  while (pos < text.length) {
    const open = lower.indexOf('<script', pos);
    const gt = open === -1 ? -1 : text.indexOf('>', open);
    if (gt === -1) break;
    const close = lower.indexOf('</script', gt);
    ranges.push([gt + 1, close === -1 ? text.length : close]);
    if (close === -1) break;
    pos = close + 8;
  }
  return ranges;
}

// `text` with everything inside (or, with keep = false, outside) the ranges turned into
// spaces. Line breaks stay, so offsets and line numbers still match the file.
function blank(text, ranges, keep) {
  const spaces = (from, to) => text.slice(from, to).replace(/[^\n]/g, ' ');
  let out = '', pos = 0;
  for (const [start, end] of ranges) {
    out += keep ? spaces(pos, start) + text.slice(start, end) : text.slice(pos, start) + spaces(start, end);
    pos = end;
  }
  return out + (keep ? spaces(pos, text.length) : text.slice(pos));
}

// Yields { name, line } for each package the text imports, and { name, line, named: true } for
// each string that is exactly one of `names` (a framework can load a package by name, as
// Express does with app.set('view engine', 'ejs')).
function* specifiers(text, file = '', names = new Set()) {
  let code = text;
  const hits = []; // fallback matches: { spec, index }
  if (SFC_EXT.test(file)) {
    const ranges = scriptRanges(text, file);
    code = blank(text, ranges, true);
    // Outside the scripts, only calls count (a Vue template can call require()).
    hits.push(...patternHits(blank(text, ranges, false), 0, CALL_PATTERNS));
  }
  const { tokens: ts, unsure } = tokens(code);
  for (const r of unsure) hits.push(...patternHits(code.slice(r.start, r.end), r.start, FALLBACK_PATTERNS));
  const aliases = new Set(['require']);
  for (let i = 0; i < ts.length; i++) {
    if (ts[i + 1]?.value !== '=') continue;
    let j = i + 2;
    if (ts[j + 1]?.value === '.') j += 2;
    if (ts[j]?.value === 'createRequire' && ts[j + 1]?.value === '(') aliases.add(ts[i].value);
  }
  const nameOf = (t) => t.template ? packageFromTemplate(t.value, t.complete) : packageNameFromSpecifier(t.value);
  const used = new Set(); // string tokens read as import specifiers
  for (let i = 0; i < ts.length; i++) {
    const t = ts[i];
    if (t.literal) {
      if (!used.has(i) && !t.template && names.has(t.value)) yield { name: t.value, line: t.line, named: true };
      continue;
    }
    if (aliases.has(t.value) || t.value === 'import') {
      let j = i + 1;
      if (ts[j]?.value === '.' && ts[j + 1]?.value === 'resolve') j += 2;
      if (ts[j]?.value === '(' && ts[j + 1]?.literal) {
        used.add(j + 1);
        yield { name: nameOf(ts[j + 1]), line: t.line };
        continue;
      }
    }
    if (t.value !== 'import' && t.value !== 'export') continue;
    if (ts[i + 1]?.value === '(' || ts[i + 1]?.value === '.') continue;
    let j = i + 1;
    if (t.value === 'import' && ts[j]?.literal) {
      used.add(j);
      yield { name: nameOf(ts[j]), line: t.line };
      i = j; continue;
    }
    for (; j < ts.length; j++) {
      const v = ts[j].value;
      if (v === ';' || v === 'import' || v === 'export' || v === '(' || ts[j].literal) break;
      if (v === 'from' && ts[j + 1]?.literal) {
        used.add(j + 1);
        yield { name: nameOf(ts[j + 1]), line: t.line };
        j += 2; break;
      }
    }
    // Resume at the token that ended the declaration. If that is "(", resume one earlier:
    // TypeScript's `import x = require('y')` puts a require call inside the declaration.
    // Each token is still visited a bounded number of times, even for malformed declarations.
    i = Math.max(i, ts[j]?.value === '(' ? j - 2 : j - 1);
  }
  // Fallback matches, with their line numbers counted in one pass over the text.
  hits.sort((a, b) => a.index - b.index);
  let line = 1, pos = 0;
  for (const hit of hits) {
    for (; pos < hit.index; pos++) if (text.charCodeAt(pos) === 10) line++;
    yield { name: packageNameFromSpecifier(hit.spec), line };
  }
}

// Returns Map(packageName -> { runtime: [file:line], test: [file:line], config: [file:line] }).
// `workspaces` are workspace folders relative to projectDir ("packages/app"); each one's
// top-level build and test folders are treated like the project root's. A string that is
// exactly one of `names` is recorded too, as `named`; resolveImports decides whether it counts.
export function findImports(projectDirArg, { workspaces = [], names = new Set() } = {}) {
  const projectDir = resolve(projectDirArg);
  const found = new Map();
  found.records = [];
  const locations = new Map();
  const workspaceRoots = ['', ...workspaces];
  const ctx = {
    realRoot: realpathSync(projectDir),
    roots: new Set(workspaceRoots.map((w) => (w ? join(projectDir, ...w.split('/')) : projectDir))),
    seen: new Set([realpathSync(projectDir)]),
    skipped: [],
  };
  const files = walk(projectDir, ctx, []);
  // Files too large to read: their imports are not counted, so the caller warns about them.
  found.skipped = ctx.skipped.map((file) => relative(ctx.realRoot, file).split(sep).join('/'));
  for (const file of files) {
    const rel = relative(ctx.realRoot, file).split(sep).join('/');
    const kind = isTestPath(rel, workspaceRoots) ? 'test' : CONFIG_FILE.test(rel) ? 'config' : 'runtime';
    const text = readFileSync(file, 'utf8');
    for (const { name, line, named } of specifiers(text, rel, names)) {
      if (!name) continue;
      if (!found.has(name)) found.set(name, { runtime: [], test: [], config: [] });
      const where = found.get(name)[kind];
      const loc = `${rel}:${line}`;
      const key = `${name}\0${kind}\0${named ? 'named' : ''}`;
      if (!locations.has(key)) locations.set(key, new Set());
      if (!locations.get(key).has(loc)) {
        locations.get(key).add(loc);
        if (!named) where.push(loc);
        found.records.push({ name, file: rel, kind, loc, ...(named ? { named: true } : {}) });
      }
    }
  }
  return found;
}

// Bind source imports to installed paths before tracing their dependencies. The same
// name in another workspace must not borrow this source file's evidence.
//   - A string that names a package counts only for a direct dependency the project declares
//     for production (not devDependencies): level "named".
//   - A config file (vite.config.js) loading a development-only package is build tooling:
//     level "config-only". Loading anything else from a config file counts as runtime code.
export function resolveImports(project, imports) {
  const reached = new Map();
  const roots = new Map();
  for (const record of imports.records) {
    const dirname = posix.dirname(record.file);
    const root = project.resolveDependency(dirname === '.' ? '' : dirname, record.name);
    if (!root) continue;
    if (record.named && !root.declaredBy?.some((d) => d.kind !== 'dev')) continue;
    let kind = record.kind;
    if (kind === 'config' && !root.dev) kind = 'runtime';
    const key = `${root.path}\0${kind}\0${record.named ? 'named' : ''}`;
    if (!roots.has(key)) roots.set(key, { root, kind, named: Boolean(record.named), evidence: new Set() });
    roots.get(key).evidence.add(record.loc);
  }
  for (const { root, kind, named, evidence } of roots.values()) {
    const rootEvidence = [...evidence];
    const stack = [root], seen = new Set();
    while (stack.length) {
      const node = stack.pop();
      if (seen.has(node.path)) continue;
      seen.add(node.path);
      const level = kind === 'test' ? 'test-only' : kind === 'config' ? 'config-only'
        : node !== root ? 'via-imported' : named ? 'named' : 'imported';
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

// "named" ranks with "via-imported": both count as loaded, on weaker evidence than an import.
export const REACHABILITY_RANK = { 'not-imported': 0, 'config-only': 1, 'test-only': 1, 'via-imported': 2, named: 2, imported: 3 };
