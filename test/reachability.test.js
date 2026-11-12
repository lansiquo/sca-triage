import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { findImports, packageNameFromSpecifier } from '../src/reachability.js';

const REACH = fileURLToPath(new URL('./fixtures/reach', import.meta.url));

function tempProject(t) {
  const dir = mkdtempSync(join(tmpdir(), 'sca-triage-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test('recognises require/import forms beyond the plain ones', () => {
  const imports = findImports(REACH);
  const runtime = (name) => imports.get(name)?.runtime ?? [];
  for (const name of [
    'tpl-literal', // require(`x`)
    'no-space', // import b from"x"
    'commented-import', // import(/* comment */ 'x')
    'via-create-require', // createRequire(import.meta.url)('x')
    'tpl-prefix', // require(`x/${y}`)
    'many-spaces',
    're-export', // export * from"x"
    'multi-line',
  ]) {
    assert.ok(runtime(name).length, `${name} should be found in runtime code`);
  }
  assert.deepEqual(runtime('tpl-prefix'), ['src/forms.js:8']);
  assert.equal(imports.has('local'), false);
});

test('scans .vue, .svelte, .astro and extensionless node scripts', () => {
  const imports = findImports(REACH);
  for (const name of ['in-vue', 'in-svelte', 'in-astro', 'from-bin']) {
    assert.ok(imports.get(name)?.runtime.length, `${name} should be found`);
  }
});

test('skips build output and test folders only at the top of the project', () => {
  const imports = findImports(REACH);
  assert.equal(imports.has('in-root-build'), false); // build/ at the root is output
  assert.deepEqual(imports.get('in-src-build')?.runtime, ['src/build/helper.js:1']);
  assert.deepEqual(imports.get('in-src-spec')?.runtime, ['src/spec/router.js:1']); // runtime code, not a test
  assert.deepEqual(imports.get('in-root-test')?.test, ['test/a.js:1']);
  assert.deepEqual(imports.get('in-jest-tests')?.test, ['src/__tests__/a.js:1']);
});

test('treats a workspace root like the project root for test folders', () => {
  const ws = fileURLToPath(new URL('./fixtures/workspaces', import.meta.url));
  const imports = findImports(ws, { workspaces: ['packages/app', 'packages/tools'] });
  assert.deepEqual(imports.get('test-lib'), { runtime: [], test: ['packages/app/test/app.test.js:2'], config: [] });
  assert.deepEqual(imports.get('express').runtime, ['packages/app/src/index.js:2']);
});

test('does not follow symlinks out of the project or around a loop', (t) => {
  const outside = tempProject(t);
  writeFileSync(join(outside, 'secret.js'), "require('outside-pkg')");
  const dir = tempProject(t);
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src', 'index.js'), "require('inside-pkg')");
  symlinkSync(outside, join(dir, 'src', 'escape'), 'dir');
  symlinkSync(join(outside, 'secret.js'), join(dir, 'src', 'linked.js'));
  symlinkSync(dir, join(dir, 'src', 'loop'), 'dir');
  const imports = findImports(dir);
  assert.deepEqual([...imports.keys()], ['inside-pkg']);
});

test('stays linear on hostile input (no ReDoS)', (t) => {
  const dir = tempProject(t);
  const size = 300_000;
  writeFileSync(join(dir, 'a.js'), 'import '.repeat(size / 7));
  writeFileSync(join(dir, 'b.js'), 'export '.repeat(size / 7));
  writeFileSync(join(dir, 'c.js'), 'require( /* '.repeat(size / 12));
  // One line of regex starts that never end, and of quotes whose partner is escaped.
  writeFileSync(join(dir, 'd.js'), '(/['.repeat(size / 3));
  writeFileSync(join(dir, 'e.js'), "'" + "\\'".repeat(size / 2));
  writeFileSync(join(dir, 'f.vue'), '<script>'.repeat(size / 8));
  // Comments that might be JSX text, each one a reason to search the rest of the file.
  writeFileSync(join(dir, 'g.jsx'), '>a/*<*/'.repeat(size / 14));
  writeFileSync(join(dir, 'h.jsx'), '}//{\n'.repeat(size / 10));
  // After such a comment: words whose gaps all run through one far "*/" and then a long row of
  // comments, and assignments whose right side is the same far word.
  writeFileSync(join(dir, 'i.jsx'), '>a/*<*/' + 'a=/*'.repeat(size / 24) + '*/' + '/**/'.repeat(size / 24) + 'b.createRequire(');
  const started = process.hrtime.bigint();
  findImports(dir);
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  assert.ok(ms < 1000, `took ${ms.toFixed(0)} ms`);
});

// Each of these hid the require from the scanner: the quote or "/*" inside a regular
// expression, or an apostrophe in JSX or HTML text, was read as the start of a string or comment.
test('finds imports after regular expressions, JSX text and HTML text that contain quotes', (t) => {
  const dir = tempProject(t);
  const files = {
    'regex-quote.js': "const re = /'/;\nconst x = require('vuln');\n",
    'regex-class.js': "const re = /[\"'/]/g;\nconst x = require('vuln');\n",
    'regex-same-line.js': "if (/'/.test(s)) require('vuln');\n",
    'regex-comment-start.js': "const p = s.replace(/^\\/*/, '');\nconst x = require('vuln');\n/** doc */\n",
    'regex-two-slashes.js': "const ok = /\\/\\//.test(u) && require('vuln');\n",
    'jsx-text.jsx': "const a = <p>Don't</p>;\nconst x = require('vuln');\n",
    'jsx-same-line.jsx': "const a = <p>Don't {require('vuln')}</p>;\n",
    'template-text.vue': "<template>\n  <p>Don't click ` here</p>\n</template>\n<script>\nimport x from 'vuln'\n</script>\n",
    'template-call.vue': "<template><img :src=\"require('vuln')\"></template>\n",
    'front.astro': "---\nimport x from 'vuln';\n---\n<p>It's fine</p>\n",
    'import-equals.ts': "import fs = require('vuln');\n",
    'division.js': "const a = b / c; const d = e / f;\nconst x = require('vuln');\n",
    'open-template.js': "const x = require('vuln');\nconst t = `never closed\nconst y = require('later');\n",
  };
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  writeFileSync(join(dir, 'comment.js'), "// const y = require('commented');\n/* import z from 'commented' */\nconst s = \"require('in-string')\";\n");
  const imports = findImports(dir);
  const found = new Set(imports.get('vuln').runtime.map((loc) => loc.split(':')[0]));
  assert.deepEqual([...found].sort(), Object.keys(files).sort());
  assert.ok(imports.get('later'), 'text after an unclosed template literal is still searched');
  assert.equal(imports.has('commented'), false);
  assert.equal(imports.has('in-string'), false);
  assert.deepEqual(imports.get('vuln').runtime.filter((loc) => loc.startsWith('template-text.vue')), ['template-text.vue:5']);
});

// "/*" or "//" in JSX text is text, not a comment. Read as a comment, it hid every import up to
// the next "*/" (or the end of the line), and the tokenizer could resume inside a string or
// template literal that it then misread.
test('finds imports after "/*" or "//" in JSX text', (t) => {
  const dir = tempProject(t);
  const files = {
    'glob.jsx': "const C = () => <code>src/*.js</code>;\nconst L = lazy(() => import('vuln'));\n/** doc */\nfunction f(){}\n",
    'glob-url.jsx': "const A = () => <a href=\"/docs\">docs/*</a>;\nexport default A;\nconst B = () => import('vuln');\n/* trailing */\n",
    'glob.js': "const C = () => <code>src/*.js</code>;\nconst x = require('vuln');\n/* end */\n",
    'glob-static.tsx': "const C = () => <p>{n}/*</p>;\nimport x from 'vuln';\n/* end */\n",
    'glob-same-line.jsx': "const C = () => <p>a/*</p>; require('vuln'); /* b */\n",
    'glob-template.jsx': "const C = () => <p>a/*</p>;\nconst t = `*/`;\nconst x = require('vuln');\nconst u = `b`;\n",
    'url.jsx': "const A = () => <p>http://example.com</p>; const x = require('vuln');\n",
    'url-template.jsx': "const A = () => <p>http://example.com</p>; const t = `\n`; const x = require('vuln'); const u = `\n`;\n",
  };
  for (const [name, text] of Object.entries(files)) writeFileSync(join(dir, name), text);
  // Real comments still don't count, in JSX and around it.
  writeFileSync(join(dir, 'comments.jsx'), [
    "// const a = require('commented');",
    "/* const b = require('commented'); */",
    'function f() {',
    "  /* require('commented') */ return <div>{/* import('commented') */}<p>a /* b */ c</p></div>; // import('commented')",
    '}',
    '/**',
    " * require('commented')",
    ' */',
    "const ok = require('plain');",
    '',
  ].join('\n'));
  const imports = findImports(dir);
  const found = new Set((imports.get('vuln')?.runtime ?? []).map((loc) => loc.split(':')[0]));
  assert.deepEqual([...found].sort(), Object.keys(files).sort());
  assert.deepEqual(imports.get('vuln').runtime.filter((loc) => loc.startsWith('glob.jsx')), ['glob.jsx:2']);
  assert.equal(imports.has('commented'), false);
  assert.deepEqual(imports.get('plain')?.runtime, ['comments.jsx:9']);
});

// Code after "/*" or "//" in JSX text: the marker with a later "*/", with none, and "//".
const JSX_MARKERS = {
  block: (code) => `const C = () => <pre>lib/*.mjs</pre>;\n${code}\n/* end */\n`,
  'block-open': (code) => `const C = () => <pre>lib/*.mjs</pre>;\n${code}\n`, // no "*/" follows
  line: (code) => `const C = () => <p>http://example.com</p>; ${code}\n`,
};

// After "/*" or "//" in JSX text the tokenizer can't be trusted, and the search that takes over
// has to know every form the tokenizer knows. It used to miss template literals, createRequire
// aliases, escaped specifiers and comments longer than the fallback patterns allow.
test('after "/*" or "//" in JSX text, every import form is still found', (t) => {
  const dir = tempProject(t);
  const forms = {
    static: "import x from 'vuln';",
    'side-effect': "import 'vuln';",
    're-export': "export * from 'vuln';",
    'import-equals': "import fs = require('vuln');",
    require: "const x = require('vuln');",
    resolve: "require.resolve('vuln');",
    dynamic: "const L = () => import('vuln');",
    'template-import': 'import(`vuln`);',
    'template-require': 'require(`vuln`);',
    'template-prefix': 'require(`vuln/${name}`);',
    alias: "const load = createRequire(import.meta.url); load('vuln');",
    'alias-module': "const load = module.createRequire(import.meta.url); load.resolve('vuln');",
    'alias-template': 'const load = createRequire(import.meta.url); load(`vuln`);',
    escaped: "require('vul\\u006e');",
    'long-comment': `require(/* ${'x'.repeat(500)} */ 'vuln');`,
    'many-comments': `import(${'/* c */ '.repeat(9)}'vuln');`,
    'comment-before-paren': "require /* c */ . /* d */ resolve /* e */ ('vuln');",
    'long-subpath': `require('vuln/${'a/'.repeat(400)}b');`,
  };
  const files = [];
  for (const ext of ['jsx', 'tsx', 'js']) {
    for (const [marker, wrap] of Object.entries(JSX_MARKERS)) {
      for (const [form, code] of Object.entries(forms)) {
        files.push(`${form}.${marker}.${ext}`);
        writeFileSync(join(dir, files.at(-1)), wrap(code));
      }
    }
  }
  // The alias is declared before the JSX text and called after it, or the other way round.
  writeFileSync(join(dir, 'template.jsx'), 'const Page = () => <pre>lib/*.mjs</pre>;\nimport(`from-template`);\n/* end */\n');
  writeFileSync(join(dir, 'alias.jsx'), "import { createRequire } from 'node:module';\nconst load = createRequire(import.meta.url);\nconst Page = () => <pre>lib/*.mjs</pre>;\nload('from-alias');\n/* end */\n");
  writeFileSync(join(dir, 'alias-later.jsx'), "function f() { return load('from-later-alias'); }\nconst Page = () => <pre>lib/*.mjs</pre>;\nconst load = createRequire(import.meta.url);\n/* end */\n");
  const imports = findImports(dir);
  const found = new Set((imports.get('vuln')?.runtime ?? []).map((loc) => loc.split(':')[0]));
  assert.deepEqual(files.filter((file) => !found.has(file)), []);
  assert.deepEqual(imports.get('vuln').runtime.filter((loc) => loc.startsWith('template-import.block.jsx')), ['template-import.block.jsx:2']);
  assert.deepEqual(imports.get('from-template')?.runtime, ['template.jsx:2']);
  assert.deepEqual(imports.get('from-alias')?.runtime, ['alias.jsx:4']);
  assert.deepEqual(imports.get('from-later-alias')?.runtime, ['alias-later.jsx:1']);
});

// A createRequire alias is known by the last token of its name as the tokenizer splits it: a
// word, or any other single character. The search after JSX text only knew words of [\w$], so
// an alias whose name ends otherwise was found everywhere except after "/*" or "//" in JSX text.
test('after "/*" or "//" in JSX text, a createRequire alias with any name is still found', (t) => {
  const dir = tempProject(t);
  const names = {
    accent: 'charg\u00e9', // chargé: ends in a character that is not ASCII
    'non-ascii': '\u0437\u0430\u0433\u0440\u0443\u0437\u0438\u0442\u044c', // загрузить: no ASCII at all
    astral: '\u{1d4b3}', // 𝒳: one character, two UTF-16 code units
    middle: 'ch\u00e4rge', // chärge: not ASCII in the middle only
    element: 'loaders[0]', // not a plain name
  };
  const declare = (name) => `${name.includes('[') ? '' : 'const '}${name} = createRequire(import.meta.url);`;
  const orders = {
    // declared before the JSX text and called after it
    before: (name, wrap) => `${declare(name)}\n${wrap(`${name}('vuln');`)}`,
    // declared and called after it
    after: (name, wrap) => wrap(`${declare(name)} ${name}.resolve('vuln');`),
    // declared after it and called before it
    'called-first': (name, wrap) => `function f() { return ${name}(\`vuln\`); }\n${wrap(declare(name))}`,
  };
  // The same files with no "/*" or "//" in the JSX text are the controls.
  const markers = { ...JSX_MARKERS, none: (code) => `const C = () => <pre>lib files</pre>;\n${code}\n/* end */\n` };
  const files = [];
  for (const ext of ['jsx', 'tsx', 'js']) {
    for (const [marker, wrap] of Object.entries(markers)) {
      for (const [label, name] of Object.entries(names)) {
        for (const [order, source] of Object.entries(orders)) {
          files.push(`${label}.${order}.${marker}.${ext}`);
          writeFileSync(join(dir, files.at(-1)), source(name, wrap));
        }
      }
    }
  }
  const imports = findImports(dir);
  const found = new Set((imports.get('vuln')?.runtime ?? []).map((loc) => loc.split(':')[0]));
  assert.deepEqual(files.filter((file) => !found.has(file)), []);
  assert.deepEqual(imports.get('vuln').runtime.filter((loc) => loc.startsWith('accent.before.block.jsx')), ['accent.before.block.jsx:3']);
});

// The price of that search: a real comment can look like JSX text. It does when the last of
// { } < > before it is ">" or "}" and it contains "<" or "{", like a JSDoc type after a function.
// From there to the end of the file, an import in a comment or a string counts as loaded. A false
// "imported" costs a reviewer a look; a false "not imported" hides a package below the gate.
test('after a comment that might be JSX text, an import in a comment or string counts as loaded', (t) => {
  const dir = tempProject(t);
  writeFileSync(join(dir, 'jsdoc-type.js'), "function example() {}\n/** @type {string} */\n// require('in-comment');\nrequire('live');\n");
  writeFileSync(join(dir, 'comparison.js'), "const comparison = 2 > 1;\n/* <doc> require('in-comment'); */\nrequire('live');\n");
  writeFileSync(join(dir, 'string.js'), "function example() {}\n/** @returns {string} */\nconst documentation = \"require('in-string')\";\nrequire('live');\n");
  writeFileSync(join(dir, 'template.js'), "function example() {}\n/** @type {string} */\n// import(`in-comment`);\n");
  // Without such a comment nothing changes: these are the same files with plain comments.
  writeFileSync(join(dir, 'plain-jsdoc.js'), "function example() {}\n/** a string */\n// require('plain-comment');\n// import(`plain-comment`);\nrequire('live');\n");
  writeFileSync(join(dir, 'plain-comparison.js'), "const comparison = 2 > 1;\n/* doc require('plain-comment'); */\nrequire('live');\n");
  writeFileSync(join(dir, 'plain-string.js'), "function example() {}\n/** returns a string */\nconst documentation = \"require('plain-string')\";\nrequire('live');\n");
  writeFileSync(join(dir, 'plain-block.js'), "function example() {\n  /** @type {string} */\n  // require('plain-comment');\n}\n");
  const imports = findImports(dir);
  assert.deepEqual(imports.get('in-comment')?.runtime, ['comparison.js:2', 'jsdoc-type.js:3', 'template.js:3']);
  assert.deepEqual(imports.get('in-string')?.runtime, ['string.js:3']);
  assert.deepEqual(imports.get('live')?.runtime, ['comparison.js:3', 'jsdoc-type.js:4', 'plain-comparison.js:3', 'plain-jsdoc.js:5', 'plain-string.js:4', 'string.js:4']);
  assert.equal(imports.has('plain-comment'), false);
  assert.equal(imports.has('plain-string'), false);
});

test('files count by their real location, and files too large to read are reported', (t) => {
  const dir = tempProject(t);
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src/index.js'), "require('vuln');\n");
  mkdirSync(join(dir, '__tests__'));
  symlinkSync('../src', join(dir, '__tests__', 'src'), 'dir'); // walked first, but it is src/
  writeFileSync(join(dir, 'big.js'), `require('hidden');\n/*${'x'.repeat(2_000_000)}*/\n`);
  const imports = findImports(dir);
  assert.deepEqual(imports.get('vuln'), { runtime: ['src/index.js:1'], test: [], config: [] });
  assert.deepEqual(imports.skipped, ['big.js']);
});

test('reads the package name from an import specifier, and ignores URL-style and subpath imports', () => {
  assert.equal(packageNameFromSpecifier('lodash/merge'), 'lodash');
  assert.equal(packageNameFromSpecifier('./local'), null);
  assert.equal(packageNameFromSpecifier('node:fs'), null);
  assert.equal(packageNameFromSpecifier('https://example.com/x.js'), null);
  assert.equal(packageNameFromSpecifier('#internal'), null);
  assert.equal(packageNameFromSpecifier('@scope'), null);
  assert.equal(packageNameFromSpecifier('@scope/pkg/sub'), '@scope/pkg');
});

test('template interpolations and escaped specifiers retain nested and subsequent imports', (t) => {
  const dir = tempProject(t);
  writeFileSync(join(dir, 'index.js'), "const value = `text ${require('inside')} tail ${`nested ${require('deep')}`} end`; require('after'); require('esc\\u0061ped');");
  const imports = findImports(dir);
  for (const name of ['inside', 'deep', 'after', 'escaped']) assert.ok(imports.has(name), name);
});
