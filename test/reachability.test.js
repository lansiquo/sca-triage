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
  assert.deepEqual(imports.get('test-lib'), { runtime: [], test: ['packages/app/test/app.test.js:2'] });
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

test('files count by their real location, and files too large to read are reported', (t) => {
  const dir = tempProject(t);
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src/index.js'), "require('vuln');\n");
  mkdirSync(join(dir, '__tests__'));
  symlinkSync('../src', join(dir, '__tests__', 'src'), 'dir'); // walked first, but it is src/
  writeFileSync(join(dir, 'big.js'), `require('hidden');\n/*${'x'.repeat(2_000_000)}*/\n`);
  const imports = findImports(dir);
  assert.deepEqual(imports.get('vuln'), { runtime: ['src/index.js:1'], test: [] });
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
