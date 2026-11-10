import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = mkdtempSync(join(tmpdir(), 'sca-pack-smoke-'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
function run(cmd, args, cwd) {
  const result = spawnSync(cmd, args, { cwd, encoding: 'utf8', shell: cmd === npm && process.platform === 'win32',
    env: { ...process.env, npm_config_cache: join(root, 'cache'), npm_config_update_notifier: 'false' } });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return result.stdout;
}
try {
  const [pack] = JSON.parse(run(npm, ['pack', '--json', '--ignore-scripts', '--pack-destination', root], process.cwd()));
  const paths = pack.files.map((file) => file.path);
  for (const path of ['bin/sca-triage.js', 'src/triage.js', 'README.md', 'SECURITY.md', 'ARCHITECTURE.md', 'CHANGELOG.md']) assert.ok(paths.includes(path), path);
  assert.ok(!paths.some((path) => path.startsWith('test/') || path.startsWith('scripts/')));
  const consumer = join(root, 'consumer'); mkdirSync(consumer);
  writeFileSync(join(consumer, 'package.json'), '{"name":"pack-consumer","version":"1.0.0","private":true}');
  run(npm, ['install', join(root, pack.filename), '--ignore-scripts', '--no-audit', '--no-fund'], consumer);
  const installed = join(consumer, 'node_modules/sca-triage');
  assert.match(run(process.execPath, [join(installed, 'bin/sca-triage.js'), '--help'], consumer), /Usage:/);
  const bin = join(consumer, 'node_modules/.bin', process.platform === 'win32' ? 'sca-triage.cmd' : 'sca-triage');
  const result = spawnSync(bin, ['--help'], { cwd: consumer, encoding: 'utf8', shell: process.platform === 'win32' });
  assert.equal(result.status, 0, result.stderr);
  const pkg = JSON.parse(readFileSync(join(installed, 'package.json')));
  assert.equal(pkg.repository.url, 'git+https://github.com/lansiquo/sca-triage.git');
  // The docs in the package are what npm shows. Check the parts that have drifted before.
  const text = (file) => readFileSync(join(installed, file), 'utf8').replace(/\r\n/g, '\n');
  const readme = text('README.md');
  for (const [, block] of readme.matchAll(/```bash\n([\s\S]*?)```/g)) {
    assert.doesNotMatch(block, /node \S*bin\/sca-triage\.js/, 'README commands should run the published tool with npx');
  }
  for (const [, version] of readme.matchAll(/@v(\d+\.\d+\.\d+)/g)) assert.equal(version, pkg.version, 'README pins another version');
  const usage = (lines) => lines.split('\n').map((line) => line.trim()).filter((line) => /^sca-triage (scan|plan|fix|--version)/.test(line));
  const help = run(process.execPath, [join(installed, 'bin/sca-triage.js'), '--help'], consumer).replace(/\r\n/g, '\n');
  assert.deepEqual(usage(readme), usage(help), 'the README usage block and --help differ');
  const changelog = text('CHANGELOG.md');
  assert.ok(changelog.includes(`\n## [${pkg.version}]`), 'CHANGELOG.md has no entry for this version');
  assert.ok(changelog.includes(`\n[${pkg.version}]: `), 'CHANGELOG.md has no link for this version');
  console.log(`Packed-consumer smoke test passed (${pack.filename}, ${paths.length} files).`);
} finally { rmSync(root, { recursive: true, force: true }); }
