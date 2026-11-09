// Explicit paths work on shells that do not expand test/*.test.js (Windows).
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
const files = readdirSync(new URL('../test/', import.meta.url)).filter((name) => name.endsWith('.test.js')).sort();
const result = spawnSync(process.execPath, ['--test', ...files.map((name) => `test/${name}`)], { stdio: 'inherit' });
if (result.error) console.error(result.error.message);
process.exitCode = result.status ?? 2;
