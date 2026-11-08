// Fixture: import forms the scanner must recognise. Not real code.
const a = require(`tpl-literal`);
import b from"no-space";
const c = await import(/* webpackChunkName: "chunk" */ 'commented-import');
import { createRequire } from 'node:module';
const req = createRequire(import.meta.url);
const d = req('via-create-require');
const e = require(`tpl-prefix/${process.platform}`);
const f = require(`./local/${process.platform}`);
const g = require(        'many-spaces');
export * from"re-export";
import {
  h,
  i,
} from 'multi-line';
