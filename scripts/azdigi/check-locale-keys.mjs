#!/usr/bin/env node
// check-locale-keys.mjs <base> <target> — exit 1 when apps/login/locales/<target>.json lacks keys of <base>.json.
// A missing target file is reported but tolerated until the locale exists (phase 2 of the AZDIGI plan).
import fs from 'node:fs';
import path from 'node:path';

const [base = 'en', target = 'vi'] = process.argv.slice(2);
const dir = path.resolve('apps/login/locales');
const read = (name) => JSON.parse(fs.readFileSync(path.join(dir, `${name}.json`), 'utf8'));
const flatten = (obj, prefix = '') =>
  Object.entries(obj).flatMap(([key, value]) =>
    value && typeof value === 'object' ? flatten(value, `${prefix}${key}.`) : [`${prefix}${key}`],
  );

if (!fs.existsSync(path.join(dir, `${target}.json`))) {
  console.log(`locales/${target}.json not present yet — skipping key check`);
  process.exit(0);
}
const baseKeys = flatten(read(base));
const targetKeys = new Set(flatten(read(target)));
const missing = baseKeys.filter((key) => !targetKeys.has(key));
if (missing.length) {
  console.error(`locales/${target}.json is missing ${missing.length} key(s):\n${missing.join('\n')}`);
  process.exit(1);
}
console.log(`locales/${target}.json covers all ${baseKeys.length} keys of ${base}.json`);
