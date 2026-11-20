#!/usr/bin/env node
// Copies the LumoAuth Guard contract (catalog, vectors, skill) from the
// sibling agent-guard repository into this package:
//   ../agent-guard/catalog/*.json   -> contract/catalog/
//   ../agent-guard/vectors/*.json   -> contract/vectors/
//   ../agent-guard/skills/<name>/** -> skills/<name>/
//
//   node scripts/sync-contract.mjs           copy
//   node scripts/sync-contract.mjs --check   exit 1 when the copy differs
//
// AGENT_GUARD_DIR overrides the source directory. No dependencies.
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const source = resolve(process.env.AGENT_GUARD_DIR ?? join(root, '..', 'agent-guard'));
const check = process.argv.includes('--check');

/** [source dir, target dir] pairs, relative to `source` and `root`. */
export const PAIRS = [
  ['catalog', 'contract/catalog'],
  ['vectors', 'contract/vectors'],
  ['skills', 'skills'],
];

function listFiles(dir) {
  if (!existsSync(dir)) return [];
  const out = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...listFiles(full).map((f) => join(entry, f)));
    else out.push(entry);
  }
  return out.sort();
}

if (!existsSync(join(source, 'SPEC.md'))) {
  const msg = `agent-guard not found at ${source}`;
  if (check) {
    console.log(`${msg}: nothing to compare.`);
    process.exit(0);
  }
  console.error(`${msg}. Set AGENT_GUARD_DIR.`);
  process.exit(1);
}

const differences = [];
for (const [from, to] of PAIRS) {
  const src = join(source, from);
  const dst = join(root, to);
  const srcFiles = listFiles(src);
  const dstFiles = listFiles(dst);
  for (const f of new Set([...srcFiles, ...dstFiles])) {
    const a = join(src, f);
    const b = join(dst, f);
    if (!existsSync(a)) differences.push(`${relative(root, b)} is not in agent-guard`);
    else if (!existsSync(b)) differences.push(`${relative(root, b)} is missing`);
    else if (!readFileSync(a).equals(readFileSync(b))) differences.push(`${relative(root, b)} differs`);
  }
  if (!check) {
    rmSync(dst, { recursive: true, force: true });
    mkdirSync(dst, { recursive: true });
    cpSync(src, dst, { recursive: true });
  }
}

if (check) {
  if (differences.length) {
    for (const d of differences) console.error(`✗ ${d}`);
    console.error('Run: npm run sync-contract');
    process.exit(1);
  }
  console.log(`Contract copy matches ${source}.`);
} else {
  console.log(differences.length ? `Synced ${differences.length} change(s) from ${source}.` : `Already in sync with ${source}.`);
}
