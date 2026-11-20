// The vendored contract matches ../agent-guard, and the package is shaped the way OpenClaw loads it.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, test } from 'node:test';
import plugin from '../src/index.ts';
import { packageRoot } from '../src/package-root.ts';

const root = packageRoot();
const agentGuard = process.env.AGENT_GUARD_DIR ?? join(root, '..', 'agent-guard');

describe('vendored contract', () => {
  test('contract/ and skills/ are identical to ../agent-guard', { skip: !existsSync(join(agentGuard, 'SPEC.md')) && 'agent-guard is not next to this package' }, () => {
    const r = spawnSync(process.execPath, [join(root, 'scripts', 'sync-contract.mjs'), '--check'], { encoding: 'utf8', env: { ...process.env, AGENT_GUARD_DIR: agentGuard } });
    assert.equal(r.status, 0, `${r.stdout}${r.stderr}`);
  });

  test('the skill ships with front matter', () => {
    const skill = readFileSync(join(root, 'skills', 'lumoauth-guard', 'SKILL.md'), 'utf8');
    assert.match(skill, /^---\nname: lumoauth-guard\ndescription: .+\n---\n/);
  });
});

describe('package shape', () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  const manifest = JSON.parse(readFileSync(join(root, 'openclaw.plugin.json'), 'utf8'));

  test('manifest: id, configSchema, skills, CLI command', () => {
    assert.equal(manifest.id, 'lumoauth');
    assert.equal(manifest.id, plugin.id, 'the export id must match the manifest');
    assert.equal(manifest.configSchema.type, 'object');
    assert.deepEqual(manifest.skills, ['./skills']);
    assert.deepEqual(manifest.cliCommands.map((c: any) => c.name), ['lumoauth']);
    assert.equal(manifest.version, pkg.version);
  });

  test('package.json: ESM, openclaw.extensions, no runtime dependencies', () => {
    assert.equal(pkg.name, '@lumoauth/openclaw');
    assert.equal(pkg.type, 'module');
    assert.deepEqual(pkg.openclaw.extensions, ['./dist/index.js']);
    assert.ok(pkg.openclaw.compat.pluginApi);
    // OpenClaw's installer refuses anything but a semver floor here.
    assert.match(pkg.openclaw.install.minHostVersion, /^>=\d+\.\d+\.\d+/);
    assert.ok(!pkg.files.includes('e2e'), 'the e2e harness is not published');
    assert.equal(pkg.dependencies, undefined);
    assert.deepEqual(Object.keys(pkg.devDependencies).sort(), ['@types/node', 'typescript']);
    for (const f of ['dist', 'contract', 'skills', 'openclaw.plugin.json']) assert.ok(pkg.files.includes(f), f);
  });
});
