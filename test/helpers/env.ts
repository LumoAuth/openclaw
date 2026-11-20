import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { GuardEnv } from '../../src/core/paths.ts';
import { packageRoot } from '../../src/package-root.ts';

export function loadVector<T = any>(name: string): T {
  return JSON.parse(readFileSync(join(packageRoot(), 'contract', 'vectors', name), 'utf8')) as T;
}

/** The machine that every vector assumes (contract/vectors/environment.json). */
export function vectorEnv(overrides: Partial<GuardEnv> = {}): GuardEnv {
  const e = loadVector('environment.json');
  return {
    home: e.home,
    stateDir: e.openclaw.stateDir,
    workspace: e.openclaw.workspace,
    workspaces: [e.openclaw.workspace],
    cwd: e.openclaw.cwd,
    guardHome: e.openclaw.guardHome,
    pluginDir: e.openclaw.pluginDir,
    platform: 'linux',
    extraProtectedPaths: [],
    allowPaths: [],
    realpath: undefined,
    ...overrides,
  };
}
