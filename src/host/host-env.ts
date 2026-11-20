import { existsSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';
import type { GuardEnv } from '../core/paths.ts';
import type { OpenClawConfigLike } from './openclaw-types.ts';

/** Where OpenClaw keeps things (src/config/state-dir.ts, src/agents/workspace-default-path.ts). */
export interface HostPaths {
  /** The OS user's home (secrets, persistence and the Guard home are below it). */
  home: string;
  /** OPENCLAW_HOME, else home. */
  openclawHome: string;
  stateDir: string;
  configPath: string;
  configPathFromEnv: string | undefined;
  /** Default workspace (agents.defaults.workspace, else OPENCLAW_WORKSPACE_DIR, else <state>/workspace). */
  workspace: string;
}

function expandTilde(p: string, home: string): string {
  if (p === '~') return home;
  if (p.startsWith('~/') || p.startsWith('~\\')) return join(home, p.slice(2));
  return p;
}

export function resolveHostPaths(env: NodeJS.ProcessEnv = process.env, config?: OpenClawConfigLike, osHome: string = homedir()): HostPaths {
  const ochome = env.OPENCLAW_HOME?.trim() ? resolve(expandTilde(env.OPENCLAW_HOME.trim(), osHome)) : osHome;
  let stateDir: string;
  const override = env.OPENCLAW_STATE_DIR?.trim();
  if (override) stateDir = resolve(ochome, expandTilde(override, ochome));
  else {
    const profile = env.OPENCLAW_PROFILE?.trim();
    stateDir = profile && profile.toLowerCase() !== 'default' ? join(ochome, `.openclaw-${profile}`) : join(ochome, '.openclaw');
  }
  const configPathFromEnv = env.OPENCLAW_CONFIG_PATH?.trim() ? resolve(expandTilde(env.OPENCLAW_CONFIG_PATH.trim(), ochome)) : undefined;
  const configured = typeof config?.agents?.defaults?.workspace === 'string' ? config.agents.defaults.workspace.trim() : '';
  const wsEnv = env.OPENCLAW_WORKSPACE_DIR?.trim();
  const workspace = configured
    ? resolve(stateDir, expandTilde(configured, ochome))
    : wsEnv
      ? resolve(expandTilde(wsEnv, ochome))
      : join(stateDir, 'workspace');
  return {
    home: osHome,
    openclawHome: ochome,
    stateDir,
    configPath: configPathFromEnv ?? join(stateDir, 'openclaw.json'),
    configPathFromEnv,
    workspace,
  };
}

/** Every configured workspace: the default and each agent's own (agents.list[].workspace). */
export function configuredWorkspaces(paths: HostPaths, config?: OpenClawConfigLike): string[] {
  const out = [paths.workspace];
  const list = config?.agents?.list;
  if (Array.isArray(list)) {
    for (const a of list) {
      const ws = typeof a?.workspace === 'string' ? a.workspace.trim() : '';
      if (ws) {
        const abs = resolve(paths.stateDir, expandTilde(ws, paths.openclawHome));
        if (!out.includes(abs)) out.push(abs);
      }
    }
  }
  return out;
}

/** The workspace of one agent (agents.list[id].workspace), else the default. */
export function workspaceForAgent(paths: HostPaths, config: OpenClawConfigLike | undefined, agentId: string | undefined): string {
  if (agentId && Array.isArray(config?.agents?.list)) {
    const a = config.agents.list.find((x: any) => x && x.id === agentId);
    const ws = typeof a?.workspace === 'string' ? a.workspace.trim() : '';
    if (ws) return resolve(paths.stateDir, expandTilde(ws, paths.openclawHome));
  }
  return paths.workspace;
}

/**
 * Symlink resolution for the rules: realpath of the deepest existing
 * ancestor plus the rest of the path, so a symlinked parent directory is
 * followed even when the file itself does not exist yet.
 */
export function deepRealpath(p: string): string | undefined {
  if (!isAbsolute(p)) return undefined;
  let current = p;
  const rest: string[] = [];
  for (let i = 0; i < 64; i++) {
    if (existsSync(current)) {
      try {
        const real = realpathSync.native(current);
        return rest.length ? join(real, ...rest.reverse()) : real;
      } catch {
        return undefined;
      }
    }
    const parent = dirname(current);
    if (parent === current) return undefined;
    rest.push(current.slice(parent.length).replace(new RegExp(`^\\${sep}+`), ''));
    current = parent;
  }
  return undefined;
}

export function buildGuardEnv(opts: {
  paths: HostPaths;
  config?: OpenClawConfigLike | undefined;
  agentId?: string | undefined;
  guardHome: string;
  pluginDir?: string | undefined;
  extraProtectedPaths?: string[];
  allowPaths?: string[];
  platform?: string;
}): GuardEnv {
  const workspace = workspaceForAgent(opts.paths, opts.config, opts.agentId);
  return {
    home: opts.paths.home,
    stateDir: opts.paths.stateDir,
    configPathFromEnv: opts.paths.configPathFromEnv,
    workspace,
    workspaces: configuredWorkspaces(opts.paths, opts.config),
    cwd: workspace,
    guardHome: opts.guardHome,
    pluginDir: opts.pluginDir,
    platform: opts.platform ?? process.platform,
    extraProtectedPaths: opts.extraProtectedPaths ?? [],
    allowPaths: opts.allowPaths ?? [],
    realpath: deepRealpath,
    aliases: {
      stateDir: deepRealpath(opts.paths.stateDir),
      lumoauthRoot: deepRealpath(join(opts.paths.home, '.lumoauth')),
    },
  };
}
