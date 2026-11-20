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
export declare function resolveHostPaths(env?: NodeJS.ProcessEnv, config?: OpenClawConfigLike, osHome?: string): HostPaths;
/** Every configured workspace: the default and each agent's own (agents.list[].workspace). */
export declare function configuredWorkspaces(paths: HostPaths, config?: OpenClawConfigLike): string[];
/** The workspace of one agent (agents.list[id].workspace), else the default. */
export declare function workspaceForAgent(paths: HostPaths, config: OpenClawConfigLike | undefined, agentId: string | undefined): string;
/**
 * Symlink resolution for the rules: realpath of the deepest existing
 * ancestor plus the rest of the path, so a symlinked parent directory is
 * followed even when the file itself does not exist yet.
 */
export declare function deepRealpath(p: string): string | undefined;
export declare function buildGuardEnv(opts: {
    paths: HostPaths;
    config?: OpenClawConfigLike | undefined;
    agentId?: string | undefined;
    guardHome: string;
    pluginDir?: string | undefined;
    extraProtectedPaths?: string[];
    allowPaths?: string[];
    platform?: string;
}): GuardEnv;
