import { type Risk } from '../core/catalog.ts';
import { type DoctorCheck } from '../doctor.ts';
import type { GuardHome } from '../guard-home.ts';
import type { HostPaths } from '../host/host-env.ts';
import type { OpenClawConfigLike } from '../host/openclaw-types.ts';
import { type FetchFn } from '../lumoauth/http.ts';
import { type CliIo } from './io.ts';
/** Writes openclaw.json through the host (api.runtime.config.mutateConfigFile). */
export type HostConfigWriter = (mutate: (draft: OpenClawConfigLike) => void) => Promise<void>;
export interface CommandDeps {
    io: CliIo;
    home: GuardHome;
    hostConfig: OpenClawConfigLike | undefined;
    paths: HostPaths;
    env?: NodeJS.ProcessEnv;
    fetchFn?: FetchFn | undefined;
    configWriter?: HostConfigWriter | undefined;
    sleep?: (ms: number) => Promise<void>;
    now?: () => number;
    hostname?: string;
}
export declare const REGIONS: Record<string, string>;
export declare class CliError extends Error {
}
/** A dashboard URL such as https://app.lumoauth.dev/orgs/acme/portal → base URL and organization. */
export declare function parseDashboardUrl(input: string): {
    baseUrl: string;
    orgId: string | undefined;
};
export interface CapabilityItem {
    scope: string;
    risk: Risk;
    label: string;
    checked: boolean;
}
export declare function mcpServerNames(hostConfig: OpenClawConfigLike | undefined): string[];
/** SPEC §8.1 step 5: every capability of the catalog, pre-ticked by the preset, plus mcp:<server>:<risk>:* per server. */
export declare function capabilityChecklist(presetName: string, servers: string[]): CapabilityItem[];
export interface SetupOptions {
    url?: string;
    region?: string;
    org?: string;
    preset?: string;
    approvals?: string;
    name?: string;
    yes?: boolean;
    force?: boolean;
}
export declare function setupCommand(deps: CommandDeps, opts: SetupOptions): Promise<void>;
export interface StatusOptions {
    json?: boolean;
    offline?: boolean;
}
export declare function statusCommand(deps: CommandDeps, opts: StatusOptions): Promise<Record<string, unknown>>;
export declare function doctorCommand(deps: CommandDeps, opts: {
    json?: boolean;
    offline?: boolean;
}): Promise<DoctorCheck[]>;
export declare function lockCommand(deps: CommandDeps, reason: string): void;
export declare function unlockCommand(deps: CommandDeps): void;
export declare function resetCommand(deps: CommandDeps, opts: {
    yes?: boolean;
}): Promise<void>;
