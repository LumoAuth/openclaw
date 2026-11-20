import type { GuardConfig } from './config.ts';
import { GuardHome } from './guard-home.ts';
import type { HostPaths } from './host/host-env.ts';
import type { OpenClawConfigLike, SecurityAuditFinding } from './host/openclaw-types.ts';
import type { FetchFn } from './lumoauth/http.ts';
export type CheckLevel = 'ok' | 'info' | 'warn' | 'critical';
export interface DoctorCheck {
    id: string;
    level: CheckLevel;
    finding: string;
    fix?: string;
}
export interface DoctorOptions {
    home: GuardHome;
    hostConfig: OpenClawConfigLike | undefined;
    paths: HostPaths;
    env?: NodeJS.ProcessEnv;
    /** Contact LumoAuth (token + /agents/me). Off: connectivity is reported from the last known state. */
    live?: boolean;
    fetchFn?: FetchFn | undefined;
    /** Result of the gateway's last refresh (status.json), used when live is false. */
    lastKnown?: {
        status?: string;
        error?: string;
    } | undefined;
}
/** Effective before_tool_call timeout for this plugin (OpenClaw: hooks.timeouts[hook] → hooks.timeoutMs → the registration's own). */
export declare function effectiveHookTimeoutMs(hostConfig: OpenClawConfigLike | undefined): number;
/** Approvals may go through LumoAuth push (needs the long hook timeout). */
export declare function mayUseLumoAuthApprovals(config: GuardConfig): boolean;
/** SPEC §9: every check. Doctor never changes anything. */
export declare function runDoctor(o: DoctorOptions): Promise<DoctorCheck[]>;
export declare function worstLevel(checks: DoctorCheck[]): CheckLevel;
/** The checks as `openclaw security audit` findings (ok checks are left out). */
export declare function toAuditFindings(checks: DoctorCheck[]): SecurityAuditFinding[];
