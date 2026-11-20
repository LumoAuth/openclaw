import type { ApprovalsMode, DecisionConfig } from './core/decide.ts';
/** SPEC §3.1 config.json. */
export interface GuardConfig extends DecisionConfig {
    version: 1;
    baseUrl: string;
    orgId: string;
    agentId: string;
    issuer: string;
    tokenEndpoint: string;
    keyId: string;
    ownerUserId: string | null;
    canActOnBehalfOfUsers: boolean;
    preset: string;
    decisionMode: 'local' | 'server';
    approvals: ApprovalsMode;
    onUngranted: 'ask' | 'block';
    taint: {
        enabled: boolean;
        windowSeconds: number;
        escalate: string[];
    };
    refreshSeconds: number;
    offlineGraceSeconds: number;
    receipts: boolean;
    rememberApprovals: boolean;
    extraProtectedPaths: string[];
    allowPaths: string[];
    /** Not in SPEC §3.1 (unknown keys are ignored by other readers): the agent's page in LumoAuth. */
    agentUrl?: string;
    /** The agent's name as enrolled. */
    name?: string;
    enrolledAt?: string;
}
export declare const DEFAULTS: {
    preset: string;
    decisionMode: "local";
    approvals: "auto";
    onUngranted: "ask";
    taint: {
        enabled: boolean;
        windowSeconds: number;
        escalate: string[];
    };
    refreshSeconds: number;
    offlineGraceSeconds: number;
    receipts: boolean;
    rememberApprovals: boolean;
};
export interface LoadedConfig {
    config: GuardConfig | null;
    /** Values that were out of range or of the wrong type and fell back to the default (reported by status). */
    issues: string[];
    /** Why the config cannot be used (missing identity fields), when config is null. */
    error?: string;
}
export declare function isHttpsUrl(v: string): boolean;
/**
 * Validate a parsed config.json. Unknown keys are ignored; a value out of
 * range falls back to its default and is listed in `issues`.
 */
export declare function parseConfig(raw: unknown): LoadedConfig;
/** The agent's page in LumoAuth (where the owner grants capabilities). */
export declare function agentPortalUrl(config: Pick<GuardConfig, 'agentUrl' | 'baseUrl' | 'orgId' | 'agentId'>): string;
