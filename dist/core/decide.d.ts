import type { Risk } from './catalog.ts';
export type ApprovalsMode = 'auto' | 'lumoauth' | 'host' | 'off';
export interface DecisionConfig {
    approvals: ApprovalsMode;
    onUngranted: 'ask' | 'block';
    taint: {
        enabled: boolean;
        windowSeconds: number;
        escalate: string[];
    };
    refreshSeconds: number;
    offlineGraceSeconds: number;
}
export interface SnapshotView {
    status: string;
    ageSeconds: number;
    capabilities: readonly string[];
}
export interface DecisionInput {
    classification: {
        capability: string;
        risk: Risk;
        egress?: boolean;
        persistsInstructions?: boolean;
    };
    hardRule: 'deny' | 'approve' | null;
    state: {
        locked: boolean;
        setUp: boolean;
    };
    /** null: no snapshot. */
    snapshot: SnapshotView | null;
    tainted: boolean;
    config: DecisionConfig;
    /**
     * Server mode (§6.2): the Ask API's answer for the capability; undefined
     * means "use the snapshot" (local mode, or the Ask API was unavailable).
     */
    serverAllowed?: boolean | undefined;
}
export type ReasonCode = 'locked' | 'not_set_up' | 'hard_rule' | 'hard_rule_approve' | 'snapshot_unavailable' | 'agent_inactive' | 'granted' | 'tainted' | 'not_granted' | 'approvals_off';
export interface Decision {
    outcome: 'allow' | 'block' | 'approve';
    reason: ReasonCode;
    /** Receipt decision for a block (SPEC §7.4). */
    receiptDecision?: 'blocked' | 'denied';
}
/** Reason texts (contract/vectors/decide.json). */
export declare const REASON_TEXT: Record<ReasonCode, string>;
/**
 * SPEC §6.1, up to the choice of approval channel. One deliberate reading:
 * the snapshot check (step 4) also runs before a hard-rule approval, so that
 * suspending the agent in LumoAuth stops every call (§1, kill switch).
 */
export declare function decide(input: DecisionInput): Decision;
