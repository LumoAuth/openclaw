/**
 * Per-session memory kept in the host process only (cleared on restart):
 * taint (SPEC §6.3) and "allow always" answers (§6.4).
 */
export declare class TaintTracker {
    private readonly until;
    /** Mark a session tainted for `windowSeconds` from `nowMs`. */
    mark(session: string, windowSeconds: number, nowMs: number): void;
    isTainted(session: string, nowMs: number): boolean;
    taintedSessions(nowMs: number): number;
    clear(): void;
    private prune;
}
export declare class RememberedApprovals {
    private readonly keys;
    private static key;
    remember(session: string, capability: string): void;
    has(session: string, capability: string): boolean;
    get size(): number;
    clear(): void;
}
