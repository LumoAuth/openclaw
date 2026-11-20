import type { SnapshotView } from '../core/decide.ts';
import type { AgentClient } from './agent-client.ts';
export interface Snapshot {
    agentId: string | undefined;
    status: string;
    capabilities: string[];
    fetchedAtMs: number;
}
export interface SnapshotError {
    atMs: number;
    kind: string;
    message: string;
}
/**
 * The agent's capability snapshot (SPEC §7.2): refreshed in the background
 * and on demand. Token `invalid_client`/401 and `/me` 401/403 clear it;
 * network and server errors keep it (offline grace is applied by decide()).
 */
export declare class SnapshotStore {
    snapshot: Snapshot | null;
    lastError: SnapshotError | null;
    private inflight;
    private readonly client;
    private readonly now;
    constructor(client: () => AgentClient | null, now?: () => number);
    ageSeconds(): number | undefined;
    view(): SnapshotView | null;
    clear(): void;
    /** Refresh now (one request in flight). Never throws. */
    refresh(): Promise<void>;
    /** Refresh when older than `maxAgeSeconds`, waiting at most `timeoutMs`. */
    ensureFresh(maxAgeSeconds: number, timeoutMs: number): Promise<void>;
    private doRefresh;
}
