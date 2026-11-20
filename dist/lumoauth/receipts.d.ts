import type { ToolCallReceipt } from './agent-client.ts';
export interface ReceiptQueueOptions {
    send: (calls: ToolCallReceipt[]) => Promise<unknown>;
    log?: {
        warn: (m: string) => void;
        error: (m: string) => void;
    } | undefined;
    now?: (() => number) | undefined;
    /** At most this many queued (oldest dropped). */
    max?: number;
    /** Flush as soon as this many are queued. */
    flushAt?: number;
    /** Receipts per request (the server accepts 50). */
    batchSize?: number;
    intervalMs?: number;
    /** A receipt whose call never completes is sent without outcome after this long. */
    pendingTimeoutMs?: number;
    /**
     * receipts-queue.jsonl (SPEC §3): receipts still queued when the process
     * exits are appended here and sent by the next process that starts the Guard.
     */
    spoolPath?: string | undefined;
}
export interface ReceiptStats {
    queued: number;
    pending: number;
    sent: number;
    dropped: number;
    rejected: number;
    lastError: string | null;
    nextAttemptAtMs: number;
}
/**
 * Tool-call receipts (SPEC §7.4): flushed every 5 s or at 20 queued, at most
 * 1,000 kept; 429/5xx/network → kept and retried with back-off; 400 → the
 * batch is dropped and logged (a bug). Kept in memory only.
 */
export declare class ReceiptQueue {
    private queue;
    private readonly pendingByKey;
    private readonly opts;
    private timer;
    private flushing;
    private failures;
    readonly stats: {
        sent: number;
        dropped: number;
        rejected: number;
        lastError: string | null;
        nextAttemptAtMs: number;
    };
    constructor(opts: ReceiptQueueOptions);
    get size(): number;
    snapshot(): ReceiptStats;
    start(): void;
    stop(): void;
    enqueue(receipt: ToolCallReceipt): void;
    /** Hold a receipt until its call completes (after_tool_call) or the pending timeout. */
    hold(key: string, receipt: ToolCallReceipt): void;
    hasPending(key: string): boolean;
    /** Complete a held receipt; returns false when none was held under `key`. */
    complete(key: string, fields: Partial<ToolCallReceipt>): boolean;
    /** Send held receipts that waited longer than the pending timeout, without outcome. */
    sweepPending(): void;
    /**
     * At process exit (synchronous): append everything not yet delivered,
     * held receipts included (without outcome), to the spool file.
     */
    spoolNow(): number;
    /** Take over the spool file left by earlier processes (atomic rename, then read). */
    claimSpool(): number;
    /** Flush queued receipts (one flush at a time; honours the back-off). */
    flush(force?: boolean): Promise<void>;
    private doFlush;
}
