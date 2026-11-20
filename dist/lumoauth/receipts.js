import { appendFileSync, chmodSync, existsSync, readFileSync, renameSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { LumoAuthError } from "./http.js";
const MAX_BACKOFF_MS = 5 * 60_000;
/**
 * Tool-call receipts (SPEC §7.4): flushed every 5 s or at 20 queued, at most
 * 1,000 kept; 429/5xx/network → kept and retried with back-off; 400 → the
 * batch is dropped and logged (a bug). Kept in memory only.
 */
export class ReceiptQueue {
    queue = [];
    pendingByKey = new Map();
    opts;
    timer;
    flushing;
    failures = 0;
    stats = { sent: 0, dropped: 0, rejected: 0, lastError: null, nextAttemptAtMs: 0 };
    constructor(opts) {
        this.opts = {
            max: 1000,
            flushAt: 20,
            batchSize: 50,
            intervalMs: 5000,
            pendingTimeoutMs: 10 * 60_000,
            now: Date.now,
            ...opts,
        };
    }
    get size() {
        return this.queue.length;
    }
    snapshot() {
        return { queued: this.queue.length, pending: this.pendingByKey.size, ...this.stats };
    }
    start() {
        if (this.timer)
            return;
        this.timer = setInterval(() => {
            this.sweepPending();
            void this.flush();
        }, this.opts.intervalMs);
        this.timer.unref?.();
    }
    stop() {
        if (this.timer)
            clearInterval(this.timer);
        this.timer = undefined;
    }
    enqueue(receipt) {
        this.queue.push(receipt);
        while (this.queue.length > this.opts.max) {
            this.queue.shift();
            this.stats.dropped++;
        }
        if (this.queue.length >= this.opts.flushAt)
            void this.flush();
    }
    /** Hold a receipt until its call completes (after_tool_call) or the pending timeout. */
    hold(key, receipt) {
        const prev = this.pendingByKey.get(key);
        if (prev)
            this.enqueue(prev.receipt);
        this.pendingByKey.set(key, { receipt, startedAtMs: this.opts.now() });
        if (this.pendingByKey.size > this.opts.max) {
            const oldest = this.pendingByKey.keys().next().value;
            if (oldest !== undefined) {
                const e = this.pendingByKey.get(oldest);
                this.pendingByKey.delete(oldest);
                if (e)
                    this.enqueue(e.receipt);
            }
        }
    }
    hasPending(key) {
        return this.pendingByKey.has(key);
    }
    /** Complete a held receipt; returns false when none was held under `key`. */
    complete(key, fields) {
        const e = this.pendingByKey.get(key);
        if (!e)
            return false;
        this.pendingByKey.delete(key);
        this.enqueue({ ...e.receipt, ...fields });
        return true;
    }
    /** Send held receipts that waited longer than the pending timeout, without outcome. */
    sweepPending() {
        const cutoff = this.opts.now() - this.opts.pendingTimeoutMs;
        for (const [key, e] of this.pendingByKey) {
            if (e.startedAtMs <= cutoff) {
                this.pendingByKey.delete(key);
                this.enqueue(e.receipt);
            }
        }
    }
    /**
     * At process exit (synchronous): append everything not yet delivered,
     * held receipts included (without outcome), to the spool file.
     */
    spoolNow() {
        const path = this.opts.spoolPath;
        const all = [...this.queue, ...[...this.pendingByKey.values()].map((e) => e.receipt)];
        if (!path || all.length === 0)
            return 0;
        try {
            appendFileSync(path, all.map((r) => JSON.stringify(r)).join('\n') + '\n', { mode: 0o600 });
            if (process.platform !== 'win32')
                chmodSync(path, 0o600);
            this.queue = [];
            this.pendingByKey.clear();
            return all.length;
        }
        catch {
            return 0;
        }
    }
    /** Take over the spool file left by earlier processes (atomic rename, then read). */
    claimSpool() {
        const path = this.opts.spoolPath;
        if (!path || !existsSync(path))
            return 0;
        const claimed = `${path}.${process.pid}.${randomBytes(4).toString('hex')}.claim`;
        let text;
        try {
            renameSync(path, claimed);
            text = readFileSync(claimed, 'utf8');
        }
        catch {
            return 0;
        }
        finally {
            rmSync(claimed, { force: true });
        }
        let n = 0;
        for (const line of text.split('\n')) {
            if (!line.trim())
                continue;
            try {
                const r = JSON.parse(line);
                if (r && typeof r.tool === 'string' && typeof r.decision === 'string') {
                    this.queue.push(r);
                    n++;
                }
            }
            catch {
                // A torn line: skip it.
            }
        }
        while (this.queue.length > this.opts.max) {
            this.queue.shift();
            this.stats.dropped++;
        }
        return n;
    }
    /** Flush queued receipts (one flush at a time; honours the back-off). */
    flush(force = false) {
        if (this.flushing)
            return this.flushing;
        if (!force && this.opts.now() < this.stats.nextAttemptAtMs)
            return Promise.resolve();
        this.flushing = this.doFlush().finally(() => {
            this.flushing = undefined;
        });
        return this.flushing;
    }
    async doFlush() {
        while (this.queue.length > 0) {
            const batch = this.queue.slice(0, this.opts.batchSize);
            try {
                await this.opts.send(batch);
                this.queue.splice(0, batch.length);
                this.stats.sent += batch.length;
                this.stats.lastError = null;
                this.failures = 0;
                this.stats.nextAttemptAtMs = 0;
            }
            catch (err) {
                const e = err instanceof LumoAuthError ? err : null;
                this.stats.lastError = e?.message ?? err?.message ?? 'failed';
                if (e && e.status === 400) {
                    // The server refused the batch: a bug in the Guard. Retrying cannot help.
                    this.queue.splice(0, batch.length);
                    this.stats.rejected += batch.length;
                    this.opts.log?.error(`LumoAuth refused ${batch.length} tool-call receipt(s) and they were dropped: ${e.message}`);
                    continue;
                }
                this.failures++;
                const delay = Math.min(MAX_BACKOFF_MS, this.opts.intervalMs * 2 ** Math.min(this.failures - 1, 10));
                this.stats.nextAttemptAtMs = this.opts.now() + delay;
                if (this.failures === 1 || this.failures % 10 === 0) {
                    this.opts.log?.warn(`LumoAuth Guard could not deliver tool-call receipts (${this.stats.lastError}); retrying later.`);
                }
                return;
            }
        }
    }
}
