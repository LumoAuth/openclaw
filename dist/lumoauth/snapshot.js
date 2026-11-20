import { LumoAuthError } from "./http.js";
/**
 * The agent's capability snapshot (SPEC §7.2): refreshed in the background
 * and on demand. Token `invalid_client`/401 and `/me` 401/403 clear it;
 * network and server errors keep it (offline grace is applied by decide()).
 */
export class SnapshotStore {
    snapshot = null;
    lastError = null;
    inflight;
    client;
    now;
    constructor(client, now = Date.now) {
        this.client = client;
        this.now = now;
    }
    ageSeconds() {
        return this.snapshot ? (this.now() - this.snapshot.fetchedAtMs) / 1000 : undefined;
    }
    view() {
        const s = this.snapshot;
        if (!s)
            return null;
        return { status: s.status, ageSeconds: (this.now() - s.fetchedAtMs) / 1000, capabilities: s.capabilities };
    }
    clear() {
        this.snapshot = null;
    }
    /** Refresh now (one request in flight). Never throws. */
    refresh() {
        if (!this.inflight) {
            this.inflight = this.doRefresh().finally(() => {
                this.inflight = undefined;
            });
        }
        return this.inflight;
    }
    /** Refresh when older than `maxAgeSeconds`, waiting at most `timeoutMs`. */
    async ensureFresh(maxAgeSeconds, timeoutMs) {
        const age = this.ageSeconds();
        if (age !== undefined && age < maxAgeSeconds)
            return;
        let timer;
        await Promise.race([
            this.refresh(),
            new Promise((resolve) => {
                timer = setTimeout(resolve, timeoutMs);
                timer.unref?.();
            }),
        ]);
        if (timer)
            clearTimeout(timer);
    }
    async doRefresh() {
        const client = this.client();
        if (!client)
            return;
        try {
            const me = await client.me();
            const caps = Array.isArray(me.capabilities) ? me.capabilities.filter((c) => typeof c === 'string') : [];
            const status = typeof me.identity?.status === 'string' ? me.identity.status : 'unknown';
            this.snapshot = {
                agentId: typeof me.identity?.agent_id === 'string' ? me.identity.agent_id : undefined,
                status,
                // An agent that is not active keeps no capabilities (decide() reports agent_inactive).
                capabilities: status === 'active' ? caps : [],
                fetchedAtMs: this.now(),
            };
            this.lastError = null;
        }
        catch (err) {
            const e = err instanceof LumoAuthError ? err : new LumoAuthError('network', err?.message ?? 'failed');
            this.lastError = { atMs: this.now(), kind: e.kind, message: e.message };
            if (e.kind === 'auth') {
                this.snapshot = null;
                client.invalidateToken();
            }
        }
    }
}
