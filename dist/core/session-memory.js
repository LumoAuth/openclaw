/**
 * Per-session memory kept in the host process only (cleared on restart):
 * taint (SPEC §6.3) and "allow always" answers (§6.4).
 */
const MAX_SESSIONS = 10_000;
export class TaintTracker {
    until = new Map();
    /** Mark a session tainted for `windowSeconds` from `nowMs`. */
    mark(session, windowSeconds, nowMs) {
        const end = nowMs + windowSeconds * 1000;
        const prev = this.until.get(session) ?? 0;
        this.until.delete(session);
        this.until.set(session, Math.max(prev, end));
        this.prune(nowMs);
    }
    isTainted(session, nowMs) {
        const end = this.until.get(session);
        if (end === undefined)
            return false;
        if (end <= nowMs) {
            this.until.delete(session);
            return false;
        }
        return true;
    }
    taintedSessions(nowMs) {
        let n = 0;
        for (const end of this.until.values())
            if (end > nowMs)
                n++;
        return n;
    }
    clear() {
        this.until.clear();
    }
    prune(nowMs) {
        if (this.until.size <= MAX_SESSIONS)
            return;
        for (const [k, end] of this.until) {
            if (end <= nowMs)
                this.until.delete(k);
        }
        // Still too many: forget the oldest entries (Map keeps insertion order).
        while (this.until.size > MAX_SESSIONS) {
            const first = this.until.keys().next().value;
            if (first === undefined)
                break;
            this.until.delete(first);
        }
    }
}
export class RememberedApprovals {
    keys = new Set();
    static key(session, capability) {
        return `${session}\u0000${capability}`;
    }
    remember(session, capability) {
        const k = RememberedApprovals.key(session, capability);
        this.keys.delete(k);
        this.keys.add(k);
        while (this.keys.size > MAX_SESSIONS) {
            const first = this.keys.values().next().value;
            if (first === undefined)
                break;
            this.keys.delete(first);
        }
    }
    has(session, capability) {
        return this.keys.has(RememberedApprovals.key(session, capability));
    }
    get size() {
        return this.keys.size;
    }
    clear() {
        this.keys.clear();
    }
}
