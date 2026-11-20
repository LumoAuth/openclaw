import type { SnapshotView } from '../core/decide.ts';
import type { AgentClient } from './agent-client.ts';
import { LumoAuthError } from './http.ts';

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
export class SnapshotStore {
  snapshot: Snapshot | null = null;
  lastError: SnapshotError | null = null;
  private inflight: Promise<void> | undefined;
  private readonly client: () => AgentClient | null;
  private readonly now: () => number;

  constructor(client: () => AgentClient | null, now: () => number = Date.now) {
    this.client = client;
    this.now = now;
  }

  ageSeconds(): number | undefined {
    return this.snapshot ? (this.now() - this.snapshot.fetchedAtMs) / 1000 : undefined;
  }

  view(): SnapshotView | null {
    const s = this.snapshot;
    if (!s) return null;
    return { status: s.status, ageSeconds: (this.now() - s.fetchedAtMs) / 1000, capabilities: s.capabilities };
  }

  clear(): void {
    this.snapshot = null;
  }

  /** Refresh now (one request in flight). Never throws. */
  refresh(): Promise<void> {
    if (!this.inflight) {
      this.inflight = this.doRefresh().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }

  /** Refresh when older than `maxAgeSeconds`, waiting at most `timeoutMs`. */
  async ensureFresh(maxAgeSeconds: number, timeoutMs: number): Promise<void> {
    const age = this.ageSeconds();
    if (age !== undefined && age < maxAgeSeconds) return;
    let timer: NodeJS.Timeout | undefined;
    await Promise.race([
      this.refresh(),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
        timer.unref?.();
      }),
    ]);
    if (timer) clearTimeout(timer);
  }

  private async doRefresh(): Promise<void> {
    const client = this.client();
    if (!client) return;
    try {
      const me = await client.me();
      const caps = Array.isArray(me.capabilities) ? me.capabilities.filter((c): c is string => typeof c === 'string') : [];
      const status = typeof me.identity?.status === 'string' ? me.identity.status : 'unknown';
      this.snapshot = {
        agentId: typeof me.identity?.agent_id === 'string' ? me.identity.agent_id : undefined,
        status,
        // An agent that is not active keeps no capabilities (decide() reports agent_inactive).
        capabilities: status === 'active' ? caps : [],
        fetchedAtMs: this.now(),
      };
      this.lastError = null;
    } catch (err) {
      const e = err instanceof LumoAuthError ? err : new LumoAuthError('network', (err as Error)?.message ?? 'failed');
      this.lastError = { atMs: this.now(), kind: e.kind, message: e.message };
      if (e.kind === 'auth') {
        this.snapshot = null;
        client.invalidateToken();
      }
    }
  }
}
