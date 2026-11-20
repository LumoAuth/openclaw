import type { KeyObject } from 'node:crypto';
import { CLIENT_ASSERTION_TYPE, clientAssertion, DpopSigner } from './crypto.ts';
import { defaultFetch, errorFor, fetchJson, LumoAuthError, type FetchFn, type JsonResponse } from './http.ts';

export interface AgentClientOptions {
  baseUrl: string;
  orgId: string;
  agentId: string;
  issuer: string;
  tokenEndpoint: string;
  keyId: string;
  key: KeyObject;
  fetchFn?: FetchFn | undefined;
  /** Milliseconds since the epoch (tests). */
  now?: (() => number) | undefined;
  userAgent?: string | undefined;
  timeoutMs?: number | undefined;
}

export interface MeResponse {
  identity?: { agent_id?: string; status?: string; [k: string]: unknown };
  capabilities?: unknown;
  scope?: unknown;
}

export interface ToolCallReceipt {
  tool: string;
  server_id?: string;
  decision: 'allowed' | 'approved' | 'denied' | 'refused' | 'expired' | 'blocked';
  outcome?: 'succeeded' | 'failed' | 'not_run';
  duration_ms?: number;
  arguments_sha256?: string;
  audit_id?: string;
  occurred_at?: string;
  error_code?: string;
}

export interface AskResult {
  allowed: boolean;
  auditId: string | undefined;
}

export interface ApprovalCreateResult {
  /** created (201): the request reached at least one channel. */
  kind: 'created' | 'email_fallback_sent' | 'no_enrolled_device' | 'delegation_not_permitted';
  approvalToken?: string;
  expiresAt?: string;
  /** Where the request went (push, slack, discord); undefined from servers that do not say. */
  delivery?: string[] | undefined;
}

/** SPEC §7.5 request body. */
export interface ApprovalRequest {
  task_id: string;
  reason: string;
  impact: string;
  on_behalf_of: string;
  expires_in: number;
  meta: {
    kind: 'tool_call';
    host: string;
    tool: string;
    server?: string;
    capability: string;
    risk: string;
    why: string;
    title: string;
    args: string[];
    arguments_sha256: string;
  };
}

const TOKEN_REFRESH_MARGIN_MS = 60_000;

/**
 * The agent's side of the LumoAuth protocol (SPEC §7): private_key_jwt token
 * requests with DPoP, and the resource requests that use the token.
 */
export class AgentClient {
  readonly options: AgentClientOptions;
  private readonly fetchFn: FetchFn;
  private readonly now: () => number;
  private readonly dpop = new DpopSigner();
  private token: { value: string; type: string; refreshAtMs: number } | undefined;
  private inflight: Promise<{ value: string; type: string }> | undefined;

  constructor(options: AgentClientOptions) {
    this.options = options;
    this.fetchFn = options.fetchFn ?? defaultFetch;
    this.now = options.now ?? Date.now;
  }

  /** `<baseUrl>/orgs/<org>/api/v1/<path>`. */
  apiUrl(path: string): string {
    const base = this.options.baseUrl.replace(/\/+$/, '');
    return `${base}/orgs/${encodeURIComponent(this.options.orgId)}/api/v1/${path.replace(/^\/+/, '')}`;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return { Accept: 'application/json', 'User-Agent': this.options.userAgent ?? 'lumoauth-openclaw', ...extra };
  }

  /** Forget the cached token (next call requests a new one). */
  invalidateToken(): void {
    this.token = undefined;
  }

  /** A valid access token: cached until 60 s before it expires; one request in flight. */
  async accessToken(): Promise<{ value: string; type: string }> {
    const t = this.token;
    if (t && this.now() < t.refreshAtMs) return t;
    if (!this.inflight) {
      this.inflight = this.requestToken().finally(() => {
        this.inflight = undefined;
      });
    }
    return this.inflight;
  }

  private async requestToken(): Promise<{ value: string; type: string }> {
    const url = this.options.tokenEndpoint;
    let nonce: string | undefined;
    for (let attempt = 0; attempt < 2; attempt++) {
      const nowS = this.now() / 1000;
      const form = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.options.agentId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: clientAssertion({
          agentId: this.options.agentId,
          issuer: this.options.issuer,
          keyId: this.options.keyId,
          key: this.options.key,
          nowSeconds: nowS,
        }),
      });
      const res = await fetchJson(
        this.fetchFn,
        url,
        {
          method: 'POST',
          headers: this.headers({
            'Content-Type': 'application/x-www-form-urlencoded',
            DPoP: this.dpop.proof({ method: 'POST', url, nowSeconds: nowS, nonce }),
          }),
          body: form.toString(),
        },
        this.options.timeoutMs,
      );
      const fresh = res.headers.get('DPoP-Nonce');
      if (fresh) this.dpop.setNonce(url, fresh);
      if (attempt === 0 && fresh && wantsNonce(res)) {
        nonce = fresh;
        continue;
      }
      if (res.status === 200 && typeof res.body?.access_token === 'string') {
        const expiresIn = typeof res.body.expires_in === 'number' && res.body.expires_in > 0 ? res.body.expires_in : 300;
        const lifetimeMs = expiresIn * 1000;
        const margin = Math.min(TOKEN_REFRESH_MARGIN_MS, lifetimeMs / 2);
        const type = typeof res.body.token_type === 'string' ? res.body.token_type : 'DPoP';
        this.token = { value: res.body.access_token, type, refreshAtMs: this.now() + lifetimeMs - margin };
        return this.token;
      }
      const err = errorFor(res, 'The token endpoint');
      const code = err.code;
      if (code === 'invalid_client' || code === 'unauthorized_client' || res.status === 401) {
        throw new LumoAuthError('auth', err.message, { status: res.status, code });
      }
      throw err;
    }
    throw new LumoAuthError('client', 'The token endpoint kept asking for a new DPoP nonce');
  }

  /**
   * A resource request with `Authorization: DPoP <token>` and a proof (with
   * `ath`). Retries once with the server's nonce, and once with a new token
   * after a 401.
   */
  async request(method: 'GET' | 'POST', path: string, body?: unknown, timeoutMs?: number): Promise<JsonResponse> {
    const url = this.apiUrl(path);
    let nonce: string | undefined;
    let renewed = false;
    for (let attempt = 0; attempt < 3; attempt++) {
      const token = await this.accessToken();
      const nowS = this.now() / 1000;
      // Enrolled agents are DPoP-only (SPEC §8.2): the token is always sent with the DPoP scheme.
      const headers = this.headers({
        Authorization: `DPoP ${token.value}`,
        DPoP: this.dpop.proof({ method, url, nowSeconds: nowS, accessToken: token.value, nonce }),
      });
      if (body !== undefined) headers['Content-Type'] = 'application/json';
      const res = await fetchJson(
        this.fetchFn,
        url,
        { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) },
        timeoutMs ?? this.options.timeoutMs,
      );
      const fresh = res.headers.get('DPoP-Nonce');
      if (fresh) this.dpop.setNonce(url, fresh);
      if (fresh && nonce === undefined && wantsNonce(res)) {
        nonce = fresh;
        continue;
      }
      if (res.status === 401 && !renewed) {
        renewed = true;
        this.invalidateToken();
        continue;
      }
      return res;
    }
    throw new LumoAuthError('auth', `LumoAuth refused the agent's token for ${path}`, { status: 401 });
  }

  /** GET /agents/me: identity, status and capabilities (SPEC §7.2). */
  async me(): Promise<MeResponse> {
    const res = await this.request('GET', 'agents/me');
    if (res.status === 200 && res.body && typeof res.body === 'object') return res.body as MeResponse;
    const err = errorFor(res, '/agents/me');
    if (res.status === 401 || res.status === 403) throw new LumoAuthError('auth', err.message, { status: res.status, code: err.code });
    throw err;
  }

  /** POST /agents/ask (server mode, SPEC §6.2). */
  async ask(action: string, context: Record<string, unknown>): Promise<AskResult> {
    const res = await this.request('POST', 'agents/ask', { action, context, audit: 'always' }, 5_000);
    if (res.status === 200 && typeof res.body?.allowed === 'boolean') {
      return { allowed: res.body.allowed, auditId: typeof res.body.audit_id === 'string' ? res.body.audit_id : undefined };
    }
    throw errorFor(res, '/agents/ask');
  }

  /** POST /agents/me/tool-calls (≤ 50 receipts). */
  async reportToolCalls(calls: ToolCallReceipt[]): Promise<number> {
    const res = await this.request('POST', 'agents/me/tool-calls', { calls });
    if (res.status === 200 || res.status === 201) return typeof res.body?.recorded === 'number' ? res.body.recorded : calls.length;
    throw errorFor(res, '/agents/me/tool-calls');
  }

  /** POST /agents/me/approvals (SPEC §7.5). */
  async createApproval(body: ApprovalRequest): Promise<ApprovalCreateResult> {
    const res = await this.request('POST', 'agents/me/approvals', body);
    if ((res.status === 201 || res.status === 200) && typeof res.body?.approval_token === 'string') {
      const delivery = Array.isArray(res.body.delivery)
        ? res.body.delivery.filter((d: unknown): d is string => typeof d === 'string' && /^[a-z_]{1,20}$/.test(d)).slice(0, 10)
        : undefined;
      return { kind: 'created', approvalToken: res.body.approval_token, expiresAt: res.body.expires_at, delivery };
    }
    if (res.status === 202) return { kind: 'email_fallback_sent' };
    if (res.status === 428) return { kind: 'no_enrolled_device' };
    if (res.status === 403 && res.body?.error === 'delegation_not_permitted') return { kind: 'delegation_not_permitted' };
    throw errorFor(res, '/agents/me/approvals');
  }

  /** GET /agents/me/approvals/{token}/status → pending, approved, denied or expired. */
  async approvalStatus(approvalToken: string): Promise<string> {
    const res = await this.request('GET', `agents/me/approvals/${encodeURIComponent(approvalToken)}/status`, undefined, 5_000);
    if (res.status === 200 && typeof res.body?.status === 'string') return res.body.status;
    throw errorFor(res, 'the approval status');
  }

  /** POST /agents/me/usage (SPEC §7.6). */
  async reportUsage(tokens: number): Promise<void> {
    const res = await this.request('POST', 'agents/me/usage', { tokens });
    if (res.status !== 200) throw errorFor(res, '/agents/me/usage');
  }
}

/** Does this answer ask for a retry with the server's DPoP nonce? */
function wantsNonce(res: JsonResponse): boolean {
  if (res.body?.error === 'use_dpop_nonce') return true;
  if (res.status === 401) return /use_dpop_nonce/i.test(res.headers.get('WWW-Authenticate') ?? '');
  return false;
}
