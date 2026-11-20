import type { KeyObject } from 'node:crypto';
import { type FetchFn, type JsonResponse } from './http.ts';
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
    identity?: {
        agent_id?: string;
        status?: string;
        [k: string]: unknown;
    };
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
/**
 * The agent's side of the LumoAuth protocol (SPEC §7): private_key_jwt token
 * requests with DPoP, and the resource requests that use the token.
 */
export declare class AgentClient {
    readonly options: AgentClientOptions;
    private readonly fetchFn;
    private readonly now;
    private readonly dpop;
    private token;
    private inflight;
    constructor(options: AgentClientOptions);
    /** `<baseUrl>/orgs/<org>/api/v1/<path>`. */
    apiUrl(path: string): string;
    private headers;
    /** Forget the cached token (next call requests a new one). */
    invalidateToken(): void;
    /** A valid access token: cached until 60 s before it expires; one request in flight. */
    accessToken(): Promise<{
        value: string;
        type: string;
    }>;
    private requestToken;
    /**
     * A resource request with `Authorization: DPoP <token>` and a proof (with
     * `ath`). Retries once with the server's nonce, and once with a new token
     * after a 401.
     */
    request(method: 'GET' | 'POST', path: string, body?: unknown, timeoutMs?: number): Promise<JsonResponse>;
    /** GET /agents/me: identity, status and capabilities (SPEC §7.2). */
    me(): Promise<MeResponse>;
    /** POST /agents/ask (server mode, SPEC §6.2). */
    ask(action: string, context: Record<string, unknown>): Promise<AskResult>;
    /** POST /agents/me/tool-calls (≤ 50 receipts). */
    reportToolCalls(calls: ToolCallReceipt[]): Promise<number>;
    /** POST /agents/me/approvals (SPEC §7.5). */
    createApproval(body: ApprovalRequest): Promise<ApprovalCreateResult>;
    /** GET /agents/me/approvals/{token}/status → pending, approved, denied or expired. */
    approvalStatus(approvalToken: string): Promise<string>;
    /** POST /agents/me/usage (SPEC §7.6). */
    reportUsage(tokens: number): Promise<void>;
}
