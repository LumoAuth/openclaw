// A local LumoAuth stand-in for tests. It verifies client assertions
// (private_key_jwt) and DPoP proofs the way the server does, binds tokens
// to the DPoP key, and validates receipts like AgentToolCallReporter.
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export const ORIGIN = 'https://lumo.test';
export const ORG = 'acme';
export const ISSUER = `${ORIGIN}/orgs/${ORG}/api/v1`;
export const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;

export interface RecordedRequest {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

type Reply = { status: number; body?: unknown; headers?: Record<string, string> };

const RECEIPT_FIELDS = ['tool', 'server_id', 'decision', 'outcome', 'duration_ms', 'arguments_sha256', 'audit_id', 'occurred_at', 'error_code'];
const DECISIONS = ['allowed', 'approved', 'denied', 'refused', 'expired', 'blocked'];

function b64json(part: string): any {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

function thumbprint(jwk: any): string {
  return createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })).digest('base64url');
}

function verifyEs256(jwt: string, jwk: any): { header: any; claims: any } {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('not a JWS');
  const [h, c, sig] = parts as [string, string, string];
  const key = createPublicKey({ key: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, format: 'jwk' });
  const ok = verify('sha256', Buffer.from(`${h}.${c}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url'));
  if (!ok) throw new Error('bad signature');
  return { header: b64json(h), claims: b64json(c) };
}

export class MockLumoAuth {
  server!: Server;
  port = 0;
  readonly requests: RecordedRequest[] = [];
  readonly errors: string[] = [];
  /** Registered agent keys (public JWK with kid) by agent id. */
  readonly agents = new Map<string, { jwk: any; status: string; capabilities: string[] }>();
  readonly receipts: any[] = [];
  readonly usage: number[] = [];
  readonly asks: any[] = [];
  readonly approvalsCreated: any[] = [];
  readonly enrollmentsStarted: any[] = [];
  requireNonce = false;
  nonce = 'n-' + randomBytes(4).toString('hex');
  tokenLifetime = 300;
  /** Queue of forced replies for /agents/me/tool-calls (then normal handling). */
  toolCallReplies: Reply[] = [];
  /** Forced reply for /agents/me/approvals create. */
  approvalCreateReply: Reply | undefined;
  /** `delivery` of a created approval; undefined imitates an older server. */
  approvalDelivery: string[] | undefined = ['push'];
  /** Statuses returned by successive approval polls (last one repeats). */
  approvalStatuses: string[] = ['pending', 'approved'];
  askAllowed = true;
  askReply: Reply | undefined;
  /** Successive answers of the enrollment token poll. */
  enrollmentPoll: Reply[] = [];
  enrollmentStartReply: Reply | undefined;
  /** When set, the start answer reports this fingerprint. */
  enrollmentFingerprint: string | undefined;
  approvedCapabilities = ['files:read', 'files:write', 'web:search'];
  tokenCount = 0;
  private readonly tokens = new Map<string, { agentId: string; jkt: string }>();
  private readonly jtis = new Set<string>();
  private approvalPolls = 0;

  async start(): Promise<this> {
    this.server = createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server.listen(0, '127.0.0.1', r));
    this.port = (this.server.address() as AddressInfo).port;
    return this;
  }

  async stop(): Promise<void> {
    this.server.closeAllConnections?.();
    await new Promise<void>((r) => this.server.close(() => r()));
  }

  /** fetch that sends https://lumo.test/... to this server. */
  get fetch(): (input: string, init?: RequestInit) => Promise<Response> {
    return (input, init) => {
      const url = String(input);
      if (!url.startsWith(ORIGIN)) return Promise.reject(new TypeError(`unexpected host in ${url}`));
      return fetch(`http://127.0.0.1:${this.port}${url.slice(ORIGIN.length)}`, init);
    };
  }

  addAgent(agentId: string, jwk: any, capabilities: string[] = this.approvedCapabilities, status = 'active'): void {
    this.agents.set(agentId, { jwk, status, capabilities });
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks).toString('utf8');
    const path = (req.url ?? '/').split('?')[0]!;
    this.requests.push({ method: req.method ?? 'GET', path, headers: req.headers, body });
    let reply: Reply;
    try {
      reply = this.route(req.method ?? 'GET', path, req.headers, body);
    } catch (err) {
      this.errors.push((err as Error).message);
      reply = { status: 500, body: { error: 'mock_error', error_description: (err as Error).message } };
    }
    res.statusCode = reply.status;
    res.setHeader('Content-Type', 'application/json');
    for (const [k, v] of Object.entries(reply.headers ?? {})) res.setHeader(k, v);
    res.end(reply.body === undefined ? '' : JSON.stringify(reply.body));
  }

  private checkDpop(headers: IncomingMessage['headers'], method: string, path: string, accessToken?: string): { jkt: string } | Reply {
    const proof = headers['dpop'];
    if (typeof proof !== 'string') return { status: 400, body: { error: 'invalid_dpop_proof', error_description: 'missing DPoP header' } };
    let header: any;
    let claims: any;
    try {
      const h = b64json(proof.split('.')[0]!);
      ({ header, claims } = verifyEs256(proof, h.jwk));
    } catch (err) {
      this.errors.push(`dpop: ${(err as Error).message}`);
      return { status: 400, body: { error: 'invalid_dpop_proof' } };
    }
    const fail = (m: string): Reply => {
      this.errors.push(`dpop: ${m}`);
      return { status: 400, body: { error: 'invalid_dpop_proof', error_description: m } };
    };
    if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256') return fail('header');
    if (header.jwk.d !== undefined) return fail('private key in jwk');
    if (claims.htm !== method) return fail('htm');
    if (claims.htu !== `${ORIGIN}${path}`) return fail(`htu ${claims.htu}`);
    if (typeof claims.iat !== 'number' || Math.abs(claims.iat - Date.now() / 1000) > 300) return fail('iat');
    if (typeof claims.jti !== 'string' || this.jtis.has(`dpop:${claims.jti}`)) return fail('jti reuse');
    this.jtis.add(`dpop:${claims.jti}`);
    if (accessToken !== undefined) {
      const ath = createHash('sha256').update(accessToken).digest('base64url');
      if (claims.ath !== ath) return fail('ath');
    } else if (claims.ath !== undefined) return fail('ath on token request');
    if (this.requireNonce && claims.nonce !== this.nonce) {
      if (accessToken !== undefined) {
        return { status: 401, body: { error: 'use_dpop_nonce' }, headers: { 'DPoP-Nonce': this.nonce, 'WWW-Authenticate': 'DPoP error="use_dpop_nonce"' } };
      }
      return { status: 400, body: { error: 'use_dpop_nonce' }, headers: { 'DPoP-Nonce': this.nonce } };
    }
    return { jkt: thumbprint(header.jwk) };
  }

  private route(method: string, path: string, headers: IncomingMessage['headers'], body: string): Reply {
    const api = `/orgs/${ORG}/api/v1`;
    if (method === 'POST' && path === `${api}/oauth/token`) return this.token(headers, body);
    if (method === 'POST' && path === `${api}/agents/enrollments`) return this.enrollStart(body);
    if (method === 'POST' && path === `${api}/agents/enrollments/token`) return this.enrollPoll(body);
    if (path.startsWith(`${api}/agents/`)) {
      const auth = headers['authorization'];
      const m = typeof auth === 'string' ? /^DPoP (.+)$/.exec(auth) : null;
      if (!m) return { status: 401, body: { error: 'Unauthorized' } };
      const dpop = this.checkDpop(headers, method, path, m[1]);
      if ('status' in dpop) return dpop;
      const tok = this.tokens.get(m[1]!);
      if (!tok) return { status: 401, body: { error: 'invalid_token' } };
      if (tok.jkt !== dpop.jkt) {
        this.errors.push('token used with another DPoP key');
        return { status: 401, body: { error: 'invalid_token' } };
      }
      const agent = this.agents.get(tok.agentId)!;
      const rest = path.slice(`${api}/agents/`.length);
      if (method === 'GET' && rest === 'me') {
        return { status: 200, body: { identity: { agent_id: tok.agentId, type: 'agent', status: agent.status }, capabilities: agent.capabilities, scope: agent.capabilities } };
      }
      if (method === 'POST' && rest === 'me/tool-calls') return this.toolCalls(body);
      if (method === 'POST' && rest === 'me/usage') {
        this.usage.push(JSON.parse(body).tokens);
        return { status: 200, body: { recorded: JSON.parse(body) } };
      }
      if (method === 'POST' && rest === 'ask') {
        this.asks.push(JSON.parse(body));
        return this.askReply ?? { status: 200, body: { allowed: this.askAllowed, action: JSON.parse(body).action, audit_id: '0123456789abcdef' } };
      }
      if (method === 'POST' && rest === 'me/approvals') {
        const b = JSON.parse(body);
        this.approvalsCreated.push(b);
        if (this.approvalCreateReply) return this.approvalCreateReply;
        if (typeof b.reason !== 'string' || b.reason.length > 480 || !b.reason) return { status: 400, body: { error: 'invalid_reason' } };
        if (!['low', 'medium', 'high', 'critical'].includes(b.impact)) return { status: 400, body: { error: 'invalid_impact' } };
        if ('expires_in' in b && (!Number.isInteger(b.expires_in) || b.expires_in < 60 || b.expires_in > 600)) return { status: 400, body: { error: 'invalid_expires_in' } };
        const meta = b.meta ?? {};
        const allowed = ['kind', 'host', 'tool', 'server', 'capability', 'risk', 'why', 'title', 'args', 'arguments_sha256'];
        const unknown = Object.keys(meta).filter((k) => !allowed.includes(k));
        if (unknown.length) return { status: 400, body: { error: 'invalid_meta', error_description: unknown.join(',') } };
        if (meta.args !== undefined && (!Array.isArray(meta.args) || meta.args.length > 5 || !meta.args.every((x: unknown) => typeof x === 'string'))) {
          return { status: 400, body: { error: 'invalid_meta', error_description: 'args' } };
        }
        this.approvalPolls = 0;
        const ttl = (b.expires_in ?? 120) * 1000;
        return {
          status: 201,
          body: {
            approval_token: 'apt_' + randomBytes(6).toString('hex'),
            status: 'pending',
            expires_at: new Date(Date.now() + ttl).toISOString(),
            ...(this.approvalDelivery ? { delivery: this.approvalDelivery } : {}),
          },
        };
      }
      const st = /^me\/approvals\/([^/]+)\/status$/.exec(rest);
      if (method === 'GET' && st) {
        const s = this.approvalStatuses[Math.min(this.approvalPolls++, this.approvalStatuses.length - 1)]!;
        return { status: 200, body: { approval_token: st[1], status: s } };
      }
    }
    return { status: 404, body: { error: 'not_found' } };
  }

  private token(headers: IncomingMessage['headers'], body: string): Reply {
    const form = new URLSearchParams(body);
    const dpop = this.checkDpop(headers, 'POST', `/orgs/${ORG}/api/v1/oauth/token`);
    if ('status' in dpop) return dpop;
    const fail = (m: string): Reply => {
      this.errors.push(`assertion: ${m}`);
      return { status: 401, body: { error: 'invalid_client', error_description: m } };
    };
    if (form.get('grant_type') !== 'client_credentials') return { status: 400, body: { error: 'unsupported_grant_type' } };
    if (form.get('client_assertion_type') !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') return fail('assertion type');
    const agentId = form.get('client_id') ?? '';
    const agent = this.agents.get(agentId);
    if (!agent) return fail('unknown client');
    let header: any;
    let claims: any;
    try {
      ({ header, claims } = verifyEs256(form.get('client_assertion') ?? '', agent.jwk));
    } catch (err) {
      return fail((err as Error).message);
    }
    if (header.alg !== 'ES256' || header.typ !== 'client-authentication+jwt' || header.kid !== agent.jwk.kid) return fail('header');
    if (claims.iss !== agentId || claims.sub !== agentId) return fail('iss/sub');
    if (claims.aud !== ISSUER) return fail(`aud ${JSON.stringify(claims.aud)}`);
    if (typeof claims.iat !== 'number' || typeof claims.exp !== 'number' || claims.exp - claims.iat > 60 || claims.exp < Date.now() / 1000) return fail('exp');
    if (typeof claims.jti !== 'string' || Buffer.from(claims.jti, 'base64url').length < 16 || this.jtis.has(claims.jti)) return fail('jti');
    this.jtis.add(claims.jti);
    const token = 'at_' + randomBytes(12).toString('hex');
    this.tokens.set(token, { agentId, jkt: dpop.jkt });
    this.tokenCount++;
    return { status: 200, body: { access_token: token, token_type: 'DPoP', expires_in: this.tokenLifetime } };
  }

  private toolCalls(body: string): Reply {
    const forced = this.toolCallReplies.shift();
    if (forced) return forced;
    const data = JSON.parse(body);
    if (!Array.isArray(data.calls) || data.calls.length === 0 || data.calls.length > 50) return { status: 400, body: { error: 'invalid_request', error_description: 'calls' } };
    for (const [i, c] of data.calls.entries()) {
      const unknown = Object.keys(c).filter((k) => !RECEIPT_FIELDS.includes(k));
      if (unknown.length) return { status: 400, body: { error: 'invalid_request', error_description: `calls[${i}]: unknown field ${unknown.join(', ')}` } };
      if (typeof c.tool !== 'string' || !c.tool || c.tool.length > 200) return { status: 400, body: { error: 'invalid_request', error_description: 'tool' } };
      if (!DECISIONS.includes(c.decision)) return { status: 400, body: { error: 'invalid_request', error_description: 'decision' } };
      if ('arguments_sha256' in c && !/^[0-9a-f]{64}$/.test(c.arguments_sha256)) return { status: 400, body: { error: 'invalid_request', error_description: 'digest' } };
      if ('server_id' in c && !/^[A-Za-z0-9._-]{1,100}$/.test(c.server_id)) return { status: 400, body: { error: 'invalid_request', error_description: 'server_id' } };
      if ('error_code' in c && !/^[A-Za-z0-9_.:-]{1,64}$/.test(c.error_code)) return { status: 400, body: { error: 'invalid_request', error_description: 'error_code' } };
      if ('occurred_at' in c && !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/.test(c.occurred_at)) return { status: 400, body: { error: 'invalid_request', error_description: 'occurred_at' } };
      if ('duration_ms' in c && (!Number.isInteger(c.duration_ms) || c.duration_ms < 0)) return { status: 400, body: { error: 'invalid_request', error_description: 'duration_ms' } };
      if ('outcome' in c && c.outcome !== 'not_run' && ['denied', 'refused', 'expired', 'blocked'].includes(c.decision)) {
        return { status: 400, body: { error: 'invalid_request', error_description: 'outcome of a call that did not run' } };
      }
      if ('audit_id' in c && !/^[0-9a-f]{16}$/.test(c.audit_id)) return { status: 400, body: { error: 'invalid_request', error_description: 'audit_id' } };
    }
    this.receipts.push(...data.calls);
    return { status: 200, body: { recorded: data.calls.length } };
  }

  private enrollStart(body: string): Reply {
    const b = JSON.parse(body);
    this.enrollmentsStarted.push(b);
    if (this.enrollmentStartReply) return this.enrollmentStartReply;
    const key = b?.jwks?.keys?.[0];
    if (!key || key.d !== undefined) return { status: 400, body: { error: 'invalid_request', error_description: 'jwks' } };
    if (!Array.isArray(b.capabilities) || b.capabilities.length < 1 || b.capabilities.length > 200) return { status: 400, body: { error: 'invalid_request', error_description: 'capabilities' } };
    for (const c of b.capabilities) {
      if (!/^[a-z0-9_*-]+(:[a-z0-9_*-]+)*$/.test(c.scope)) return { status: 400, body: { error: 'invalid_request', error_description: `capabilities: ${c.scope}` } };
      if (typeof c.label !== 'string' || c.label.length > 120) return { status: 400, body: { error: 'invalid_request', error_description: 'label' } };
    }
    if (typeof b.name !== 'string' || b.name.length > 100 || b.host !== 'openclaw') return { status: 400, body: { error: 'invalid_request', error_description: 'name/host' } };
    const fp = thumbprint(key);
    return {
      status: 201,
      body: {
        enrollment_code: randomBytes(32).toString('base64url'),
        user_code: 'BCDF-GHJK',
        verification_uri: `${ORIGIN}/orgs/${ORG}/portal/agents/enroll`,
        verification_uri_complete: `${ORIGIN}/orgs/${ORG}/portal/agents/enroll?code=BCDF-GHJK`,
        key_fingerprint: this.enrollmentFingerprint ?? [0, 4, 8, 12].map((i) => fp.slice(i, i + 4)).join('-'),
        expires_in: 900,
        interval: 5,
      },
    };
  }

  private enrollPoll(body: string): Reply {
    const b = JSON.parse(body);
    if (typeof b.enrollment_code !== 'string') return { status: 400, body: { error: 'invalid_request' } };
    const next = this.enrollmentPoll.shift();
    if (next) return next;
    // Approve: register the key from the last start.
    const start = this.enrollmentsStarted.at(-1);
    const jwk = start.jwks.keys[0];
    const agentId = 'agt_' + randomBytes(8).toString('hex');
    this.addAgent(agentId, jwk, this.approvedCapabilities);
    return {
      status: 200,
      body: {
        agent_id: agentId,
        client_id: agentId,
        issuer: ISSUER,
        token_endpoint: TOKEN_ENDPOINT,
        key_id: jwk.kid,
        capabilities: this.approvedCapabilities,
        can_act_on_behalf_of_users: start.delegation === true,
        owner_user_id: '0197aaaa-bbbb-7ccc-8ddd-eeeeffff0000',
        agent_url: `${ORIGIN}/orgs/${ORG}/portal/agents/${agentId}`,
      },
    };
  }
}
