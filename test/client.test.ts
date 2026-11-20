import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, test } from 'node:test';
import { AgentClient } from '../src/lumoauth/agent-client.ts';
import { generateAgentKey, jwkThumbprint, keyFingerprint, publicJwk } from '../src/lumoauth/crypto.ts';
import { EnrollmentError, pollEnrollment, startEnrollment, type EnrollmentRequest } from '../src/lumoauth/enrollment.ts';
import { LumoAuthError } from '../src/lumoauth/http.ts';
import { ReceiptQueue } from '../src/lumoauth/receipts.ts';
import { SnapshotStore } from '../src/lumoauth/snapshot.ts';
import { ISSUER, MockLumoAuth, ORG, ORIGIN, TOKEN_ENDPOINT } from './helpers/mock-lumoauth.ts';
import { noSleep } from './helpers/fixtures.ts';

let mock: MockLumoAuth;
before(async () => {
  mock = await new MockLumoAuth().start();
});
after(async () => {
  await mock.stop();
});
beforeEach(() => {
  mock.requireNonce = false;
  mock.errors.length = 0;
  mock.toolCallReplies = [];
});

function newAgent(capabilities = ['files:read'], status = 'active') {
  const key = generateAgentKey();
  const jwk = publicJwk(key);
  const kid = jwkThumbprint(jwk);
  const agentId = `agt_${Math.random().toString(16).slice(2, 18)}`;
  mock.addAgent(agentId, { ...jwk, kid }, capabilities, status);
  const client = new AgentClient({ baseUrl: ORIGIN, orgId: ORG, agentId, issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, keyId: kid, key, fetchFn: mock.fetch });
  return { client, agentId, key, kid };
}

describe('crypto', () => {
  test('fingerprint is the first 4 groups of 4 characters of the thumbprint', () => {
    assert.equal(keyFingerprint('Zx3a91Kcp0Qe7tLmXXXXYYYY'), 'Zx3a-91Kc-p0Qe-7tLm');
  });
  test('thumbprint follows RFC 7638 (RFC 7638 §3.1 style check with a known key)', () => {
    // RFC 7638 has an RSA example only; check stability and base64url length instead.
    const jwk = { kty: 'EC' as const, crv: 'P-256' as const, x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };
    assert.equal(jwkThumbprint(jwk), 'oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U');
  });
});

describe('AgentClient: token and resource requests', () => {
  test('private_key_jwt assertion and DPoP proofs are accepted; the token is cached', async () => {
    const { client, agentId } = newAgent(['files:read', 'web:*']);
    const before = mock.tokenCount;
    const me = await client.me();
    assert.equal(me.identity?.agent_id, agentId);
    assert.deepEqual(me.capabilities, ['files:read', 'web:*']);
    await client.me();
    assert.equal(mock.tokenCount - before, 1, 'one token for two requests');
    assert.deepEqual(mock.errors, []);
    const tokenReq = mock.requests.find((r) => r.path.endsWith('/oauth/token'))!;
    assert.match(String(tokenReq.headers['dpop']), /^ey/);
    const meReq = mock.requests.filter((r) => r.path.endsWith('/agents/me')).at(-1)!;
    assert.match(String(meReq.headers['authorization']), /^DPoP at_/);
  });

  test('a use_dpop_nonce answer is retried once with the nonce (token and resource)', async () => {
    mock.requireNonce = true;
    const { client } = newAgent();
    const me = await client.me();
    assert.equal(me.identity?.status, 'active');
    assert.deepEqual(mock.errors, []);
  });

  test('an unknown client gets an auth error', async () => {
    const key = generateAgentKey();
    const kid = jwkThumbprint(publicJwk(key));
    const client = new AgentClient({ baseUrl: ORIGIN, orgId: ORG, agentId: 'agt_unknown', issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, keyId: kid, key, fetchFn: mock.fetch });
    await assert.rejects(client.me(), (e: unknown) => e instanceof LumoAuthError && e.kind === 'auth' && e.code === 'invalid_client');
  });

  test('a wrong audience is refused by the server (assertion aud = issuer)', async () => {
    const { key, kid, agentId } = newAgent();
    const client = new AgentClient({ baseUrl: ORIGIN, orgId: ORG, agentId, issuer: `${ISSUER}/x`, tokenEndpoint: TOKEN_ENDPOINT, keyId: kid, key, fetchFn: mock.fetch });
    await assert.rejects(client.me(), (e: unknown) => e instanceof LumoAuthError && e.kind === 'auth');
    assert.ok(mock.errors.some((e) => e.startsWith('assertion: aud')));
  });

  test('network failures become LumoAuthError(network) without secrets in the message', async () => {
    const { key, kid, agentId } = newAgent();
    const client = new AgentClient({
      baseUrl: ORIGIN,
      orgId: ORG,
      agentId,
      issuer: ISSUER,
      tokenEndpoint: TOKEN_ENDPOINT,
      keyId: kid,
      key,
      fetchFn: () => Promise.reject(Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } })),
    });
    await assert.rejects(client.me(), (e: unknown) => e instanceof LumoAuthError && e.kind === 'network' && /ECONNREFUSED/.test(e.message));
  });

  test('ask sends audit: always and returns the audit id', async () => {
    const { client } = newAgent();
    const r = await client.ask('shell:exec', { tool: 'exec', server: null, host: 'openclaw' });
    assert.equal(r.allowed, true);
    assert.equal(r.auditId, '0123456789abcdef');
    assert.equal(mock.asks.at(-1).audit, 'always');
  });
});

describe('SnapshotStore', () => {
  test('refresh stores capabilities and status; 401/invalid_client clears it', async () => {
    const { client, agentId } = newAgent(['files:read']);
    const store = new SnapshotStore(() => client);
    await store.refresh();
    assert.equal(store.snapshot?.status, 'active');
    assert.deepEqual(store.snapshot?.capabilities, ['files:read']);
    mock.agents.delete(agentId);
    client.invalidateToken();
    await store.refresh();
    assert.equal(store.snapshot, null);
    assert.equal(store.lastError?.kind, 'auth');
  });

  test('a suspended agent keeps no capabilities', async () => {
    const { client } = newAgent(['*'], 'suspended');
    const store = new SnapshotStore(() => client);
    await store.refresh();
    assert.equal(store.snapshot?.status, 'suspended');
    assert.deepEqual(store.snapshot?.capabilities, []);
  });

  test('network errors keep the last snapshot', async () => {
    let fail = false;
    const { key, kid, agentId } = newAgent(['files:read']);
    const client = new AgentClient({
      baseUrl: ORIGIN, orgId: ORG, agentId, issuer: ISSUER, tokenEndpoint: TOKEN_ENDPOINT, keyId: kid, key,
      fetchFn: (i, init) => (fail ? Promise.reject(new TypeError('fetch failed')) : mock.fetch(i, init)),
    });
    const store = new SnapshotStore(() => client);
    await store.refresh();
    fail = true;
    client.invalidateToken();
    await store.refresh();
    assert.deepEqual(store.snapshot?.capabilities, ['files:read']);
    assert.equal(store.lastError?.kind, 'network');
  });
});

describe('ReceiptQueue', () => {
  const receipt = (i: number) => ({ tool: `t${i}`, decision: 'allowed' as const, outcome: 'succeeded' as const });

  test('batches of at most 50, flushed at 20 queued', async () => {
    const batches: number[] = [];
    const q = new ReceiptQueue({ send: async (calls) => void batches.push(calls.length) });
    for (let i = 0; i < 19; i++) q.enqueue(receipt(i));
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(batches, [], 'below the flush threshold');
    for (let i = 19; i < 120; i++) q.enqueue(receipt(i));
    await q.flush(true);
    await q.flush(true);
    assert.equal(batches.reduce((a, b) => a + b, 0), 120);
    assert.ok(batches.every((b) => b <= 50));
    assert.equal(q.size, 0);
  });

  test('at most 1,000 queued; the oldest are dropped and counted', () => {
    const q = new ReceiptQueue({ send: async () => { throw new LumoAuthError('network', 'down'); }, flushAt: 10_000 });
    for (let i = 0; i < 1005; i++) q.enqueue(receipt(i));
    assert.equal(q.size, 1000);
    assert.equal(q.snapshot().dropped, 5);
  });

  test('429 keeps the batch and backs off; 400 drops it and logs', async () => {
    let now = 1_000_000;
    const errors: string[] = [];
    let mode: 'r429' | 'r400' | 'ok' = 'r429';
    const sent: number[] = [];
    const q = new ReceiptQueue({
      now: () => now,
      flushAt: 1000,
      log: { warn: () => {}, error: (m) => void errors.push(m) },
      send: async (calls) => {
        if (mode === 'r429') throw new LumoAuthError('rate_limited', 'rate limited', { status: 429 });
        if (mode === 'r400') throw new LumoAuthError('client', 'bad', { status: 400 });
        sent.push(calls.length);
      },
    });
    q.enqueue(receipt(1));
    await q.flush();
    assert.equal(q.size, 1);
    assert.ok(q.snapshot().nextAttemptAtMs > now);
    await q.flush();
    assert.equal(q.size, 1, 'no attempt during back-off');
    mode = 'r400';
    now += 10 * 60_000;
    await q.flush();
    assert.equal(q.size, 0);
    assert.equal(q.snapshot().rejected, 1);
    assert.equal(errors.length, 1);
    mode = 'ok';
    q.enqueue(receipt(2));
    await q.flush();
    assert.deepEqual(sent, [1]);
  });

  test('held receipts complete on after_tool_call or are sent without outcome after 10 minutes', async () => {
    let now = 0;
    const sent: any[] = [];
    const q = new ReceiptQueue({ now: () => now, flushAt: 1000, send: async (c) => void sent.push(...c) });
    q.hold('a', { tool: 'read', decision: 'allowed' });
    q.hold('b', { tool: 'exec', decision: 'approved' });
    assert.equal(q.complete('a', { outcome: 'succeeded', duration_ms: 5 }), true);
    now = 11 * 60_000;
    q.sweepPending();
    await q.flush(true);
    assert.deepEqual(sent, [
      { tool: 'read', decision: 'allowed', outcome: 'succeeded', duration_ms: 5 },
      { tool: 'exec', decision: 'approved' },
    ]);
  });

  test('at exit, undelivered receipts go to receipts-queue.jsonl (0600); the next process claims them', async () => {
    const { mkdtempSync, readFileSync, statSync, existsSync } = await import('node:fs');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const dir = mkdtempSync(join(tmpdir(), 'spool-'));
    const spoolPath = join(dir, 'receipts-queue.jsonl');
    const a = new ReceiptQueue({ spoolPath, flushAt: 1000, send: async () => { throw new LumoAuthError('network', 'down'); } });
    a.enqueue(receipt(1));
    a.hold('k', { tool: 'held', decision: 'approved' });
    assert.equal(a.spoolNow(), 2);
    assert.equal(statSync(spoolPath).mode & 0o777, 0o600);
    assert.equal(readFileSync(spoolPath, 'utf8').trim().split('\n').length, 2);
    const sent: any[] = [];
    const b = new ReceiptQueue({ spoolPath, flushAt: 1000, send: async (c) => void sent.push(...c) });
    assert.equal(b.claimSpool(), 2);
    assert.equal(existsSync(spoolPath), false);
    await b.flush(true);
    assert.deepEqual(sent.map((r) => r.tool), ['t1', 'held']);
  });

  test('receipts are validated like the server (mock): the Guard sends no unknown fields', async () => {
    const { client } = newAgent();
    await client.reportToolCalls([{ tool: 'x', decision: 'blocked', outcome: 'not_run', error_code: 'hard_rule', arguments_sha256: 'a'.repeat(64), occurred_at: '2026-11-19T10:15:00Z' }]);
    await assert.rejects(client.reportToolCalls([{ tool: 'x', decision: 'allowed', args: {} } as any]), (e: unknown) => e instanceof LumoAuthError && e.status === 400);
  });
});

describe('Enrollment', () => {
  const request = (): EnrollmentRequest => {
    const jwk = publicJwk(generateAgentKey());
    return {
      name: 'OpenClaw on test',
      host: 'openclaw',
      host_label: 'test',
      jwks: { keys: [{ ...jwk, kid: jwkThumbprint(jwk), use: 'sig', alg: 'ES256' }] },
      capabilities: [{ scope: 'files:read', risk: 'read', label: 'Read files', checked: true }],
      delegation: true,
      inventory: { tools: 1, mcp_servers: [] },
    };
  };

  test('start, then authorization_pending, slow_down (interval +5) and approval', async () => {
    const start = await startEnrollment(mock.fetch, ORIGIN, ORG, request());
    assert.equal(start.user_code, 'BCDF-GHJK');
    mock.enrollmentPoll = [
      { status: 400, body: { error: 'authorization_pending' } },
      { status: 400, body: { error: 'slow_down' } },
      { status: 400, body: { error: 'authorization_pending' } },
    ];
    const sleeps: number[] = [];
    const result = await pollEnrollment(mock.fetch, ORIGIN, ORG, start.enrollment_code, {
      interval: start.interval,
      expiresIn: start.expires_in,
      sleep: async (ms) => void sleeps.push(ms),
    });
    assert.match(result.agent_id, /^agt_/);
    assert.equal(result.can_act_on_behalf_of_users, true);
    assert.deepEqual(sleeps, [5000, 5000, 10000, 10000]);
  });

  test('access_denied and expired_token stop polling', async () => {
    const start = await startEnrollment(mock.fetch, ORIGIN, ORG, request());
    mock.enrollmentPoll = [{ status: 400, body: { error: 'access_denied' } }];
    await assert.rejects(
      pollEnrollment(mock.fetch, ORIGIN, ORG, start.enrollment_code, { interval: 5, expiresIn: 900, sleep: noSleep }),
      (e: unknown) => e instanceof EnrollmentError && e.code === 'access_denied',
    );
    mock.enrollmentPoll = [{ status: 400, body: { error: 'expired_token' } }];
    await assert.rejects(
      pollEnrollment(mock.fetch, ORIGIN, ORG, start.enrollment_code, { interval: 5, expiresIn: 900, sleep: noSleep }),
      (e: unknown) => e instanceof EnrollmentError && e.code === 'expired_token',
    );
  });

  test('the local deadline ends polling', async () => {
    let now = 0;
    mock.enrollmentPoll = Array.from({ length: 50 }, () => ({ status: 400, body: { error: 'authorization_pending' } }));
    await assert.rejects(
      pollEnrollment(mock.fetch, ORIGIN, ORG, 'code', { interval: 5, expiresIn: 12, now: () => now, sleep: async (ms) => void (now += ms) }),
      (e: unknown) => e instanceof EnrollmentError && e.code === 'expired_token',
    );
    mock.enrollmentPoll = [];
  });

  test('start errors: 404 unknown organization, 400 names the field, 429', async () => {
    mock.enrollmentStartReply = { status: 404, body: { error: 'not_found' } };
    await assert.rejects(startEnrollment(mock.fetch, ORIGIN, ORG, request()), (e: unknown) => e instanceof EnrollmentError && e.code === 'not_found');
    mock.enrollmentStartReply = { status: 400, body: { error: 'invalid_request', error_description: 'capabilities[3].scope' } };
    await assert.rejects(startEnrollment(mock.fetch, ORIGIN, ORG, request()), (e: unknown) => e instanceof EnrollmentError && /capabilities\[3\]/.test(e.message));
    mock.enrollmentStartReply = { status: 429, body: { error: 'rate_limited' } };
    await assert.rejects(startEnrollment(mock.fetch, ORIGIN, ORG, request()), (e: unknown) => e instanceof EnrollmentError && e.code === 'rate_limited');
    mock.enrollmentStartReply = { status: 201, body: { enrollment_code: 'x', user_code: 'A', verification_uri: 'http://evil.test/' } };
    await assert.rejects(startEnrollment(mock.fetch, ORIGIN, ORG, request()), (e: unknown) => e instanceof EnrollmentError && e.code === 'invalid_response');
    mock.enrollmentStartReply = undefined;
  });
});
