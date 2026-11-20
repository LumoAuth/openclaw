import { errorFor, fetchJson, LumoAuthError, type FetchFn } from './http.ts';

/** SPEC §8.2 start request. */
export interface EnrollmentRequest {
  name: string;
  host: 'openclaw';
  host_label: string;
  jwks: { keys: Record<string, string>[] };
  capabilities: { scope: string; risk: string; label: string; checked: boolean }[];
  delegation: boolean;
  inventory: { tools: number; mcp_servers: { name: string }[] };
}

export interface EnrollmentStart {
  enrollment_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  key_fingerprint?: string;
  expires_in: number;
  interval: number;
}

export interface EnrollmentResult {
  agent_id: string;
  client_id?: string;
  issuer: string;
  token_endpoint: string;
  key_id: string;
  capabilities: string[];
  can_act_on_behalf_of_users: boolean;
  owner_user_id?: string | null;
  agent_url?: string;
}

export class EnrollmentError extends Error {
  readonly code: 'access_denied' | 'expired_token' | 'invalid_request' | 'not_found' | 'rate_limited' | 'server' | 'network' | 'invalid_response' | 'aborted';
  constructor(code: EnrollmentError['code'], message: string) {
    super(message);
    this.name = 'EnrollmentError';
    this.code = code;
  }
}

function enrollmentsUrl(baseUrl: string, orgId: string, suffix = ''): string {
  return `${baseUrl.replace(/\/+$/, '')}/orgs/${encodeURIComponent(orgId)}/api/v1/agents/enrollments${suffix}`;
}

const JSON_HEADERS = { 'Content-Type': 'application/json', Accept: 'application/json' };

/** POST /agents/enrollments (no credential). */
export async function startEnrollment(
  fetchFn: FetchFn,
  baseUrl: string,
  orgId: string,
  body: EnrollmentRequest,
  userAgent = 'lumoauth-openclaw',
): Promise<EnrollmentStart> {
  let res;
  try {
    res = await fetchJson(fetchFn, enrollmentsUrl(baseUrl, orgId), {
      method: 'POST',
      headers: { ...JSON_HEADERS, 'User-Agent': userAgent },
      body: JSON.stringify(body),
    });
  } catch (err) {
    throw new EnrollmentError('network', (err as Error).message);
  }
  if (res.status === 201 || res.status === 200) {
    const b = res.body;
    if (
      typeof b?.enrollment_code === 'string' &&
      typeof b.user_code === 'string' &&
      typeof b.verification_uri === 'string' &&
      /^https:\/\//.test(b.verification_uri)
    ) {
      return {
        enrollment_code: b.enrollment_code,
        user_code: b.user_code,
        verification_uri: b.verification_uri,
        verification_uri_complete:
          typeof b.verification_uri_complete === 'string' && /^https:\/\//.test(b.verification_uri_complete) ? b.verification_uri_complete : undefined,
        key_fingerprint: typeof b.key_fingerprint === 'string' ? b.key_fingerprint : undefined,
        expires_in: typeof b.expires_in === 'number' && b.expires_in > 0 ? b.expires_in : 900,
        interval: typeof b.interval === 'number' && b.interval > 0 ? b.interval : 5,
      };
    }
    throw new EnrollmentError('invalid_response', 'LumoAuth answered the enrollment request without a code.');
  }
  const err = errorFor(res, 'LumoAuth');
  if (res.status === 404) throw new EnrollmentError('not_found', 'LumoAuth does not know this organization. Check the URL.');
  if (res.status === 429) throw new EnrollmentError('rate_limited', 'LumoAuth is rate limiting enrollments. Wait a minute and try again.');
  if (res.status >= 500) throw new EnrollmentError('server', err.message);
  throw new EnrollmentError('invalid_request', err.message);
}

export interface PollOptions {
  interval: number;
  expiresIn: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  onWait?: (secondsLeft: number) => void;
  signal?: AbortSignal;
  userAgent?: string;
}

const defaultSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Poll POST /agents/enrollments/token until approved, denied or expired. */
export async function pollEnrollment(
  fetchFn: FetchFn,
  baseUrl: string,
  orgId: string,
  enrollmentCode: string,
  opts: PollOptions,
): Promise<EnrollmentResult> {
  const now = opts.now ?? Date.now;
  const sleep = opts.sleep ?? defaultSleep;
  const deadline = now() + opts.expiresIn * 1000;
  let interval = Math.max(1, opts.interval);
  let networkFailures = 0;
  for (;;) {
    if (opts.signal?.aborted) throw new EnrollmentError('aborted', 'Setup was stopped.');
    const left = Math.round((deadline - now()) / 1000);
    if (left <= 0) throw new EnrollmentError('expired_token', 'The enrollment code expired before it was approved.');
    opts.onWait?.(left);
    await sleep(interval * 1000);
    let res;
    try {
      res = await fetchJson(fetchFn, enrollmentsUrl(baseUrl, orgId, '/token'), {
        method: 'POST',
        headers: { ...JSON_HEADERS, 'User-Agent': opts.userAgent ?? 'lumoauth-openclaw' },
        body: JSON.stringify({ enrollment_code: enrollmentCode }),
      });
      networkFailures = 0;
    } catch (err) {
      if (++networkFailures >= 5) throw new EnrollmentError('network', (err as LumoAuthError).message);
      continue;
    }
    if (res.status === 200) {
      const b = res.body;
      if (typeof b?.agent_id !== 'string' || typeof b.issuer !== 'string' || typeof b.token_endpoint !== 'string' || typeof b.key_id !== 'string') {
        throw new EnrollmentError('invalid_response', 'LumoAuth approved the enrollment but the answer is incomplete.');
      }
      return {
        agent_id: b.agent_id,
        client_id: typeof b.client_id === 'string' ? b.client_id : undefined,
        issuer: b.issuer,
        token_endpoint: b.token_endpoint,
        key_id: b.key_id,
        capabilities: Array.isArray(b.capabilities) ? b.capabilities.filter((c: unknown): c is string => typeof c === 'string') : [],
        can_act_on_behalf_of_users: b.can_act_on_behalf_of_users === true,
        owner_user_id: typeof b.owner_user_id === 'string' ? b.owner_user_id : null,
        agent_url: typeof b.agent_url === 'string' ? b.agent_url : undefined,
      };
    }
    const code = typeof res.body?.error === 'string' ? res.body.error : undefined;
    if (res.status === 400 && code === 'authorization_pending') continue;
    if (res.status === 400 && code === 'slow_down') {
      interval += 5;
      continue;
    }
    if (code === 'access_denied') throw new EnrollmentError('access_denied', 'The enrollment was denied in LumoAuth.');
    if (code === 'expired_token') throw new EnrollmentError('expired_token', 'The enrollment code expired (or its result was already collected).');
    if (res.status === 429) {
      interval += 5;
      continue;
    }
    if (res.status >= 500) {
      if (++networkFailures >= 5) throw new EnrollmentError('server', errorFor(res, 'LumoAuth').message);
      continue;
    }
    throw new EnrollmentError('invalid_request', errorFor(res, 'LumoAuth').message);
  }
}
