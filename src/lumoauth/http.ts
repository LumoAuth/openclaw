export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;

/** The global fetch (Node ≥ 24). */
export const defaultFetch: FetchFn = (input, init) => fetch(input, init);

export type ErrorKind = 'auth' | 'network' | 'server' | 'rate_limited' | 'client';

/** A LumoAuth request that failed. `message` never holds a token or a key. */
export class LumoAuthError extends Error {
  readonly kind: ErrorKind;
  readonly status: number | undefined;
  readonly code: string | undefined;
  readonly body: unknown;

  constructor(kind: ErrorKind, message: string, opts: { status?: number | undefined; code?: string | undefined; body?: unknown } = {}) {
    super(message);
    this.name = 'LumoAuthError';
    this.kind = kind;
    this.status = opts.status;
    this.code = opts.code;
    this.body = opts.body;
  }

  /** Worth retrying later (network, 5xx, 429). */
  get transient(): boolean {
    return this.kind === 'network' || this.kind === 'server' || this.kind === 'rate_limited';
  }
}

export interface JsonResponse {
  status: number;
  headers: Headers;
  body: any;
}

export const DEFAULT_TIMEOUT_MS = 10_000;

/** fetch with a timeout; parses a JSON body when there is one. Network failures become LumoAuthError('network'). */
export async function fetchJson(fetchFn: FetchFn, url: string, init: RequestInit, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<JsonResponse> {
  let res: Response;
  try {
    res = await fetchFn(url, { ...init, signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
  } catch (err) {
    const reason = err instanceof Error ? (err.name === 'TimeoutError' ? 'timed out' : describeNetworkError(err)) : 'failed';
    throw new LumoAuthError('network', `Cannot reach LumoAuth (${new URL(url).host}): ${reason}`);
  }
  const text = await res.text().catch(() => '');
  let body: unknown = undefined;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
  }
  return { status: res.status, headers: res.headers, body };
}

function describeNetworkError(err: Error): string {
  const cause = (err as { cause?: { code?: string; message?: string } }).cause;
  if (cause?.code) {
    if (cause.code === 'SELF_SIGNED_CERT_IN_CHAIN' || cause.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || cause.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
      return `${cause.code} (the TLS certificate is not trusted; set NODE_EXTRA_CA_CERTS or start Node with --use-system-ca)`;
    }
    return cause.code;
  }
  return err.message || 'failed';
}

/** Turn an error answer into a LumoAuthError. */
export function errorFor(res: JsonResponse, what: string): LumoAuthError {
  const code = typeof res.body?.error === 'string' ? res.body.error : undefined;
  const desc = typeof res.body?.error_description === 'string' ? `: ${res.body.error_description}` : '';
  const label = `${what} answered ${res.status}${code ? ` ${code}` : ''}${desc}`;
  if (res.status === 429) return new LumoAuthError('rate_limited', label, { status: res.status, code, body: res.body });
  if (res.status >= 500) return new LumoAuthError('server', label, { status: res.status, code, body: res.body });
  if (res.status === 401) return new LumoAuthError('auth', label, { status: res.status, code, body: res.body });
  return new LumoAuthError('client', label, { status: res.status, code, body: res.body });
}
