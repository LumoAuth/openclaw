export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;
/** The global fetch (Node ≥ 24). */
export declare const defaultFetch: FetchFn;
export type ErrorKind = 'auth' | 'network' | 'server' | 'rate_limited' | 'client';
/** A LumoAuth request that failed. `message` never holds a token or a key. */
export declare class LumoAuthError extends Error {
    readonly kind: ErrorKind;
    readonly status: number | undefined;
    readonly code: string | undefined;
    readonly body: unknown;
    constructor(kind: ErrorKind, message: string, opts?: {
        status?: number | undefined;
        code?: string | undefined;
        body?: unknown;
    });
    /** Worth retrying later (network, 5xx, 429). */
    get transient(): boolean;
}
export interface JsonResponse {
    status: number;
    headers: Headers;
    body: any;
}
export declare const DEFAULT_TIMEOUT_MS = 10000;
/** fetch with a timeout; parses a JSON body when there is one. Network failures become LumoAuthError('network'). */
export declare function fetchJson(fetchFn: FetchFn, url: string, init: RequestInit, timeoutMs?: number): Promise<JsonResponse>;
/** Turn an error answer into a LumoAuthError. */
export declare function errorFor(res: JsonResponse, what: string): LumoAuthError;
