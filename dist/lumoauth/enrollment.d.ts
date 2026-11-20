import { type FetchFn } from './http.ts';
/** SPEC §8.2 start request. */
export interface EnrollmentRequest {
    name: string;
    host: 'openclaw';
    host_label: string;
    jwks: {
        keys: Record<string, string>[];
    };
    capabilities: {
        scope: string;
        risk: string;
        label: string;
        checked: boolean;
    }[];
    delegation: boolean;
    inventory: {
        tools: number;
        mcp_servers: {
            name: string;
        }[];
    };
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
export declare class EnrollmentError extends Error {
    readonly code: 'access_denied' | 'expired_token' | 'invalid_request' | 'not_found' | 'rate_limited' | 'server' | 'network' | 'invalid_response' | 'aborted';
    constructor(code: EnrollmentError['code'], message: string);
}
/** POST /agents/enrollments (no credential). */
export declare function startEnrollment(fetchFn: FetchFn, baseUrl: string, orgId: string, body: EnrollmentRequest, userAgent?: string): Promise<EnrollmentStart>;
export interface PollOptions {
    interval: number;
    expiresIn: number;
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
    onWait?: (secondsLeft: number) => void;
    signal?: AbortSignal;
    userAgent?: string;
}
/** Poll POST /agents/enrollments/token until approved, denied or expired. */
export declare function pollEnrollment(fetchFn: FetchFn, baseUrl: string, orgId: string, enrollmentCode: string, opts: PollOptions): Promise<EnrollmentResult>;
