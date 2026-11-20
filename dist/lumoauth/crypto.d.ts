import { type KeyObject } from 'node:crypto';
/** Public members of an EC P-256 key as a JWK. */
export interface EcPublicJwk {
    kty: 'EC';
    crv: 'P-256';
    x: string;
    y: string;
}
export declare function generateAgentKey(): KeyObject;
/** PKCS#8 PEM of a private key (for agent-key.pem). */
export declare function privateKeyToPem(key: KeyObject): string;
/** Load agent-key.pem; only EC P-256 private keys are accepted. */
export declare function loadPrivateKey(pem: string): KeyObject;
export declare function publicJwk(key: KeyObject): EcPublicJwk;
/** RFC 7638 JWK thumbprint (base64url SHA-256 of the required members in lexical order). */
export declare function jwkThumbprint(jwk: EcPublicJwk): string;
/** The key fingerprint shown to people: the first 4 groups of 4 characters of the thumbprint. */
export declare function keyFingerprint(thumbprint: string): string;
/** Sign a compact JWS with ES256 (P-256, SHA-256, IEEE P1363 signature). */
export declare function signEs256Jwt(header: Record<string, unknown>, claims: Record<string, unknown>, key: KeyObject): string;
export declare const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/** SPEC §7.1: private_key_jwt client assertion (RFC 7523). */
export declare function clientAssertion(opts: {
    agentId: string;
    issuer: string;
    keyId: string;
    key: KeyObject;
    nowSeconds: number;
}): string;
/** `htu`: the URL without query and fragment (RFC 9449 §4.2). */
export declare function dpopHtu(url: string): string;
export declare function dpopAth(accessToken: string): string;
/**
 * RFC 9449 DPoP proofs with a short-lived P-256 key that exists only in this
 * process's memory. Remembers the latest server nonce per origin.
 */
export declare class DpopSigner {
    readonly jwk: EcPublicJwk;
    readonly thumbprint: string;
    private readonly key;
    private readonly nonces;
    constructor(key?: KeyObject);
    proof(opts: {
        method: string;
        url: string;
        nowSeconds: number;
        accessToken?: string | undefined;
        nonce?: string | undefined;
    }): string;
    setNonce(url: string, nonce: string): void;
}
