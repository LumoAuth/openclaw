import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign as cryptoSign, } from 'node:crypto';
export function generateAgentKey() {
    return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
}
/** PKCS#8 PEM of a private key (for agent-key.pem). */
export function privateKeyToPem(key) {
    return key.export({ type: 'pkcs8', format: 'pem' }).toString();
}
/** Load agent-key.pem; only EC P-256 private keys are accepted. */
export function loadPrivateKey(pem) {
    const key = createPrivateKey(pem);
    if (key.type !== 'private' || key.asymmetricKeyType !== 'ec')
        throw new Error('agent-key.pem is not an EC private key');
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (curve !== 'prime256v1' && curve !== 'P-256')
        throw new Error('agent-key.pem must use the P-256 curve');
    return key;
}
export function publicJwk(key) {
    const jwk = createPublicKey(key).export({ format: 'jwk' });
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
        throw new Error('expected an EC P-256 key');
    }
    return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}
/** RFC 7638 JWK thumbprint (base64url SHA-256 of the required members in lexical order). */
export function jwkThumbprint(jwk) {
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}
/** The key fingerprint shown to people: the first 4 groups of 4 characters of the thumbprint. */
export function keyFingerprint(thumbprint) {
    return [0, 4, 8, 12].map((i) => thumbprint.slice(i, i + 4)).join('-');
}
function b64urlJson(value) {
    return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}
/** Sign a compact JWS with ES256 (P-256, SHA-256, IEEE P1363 signature). */
export function signEs256Jwt(header, claims, key) {
    const input = `${b64urlJson(header)}.${b64urlJson(claims)}`;
    const sig = cryptoSign('sha256', Buffer.from(input, 'utf8'), { key, dsaEncoding: 'ieee-p1363' });
    return `${input}.${sig.toString('base64url')}`;
}
export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
/** SPEC §7.1: private_key_jwt client assertion (RFC 7523). */
export function clientAssertion(opts) {
    const iat = Math.floor(opts.nowSeconds);
    return signEs256Jwt({ alg: 'ES256', typ: 'client-authentication+jwt', kid: opts.keyId }, {
        iss: opts.agentId,
        sub: opts.agentId,
        aud: opts.issuer,
        iat,
        exp: iat + 60,
        jti: randomBytes(16).toString('base64url'),
    }, opts.key);
}
/** `htu`: the URL without query and fragment (RFC 9449 §4.2). */
export function dpopHtu(url) {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
}
export function dpopAth(accessToken) {
    return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}
/**
 * RFC 9449 DPoP proofs with a short-lived P-256 key that exists only in this
 * process's memory. Remembers the latest server nonce per origin.
 */
export class DpopSigner {
    jwk;
    thumbprint;
    key;
    nonces = new Map();
    constructor(key = generateAgentKey()) {
        this.key = key;
        this.jwk = publicJwk(key);
        this.thumbprint = jwkThumbprint(this.jwk);
    }
    proof(opts) {
        const claims = {
            jti: randomBytes(16).toString('base64url'),
            htm: opts.method.toUpperCase(),
            htu: dpopHtu(opts.url),
            iat: Math.floor(opts.nowSeconds),
        };
        if (opts.accessToken)
            claims.ath = dpopAth(opts.accessToken);
        const nonce = opts.nonce ?? this.nonces.get(new URL(opts.url).origin);
        if (nonce)
            claims.nonce = nonce;
        return signEs256Jwt({ typ: 'dpop+jwt', alg: 'ES256', jwk: this.jwk }, claims, this.key);
    }
    setNonce(url, nonce) {
        this.nonces.set(new URL(url).origin, nonce);
    }
}
