import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  type KeyObject,
} from 'node:crypto';

/** Public members of an EC P-256 key as a JWK. */
export interface EcPublicJwk {
  kty: 'EC';
  crv: 'P-256';
  x: string;
  y: string;
}

export function generateAgentKey(): KeyObject {
  return generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
}

/** PKCS#8 PEM of a private key (for agent-key.pem). */
export function privateKeyToPem(key: KeyObject): string {
  return key.export({ type: 'pkcs8', format: 'pem' }).toString();
}

/** Load agent-key.pem; only EC P-256 private keys are accepted. */
export function loadPrivateKey(pem: string): KeyObject {
  const key = createPrivateKey(pem);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ec') throw new Error('agent-key.pem is not an EC private key');
  const curve = key.asymmetricKeyDetails?.namedCurve;
  if (curve !== 'prime256v1' && curve !== 'P-256') throw new Error('agent-key.pem must use the P-256 curve');
  return key;
}

export function publicJwk(key: KeyObject): EcPublicJwk {
  const jwk = createPublicKey(key).export({ format: 'jwk' }) as Record<string, unknown>;
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('expected an EC P-256 key');
  }
  return { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y };
}

/** RFC 7638 JWK thumbprint (base64url SHA-256 of the required members in lexical order). */
export function jwkThumbprint(jwk: EcPublicJwk): string {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash('sha256').update(canonical, 'utf8').digest('base64url');
}

/** The key fingerprint shown to people: the first 4 groups of 4 characters of the thumbprint. */
export function keyFingerprint(thumbprint: string): string {
  return [0, 4, 8, 12].map((i) => thumbprint.slice(i, i + 4)).join('-');
}

function b64urlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

/** Sign a compact JWS with ES256 (P-256, SHA-256, IEEE P1363 signature). */
export function signEs256Jwt(header: Record<string, unknown>, claims: Record<string, unknown>, key: KeyObject): string {
  const input = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const sig = cryptoSign('sha256', Buffer.from(input, 'utf8'), { key, dsaEncoding: 'ieee-p1363' });
  return `${input}.${sig.toString('base64url')}`;
}

export const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** SPEC §7.1: private_key_jwt client assertion (RFC 7523). */
export function clientAssertion(opts: { agentId: string; issuer: string; keyId: string; key: KeyObject; nowSeconds: number }): string {
  const iat = Math.floor(opts.nowSeconds);
  return signEs256Jwt(
    { alg: 'ES256', typ: 'client-authentication+jwt', kid: opts.keyId },
    {
      iss: opts.agentId,
      sub: opts.agentId,
      aud: opts.issuer,
      iat,
      exp: iat + 60,
      jti: randomBytes(16).toString('base64url'),
    },
    opts.key,
  );
}

/** `htu`: the URL without query and fragment (RFC 9449 §4.2). */
export function dpopHtu(url: string): string {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

export function dpopAth(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

/**
 * RFC 9449 DPoP proofs with a short-lived P-256 key that exists only in this
 * process's memory. Remembers the latest server nonce per origin.
 */
export class DpopSigner {
  readonly jwk: EcPublicJwk;
  readonly thumbprint: string;
  private readonly key: KeyObject;
  private readonly nonces = new Map<string, string>();

  constructor(key: KeyObject = generateAgentKey()) {
    this.key = key;
    this.jwk = publicJwk(key);
    this.thumbprint = jwkThumbprint(this.jwk);
  }

  proof(opts: { method: string; url: string; nowSeconds: number; accessToken?: string | undefined; nonce?: string | undefined }): string {
    const claims: Record<string, unknown> = {
      jti: randomBytes(16).toString('base64url'),
      htm: opts.method.toUpperCase(),
      htu: dpopHtu(opts.url),
      iat: Math.floor(opts.nowSeconds),
    };
    if (opts.accessToken) claims.ath = dpopAth(opts.accessToken);
    const nonce = opts.nonce ?? this.nonces.get(new URL(opts.url).origin);
    if (nonce) claims.nonce = nonce;
    return signEs256Jwt({ typ: 'dpop+jwt', alg: 'ES256', jwk: this.jwk }, claims, this.key);
  }

  setNonce(url: string, nonce: string): void {
    this.nonces.set(new URL(url).origin, nonce);
  }
}
