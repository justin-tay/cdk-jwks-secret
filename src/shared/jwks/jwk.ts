import { createHash } from 'node:crypto';
import type { JwkAlgorithm, JwkEcCurve, JwkKeyType, JwkPublicKeyUse } from './options';

/** A JWK as stored in the secret. Private members are present on private keys only. */
export interface Jwk {
  readonly kty: JwkKeyType;
  readonly kid: string;
  readonly use: JwkPublicKeyUse;
  readonly alg: JwkAlgorithm;
  // RSA public members
  readonly n?: string;
  readonly e?: string;
  // EC public members
  readonly crv?: JwkEcCurve;
  readonly x?: string;
  readonly y?: string;
  // Private members
  readonly d?: string;
  readonly p?: string;
  readonly q?: string;
  readonly dp?: string;
  readonly dq?: string;
  readonly qi?: string;
}

/** A JWK Set, stored verbatim as the secret string. */
export interface Jwks {
  readonly keys: readonly Jwk[];
}

/** Members of a private JWK that a public JWK must not have (RFC 7518 sections 6.2.2 and 6.3.2). */
export const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'] as const;

export function isPrivateJwk(jwk: Jwk): boolean {
  return jwk.d !== undefined;
}

/** Returns a copy of the JWK without its private members. */
export function toPublicJwk(jwk: Jwk): Jwk {
  const copy: Record<string, unknown> = { ...jwk };
  for (const member of PRIVATE_MEMBERS) {
    delete copy[member];
  }
  return copy as unknown as Jwk;
}

/** The RFC 7638 JWK SHA-256 thumbprint, base64url encoded. */
export function computeThumbprint(jwk: Pick<Jwk, 'kty' | 'n' | 'e' | 'crv' | 'x' | 'y'>): string {
  // Required members only, in lexicographic order, no whitespace.
  const members =
    jwk.kty === 'RSA'
      ? { e: jwk.e, kty: jwk.kty, n: jwk.n }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  return createHash('sha256').update(JSON.stringify(members)).digest('base64url');
}

/** The bit length of an RSA JWK's modulus. */
export function rsaModulusLength(jwk: Pick<Jwk, 'n'>): number {
  const bytes = Buffer.from(jwk.n ?? '', 'base64url');
  let offset = 0;
  while (offset < bytes.length && bytes[offset] === 0) {
    offset++;
  }
  if (offset === bytes.length) {
    return 0;
  }
  return (bytes.length - offset) * 8 - (Math.clz32(bytes[offset]) - 24);
}
