import { isPrivateJwk, toPublicJwk, type Jwk, type Jwks } from './jwk';
import { MAX_KEY_COUNT } from './validate';

/**
 * The JWKS to serve from the JWKS endpoint: the keys the OpenID Connect
 * server may use, without private members.
 *
 * - `sig`: every key. The retired key stays published so assertions signed
 *   by a server instance with a cached secret still verify.
 * - `enc`: every key except the oldest once there are 3. The oldest is
 *   dropped at the next rotation, so it is unpublished one rotation early
 *   while its private key is kept to decrypt anything still encrypted to it.
 *
 * Pass a JWKS obtained from `parseJwks`; this function does not re-validate.
 */
export function toPublicJwks(jwks: Jwks): Jwks {
  const { keys } = jwks;
  const published = keys[0]?.use === 'enc' && keys.length === MAX_KEY_COUNT ? keys.slice(1) : keys;
  return { keys: published.map(toPublicJwk) };
}

/**
 * The key to sign with (e.g. the `private_key_jwt` client assertion): the
 * first key that has a private part.
 *
 * @throws Error if the JWKS holds `enc` keys or is not yet initialised
 */
export function selectSigningKey(jwks: Jwks): Jwk {
  const key = jwks.keys.find(isPrivateJwk);
  if (!key) {
    throw new Error('JWKS has no private key; it has not been initialised by a rotation yet');
  }
  if (key.use !== 'sig') {
    throw new Error(`JWKS holds "${key.use}" keys, not "sig" keys`);
  }
  return key;
}

/**
 * The private key to decrypt a JWE whose header names `kid`, or undefined if
 * there is none.
 *
 * @throws Error if the JWKS holds `sig` keys
 */
export function selectDecryptionKey(jwks: Jwks, kid: string): Jwk | undefined {
  if (jwks.keys.length > 0 && jwks.keys[0].use !== 'enc') {
    throw new Error(`JWKS holds "${jwks.keys[0].use}" keys, not "enc" keys`);
  }
  return jwks.keys.find((jwk) => jwk.kid === kid && isPrivateJwk(jwk));
}
