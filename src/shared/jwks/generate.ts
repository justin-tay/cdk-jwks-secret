import { generateKeyPair, type KeyObject } from 'node:crypto';
import { computeThumbprint, type Jwk } from './jwk';
import type { JwkEcCurve, ResolvedJwkOptions } from './options';

const OPENSSL_CURVE_NAMES: Readonly<Record<JwkEcCurve, string>> = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
};

function generatePrivateKey(options: ResolvedJwkOptions): Promise<KeyObject> {
  return new Promise((resolve, reject) => {
    const callback = (error: Error | null, _publicKey: KeyObject, privateKey: KeyObject) =>
      error ? reject(error) : resolve(privateKey);
    if (options.keyType === 'RSA') {
      generateKeyPair('rsa', { modulusLength: options.rsaModulusLength!, publicExponent: 0x10001 }, callback);
    } else {
      generateKeyPair('ec', { namedCurve: OPENSSL_CURVE_NAMES[options.curve!] }, callback);
    }
  });
}

/** Generates a new private JWK with `kid` (RFC 7638 thumbprint), `use` and `alg` set. */
export async function generateJwk(options: ResolvedJwkOptions): Promise<Jwk> {
  const privateKey = await generatePrivateKey(options);
  const exported = privateKey.export({ format: 'jwk' }) as Omit<Jwk, 'kid' | 'use' | 'alg'>;
  const { kty, ...members } = exported;
  return {
    kty,
    kid: computeThumbprint(exported),
    use: options.use,
    alg: options.algorithm,
    ...members,
  };
}
