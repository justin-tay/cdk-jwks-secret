import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import {
  assertIsRotationOf,
  assertJwks,
  computeThumbprint,
  generateJwk,
  isPrivateJwk,
  JwkOptionsMismatchError,
  JwksValidationError,
  resolveJwkOptions,
  rotateJwks,
  rsaModulusLength,
  toPublicJwk,
  type Jwks,
} from '../../../src/shared/jwks';

const es256 = resolveJwkOptions({ algorithm: 'ES256' });
const ecdhEs = resolveJwkOptions({ algorithm: 'ECDH-ES' });

const kids = (jwks: Jwks) => jwks.keys.map((jwk) => jwk.kid);
const privateFlags = (jwks: Jwks) => jwks.keys.map(isPrivateJwk);

describe('generateJwk', () => {
  test('generates an RSA key with kid, use and alg', async () => {
    const jwk = await generateJwk(resolveJwkOptions({ algorithm: 'PS256', rsaModulusLength: 3072 }));
    expect(jwk).toMatchObject({ kty: 'RSA', use: 'sig', alg: 'PS256' });
    expect(Object.keys(jwk).slice(0, 4)).toEqual(['kty', 'kid', 'use', 'alg']);
    expect(jwk.kid).toBe(computeThumbprint(jwk));
    expect(rsaModulusLength(jwk)).toBe(3072);
    expect(jwk.d).toBeDefined();
  });

  test.each(['P-256', 'P-384', 'P-521'] as const)('generates an ECDH-ES key on %s', async (curve) => {
    const jwk = await generateJwk(resolveJwkOptions({ algorithm: 'ECDH-ES', curve }));
    expect(jwk).toMatchObject({ kty: 'EC', crv: curve, use: 'enc', alg: 'ECDH-ES' });
  });

  test('generates an ECDH-ES+A128KW key', async () => {
    const jwk = await generateJwk(resolveJwkOptions({ use: 'enc' }));
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-256', use: 'enc', alg: 'ECDH-ES+A128KW' });
    expect(jwk.kid).toBe(computeThumbprint(jwk));
  });

  test('generates a usable key pair', async () => {
    const jwk = await generateJwk(es256);
    const privateKey = createPrivateKey({ key: jwk as never, format: 'jwk' });
    const publicKey = createPublicKey({ key: toPublicJwk(jwk) as never, format: 'jwk' });
    const signature = sign('sha256', Buffer.from('data'), privateKey);
    expect(verify('sha256', Buffer.from('data'), publicKey, signature)).toBe(true);
  });
});

describe('computeThumbprint', () => {
  test('matches the RFC 7638 section 3.1 example', () => {
    const jwk = {
      kty: 'RSA' as const,
      n:
        '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP' +
        'ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY' +
        '368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0f' +
        'M4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
    };
    expect(computeThumbprint(jwk)).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });
});

describe('rsaModulusLength', () => {
  test.each([
    ['', 0],
    ['AAAA', 0],
    [Buffer.from([0x00, 0x80, 0x00]).toString('base64url'), 16],
    [Buffer.from([0x01, 0x00]).toString('base64url'), 9],
  ])('of n=%j is %d bits', (n, bits) => {
    expect(rsaModulusLength({ n })).toBe(bits);
  });
});

describe('rotateJwks', () => {
  test('initialises an empty JWKS with 2 private keys', async () => {
    const jwks = await rotateJwks({ keys: [] }, es256);
    expect(jwks.keys).toHaveLength(2);
    expect(privateFlags(jwks)).toEqual([true, true]);
    assertJwks(jwks);
  });

  test('sig: appends a key, keeps at most 3 and strips the private key at index 0', async () => {
    const initial = await rotateJwks({ keys: [] }, es256);
    const [a, b] = kids(initial);

    const first = await rotateJwks(initial, es256);
    const c = kids(first)[2];
    expect(kids(first)).toEqual([a, b, c]);
    expect(privateFlags(first)).toEqual([false, true, true]);

    const second = await rotateJwks(first, es256);
    const d = kids(second)[2];
    expect(kids(second)).toEqual([b, c, d]);
    expect(privateFlags(second)).toEqual([false, true, true]);
    expect(second.keys[0]).toEqual(toPublicJwk(first.keys[1]));
    assertJwks(second);
  });

  test('enc: keeps every key private and drops the oldest', async () => {
    const initial = await rotateJwks({ keys: [] }, ecdhEs);
    const first = await rotateJwks(initial, ecdhEs);
    const second = await rotateJwks(first, ecdhEs);
    expect(kids(second)).toEqual([...kids(first).slice(1), kids(second)[2]]);
    expect(privateFlags(first)).toEqual([true, true, true]);
    expect(privateFlags(second)).toEqual([true, true, true]);
    assertJwks(second);
  });

  test('does not modify the current JWKS', async () => {
    const initial = await rotateJwks({ keys: [] }, es256);
    const first = await rotateJwks(initial, es256);
    const snapshot = JSON.stringify(first);
    await rotateJwks(first, es256);
    expect(JSON.stringify(first)).toBe(snapshot);
  });

  test.each([
    [{ algorithm: 'ES384' }, /keys\[0\]\.alg is ES256, expected ES384/],
    [{ algorithm: 'ECDH-ES' }, /keys\[0\]\.use is sig, expected enc/],
    [{ algorithm: 'RS256' }, /keys\[0\]\.kty is EC, expected RSA/],
  ] as const)('fails when the options change to %j', async (options, message) => {
    const initial = await rotateJwks({ keys: [] }, es256);
    const rotation = rotateJwks(initial, resolveJwkOptions(options));
    await expect(rotation).rejects.toThrow(JwkOptionsMismatchError);
    await expect(rotation).rejects.toThrow(message);
  });

  test('fails when the curve changes', async () => {
    const initial = await rotateJwks({ keys: [] }, ecdhEs);
    await expect(
      rotateJwks(initial, resolveJwkOptions({ algorithm: 'ECDH-ES', curve: 'P-384' })),
    ).rejects.toThrow(/crv is P-256, expected P-384/);
  });

  test('fails when the RSA modulus length changes', async () => {
    const rs256 = resolveJwkOptions({ algorithm: 'RS256' });
    const initial = await rotateJwks({ keys: [] }, rs256);
    await expect(
      rotateJwks(initial, resolveJwkOptions({ algorithm: 'RS256', rsaModulusLength: 3072 })),
    ).rejects.toThrow(/modulus length is 2048, expected 3072/);
  });

  test('fails on a malformed JWKS', async () => {
    const initial = await rotateJwks({ keys: [] }, es256);
    await expect(rotateJwks({ keys: initial.keys.slice(0, 1) }, es256)).rejects.toThrow(JwksValidationError);
  });
});

describe('assertIsRotationOf', () => {
  test.each([
    ['sig', es256],
    ['enc', ecdhEs],
  ] as const)('accepts every rotation of %s keys computed by rotateJwks', async (_use, options) => {
    let previous: Jwks = { keys: [] };
    for (let i = 0; i < 4; i++) {
      const next = await rotateJwks(previous, options);
      expect(() => assertIsRotationOf(previous, next)).not.toThrow();
      previous = next;
    }
  });

  test.each([
    [
      'initial keys that are not 2 keys',
      async () => [{ keys: [] }, await rotateJwks(await rotateJwks({ keys: [] }, es256), es256)],
    ],
    [
      'dropping the signing key',
      async (initial: Jwks) => {
        const next = await rotateJwks(initial, es256);
        return [initial, { keys: [next.keys[0], next.keys[2], next.keys[2]] }];
      },
    ],
    [
      'a changed kept key',
      async (initial: Jwks) => {
        const next = await rotateJwks(initial, es256);
        return [initial, { keys: [next.keys[0], { ...next.keys[1], d: next.keys[2].d }, next.keys[2]] }];
      },
    ],
    [
      'keeping the private part of the retired sig key',
      async (initial: Jwks) => {
        const next = await rotateJwks(initial, es256);
        return [initial, { keys: [initial.keys[0], next.keys[1], next.keys[2]] }];
      },
    ],
    ['no new key', async (initial: Jwks) => [initial, { keys: initial.keys }]],
    [
      'a reused key as the new key',
      async (initial: Jwks) => {
        const next = await rotateJwks(initial, es256);
        return [next, { keys: [toPublicJwk(next.keys[1]), next.keys[2], next.keys[1]] }];
      },
    ],
  ] as const)('rejects %s', async (_name, arrange) => {
    const initial = await rotateJwks({ keys: [] }, es256);
    const [previous, next] = await arrange(initial);
    expect(() => assertIsRotationOf(previous, next)).toThrow(/not a rotation of the current JWKS/);
  });
});

describe('assertJwks', () => {
  let jwks: Jwks;
  beforeAll(async () => {
    jwks = await rotateJwks(await rotateJwks({ keys: [] }, es256), es256);
  });

  test.each([
    ['a non-object', () => 'x', /must be an object/],
    ['a missing keys array', () => ({}), /must have a keys array/],
    ['too many keys', () => ({ keys: [...jwks.keys, jwks.keys[1]] }), /0 or 2 to 3 keys/],
    ['duplicate kids', () => ({ keys: [jwks.keys[0], jwks.keys[1], jwks.keys[1]] }), /unique/],
    [
      'a wrong kid',
      () => ({ keys: [jwks.keys[0], { ...jwks.keys[1], kid: 'x' }, jwks.keys[2]] }),
      /thumbprint/,
    ],
    [
      'a private key at index 0',
      () => ({ keys: [jwks.keys[1], jwks.keys[2], jwks.keys[0]] }),
      /keys\[0\]: expected a public-only key/,
    ],
    ['a mismatched alg', () => ({ keys: jwks.keys.map((k) => ({ ...k, alg: 'ES384' })) }), /crv/],
    [
      'an unsupported alg',
      () => ({ keys: jwks.keys.map((k) => ({ ...k, alg: 'none' })) }),
      /unsupported alg/,
    ],
    ['a key that is not an object', () => ({ keys: [1, 2] }), /keys\[0\]: must be an object/],
    ['a missing kid', () => ({ keys: jwks.keys.map((k) => ({ ...k, kid: '' })) }), /kid must be/],
    ['an unknown use', () => ({ keys: jwks.keys.map((k) => ({ ...k, use: 'x' })) }), /use must be/],
    [
      'a use that does not match the alg',
      () => ({ keys: jwks.keys.map((k) => ({ ...k, use: 'enc' })) }),
      /use "enc" does not match/,
    ],
    ['an unknown kty', () => ({ keys: jwks.keys.map((k) => ({ ...k, kty: 'OKP' })) }), /kty must be/],
    [
      'a kty that does not match the alg',
      () => ({ keys: jwks.keys.map((k) => ({ ...k, kty: 'RSA' })) }),
      /kty "RSA" does not match/,
    ],
    [
      'an unsupported crv',
      () => ({ keys: jwks.keys.map((k) => ({ ...k, crv: 'X25519' })) }),
      /unsupported crv/,
    ],
    [
      'a missing EC coordinate',
      () => ({ keys: jwks.keys.map((k) => ({ ...k, y: undefined })) }),
      /must have x and y/,
    ],
    ['an empty d', () => ({ keys: jwks.keys.map((k) => ({ ...k, d: '' })) }), /d must be/],
  ])('rejects %s', (_name, value, message) => {
    expect(() => assertJwks(value())).toThrow(message);
  });

  test('rejects a public-only key in a 2 key JWKS', () => {
    expect(() => assertJwks({ keys: jwks.keys.slice(0, 2) })).toThrow(/expected a private key/);
  });

  test('rejects a public-only RSA key that keeps its other private members', async () => {
    const rs256 = resolveJwkOptions({ algorithm: 'RS256' });
    const before = await rotateJwks({ keys: [] }, rs256);
    const after = await rotateJwks(before, rs256);
    // The retired key without d, but still with the primes that reveal the private key.
    const retired = { ...after.keys[0], p: before.keys[0].p, q: before.keys[0].q };
    expect(() => assertJwks({ keys: [retired, after.keys[1], after.keys[2]] })).toThrow(
      /keys\[0\]: public-only key must not have private members p, q/,
    );
  });

  test('rejects an RSA key under 2048 bits', () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const exported = privateKey.export({ format: 'jwk' });
    const jwk = { ...exported, kid: computeThumbprint(exported as never), use: 'sig', alg: 'RS256' };
    expect(() => assertJwks({ keys: [jwk, jwk] })).toThrow(/RSA modulus is 1024 bits, less than 2048/);
  });

  test('rejects an RSA key without a modulus', async () => {
    const rsa = await generateJwk(resolveJwkOptions({ algorithm: 'RS256' }));
    expect(() => assertJwks({ keys: [{ ...rsa, n: undefined }, rsa] })).toThrow(/must have n and e/);
  });

  test('rejects mixed uses', async () => {
    const enc = await generateJwk(ecdhEs);
    expect(() => assertJwks({ keys: [jwks.keys[1], enc] })).toThrow(/same use/);
  });
});
