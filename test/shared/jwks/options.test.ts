import { parseJwkOptions, resolveJwkOptions } from '../../../src/shared/jwks';

describe('resolveJwkOptions', () => {
  test('defaults to ES256 on P-256', () => {
    expect(resolveJwkOptions()).toEqual({ algorithm: 'ES256', use: 'sig', keyType: 'EC', curve: 'P-256' });
  });

  test('defaults sig keys to ES256 and enc keys to ECDH-ES+A128KW on P-256', () => {
    expect(resolveJwkOptions({ use: 'sig' })).toEqual(resolveJwkOptions());
    expect(resolveJwkOptions({ use: 'enc' })).toEqual({
      algorithm: 'ECDH-ES+A128KW',
      use: 'enc',
      keyType: 'EC',
      curve: 'P-256',
    });
  });

  test('defaults RSA keys to a 2048 bit modulus', () => {
    expect(resolveJwkOptions({ algorithm: 'RS256' }).rsaModulusLength).toBe(2048);
  });

  test('accepts a use that matches the algorithm', () => {
    expect(resolveJwkOptions({ use: 'enc', algorithm: 'RSA-OAEP-256' }).algorithm).toBe('RSA-OAEP-256');
  });

  test.each([
    ['PS384', { use: 'sig', keyType: 'RSA', rsaModulusLength: 2048 }],
    ['ES256', { use: 'sig', keyType: 'EC', curve: 'P-256' }],
    ['ES384', { use: 'sig', keyType: 'EC', curve: 'P-384' }],
    ['ES512', { use: 'sig', keyType: 'EC', curve: 'P-521' }],
    ['RSA-OAEP-256', { use: 'enc', keyType: 'RSA', rsaModulusLength: 2048 }],
    ['ECDH-ES', { use: 'enc', keyType: 'EC', curve: 'P-256' }],
    ['ECDH-ES+A128KW', { use: 'enc', keyType: 'EC', curve: 'P-256' }],
    ['ECDH-ES+A192KW', { use: 'enc', keyType: 'EC', curve: 'P-256' }],
    ['ECDH-ES+A256KW', { use: 'enc', keyType: 'EC', curve: 'P-256' }],
  ] as const)('derives the rest from %s', (algorithm, expected) => {
    expect(resolveJwkOptions({ algorithm })).toEqual({ algorithm, ...expected });
  });

  test('allows choosing the curve for ECDH-ES', () => {
    expect(resolveJwkOptions({ algorithm: 'ECDH-ES', curve: 'P-384' }).curve).toBe('P-384');
  });

  test('allows a curve that matches an ES algorithm', () => {
    expect(resolveJwkOptions({ algorithm: 'ES384', curve: 'P-384' }).curve).toBe('P-384');
  });

  test.each([
    [{ algorithm: 'HS256' }, /Unsupported algorithm "HS256"/],
    [{ algorithm: 'ES256', curve: 'P-384' }, /ES256 requires curve P-256/],
    [{ algorithm: 'RS256', curve: 'P-256' }, /curve is not applicable/],
    [{ algorithm: 'ES256', rsaModulusLength: 2048 }, /rsaModulusLength is not applicable/],
    [{ algorithm: 'ECDH-ES', curve: 'X25519' }, /Unsupported curve/],
    [{ algorithm: 'RS256', rsaModulusLength: 1024 }, /rsaModulusLength must be/],
    [{ algorithm: 'RS256', rsaModulusLength: 8192 }, /rsaModulusLength must be/],
    [{ algorithm: 'RS256', rsaModulusLength: 2049 }, /rsaModulusLength must be/],
    [{ rsaModulusLength: 2048 }, /rsaModulusLength is not applicable/],
    [{ use: 'enc', algorithm: 'ES256' }, /ES256 is a "sig" algorithm, but use is "enc"/],
    [{ use: 'sig', algorithm: 'ECDH-ES+A128KW' }, /is a "enc" algorithm, but use is "sig"/],
    [{ use: 'both' }, /use must be "sig" or "enc"/],
  ])('rejects %j', (options, error) => {
    expect(() => resolveJwkOptions(options as never)).toThrow(error);
  });
});

describe('parseJwkOptions', () => {
  test('round-trips resolved options', () => {
    const options = resolveJwkOptions({ algorithm: 'PS256', rsaModulusLength: 3072 });
    expect(parseJwkOptions(JSON.stringify(options))).toEqual(options);
  });

  test.each([
    [undefined, /JWK_OPTIONS is not set/],
    ['', /JWK_OPTIONS is not set/],
    ['nope', /JWK_OPTIONS is not valid JSON/],
    ['[]', /JWK_OPTIONS must be a JSON object/],
    ['{"algorithm":"none"}', /Unsupported algorithm "none"/],
  ])('rejects %j', (value, error) => {
    expect(() => parseJwkOptions(value)).toThrow(error);
  });
});
