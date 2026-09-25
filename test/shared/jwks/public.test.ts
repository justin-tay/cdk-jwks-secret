import {
  parseJwks,
  resolveJwkOptions,
  rotateJwks,
  selectDecryptionKey,
  selectSigningKey,
  toPublicJwks,
  type Jwks,
} from '../../../src/shared/jwks';

const es256 = resolveJwkOptions({ algorithm: 'ES256' });
const ecdhEs = resolveJwkOptions({ algorithm: 'ECDH-ES' });

async function states(options = es256): Promise<Jwks[]> {
  const initial = await rotateJwks({ keys: [] }, options);
  const first = await rotateJwks(initial, options);
  const second = await rotateJwks(first, options);
  return [initial, first, second];
}

const kids = (jwks: Jwks) => jwks.keys.map((jwk) => jwk.kid);

describe('sig', () => {
  test('publishes every key without private members', async () => {
    for (const jwks of await states()) {
      const published = toPublicJwks(jwks);
      expect(kids(published)).toEqual(kids(jwks));
      expect(published.keys.every((jwk) => jwk.d === undefined)).toBe(true);
    }
  });

  test('signs with the first key while there are 2 keys, then the second', async () => {
    const [initial, first, second] = await states();
    expect(selectSigningKey(initial)).toBe(initial.keys[0]);
    expect(selectSigningKey(first)).toBe(first.keys[1]);
    expect(selectSigningKey(second)).toBe(second.keys[1]);
  });

  test('the signing key was published one rotation before it is used', async () => {
    const [initial, first, second] = await states();
    expect(kids(toPublicJwks(initial))).toContain(selectSigningKey(first).kid);
    expect(kids(toPublicJwks(first))).toContain(selectSigningKey(second).kid);
  });

  test('refuses an uninitialised JWKS or enc keys', async () => {
    expect(() => selectSigningKey({ keys: [] })).toThrow(/not been initialised/);
    const [initial] = await states(ecdhEs);
    expect(() => selectSigningKey(initial)).toThrow(/"enc" keys/);
    expect(() => selectDecryptionKey(initial, 'x')).not.toThrow();
  });
});

describe('enc', () => {
  test('publishes all keys while there are 2, then all but the oldest', async () => {
    const [initial, first, second] = await states(ecdhEs);
    expect(kids(toPublicJwks(initial))).toEqual(kids(initial));
    expect(kids(toPublicJwks(first))).toEqual(kids(first).slice(1));
    expect(kids(toPublicJwks(second))).toEqual(kids(second).slice(1));
    expect(toPublicJwks(second).keys.every((jwk) => jwk.d === undefined)).toBe(true);
  });

  test('an unpublished key can still decrypt for one rotation before it is dropped', async () => {
    const [initial, first, second] = await states(ecdhEs);
    const unpublished = first.keys[0];
    expect(kids(toPublicJwks(initial))).toContain(unpublished.kid);
    expect(kids(toPublicJwks(first))).not.toContain(unpublished.kid);
    expect(selectDecryptionKey(first, unpublished.kid)).toBe(unpublished);
    expect(selectDecryptionKey(second, unpublished.kid)).toBeUndefined();
  });

  test('every published key has a private key until it is dropped', async () => {
    const [initial, first] = await states(ecdhEs);
    for (const kid of kids(toPublicJwks(initial))) {
      expect(selectDecryptionKey(first, kid)).toBeDefined();
    }
  });

  test('refuses sig keys', async () => {
    const [initial] = await states();
    expect(() => selectDecryptionKey(initial, initial.keys[0].kid)).toThrow(/"sig" keys/);
  });
});

test('toPublicJwks of an uninitialised JWKS is empty', () => {
  expect(toPublicJwks(parseJwks('{"keys":[]}'))).toEqual({ keys: [] });
});

test('parseJwks rejects invalid JSON', () => {
  expect(() => parseJwks('{')).toThrow(/not valid JSON/);
});
