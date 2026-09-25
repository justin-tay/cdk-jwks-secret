import { isDeepStrictEqual } from 'node:util';
import { generateJwk } from './generate';
import { toPublicJwk, type Jwk, type Jwks } from './jwk';
import type { ResolvedJwkOptions } from './options';
import {
  assertJwks,
  assertJwksMatchesOptions,
  INITIAL_KEY_COUNT,
  JwksValidationError,
  MAX_KEY_COUNT,
} from './validate';

/**
 * Computes the next JWKS.
 *
 * - An empty JWKS is initialised with 2 new private keys.
 * - Otherwise a new private key is appended and the oldest key dropped once
 *   there would be more than 3. For `sig` keys, the key at index 0 then has
 *   its private members removed; `enc` keys all stay private.
 *
 * The current JWKS is validated, so it may be passed unchecked, e.g. straight
 * from `parseSecretJson`.
 *
 * @throws JwksValidationError if the current JWKS is malformed
 * @throws JwkOptionsMismatchError if the current keys do not match the options
 */
export async function rotateJwks(
  current: unknown,
  options: ResolvedJwkOptions,
  generate: (options: ResolvedJwkOptions) => Promise<Jwk> = generateJwk,
): Promise<Jwks> {
  assertJwks(current);
  if (current.keys.length === 0) {
    const keys = await Promise.all(Array.from({ length: INITIAL_KEY_COUNT }, () => generate(options)));
    return { keys };
  }
  assertJwksMatchesOptions(current, options);

  const keys = [...current.keys, await generate(options)].slice(-MAX_KEY_COUNT);
  if (options.use === 'sig') {
    keys[0] = toPublicJwk(keys[0]);
  }
  return { keys };
}

function fail(reason: string): never {
  throw new JwksValidationError(`not a rotation of the current JWKS: ${reason}`);
}

/**
 * Asserts that `next` is a valid rotation of `previous`, as `rotateJwks` would
 * compute it: the kept keys unchanged and in order (the oldest made
 * public-only for `sig` keys), plus exactly one new key. An empty `previous`
 * must be followed by the initial keys.
 *
 * Both JWKS must already be valid, e.g. from `parseJwks`.
 *
 * @throws JwksValidationError describing the first difference
 */
export function assertIsRotationOf(previous: Jwks, next: Jwks): void {
  const previousKids = new Set(previous.keys.map((jwk) => jwk.kid));
  if (previous.keys.length === 0) {
    if (next.keys.length !== INITIAL_KEY_COUNT) {
      fail(`expected ${INITIAL_KEY_COUNT} initial keys, got ${next.keys.length}`);
    }
    return;
  }
  const kept = previous.keys.slice(-(MAX_KEY_COUNT - 1));
  if (next.keys.length !== kept.length + 1) {
    fail(`expected ${kept.length + 1} keys, got ${next.keys.length}`);
  }
  kept.forEach((jwk, index) => {
    // The oldest kept key loses its private part when sig keys rotate.
    const expected = index === 0 && jwk.use === 'sig' ? toPublicJwk(jwk) : jwk;
    if (!isDeepStrictEqual(next.keys[index], expected)) {
      fail(`keys[${index}] should be key ${jwk.kid}${expected === jwk ? '' : ' without its private part'}`);
    }
  });
  const added = next.keys[next.keys.length - 1];
  if (previousKids.has(added.kid)) {
    fail(`the last key ${added.kid} is not new`);
  }
}
