export type JwkPublicKeyUse = 'sig' | 'enc';

export type JwkKeyType = 'RSA' | 'EC';

export type JwkEcCurve = 'P-256' | 'P-384' | 'P-521';

export type JwkAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'RSA-OAEP-256'
  | 'ECDH-ES'
  | 'ECDH-ES+A128KW'
  | 'ECDH-ES+A192KW'
  | 'ECDH-ES+A256KW';

interface AlgorithmSpec {
  readonly use: JwkPublicKeyUse;
  readonly keyType: JwkKeyType;
  /** Curve implied by the algorithm (the default when the curve is configurable). */
  readonly curve?: JwkEcCurve;
  /** Whether the curve may be chosen, i.e. the algorithm does not pin it. */
  readonly curveConfigurable?: boolean;
}

const ALGORITHMS: Readonly<Record<JwkAlgorithm, AlgorithmSpec>> = {
  RS256: { use: 'sig', keyType: 'RSA' },
  RS384: { use: 'sig', keyType: 'RSA' },
  RS512: { use: 'sig', keyType: 'RSA' },
  PS256: { use: 'sig', keyType: 'RSA' },
  PS384: { use: 'sig', keyType: 'RSA' },
  PS512: { use: 'sig', keyType: 'RSA' },
  ES256: { use: 'sig', keyType: 'EC', curve: 'P-256' },
  ES384: { use: 'sig', keyType: 'EC', curve: 'P-384' },
  ES512: { use: 'sig', keyType: 'EC', curve: 'P-521' },
  'RSA-OAEP-256': { use: 'enc', keyType: 'RSA' },
  'ECDH-ES': { use: 'enc', keyType: 'EC', curve: 'P-256', curveConfigurable: true },
  'ECDH-ES+A128KW': { use: 'enc', keyType: 'EC', curve: 'P-256', curveConfigurable: true },
  'ECDH-ES+A192KW': { use: 'enc', keyType: 'EC', curve: 'P-256', curveConfigurable: true },
  'ECDH-ES+A256KW': { use: 'enc', keyType: 'EC', curve: 'P-256', curveConfigurable: true },
};

export const SUPPORTED_ALGORITHMS = Object.keys(ALGORITHMS) as readonly JwkAlgorithm[];

export const SUPPORTED_EC_CURVES: readonly JwkEcCurve[] = ['P-256', 'P-384', 'P-521'];

export const DEFAULT_USE: JwkPublicKeyUse = 'sig';

/** The algorithm used for each `use` when no algorithm is given. */
export const DEFAULT_ALGORITHMS: Readonly<Record<JwkPublicKeyUse, JwkAlgorithm>> = {
  sig: 'ES256',
  enc: 'ECDH-ES+A128KW',
};

export const DEFAULT_RSA_MODULUS_LENGTH = 2048;

export const MIN_RSA_MODULUS_LENGTH = 2048;

/** Upper bound keeps key generation well within the rotation Lambda's timeout. */
export const MAX_RSA_MODULUS_LENGTH = 4096;

/** Environment variable through which the construct passes the resolved options to the rotation Lambda. */
export const JWK_OPTIONS_ENV = 'JWK_OPTIONS';

/**
 * Options for the keys in a JWKS secret. The algorithm determines the key
 * type, the public key use and, for most EC algorithms, the curve.
 */
export interface JwkOptions {
  /**
   * The public key use of every key. Selects the default algorithm; if
   * `algorithm` is given as well, it must have this use.
   *
   * @default the use of `algorithm`, or 'sig'
   */
  readonly use?: JwkPublicKeyUse;

  /**
   * The JWA algorithm of every key.
   *
   * @default 'ES256' for 'sig' keys, 'ECDH-ES+A128KW' for 'enc' keys
   */
  readonly algorithm?: JwkAlgorithm;

  /**
   * The curve of an EC key. Only needed for algorithms that do not pin the
   * curve (`ECDH-ES` and `ECDH-ES+A*KW`). For `ES256`/`ES384`/`ES512` it may
   * be given but must match the algorithm.
   *
   * @default the curve implied by the algorithm, or 'P-256' for 'ECDH-ES' and 'ECDH-ES+A*KW'
   */
  readonly curve?: JwkEcCurve;

  /**
   * The modulus length in bits of an RSA key. Only valid for RSA algorithms.
   *
   * @default 2048
   */
  readonly rsaModulusLength?: number;
}

/** Fully resolved and validated key options. */
export interface ResolvedJwkOptions {
  readonly algorithm: JwkAlgorithm;
  readonly use: JwkPublicKeyUse;
  readonly keyType: JwkKeyType;
  /** Present for EC keys only. */
  readonly curve?: JwkEcCurve;
  /** Present for RSA keys only. */
  readonly rsaModulusLength?: number;
}

export function isSupportedAlgorithm(value: unknown): value is JwkAlgorithm {
  return typeof value === 'string' && Object.hasOwn(ALGORITHMS, value);
}

export function isSupportedCurve(value: unknown): value is JwkEcCurve {
  return SUPPORTED_EC_CURVES.includes(value as JwkEcCurve);
}

/** The public key use and key type implied by an algorithm. */
export function algorithmSpec(algorithm: JwkAlgorithm): {
  readonly use: JwkPublicKeyUse;
  readonly keyType: JwkKeyType;
  readonly curve?: JwkEcCurve;
  readonly curveConfigurable: boolean;
} {
  const spec = ALGORITHMS[algorithm];
  return { ...spec, curveConfigurable: spec.curveConfigurable ?? false };
}

/**
 * Validates the options and derives everything the algorithm implies.
 *
 * @throws Error if the algorithm is unsupported or the options contradict it
 */
export function resolveJwkOptions(options: JwkOptions = {}): ResolvedJwkOptions {
  if (options.use !== undefined && options.use !== 'sig' && options.use !== 'enc') {
    throw new Error(`use must be "sig" or "enc", got "${String(options.use)}"`);
  }
  const algorithm = options.algorithm ?? DEFAULT_ALGORITHMS[options.use ?? DEFAULT_USE];
  if (!isSupportedAlgorithm(algorithm)) {
    throw new Error(
      `Unsupported algorithm "${String(algorithm)}". Supported algorithms: ${SUPPORTED_ALGORITHMS.join(', ')}`,
    );
  }
  const spec = algorithmSpec(algorithm);
  if (options.use !== undefined && options.use !== spec.use) {
    throw new Error(`${algorithm} is a "${spec.use}" algorithm, but use is "${options.use}"`);
  }

  if (spec.keyType === 'RSA') {
    if (options.curve !== undefined) {
      throw new Error(`curve is not applicable to the RSA algorithm ${algorithm}`);
    }
    const rsaModulusLength = options.rsaModulusLength ?? DEFAULT_RSA_MODULUS_LENGTH;
    if (
      !Number.isInteger(rsaModulusLength) ||
      rsaModulusLength < MIN_RSA_MODULUS_LENGTH ||
      rsaModulusLength > MAX_RSA_MODULUS_LENGTH ||
      rsaModulusLength % 8 !== 0
    ) {
      throw new Error(
        `rsaModulusLength must be a multiple of 8 between ${MIN_RSA_MODULUS_LENGTH} and ${MAX_RSA_MODULUS_LENGTH}, got ${rsaModulusLength}`,
      );
    }
    return { algorithm, use: spec.use, keyType: 'RSA', rsaModulusLength };
  }

  if (options.rsaModulusLength !== undefined) {
    throw new Error(`rsaModulusLength is not applicable to the EC algorithm ${algorithm}`);
  }
  let curve = spec.curve;
  if (options.curve !== undefined) {
    if (!isSupportedCurve(options.curve)) {
      throw new Error(
        `Unsupported curve "${String(options.curve)}". Supported curves: ${SUPPORTED_EC_CURVES.join(', ')}`,
      );
    }
    if (!spec.curveConfigurable && options.curve !== spec.curve) {
      throw new Error(`${algorithm} requires curve ${spec.curve}, got ${options.curve}`);
    }
    curve = options.curve;
  }
  return { algorithm, use: spec.use, keyType: 'EC', curve };
}

/**
 * Parses the options the construct serialised into the rotation Lambda's
 * environment, re-validating them.
 */
export function parseJwkOptions(json: string | undefined): ResolvedJwkOptions {
  if (json === undefined || json === '') {
    throw new Error(`${JWK_OPTIONS_ENV} is not set`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new Error(`${JWK_OPTIONS_ENV} is not valid JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${JWK_OPTIONS_ENV} must be a JSON object`);
  }
  const { use, algorithm, curve, rsaModulusLength } = parsed as Record<string, unknown>;
  return resolveJwkOptions({
    use: use as JwkPublicKeyUse | undefined,
    algorithm: algorithm as JwkAlgorithm | undefined,
    curve: curve as JwkEcCurve | undefined,
    rsaModulusLength: rsaModulusLength as number | undefined,
  });
}
