import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { parseJwks, toPublicJwks, type Jwks } from 'cdk-jwks-secret/jwks';

/** ARNs of the JWKS secrets whose public keys are served together. */
const SECRET_ARNS: readonly string[] = JSON.parse(process.env.JWKS_SECRET_ARNS ?? '[]');

/** How long each secret is cached; also the Cache-Control max-age. 0 disables caching. */
const CACHE_TTL_SECONDS = Number(process.env.JWKS_CACHE_SECONDS ?? '0');

interface FunctionUrlEvent {
  readonly requestContext: { readonly http: { readonly method: string } };
}

interface FunctionUrlResult {
  readonly statusCode: number;
  readonly headers?: Record<string, string>;
  readonly body?: string;
}

const client = new SecretsManagerClient({});

const cache = new Map<string, { readonly jwks: Jwks; readonly expiresAt: number }>();

/** Whether a JWKS may be cached; not the empty JWKS served before the first rotation completes. */
function isCacheable(jwks: Jwks): boolean {
  return CACHE_TTL_SECONDS > 0 && jwks.keys.length > 0;
}

async function getJwks(secretArn: string): Promise<Jwks> {
  const cached = cache.get(secretArn);
  if (cached && Date.now() < cached.expiresAt) {
    return cached.jwks;
  }
  const { SecretString } = await client.send(new GetSecretValueCommand({ SecretId: secretArn }));
  const jwks = parseJwks(SecretString ?? '');
  if (isCacheable(jwks)) {
    cache.set(secretArn, { jwks, expiresAt: Date.now() + CACHE_TTL_SECONDS * 1000 });
  } else {
    cache.delete(secretArn);
  }
  return jwks;
}

export async function handler(event: FunctionUrlEvent): Promise<FunctionUrlResult> {
  const method = event.requestContext.http.method;
  if (method !== 'GET' && method !== 'HEAD') {
    return { statusCode: 405, headers: { Allow: 'GET, HEAD' } };
  }
  const jwksList = await Promise.all(SECRET_ARNS.map(getJwks));
  // toPublicJwks applies the publishing rule for each secret's use (sig or enc).
  const keys = jwksList.flatMap((jwks) => toPublicJwks(jwks).keys);
  return {
    statusCode: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': jwksList.every(isCacheable) ? `public, max-age=${CACHE_TTL_SECONDS}` : 'no-cache',
    },
    body: JSON.stringify({ keys }),
  };
}
