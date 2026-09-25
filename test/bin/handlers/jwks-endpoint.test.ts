import { resolveJwkOptions, rotateJwks, type Jwks, type ResolvedJwkOptions } from 'cdk-jwks-secret/jwks';

type Endpoint = typeof import('../../../bin/handlers/jwks-endpoint');
type SecretsManager = typeof import('@aws-sdk/client-secrets-manager');

const SIG_ARN = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:sig-AbCdEf';
const ENC_ARN = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:enc-AbCdEf';

const request = (method: string) => ({ requestContext: { http: { method } } });

let send: jest.SpyInstance;

/** A JWKS after `rotations` rotations, the first of which initialises it. */
async function jwksAfter(options: ResolvedJwkOptions, rotations: number): Promise<Jwks> {
  let jwks: Jwks = { keys: [] };
  for (let i = 0; i < rotations; i++) {
    jwks = await rotateJwks(jwks, options);
  }
  return jwks;
}

function secretsHold(secrets: Record<string, Jwks>) {
  send.mockImplementation(async (command: { input: { SecretId: string } }) => ({
    SecretString: JSON.stringify(secrets[command.input.SecretId]),
  }));
}

/** Loads a fresh handler (resetting its cache and config) and spies on the SDK copy it uses. */
function loadHandler(cacheSeconds: string | undefined, secretArns: string[] | null = [SIG_ARN, ENC_ARN]) {
  setEnv('JWKS_SECRET_ARNS', secretArns === null ? undefined : JSON.stringify(secretArns));
  setEnv('JWKS_CACHE_SECONDS', cacheSeconds);
  let handler!: Endpoint['handler'];
  jest.isolateModules(() => {
    const { SecretsManagerClient } = require('@aws-sdk/client-secrets-manager') as SecretsManager;
    send = jest.spyOn(SecretsManagerClient.prototype, 'send') as jest.SpyInstance;
    send.mockRejectedValue(new Error('unexpected call'));
    ({ handler } = require('../../../bin/handlers/jwks-endpoint') as Endpoint);
  });
  return handler;
}

function setEnv(name: string, value: string | undefined) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

const sig = resolveJwkOptions({ use: 'sig' });
const enc = resolveJwkOptions({ use: 'enc' });

afterEach(() => {
  jest.restoreAllMocks();
});

test('serves the public sig and enc keys in one JWKS', async () => {
  const handler = loadHandler('0');
  const sigJwks = await jwksAfter(sig, 2);
  const encJwks = await jwksAfter(enc, 2);
  secretsHold({ [SIG_ARN]: sigJwks, [ENC_ARN]: encJwks });

  const response = await handler(request('GET'));
  expect(response.statusCode).toBe(200);
  expect(response.headers!['Content-Type']).toBe('application/json');
  const { keys } = JSON.parse(response.body!);
  // All 3 sig keys, and the enc keys except the oldest of 3.
  expect(keys.map((jwk: { kid: string }) => jwk.kid)).toEqual([
    ...sigJwks.keys.map((jwk) => jwk.kid),
    ...encJwks.keys.slice(1).map((jwk) => jwk.kid),
  ]);
  expect(keys.every((jwk: { d?: string }) => jwk.d === undefined)).toBe(true);
});

test('with a cache TTL of 0, reads the secrets on every request', async () => {
  const handler = loadHandler('0');
  secretsHold({ [SIG_ARN]: await jwksAfter(sig, 1), [ENC_ARN]: await jwksAfter(enc, 1) });
  const response = await handler(request('GET'));
  expect(response.headers!['Cache-Control']).toBe('no-cache');
  await handler(request('GET'));
  expect(send).toHaveBeenCalledTimes(4);
});

test('with a cache TTL, caches the secrets and sets max-age', async () => {
  const handler = loadHandler('300');
  secretsHold({ [SIG_ARN]: await jwksAfter(sig, 1), [ENC_ARN]: await jwksAfter(enc, 1) });
  const response = await handler(request('GET'));
  expect(response.headers!['Cache-Control']).toBe('public, max-age=300');
  await handler(request('GET'));
  expect(send).toHaveBeenCalledTimes(2);
});

test('does not cache a secret before it is initialised', async () => {
  const handler = loadHandler('300');
  secretsHold({ [SIG_ARN]: await jwksAfter(sig, 1), [ENC_ARN]: { keys: [] } });
  const response = await handler(request('GET'));
  expect(JSON.parse(response.body!).keys).toHaveLength(2);
  expect(response.headers!['Cache-Control']).toBe('no-cache');
  await handler(request('GET'));
  // The sig secret is cached; the uninitialised enc secret is read again.
  expect(send).toHaveBeenCalledTimes(3);
});

test('serves an empty JWKS without caching when not configured', async () => {
  const handler = loadHandler(undefined, null);
  const response = await handler(request('GET'));
  expect(JSON.parse(response.body!)).toEqual({ keys: [] });
  expect(response.headers!['Cache-Control']).toBe('public, max-age=0');
  expect(send).not.toHaveBeenCalled();
});

test('rejects methods other than GET and HEAD', async () => {
  const handler = loadHandler('0');
  expect(await handler(request('POST'))).toEqual({ statusCode: 405, headers: { Allow: 'GET, HEAD' } });
  expect(send).not.toHaveBeenCalled();
});
