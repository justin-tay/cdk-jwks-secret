import {
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  ResourceNotFoundException,
  SecretsManagerClient,
  UpdateSecretVersionStageCommand,
} from '@aws-sdk/client-secrets-manager';
import {
  assertIsRotationOf,
  assertJwksMatchesOptions,
  JWK_OPTIONS_ENV,
  JwksValidationError,
  parseJwkOptions,
  parseJwks,
  parseSecretJson,
  rotateJwks,
  type Jwks,
  type ResolvedJwkOptions,
} from '../../../shared/jwks';

export type RotationStep = 'createSecret' | 'setSecret' | 'testSecret' | 'finishSecret';

/** The event Secrets Manager sends to a rotation Lambda. */
export interface RotationEvent {
  readonly Step: RotationStep;
  readonly SecretId: string;
  readonly ClientRequestToken: string;
  readonly RotationToken?: string;
}

const AWSCURRENT = 'AWSCURRENT';
const AWSPENDING = 'AWSPENDING';

function log(message: string, fields: Record<string, unknown>): void {
  // Only ever log kids, never key material.
  console.log(JSON.stringify({ message, ...fields }));
}

function kidsOf(jwks: Jwks): string[] {
  return jwks.keys.map((jwk) => jwk.kid);
}

export function createRotationHandler(
  client: Pick<SecretsManagerClient, 'send'>,
  options: ResolvedJwkOptions,
): (event: RotationEvent) => Promise<void> {
  async function getSecretString(secretId: string, stage: string, versionId?: string): Promise<string> {
    const value = await client.send(
      new GetSecretValueCommand({ SecretId: secretId, VersionStage: stage, VersionId: versionId }),
    );
    if (value.SecretString === undefined) {
      throw new JwksValidationError(`${stage} version of ${secretId} has no secret string`);
    }
    return value.SecretString;
  }

  async function createSecret(secretId: string, token: string): Promise<void> {
    try {
      await client.send(
        new GetSecretValueCommand({ SecretId: secretId, VersionId: token, VersionStage: AWSPENDING }),
      );
      log('createSecret: pending version already exists', { secretId, token });
      return;
    } catch (error) {
      if (!(error instanceof ResourceNotFoundException)) {
        throw error;
      }
    }
    // rotateJwks validates the current JWKS.
    const current = parseSecretJson(await getSecretString(secretId, AWSCURRENT));
    const next = await rotateJwks(current, options);
    await client.send(
      new PutSecretValueCommand({
        SecretId: secretId,
        ClientRequestToken: token,
        SecretString: JSON.stringify(next),
        VersionStages: [AWSPENDING],
      }),
    );
    log('createSecret: created pending version', {
      secretId,
      token,
      previousKids: kidsOf(current as Jwks),
      kids: kidsOf(next),
    });
  }

  async function testSecret(secretId: string, token: string): Promise<void> {
    const pending = parseJwks(await getSecretString(secretId, AWSPENDING, token));
    const current = parseJwks(await getSecretString(secretId, AWSCURRENT));
    assertJwksMatchesOptions(pending, options);
    assertIsRotationOf(current, pending);
    log('testSecret: pending version is valid', { secretId, token, kids: kidsOf(pending) });
  }

  async function finishSecret(
    secretId: string,
    token: string,
    versions: Record<string, string[]>,
  ): Promise<void> {
    const currentVersion = Object.keys(versions).find((id) => versions[id].includes(AWSCURRENT));
    await client.send(
      new UpdateSecretVersionStageCommand({
        SecretId: secretId,
        VersionStage: AWSCURRENT,
        MoveToVersionId: token,
        RemoveFromVersionId: currentVersion,
      }),
    );
    log('finishSecret: promoted pending version', { secretId, token, previousVersion: currentVersion });
  }

  return async (event) => {
    const { Step: step, SecretId: secretId, ClientRequestToken: token } = event;

    const metadata = await client.send(new DescribeSecretCommand({ SecretId: secretId }));
    if (!metadata.RotationEnabled) {
      throw new Error(`Secret ${secretId} is not enabled for rotation`);
    }
    const versions = metadata.VersionIdsToStages ?? {};
    const stages = versions[token];
    if (!stages) {
      throw new Error(`Secret version ${token} has no stage for rotation of secret ${secretId}`);
    }
    if (stages.includes(AWSCURRENT)) {
      log('Secret version is already AWSCURRENT', { step, secretId, token });
      return;
    }
    if (!stages.includes(AWSPENDING)) {
      throw new Error(`Secret version ${token} is not AWSPENDING for rotation of secret ${secretId}`);
    }

    switch (step) {
      case 'createSecret':
        return createSecret(secretId, token);
      case 'setSecret':
        // Nothing to push: the OpenID Connect server fetches the public keys from the JWKS endpoint.
        return;
      case 'testSecret':
        return testSecret(secretId, token);
      case 'finishSecret':
        return finishSecret(secretId, token, versions);
      default:
        throw new Error(`Unknown rotation step ${String(step)}`);
    }
  };
}

let rotationHandler: ((event: RotationEvent) => Promise<void>) | undefined;

export async function handler(event: RotationEvent): Promise<void> {
  rotationHandler ??= createRotationHandler(
    new SecretsManagerClient({}),
    parseJwkOptions(process.env[JWK_OPTIONS_ENV]),
  );
  return rotationHandler(event);
}
