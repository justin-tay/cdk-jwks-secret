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
import {
  errorFields,
  kidChanges,
  kidsOf,
  logEvent,
  rotationFields,
  type EventAction,
  type LogFields,
} from '../logger';
import { RotationStateError } from '../rotation-error';

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

/** The `event.action` each step logs under. Only kids are ever logged, never key material. */
const STEP_ACTIONS: Readonly<Record<string, EventAction | undefined>> = {
  createSecret: 'create_secret',
  setSecret: 'rotate_secret',
  testSecret: 'test_secret',
  finishSecret: 'finish_secret',
};

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

  async function createSecret(secretId: string, token: string, base: LogFields): Promise<void> {
    try {
      await client.send(
        new GetSecretValueCommand({ SecretId: secretId, VersionId: token, VersionStage: AWSPENDING }),
      );
      logEvent('rotate_secret', 'success', 'createSecret: pending version already exists', {
        ...base,
        'event.reason': 'pending_exists',
      });
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
    logEvent('create_secret', 'success', 'createSecret: created pending version', {
      ...base,
      ...kidChanges(current as Jwks, next),
    });
  }

  async function testSecret(secretId: string, token: string, base: LogFields): Promise<void> {
    const pending = parseJwks(await getSecretString(secretId, AWSPENDING, token));
    const current = parseJwks(await getSecretString(secretId, AWSCURRENT));
    assertJwksMatchesOptions(pending, options);
    assertIsRotationOf(current, pending);
    logEvent('test_secret', 'success', 'testSecret: pending version is valid', {
      ...base,
      'jwks.kids.current': kidsOf(pending),
    });
  }

  async function finishSecret(
    secretId: string,
    token: string,
    versions: Record<string, string[]>,
    base: LogFields,
  ): Promise<void> {
    const currentVersion = Object.keys(versions).find((id) => versions[id].includes(AWSCURRENT));
    // Read before promoting, so a failure here leaves the rotation to be retried.
    const pending = parseJwks(await getSecretString(secretId, AWSPENDING, token));
    const current = parseJwks(await getSecretString(secretId, AWSCURRENT));
    await client.send(
      new UpdateSecretVersionStageCommand({
        SecretId: secretId,
        VersionStage: AWSCURRENT,
        MoveToVersionId: token,
        RemoveFromVersionId: currentVersion,
      }),
    );
    logEvent('finish_secret', 'success', 'finishSecret: promoted pending version', {
      ...base,
      ...kidChanges(current, pending),
      'aws.secretsmanager.secret.previous_version.id': currentVersion,
    });
  }

  async function rotate(event: RotationEvent): Promise<void> {
    const { Step: step, SecretId: secretId, ClientRequestToken: token } = event;
    const base = rotationFields(step, secretId, token);

    const metadata = await client.send(new DescribeSecretCommand({ SecretId: secretId }));
    if (!metadata.RotationEnabled) {
      throw new RotationStateError('rotation_disabled', `Secret ${secretId} is not enabled for rotation`);
    }
    const versions = metadata.VersionIdsToStages ?? {};
    const stages = versions[token];
    if (!stages) {
      throw new RotationStateError(
        'version_not_found',
        `Secret version ${token} has no stage for rotation of secret ${secretId}`,
      );
    }
    if (stages.includes(AWSCURRENT)) {
      logEvent('rotate_secret', 'success', `${step}: secret version is already AWSCURRENT`, {
        ...base,
        'event.reason': 'already_current',
      });
      return;
    }
    if (!stages.includes(AWSPENDING)) {
      throw new RotationStateError(
        'version_not_pending',
        `Secret version ${token} is not AWSPENDING for rotation of secret ${secretId}`,
      );
    }

    switch (step) {
      case 'createSecret':
        return createSecret(secretId, token, base);
      case 'setSecret':
        // Nothing to push: the OpenID Connect server fetches the public keys from the JWKS endpoint.
        return;
      case 'testSecret':
        return testSecret(secretId, token, base);
      case 'finishSecret':
        return finishSecret(secretId, token, versions, base);
      default:
        throw new RotationStateError('unknown_step', `Unknown rotation step ${String(step)}`);
    }
  }

  return async (event) => {
    try {
      await rotate(event);
    } catch (error) {
      const base = rotationFields(event.Step, event.SecretId, event.ClientRequestToken);
      if (error instanceof RotationStateError) {
        logEvent('validate_rotation', 'failure', error.message, {
          ...base,
          ...errorFields(error),
          'event.reason': error.reason,
        });
      } else {
        logEvent(STEP_ACTIONS[event.Step] ?? 'rotate_secret', 'failure', `${event.Step}: failed`, {
          ...base,
          ...errorFields(error),
        });
      }
      throw error;
    }
  };
}

let rotationHandler: ((event: RotationEvent) => Promise<void>) | undefined;

export function initialiseRotationHandler(
  client: Pick<SecretsManagerClient, 'send'> = new SecretsManagerClient({}),
): (event: RotationEvent) => Promise<void> {
  try {
    const options = parseJwkOptions(process.env[JWK_OPTIONS_ENV]);
    const created = createRotationHandler(client, options);
    logEvent('start_function', 'success', 'rotation function started', {
      'jwks.use': options.use,
      'jwks.alg': options.algorithm,
      'jwks.key_type': options.keyType,
      'jwks.curve': options.curve,
      'jwks.rsa_modulus_length': options.rsaModulusLength,
    });
    return created;
  } catch (error) {
    logEvent('start_function', 'failure', 'rotation function failed to start', errorFields(error));
    throw error;
  }
}

export async function handler(event: RotationEvent): Promise<void> {
  rotationHandler ??= initialiseRotationHandler();
  return rotationHandler(event);
}
