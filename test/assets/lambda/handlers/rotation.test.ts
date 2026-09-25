import {
  DescribeSecretCommand,
  GetSecretValueCommand,
  PutSecretValueCommand,
  ResourceNotFoundException,
  UpdateSecretVersionStageCommand,
} from '@aws-sdk/client-secrets-manager';
import {
  createRotationHandler,
  handler,
  type RotationEvent,
  type RotationStep,
} from '../../../../src/assets/lambda/handlers/rotation';
import {
  isPrivateJwk,
  parseJwks,
  resolveJwkOptions,
  rotateJwks,
  type Jwks,
  type ResolvedJwkOptions,
} from '../../../../src/shared/jwks';

const SECRET_ID = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:jwks-AbCdEf';

/** Just enough of Secrets Manager's versioning behaviour to drive a rotation. */
class FakeSecretsManager {
  public rotationEnabled = true;
  public readonly versions = new Map<string, { value?: string; stages: string[] }>();
  private nextToken = 1;

  constructor(initialValue: string) {
    this.versions.set('v0', { value: initialValue, stages: ['AWSCURRENT'] });
  }

  public send = async (command: unknown): Promise<unknown> => {
    if (command instanceof DescribeSecretCommand) {
      return {
        RotationEnabled: this.rotationEnabled,
        VersionIdsToStages: Object.fromEntries(
          [...this.versions].map(([id, version]) => [id, [...version.stages]]),
        ),
      };
    }
    if (command instanceof GetSecretValueCommand) {
      const { VersionId, VersionStage } = command.input;
      const entry = VersionId
        ? this.versions.get(VersionId)
        : [...this.versions.values()].find((version) => version.stages.includes(VersionStage!));
      if (!entry || entry.value === undefined || (VersionStage && !entry.stages.includes(VersionStage))) {
        throw new ResourceNotFoundException({ message: 'not found', $metadata: {} });
      }
      return { SecretString: entry.value };
    }
    if (command instanceof PutSecretValueCommand) {
      const { ClientRequestToken, SecretString, VersionStages } = command.input;
      this.versions.set(ClientRequestToken!, { value: SecretString, stages: [...VersionStages!] });
      return {};
    }
    if (command instanceof UpdateSecretVersionStageCommand) {
      const { VersionStage, MoveToVersionId, RemoveFromVersionId } = command.input;
      const from = this.versions.get(RemoveFromVersionId!)!;
      from.stages = from.stages.filter((stage) => stage !== VersionStage);
      this.versions.get(MoveToVersionId!)!.stages.push(VersionStage!);
      return {};
    }
    throw new Error(`Unexpected command ${String(command)}`);
  };

  /** Starts a rotation the way Secrets Manager does: an AWSPENDING version with no value yet. */
  public startRotation(): string {
    const token = `v${this.nextToken++}`;
    this.versions.set(token, { stages: ['AWSPENDING'] });
    return token;
  }

  public endRotation(token: string): void {
    const version = this.versions.get(token)!;
    version.stages = version.stages.filter((stage) => stage !== 'AWSPENDING');
  }

  public current(): Jwks {
    const entry = [...this.versions.values()].find((version) => version.stages.includes('AWSCURRENT'))!;
    return parseJwks(entry.value!);
  }
}

const STEPS: RotationStep[] = ['createSecret', 'setSecret', 'testSecret', 'finishSecret'];

const event = (step: RotationStep, token: string): RotationEvent => ({
  Step: step,
  SecretId: SECRET_ID,
  ClientRequestToken: token,
});

function setup(options: ResolvedJwkOptions = resolveJwkOptions({ algorithm: 'ES256' })) {
  const secretsManager = new FakeSecretsManager('{"keys":[]}');
  const rotationHandler = createRotationHandler(secretsManager as never, options);
  const rotate = async () => {
    const token = secretsManager.startRotation();
    for (const step of STEPS) {
      await rotationHandler(event(step, token));
    }
    secretsManager.endRotation(token);
    return secretsManager.current();
  };
  return { secretsManager, rotationHandler, rotate };
}

beforeEach(() => {
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

test('the first rotation initialises the empty secret with 2 keys', async () => {
  const { rotate } = setup();
  const jwks = await rotate();
  expect(jwks.keys.map(isPrivateJwk)).toEqual([true, true]);
});

test('later rotations add a key and keep at most 3', async () => {
  const { rotate } = setup();
  const initial = await rotate();
  const first = await rotate();
  const second = await rotate();
  expect(first.keys.slice(0, 2).map((jwk) => jwk.kid)).toEqual(initial.keys.map((jwk) => jwk.kid));
  expect(second.keys.slice(0, 2).map((jwk) => jwk.kid)).toEqual(first.keys.slice(1).map((jwk) => jwk.kid));
  expect(second.keys.map(isPrivateJwk)).toEqual([false, true, true]);
});

test('enc keys all stay private', async () => {
  const { rotate } = setup(resolveJwkOptions({ algorithm: 'ECDH-ES' }));
  await rotate();
  await rotate();
  expect((await rotate()).keys.map(isPrivateJwk)).toEqual([true, true, true]);
});

test('createSecret is idempotent for a token', async () => {
  const { secretsManager, rotationHandler } = setup();
  const token = secretsManager.startRotation();
  await rotationHandler(event('createSecret', token));
  const pending = secretsManager.versions.get(token)!.value;
  await rotationHandler(event('createSecret', token));
  expect(secretsManager.versions.get(token)!.value).toBe(pending);
});

test('a key option mismatch fails the rotation and leaves the secret unchanged', async () => {
  const { secretsManager, rotate } = setup();
  const initial = await rotate();
  const mismatched = createRotationHandler(
    secretsManager as never,
    resolveJwkOptions({ algorithm: 'ES384' }),
  );
  const token = secretsManager.startRotation();
  await expect(mismatched(event('createSecret', token))).rejects.toThrow(/alg is ES256, expected ES384/);
  expect(secretsManager.current()).toEqual(initial);
  expect(secretsManager.versions.get(token)!.value).toBeUndefined();
});

test('testSecret rejects a pending version without keys', async () => {
  const { secretsManager, rotationHandler } = setup();
  const token = secretsManager.startRotation();
  secretsManager.versions.set(token, { value: '{"keys":[]}', stages: ['AWSPENDING'] });
  await expect(rotationHandler(event('testSecret', token))).rejects.toThrow(/expected 2 initial keys, got 0/);
});

test('testSecret rejects a pending version that is not a rotation of the current one', async () => {
  const { secretsManager, rotationHandler, rotate } = setup();
  await rotate();
  const token = secretsManager.startRotation();
  // A well-formed JWKS that replaces the current keys instead of adding one.
  const unrelated = await rotateJwks({ keys: [] }, resolveJwkOptions({ algorithm: 'ES256' }));
  secretsManager.versions.set(token, { value: JSON.stringify(unrelated), stages: ['AWSPENDING'] });
  await expect(rotationHandler(event('testSecret', token))).rejects.toThrow(
    /not a rotation of the current JWKS/,
  );
});

test('createSecret checks for an existing pending version before reading the current one', async () => {
  const { secretsManager, rotationHandler } = setup();
  const token = secretsManager.startRotation();
  await rotationHandler(event('createSecret', token));
  const send = jest.fn(secretsManager.send);
  secretsManager.send = send;
  await rotationHandler(event('createSecret', token));
  const reads = send.mock.calls
    .map(([command]) => command)
    .filter((command) => command instanceof GetSecretValueCommand)
    .map((command) => command.input.VersionStage);
  expect(reads).toEqual(['AWSPENDING']);
});

test('does nothing for a token that is already AWSCURRENT', async () => {
  const { secretsManager, rotationHandler } = setup();
  await rotationHandler(event('createSecret', 'v0'));
  expect(secretsManager.versions.size).toBe(1);
});

test.each([
  [
    'rotation is disabled',
    (sm: FakeSecretsManager) => (sm.rotationEnabled = false),
    /not enabled for rotation/,
  ],
  ['the token is unknown', () => undefined, /has no stage/],
])('fails when %s', async (_name, arrange, message) => {
  const { secretsManager, rotationHandler } = setup();
  arrange(secretsManager);
  const token = secretsManager.rotationEnabled ? 'unknown' : secretsManager.startRotation();
  await expect(rotationHandler(event('createSecret', token))).rejects.toThrow(message);
});

test('fails when the token is not AWSPENDING', async () => {
  const { secretsManager, rotationHandler } = setup();
  secretsManager.versions.set('v9', { value: '{"keys":[]}', stages: ['AWSPREVIOUS'] });
  await expect(rotationHandler(event('createSecret', 'v9'))).rejects.toThrow(/is not AWSPENDING/);
});

test('fails when the current version is a binary secret', async () => {
  const { secretsManager, rotationHandler } = setup();
  const token = secretsManager.startRotation();
  const send = secretsManager.send;
  secretsManager.send = async (command: unknown) =>
    command instanceof GetSecretValueCommand && command.input.VersionStage === 'AWSCURRENT'
      ? { SecretBinary: new Uint8Array([1]) }
      : send(command);
  await expect(rotationHandler(event('createSecret', token))).rejects.toThrow(
    /AWSCURRENT version of .* has no secret string/,
  );
});

test('rethrows errors other than a missing pending version', async () => {
  const { secretsManager, rotationHandler } = setup();
  const token = secretsManager.startRotation();
  const send = secretsManager.send;
  const denied = new Error('AccessDeniedException');
  secretsManager.send = async (command: unknown) => {
    if (command instanceof GetSecretValueCommand && command.input.VersionId === token) {
      throw denied;
    }
    return send(command);
  };
  await expect(rotationHandler(event('createSecret', token))).rejects.toBe(denied);
  expect(secretsManager.versions.get(token)!.value).toBeUndefined();
});

test('fails on an unknown step', async () => {
  const { secretsManager, rotationHandler } = setup();
  const token = secretsManager.startRotation();
  await expect(rotationHandler(event('rollback' as RotationStep, token))).rejects.toThrow(
    /Unknown rotation step rollback/,
  );
});

test('handler fails when JWK_OPTIONS is not set', async () => {
  delete process.env.JWK_OPTIONS;
  await expect(handler(event('createSecret', 'v1'))).rejects.toThrow(/JWK_OPTIONS is not set/);
});
