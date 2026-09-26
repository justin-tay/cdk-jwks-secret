import { Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { Vpc } from 'aws-cdk-lib/aws-ec2';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { RetentionDays } from 'aws-cdk-lib/aws-logs';
import { JwksSecret, type JwksSecretProps } from '../../src/constructs';

function synth(props?: JwksSecretProps) {
  const stack = new Stack(undefined, 'TestStack', { env: { region: 'us-east-1', account: '123456789012' } });
  const jwksSecret = new JwksSecret(stack, 'JwksSecret', props);
  return { stack, jwksSecret, template: Template.fromStack(stack) };
}

test('creates an empty, retained secret', () => {
  const { template } = synth();
  template.hasResource('AWS::SecretsManager::Secret', {
    Properties: { SecretString: '{"keys":[]}', GenerateSecretString: Match.absent() },
    DeletionPolicy: 'Retain',
    UpdateReplacePolicy: 'Retain',
  });
});

test('keeps the rotation Lambda logs for a year in a log group that follows the removal policy', () => {
  const { template } = synth();
  template.hasResource('AWS::Logs::LogGroup', {
    Properties: { RetentionInDays: 365 },
    DeletionPolicy: 'Retain',
  });
  template.hasResourceProperties('AWS::Lambda::Function', {
    LoggingConfig: { LogGroup: { Ref: Match.stringLikeRegexp('RotationLambdaLogGroup') } },
  });
});

test('uses the Text log format, so the ECS records the function writes are not wrapped', () => {
  const { template } = synth();
  template.hasResourceProperties('AWS::Lambda::Function', {
    LoggingConfig: { LogFormat: 'Text' },
  });
});

test('encrypts the log group with the given key', () => {
  const stack = new Stack(undefined, 'TestStack', { env: { region: 'us-east-1', account: '123456789012' } });
  const encryptionKey = new Key(stack, 'LogKey');
  new JwksSecret(stack, 'JwksSecret', { rotationLogGroupProps: { encryptionKey } });
  Template.fromStack(stack).hasResourceProperties('AWS::Logs::LogGroup', {
    KmsKeyId: Match.anyValue(),
  });
});

test('creates a Node 24 arm64 rotation Lambda configured with the resolved options', () => {
  const { template } = synth();
  template.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'nodejs24.x',
    Architectures: ['arm64'],
    Handler: 'index.handler',
    Environment: {
      Variables: {
        JWK_OPTIONS: JSON.stringify({ algorithm: 'ES256', use: 'sig', keyType: 'EC', curve: 'P-256' }),
      },
    },
  });
});

test('lets the log group removal policy differ from the secret', () => {
  const { template } = synth({ rotationLogGroupProps: { removalPolicy: RemovalPolicy.DESTROY } });
  template.hasResource('AWS::SecretsManager::Secret', { DeletionPolicy: 'Retain' });
  template.hasResource('AWS::Logs::LogGroup', { DeletionPolicy: 'Delete' });
});

test('defaults enc keys to ECDH-ES+A128KW', () => {
  const { template } = synth({ use: 'enc' });
  template.hasResourceProperties('AWS::Lambda::Function', {
    Environment: {
      Variables: {
        JWK_OPTIONS: JSON.stringify({
          algorithm: 'ECDH-ES+A128KW',
          use: 'enc',
          keyType: 'EC',
          curve: 'P-256',
        }),
      },
    },
  });
});

test.each([
  [{}, 128],
  [{ use: 'enc' }, 128],
  [{ algorithm: 'RS256' }, 128],
  [{ algorithm: 'RS256', rsaModulusLength: 3072 }, 512],
  [{ algorithm: 'RSA-OAEP-256', rsaModulusLength: 4096 }, 512],
  [{ algorithm: 'RS256', rsaModulusLength: 4096, rotationLambdaProps: { memorySize: 1024 } }, 1024],
  [{ rotationLambdaProps: { memorySize: 256 } }, 256],
] as const)('sizes the rotation Lambda for %j at %d MB', (props, memorySize) => {
  const { template } = synth(props);
  template.hasResourceProperties('AWS::Lambda::Function', { MemorySize: memorySize });
});

test('rotates every 28 days and immediately on creation', () => {
  const { template } = synth();
  template.hasResourceProperties('AWS::SecretsManager::RotationSchedule', {
    RotationRules: { ScheduleExpression: 'rate(28 days)' },
    RotateImmediatelyOnUpdate: true,
    RotationLambdaARN: Match.anyValue(),
  });
});

test('allows Secrets Manager to invoke the Lambda and the Lambda to rotate the secret', () => {
  const { template } = synth();
  template.hasResourceProperties('AWS::Lambda::Permission', {
    Principal: 'secretsmanager.amazonaws.com',
  });
  template.hasResourceProperties('AWS::IAM::Policy', {
    PolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: [
            'secretsmanager:DescribeSecret',
            'secretsmanager:GetSecretValue',
            'secretsmanager:PutSecretValue',
            'secretsmanager:UpdateSecretVersionStage',
          ],
        }),
      ]),
    },
  });
});

test('applies the optional props', () => {
  const stack = new Stack(undefined, 'TestStack', { env: { region: 'us-east-1', account: '123456789012' } });
  const encryptionKey = new Key(stack, 'Key');
  const vpc = new Vpc(stack, 'Vpc');
  new JwksSecret(stack, 'JwksSecret', {
    secretProps: {
      secretName: 'oidc-client-jwks',
      description: 'JWKS',
      encryptionKey,
      removalPolicy: RemovalPolicy.DESTROY,
    },
    algorithm: 'ECDH-ES',
    curve: 'P-384',
    rotationLogGroupProps: { retention: RetentionDays.ONE_MONTH },
    rotationScheduleProps: { automaticallyAfter: Duration.days(7) },
    rotationLambdaProps: { vpc },
  });
  const template = Template.fromStack(stack);

  template.hasResource('AWS::Logs::LogGroup', {
    Properties: { RetentionInDays: 30 },
    DeletionPolicy: 'Delete',
  });

  template.hasResource('AWS::SecretsManager::Secret', {
    Properties: { Name: 'oidc-client-jwks', Description: 'JWKS', KmsKeyId: Match.anyValue() },
    DeletionPolicy: 'Delete',
  });
  template.hasResourceProperties('AWS::SecretsManager::RotationSchedule', {
    RotationRules: { ScheduleExpression: 'rate(7 days)' },
  });
  template.hasResourceProperties('AWS::Lambda::Function', {
    VpcConfig: Match.objectLike({ SubnetIds: Match.anyValue() }),
    Environment: {
      Variables: {
        JWK_OPTIONS: JSON.stringify({ algorithm: 'ECDH-ES', use: 'enc', keyType: 'EC', curve: 'P-384' }),
      },
    },
  });
  // The rotation Lambda may use the key through Secrets Manager.
  template.hasResourceProperties('AWS::KMS::Key', {
    KeyPolicy: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: Match.arrayWith(['kms:Decrypt', 'kms:Encrypt']),
          Condition: { StringEquals: { 'kms:ViaService': 'secretsmanager.us-east-1.amazonaws.com' } },
        }),
      ]),
    },
  });
});

test('exposes the resolved options and grants read access', () => {
  const stack = new Stack(undefined, 'TestStack');
  const jwksSecret = new JwksSecret(stack, 'JwksSecret', { algorithm: 'ES256' });
  expect(jwksSecret.jwkOptions).toEqual({ algorithm: 'ES256', use: 'sig', keyType: 'EC', curve: 'P-256' });

  const role = new Role(stack, 'ServerRole', { assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com') });
  jwksSecret.grantRead(role);
  Template.fromStack(stack).hasResourceProperties('AWS::IAM::Policy', {
    Roles: [{ Ref: Match.stringLikeRegexp('ServerRole') }],
    PolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({ Action: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'] }),
      ]),
    },
  });
});

test('explains how to build a missing rotation Lambda bundle', () => {
  // Spy on the module object itself, which the construct's named import reads from.
  jest.spyOn(require('node:fs') as typeof import('node:fs'), 'existsSync').mockReturnValue(false);
  try {
    expect(() => synth()).toThrow(/Rotation Lambda bundle not found .* Run "npm run build:lambda"/);
  } finally {
    jest.restoreAllMocks();
  }
});

test.each([
  [{ algorithm: 'HS256' }, /Unsupported algorithm/],
  [{ algorithm: 'ES256', rsaModulusLength: 2048 }, /not applicable/],
  [{ use: 'enc', algorithm: 'ES256' }, /but use is "enc"/],
  [
    { rotationLambdaProps: { memorySize: 64 } },
    /rotationLambdaProps.memorySize must be an integer from 128 to 10240/,
  ],
  [{ rotationLambdaProps: { memorySize: 256.5 } }, /rotationLambdaProps.memorySize must be/],
  [{ rotationScheduleProps: { automaticallyAfter: Duration.hours(1) } }, /must not be smaller than 4 hours/],
])('rejects invalid props %j at synth time', (props, error) => {
  expect(() => synth(props as JwksSecretProps)).toThrow(error);
});
