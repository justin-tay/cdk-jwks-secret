import { existsSync } from 'node:fs';
import * as path from 'node:path';
import { Duration, RemovalPolicy, SecretValue, Validations } from 'aws-cdk-lib';
import { ManagedPolicy, Role, ServicePrincipal, type Grant, type IGrantable } from 'aws-cdk-lib/aws-iam';
import { Architecture, Code, Function as LambdaFunction, Runtime } from 'aws-cdk-lib/aws-lambda';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { RotationSchedule, Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';
import { JWK_OPTIONS_ENV, resolveJwkOptions, type Jwks, type ResolvedJwkOptions } from '../../shared/jwks';
import type { JwksSecretProps } from './jwks-secret-props';

// src/ and lib/ sit at the same depth, so this resolves to the bundle under
// lib/ both from the compiled construct and from the TypeScript source in tests.
const ROTATION_HANDLER_ASSET_PATH = path.join(
  __dirname,
  '..',
  '..',
  '..',
  'lib',
  'assets',
  'lambda',
  'handlers',
  'rotation',
);

const EMPTY_JWKS: Jwks = { keys: [] };

/** Enough CPU to generate 2 keys well within the timeout: large RSA keys need more than the minimum. */
function defaultRotationLambdaMemorySize(options: ResolvedJwkOptions): number {
  return options.keyType === 'RSA' && options.rsaModulusLength! > 2048 ? 512 : 128;
}

/**
 * A JWKS stored verbatim (`{"keys":[...]}`) in a Secrets Manager secret and
 * rotated by a Lambda. The secret starts empty; the rotation triggered when
 * the schedule is created initialises it with 2 keys, and each later rotation
 * adds a key, keeping at most 3.
 */
export class JwksSecret extends Construct {
  public readonly secret: Secret;

  public readonly rotationSchedule: RotationSchedule;

  public readonly rotationLambda: LambdaFunction;

  public readonly rotationLogGroup: LogGroup;

  public readonly rotationLambdaRole: Role;

  /** The resolved key options, including the `use` derived from the algorithm. */
  public readonly jwkOptions: ResolvedJwkOptions;

  constructor(scope: Construct, id: string, props: JwksSecretProps = {}) {
    super(scope, id);

    this.jwkOptions = resolveJwkOptions({
      use: props.use,
      algorithm: props.algorithm,
      curve: props.curve,
      rsaModulusLength: props.rsaModulusLength,
    });

    if (!existsSync(path.join(ROTATION_HANDLER_ASSET_PATH, 'index.js'))) {
      throw new Error(
        `Rotation Lambda bundle not found at ${ROTATION_HANDLER_ASSET_PATH}. Run "npm run build:lambda".`,
      );
    }

    const { secretProps = {}, rotationLambdaProps = {}, rotationLogGroupProps = {} } = props;

    const memorySize = rotationLambdaProps.memorySize ?? defaultRotationLambdaMemorySize(this.jwkOptions);
    if (!Number.isInteger(memorySize) || memorySize < 128 || memorySize > 10240) {
      throw new Error(
        `rotationLambdaProps.memorySize must be an integer from 128 to 10240, got ${memorySize}`,
      );
    }

    const removalPolicy = secretProps.removalPolicy ?? RemovalPolicy.RETAIN;

    this.secret = new Secret(this, 'Secret', {
      ...secretProps,
      removalPolicy,
      // Contains no key material: the first rotation generates the keys.
      secretStringValue: SecretValue.unsafePlainText(JSON.stringify(EMPTY_JWKS)),
    });

    this.rotationLogGroup = new LogGroup(this, 'RotationLambdaLogGroup', {
      retention: rotationLogGroupProps.retention ?? RetentionDays.ONE_YEAR,
      removalPolicy: rotationLogGroupProps.removalPolicy ?? removalPolicy,
    });

    // Instead of AWSLambdaBasicExecutionRole, which may write to any log group,
    // the role may write only to the rotation Lambda's own log group.
    this.rotationLambdaRole = new Role(this, 'RotationLambdaRole', {
      assumedBy: new ServicePrincipal('lambda.amazonaws.com'),
    });
    this.rotationLogGroup.grantWrite(this.rotationLambdaRole);
    if (rotationLambdaProps.vpc) {
      this.rotationLambdaRole.addManagedPolicy(
        ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaVPCAccessExecutionRole'),
      );
      Validations.of(this.rotationLambdaRole).acknowledge({
        id: 'AwsSolutions::AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole]',
        reason:
          'Lambda needs these network interface permissions to run in a VPC; they do not support resource-level permissions.',
      });
    }

    this.rotationLambda = new LambdaFunction(this, 'RotationLambda', {
      description: 'Rotates the JWKS secret',
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      handler: 'index.handler',
      code: Code.fromAsset(ROTATION_HANDLER_ASSET_PATH),
      memorySize,
      timeout: Duration.minutes(1),
      environment: {
        [JWK_OPTIONS_ENV]: JSON.stringify(this.jwkOptions),
      },
      logGroup: this.rotationLogGroup,
      role: this.rotationLambdaRole,
      vpc: rotationLambdaProps.vpc,
      vpcSubnets: rotationLambdaProps.vpcSubnets,
      securityGroups: rotationLambdaProps.securityGroups,
    });

    this.rotationSchedule = this.secret.addRotationSchedule('RotationSchedule', {
      rotationLambda: this.rotationLambda,
      automaticallyAfter: props.rotationScheduleProps?.automaticallyAfter ?? Duration.days(28),
      // Required: the immediate rotation is what initialises the empty secret.
      rotateImmediatelyOnUpdate: true,
    });
    // Acknowledgements apply to the whole role, which is one reason the role is
    // the construct's alone; see "cdk-nag" in README.md.
    Validations.of(this.rotationLambdaRole).acknowledge({
      id: 'AwsSolutions::AwsSolutions-IAM5[Resource::*]',
      reason:
        'secretsmanager:GetRandomPassword, added by the CDK rotation schedule, does not support resource-level permissions and reads no data.',
    });
  }

  /** Grants read access to the secret, e.g. to the server that serves the JWKS endpoint. */
  public grantRead(grantee: IGrantable): Grant {
    return this.secret.grantRead(grantee);
  }
}
