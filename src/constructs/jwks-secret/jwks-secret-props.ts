import type { FunctionProps } from 'aws-cdk-lib/aws-lambda';
import type { LogGroupProps } from 'aws-cdk-lib/aws-logs';
import type { RotationScheduleOptions, SecretProps } from 'aws-cdk-lib/aws-secretsmanager';
import type { JwkOptions } from '../../shared/jwks';

/**
 * Props for `JwksSecret`. The key options (`use`, `algorithm`, `curve`,
 * `rsaModulusLength`) are the construct's own; the other props override the
 * defaults of the underlying resources.
 */
export interface JwksSecretProps extends JwkOptions {
  /**
   * Overrides for the secret. The secret's value is always managed by the
   * construct.
   *
   * @default a generated name, no description, the AWS managed key
   * `aws/secretsmanager`, and `RemovalPolicy.RETAIN`, since deleting the secret
   * loses the private keys the OpenID Connect client registration relies on
   */
  readonly secretProps?: Pick<SecretProps, 'secretName' | 'description' | 'encryptionKey' | 'removalPolicy'>;

  /**
   * Overrides for the rotation Lambda. In a VPC, the subnets need a route to
   * Secrets Manager, through a VPC endpoint or NAT.
   *
   * @default not in a VPC, and 512 MB memory for RSA keys larger than 2048
   * bits (Lambda allocates CPU in proportion to memory, which RSA key
   * generation needs), 128 MB otherwise
   */
  readonly rotationLambdaProps?: Pick<FunctionProps, 'memorySize' | 'vpc' | 'vpcSubnets' | 'securityGroups'>;

  /**
   * Overrides for the rotation Lambda's log group.
   *
   * @default `RetentionDays.ONE_YEAR`, and the secret's removal policy
   */
  readonly rotationLogGroupProps?: Pick<LogGroupProps, 'retention' | 'removalPolicy'>;

  /**
   * Overrides for the rotation schedule. `automaticallyAfter` is also how long
   * a new key is published before it is used, so it should exceed the OpenID
   * Connect server's JWKS cache lifetime. The schedule always rotates
   * immediately when created or updated, which initialises the secret.
   *
   * @default rotation every 28 days
   */
  readonly rotationScheduleProps?: Pick<RotationScheduleOptions, 'automaticallyAfter'>;
}
