import * as path from 'node:path';
import { CfnOutput, Duration, RemovalPolicy, Stack } from 'aws-cdk-lib';
import { Architecture, FunctionUrlAuthType, Runtime } from 'aws-cdk-lib/aws-lambda';
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import type { Construct } from 'constructs';
import { JwksSecret, type JwkPublicKeyUse, type JwksSecretProps } from 'cdk-jwks-secret';
import type { AppStackProps } from './app-stack-props';

/**
 * Example of using `JwksSecret`: a rotated JWKS secret of signing keys and one
 * of encryption keys, and a public JWKS endpoint that serves the public keys of
 * both, as an OpenID Connect client's `jwks_uri` would.
 */
export class AppStack extends Stack {
  public readonly sigJwksSecret: JwksSecret;

  public readonly encJwksSecret: JwksSecret;

  public readonly jwksEndpoint: NodejsFunction;

  constructor(scope: Construct, id: string, props: AppStackProps = {}) {
    super(scope, id, props);

    this.sigJwksSecret = new JwksSecret(
      this,
      'SigJwksSecret',
      withExampleDefaults(props.sigJwksSecret, 'sig'),
    );
    this.encJwksSecret = new JwksSecret(
      this,
      'EncJwksSecret',
      withExampleDefaults(props.encJwksSecret, 'enc'),
    );
    const jwksSecrets = [this.sigJwksSecret, this.encJwksSecret];

    this.jwksEndpoint = new NodejsFunction(this, 'JwksEndpoint', {
      description: 'Serves the public keys of the JWKS secrets',
      entry: path.join(__dirname, 'handlers', 'jwks-endpoint.ts'),
      runtime: Runtime.NODEJS_24_X,
      architecture: Architecture.ARM_64,
      environment: {
        JWKS_SECRET_ARNS: this.toJsonString(jwksSecrets.map((jwksSecret) => jwksSecret.secret.secretArn)),
        JWKS_CACHE_SECONDS: String((props.jwksCacheTtl ?? Duration.seconds(0)).toSeconds()),
      },
      logGroup: new LogGroup(this, 'JwksEndpointLogGroup', {
        retention: RetentionDays.ONE_WEEK,
        removalPolicy: RemovalPolicy.DESTROY,
      }),
    });
    for (const jwksSecret of jwksSecrets) {
      jwksSecret.grantRead(this.jwksEndpoint);
    }

    // A JWKS is public by design, so the endpoint needs no authentication.
    const jwksUrl = this.jwksEndpoint.addFunctionUrl({ authType: FunctionUrlAuthType.NONE });

    new CfnOutput(this, 'JwksUrl', { value: jwksUrl.url });
    new CfnOutput(this, 'SigSecretArn', { value: this.sigJwksSecret.secret.secretArn });
    new CfnOutput(this, 'EncSecretArn', { value: this.encJwksSecret.secret.secretArn });
    new CfnOutput(this, 'SigRotationLogGroup', { value: this.sigJwksSecret.rotationLogGroup.logGroupName });
    new CfnOutput(this, 'EncRotationLogGroup', { value: this.encJwksSecret.rotationLogGroup.logGroupName });
  }
}

/** The example's defaults, overridable by `props`, for a secret with the given use. */
function withExampleDefaults(
  props: Omit<JwksSecretProps, 'use'> = {},
  use: JwkPublicKeyUse,
): JwksSecretProps {
  return {
    ...props,
    use,
    // Clean up on `cdk destroy`; the construct retains the secret by default.
    secretProps: { removalPolicy: RemovalPolicy.DESTROY, ...props.secretProps },
    rotationLogGroupProps: { retention: RetentionDays.ONE_WEEK, ...props.rotationLogGroupProps },
  };
}
