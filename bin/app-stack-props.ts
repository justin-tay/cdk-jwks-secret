import type { Duration, StackProps } from 'aws-cdk-lib';
import type { JwksSecretProps } from 'cdk-jwks-secret';

export interface AppStackProps extends StackProps {
  /**
   * Props for the JWKS secret holding the signing (`sig`) keys, e.g. for
   * `private_key_jwt`. `use` is always 'sig'.
   *
   * @default ES256 keys rotated every 28 days, destroyed with the stack
   */
  readonly sigJwksSecret?: Omit<JwksSecretProps, 'use'>;

  /**
   * Props for the JWKS secret holding the encryption (`enc`) keys, e.g. for
   * encrypted ID tokens. `use` is always 'enc'.
   *
   * @default ECDH-ES+A128KW keys rotated every 28 days, destroyed with the stack
   */
  readonly encJwksSecret?: Omit<JwksSecretProps, 'use'>;

  /**
   * How long the JWKS endpoint caches the secrets, also used as the
   * Cache-Control max-age. A real endpoint would cache for a few minutes;
   * the example doesn't, so a rotation shows up immediately.
   *
   * @default Duration.seconds(0)
   */
  readonly jwksCacheTtl?: Duration;
}
