import { App, Stack, Validations } from 'aws-cdk-lib';
import { Vpc } from 'aws-cdk-lib/aws-ec2';
import { Key } from 'aws-cdk-lib/aws-kms';
import { AwsSolutionsChecks } from 'cdk-nag';
import { JwksSecret } from '../../src/constructs';

test.each([
  ['the defaults', () => ({})],
  ['enc keys', () => ({ use: 'enc' })],
  ['RSA keys', () => ({ algorithm: 'PS256', rsaModulusLength: 3072 })],
  ['a VPC', (stack: Stack) => ({ rotationLambdaProps: { vpc: vpcWithoutFindings(stack) } })],
  [
    'a customer managed key',
    (stack: Stack) => ({
      secretProps: { encryptionKey: new Key(stack, 'Key', { enableKeyRotation: true }) },
    }),
  ],
] as const)('passes the AWS Solutions cdk-nag checks with %s', (_name, props) => {
  const app = new App();
  const stack = new Stack(app, 'NagStack');
  new JwksSecret(stack, 'JwksSecret', props(stack));
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app));
  expect(() => app.synth()).not.toThrow();
});

/** A VPC whose own findings (e.g. no flow logs) are out of scope for these tests. */
function vpcWithoutFindings(stack: Stack): Vpc {
  const vpc = new Vpc(stack, 'Vpc');
  Validations.of(vpc).acknowledge({ id: 'AwsSolutions::AwsSolutions-VPC7', reason: 'Test VPC' });
  return vpc;
}
