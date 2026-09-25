import { App, Duration } from 'aws-cdk-lib';
import type { JwkAlgorithm } from 'cdk-jwks-secret';
import { AppStack } from './app-stack';

const app = new App();

// e.g. npx cdk deploy -c sigAlgorithm=PS256 -c encAlgorithm=RSA-OAEP-256 -c rotationIntervalDays=1 -c jwksCacheSeconds=300
const sigAlgorithm: JwkAlgorithm | undefined = app.node.tryGetContext('sigAlgorithm');
const encAlgorithm: JwkAlgorithm | undefined = app.node.tryGetContext('encAlgorithm');
const rotationIntervalDays: string | undefined = app.node.tryGetContext('rotationIntervalDays');
const jwksCacheSeconds: string | undefined = app.node.tryGetContext('jwksCacheSeconds');

const rotationScheduleProps =
  rotationIntervalDays === undefined
    ? undefined
    : { automaticallyAfter: Duration.days(Number(rotationIntervalDays)) };

new AppStack(app, 'JwksSecretExampleApp', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  sigJwksSecret: { algorithm: sigAlgorithm, rotationScheduleProps },
  encJwksSecret: { algorithm: encAlgorithm, rotationScheduleProps },
  jwksCacheTtl: jwksCacheSeconds === undefined ? undefined : Duration.seconds(Number(jwksCacheSeconds)),
});
