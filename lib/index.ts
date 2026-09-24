// import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
// import * as sqs from 'aws-cdk-lib/aws-sqs';

export interface CdkJwksSecretProps {
  // Define construct properties here
}

export class CdkJwksSecret extends Construct {

  constructor(scope: Construct, id: string, props: CdkJwksSecretProps = {}) {
    super(scope, id);

    // Define construct contents here

    // example resource
    // const queue = new sqs.Queue(this, 'CdkJwksSecretQueue', {
    //   visibilityTimeout: cdk.Duration.seconds(300)
    // });
  }
}
