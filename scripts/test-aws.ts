/**
 * End-to-end test against a real AWS account: deploys the example app, checks
 * the JWKS endpoint through the first rotation and a manual rotation of each
 * secret, checks that each rotation Lambda's log group holds only bare ECS
 * records describing those rotations, then destroys the stack.
 *
 * Uses the AWS credentials and region of the current environment, and costs a
 * few cents. Run with `npm run test:aws`; pass `--keep` to skip the destroy.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { CloudWatchLogsClient, FilterLogEventsCommand } from '@aws-sdk/client-cloudwatch-logs';
import {
  GetSecretValueCommand,
  RotateSecretCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import { parseJwks, PRIVATE_MEMBERS } from 'cdk-jwks-secret/jwks';

const STACK = 'JwksSecretExampleApp';
const TIMEOUT_MS = 5 * 60 * 1000;
const POLL_MS = 5000;

interface PublicJwk {
  readonly kid: string;
  readonly use: 'sig' | 'enc';
  readonly d?: string;
}

function cdk(...args: string[]): void {
  const result = spawnSync('npx', ['cdk', ...args], {
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (result.status !== 0) {
    throw new Error(`cdk ${args[0]} failed with exit code ${result.status}`);
  }
}

async function fetchKeys(url: string): Promise<PublicJwk[]> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`GET ${url} returned ${response.status}`);
  }
  const { keys } = (await response.json()) as { keys: PublicJwk[] };
  const withPrivatePart = keys.filter((jwk) => jwk.d !== undefined);
  if (withPrivatePart.length > 0) {
    throw new Error(`The endpoint serves private keys: ${withPrivatePart.map((jwk) => jwk.kid).join(', ')}`);
  }
  return keys;
}

const kidsOf = (keys: PublicJwk[], use: PublicJwk['use']) =>
  keys.filter((jwk) => jwk.use === use).map((jwk) => jwk.kid);

/** Polls the endpoint until `done` holds for its keys. */
async function waitFor(
  url: string,
  description: string,
  done: (keys: PublicJwk[]) => boolean,
): Promise<PublicJwk[]> {
  const deadline = Date.now() + TIMEOUT_MS;
  for (;;) {
    const keys = await fetchKeys(url);
    if (done(keys)) {
      console.log(`✓ ${description}`);
      return keys;
    }
    if (Date.now() > deadline) {
      throw new Error(`Timed out waiting until ${description}; last keys: ${JSON.stringify(keys)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}

type EcsRecord = Readonly<Record<string, unknown>>;

/** Lines the Lambda service itself writes to a log group; every other line must be an ECS record. */
const PLATFORM_LINE = /^(INIT_START|START|END|REPORT|XRAY)\b/;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchLogMessages(logs: CloudWatchLogsClient, logGroupName: string): Promise<string[]> {
  const messages: string[] = [];
  let nextToken: string | undefined;
  do {
    const page = await logs.send(new FilterLogEventsCommand({ logGroupName, nextToken }));
    messages.push(...(page.events ?? []).map((event) => event.message ?? ''));
    nextToken = page.nextToken;
  } while (nextToken);
  return messages;
}

/** Parses the function's log lines, which must be bare JSON ECS records, not prefixed by Lambda. */
function parseEcsRecords(messages: string[]): EcsRecord[] {
  return messages
    .map((message) => message.trimEnd())
    .filter((message) => message !== '' && !PLATFORM_LINE.test(message))
    .map((message) => {
      let record: unknown;
      try {
        record = JSON.parse(message);
      } catch {
        throw new Error(`A log line is not a bare JSON record: ${message}`);
      }
      if (typeof record !== 'object' || record === null || !('ecs.version' in record)) {
        throw new Error(`A log line is not an ECS record: ${message}`);
      }
      return record;
    });
}

/**
 * Checks the rotation Lambda's log group after two rotations of one secret (the
 * first, which initialises it, and a manual one): every line is an ECS record,
 * none is a failure, each rotation logged its three steps under one `event.id`,
 * the kids match the secret, and no private key member was logged.
 */
async function checkRotationLogs(
  logs: CloudWatchLogsClient,
  secretsManager: SecretsManagerClient,
  name: string,
  logGroupName: string,
  secretArn: string,
): Promise<void> {
  const deadline = Date.now() + TIMEOUT_MS;
  let messages: string[];
  let records: EcsRecord[];
  for (;;) {
    messages = await fetchLogMessages(logs, logGroupName);
    records = parseEcsRecords(messages);
    if (records.filter((record) => record['event.action'] === 'finish_secret').length >= 2) {
      break;
    }
    if (Date.now() > deadline) {
      throw new Error(`Timed out waiting for 2 finish_secret events in ${logGroupName}`);
    }
    await sleep(POLL_MS);
  }

  const failures = records.filter((record) => record['event.outcome'] === 'failure');
  if (failures.length > 0) {
    throw new Error(`${name}: rotation failures were logged: ${JSON.stringify(failures)}`);
  }
  if (!records.some((record) => record['event.action'] === 'start_function')) {
    throw new Error(`${name}: no start_function event was logged`);
  }

  const finishes = records.filter((record) => record['event.action'] === 'finish_secret');
  if (finishes.length !== 2) {
    throw new Error(`${name}: expected 2 finish_secret events, got ${finishes.length}`);
  }
  for (const finish of finishes) {
    const steps = new Set(
      records
        .filter((record) => record['event.id'] === finish['event.id'])
        .map((record) => record['event.action']),
    );
    for (const step of ['create_secret', 'test_secret', 'finish_secret']) {
      if (!steps.has(step)) {
        throw new Error(`${name}: rotation ${String(finish['event.id'])} did not log ${step}`);
      }
    }
  }
  const [first, second] = finishes;
  if (
    (first['jwks.kids.added'] as string[]).length !== 2 ||
    (first['jwks.kids.removed'] as string[]).length
  ) {
    throw new Error(`${name}: the first rotation should add 2 keys and remove none`);
  }
  if (
    (second['jwks.kids.added'] as string[]).length !== 1 ||
    (second['jwks.kids.removed'] as string[]).length
  ) {
    throw new Error(`${name}: the second rotation should add 1 key and remove none`);
  }

  const { SecretString } = await secretsManager.send(new GetSecretValueCommand({ SecretId: secretArn }));
  const jwks = parseJwks(SecretString ?? '');
  const kids = jwks.keys.map((jwk) => jwk.kid);
  if (JSON.stringify(second['jwks.kids.current']) !== JSON.stringify(kids)) {
    throw new Error(`${name}: the last finish_secret kids do not match the secret's kids`);
  }

  const output = messages.join('\n');
  for (const jwk of jwks.keys) {
    for (const member of PRIVATE_MEMBERS) {
      const value = (jwk as unknown as Record<string, unknown>)[member];
      if (typeof value === 'string' && output.includes(value)) {
        throw new Error(`${name}: the private member "${member}" of key ${jwk.kid} was logged`);
      }
    }
  }
  console.log(
    `✓ ${name} rotation logs are bare ECS records that describe the rotations and hold no key material`,
  );
}

async function main(): Promise<void> {
  const keep = process.argv.includes('--keep');
  const outDir = mkdtempSync(path.join(tmpdir(), 'jwks-secret-test-aws-'));
  const outputsFile = path.join(outDir, 'outputs.json');
  const secretsManager = new SecretsManagerClient({});
  const logs = new CloudWatchLogsClient({});
  try {
    cdk('deploy', STACK, '--require-approval', 'never', '--outputs-file', outputsFile);
    const outputs = JSON.parse(readFileSync(outputsFile, 'utf8'))[STACK] as Record<string, string>;
    const url = outputs.JwksUrl;

    const initial = await waitFor(
      url,
      'the first rotation published 2 sig and 2 enc keys',
      (keys) => kidsOf(keys, 'sig').length === 2 && kidsOf(keys, 'enc').length === 2,
    );

    await secretsManager.send(new RotateSecretCommand({ SecretId: outputs.SigSecretArn }));
    const afterSig = await waitFor(
      url,
      'rotating the sig secret added a third sig key and kept the previous ones',
      (keys) =>
        kidsOf(keys, 'sig').length === 3 &&
        kidsOf(initial, 'sig').every((kid) => kidsOf(keys, 'sig').includes(kid)),
    );

    await secretsManager.send(new RotateSecretCommand({ SecretId: outputs.EncSecretArn }));
    await waitFor(
      url,
      'rotating the enc secret published a new enc key and unpublished the oldest',
      (keys) => {
        const enc = kidsOf(keys, 'enc');
        const [oldest, previous] = kidsOf(afterSig, 'enc');
        return enc.length === 2 && !enc.includes(oldest) && enc[0] === previous;
      },
    );

    await checkRotationLogs(logs, secretsManager, 'sig', outputs.SigRotationLogGroup, outputs.SigSecretArn);
    await checkRotationLogs(logs, secretsManager, 'enc', outputs.EncRotationLogGroup, outputs.EncSecretArn);

    console.log('All checks passed.');
  } finally {
    if (keep) {
      console.log(`--keep: not destroying ${STACK}.`);
    } else {
      cdk('destroy', STACK, '--force');
    }
    rmSync(outDir, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
