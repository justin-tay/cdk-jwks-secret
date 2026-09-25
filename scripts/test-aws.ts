/**
 * End-to-end test against a real AWS account: deploys the example app, checks
 * the JWKS endpoint through the first rotation and a manual rotation of each
 * secret, then destroys the stack.
 *
 * Uses the AWS credentials and region of the current environment, and costs a
 * few cents. Run with `npm run test:aws`; pass `--keep` to skip the destroy.
 */
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { RotateSecretCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

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

async function main(): Promise<void> {
  const keep = process.argv.includes('--keep');
  const outDir = mkdtempSync(path.join(tmpdir(), 'jwks-secret-test-aws-'));
  const outputsFile = path.join(outDir, 'outputs.json');
  const secretsManager = new SecretsManagerClient({});
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
