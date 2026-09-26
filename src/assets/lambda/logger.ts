import { SecretsManagerServiceException } from '@aws-sdk/client-secrets-manager';
import { JwkOptionsMismatchError, JwksValidationError, type Jwks } from '../../shared/jwks';
import { RotationStateError } from './rotation-error';

/** The ECS version the log records follow. */
export const ECS_VERSION = '8.11.0';

/**
 * The closed catalogue of events; see docs/logging.md. Add an entry here
 * before logging a new kind of event, never an ad hoc message.
 */
const EVENTS = {
  start_function: { category: ['process'], type: ['start'] },
  create_secret: { category: ['configuration'], type: ['change'] },
  test_secret: { category: ['configuration'], type: ['info'] },
  finish_secret: { category: ['configuration'], type: ['change'] },
  rotate_secret: { category: ['configuration'], type: ['info'] },
  validate_rotation: { category: ['configuration'], type: ['info'] },
} as const;

export type EventAction = keyof typeof EVENTS;

export type EventOutcome = 'success' | 'failure';

/** Controlled values of `event.reason`. */
export type EventReason = 'pending_exists' | 'already_current' | RotationStateError['reason'];

/** ECS and project fields, by their dotted names. `undefined` values are omitted. */
export type LogFields = Readonly<Record<string, unknown>>;

const TRACE_HEADER_ENV = '_X_AMZN_TRACE_ID';

/** Reads the trace ID from `_X_AMZN_TRACE_ID`, which Lambda sets for each invocation with trace context. */
function xrayTraceId(): string | undefined {
  return /(?:^|;)Root=([^;]+)/.exec(process.env[TRACE_HEADER_ENV] ?? '')?.[1];
}

/**
 * Writes one ECS JSON record to stdout. It is written with `process.stdout`
 * rather than `console.log`, which Lambda's Text log format prefixes with a
 * timestamp, request ID and level. A failure to log never fails a rotation.
 */
export function logEvent(
  action: EventAction,
  outcome: EventOutcome,
  message: string,
  fields: LogFields = {},
): void {
  try {
    const failure = outcome === 'failure';
    const record = {
      '@timestamp': new Date().toISOString(),
      'log.level': failure ? 'error' : 'info',
      message,
      'ecs.version': ECS_VERSION,
      'service.name': process.env.AWS_LAMBDA_FUNCTION_NAME,
      'cloud.provider': 'aws',
      'cloud.region': process.env.AWS_REGION,
      'event.category': EVENTS[action].category,
      'event.type': failure ? ['error'] : EVENTS[action].type,
      'event.action': action,
      'event.outcome': outcome,
      'aws.xray.trace.id': xrayTraceId(),
      ...fields,
    };
    process.stdout.write(`${JSON.stringify(record)}\n`);
  } catch {
    // Deliberately ignored: logging must never fail a rotation.
  }
}

/** Fields identifying a rotation, from the rotation event's secret ARN and token. */
export function rotationFields(
  step: string,
  secretId: string,
  token: string,
  extra: LogFields = {},
): LogFields {
  // arn:<partition>:secretsmanager:<region>:<account>:secret:<name>
  const account = /^arn:[^:]+:secretsmanager:[^:]*:(\d{12}):/.exec(secretId)?.[1];
  return {
    'event.id': token,
    'cloud.account.id': account,
    'aws.secretsmanager.rotation.step': step,
    'aws.secretsmanager.secret.arn': secretId,
    'aws.secretsmanager.secret.version.id': token,
    ...extra,
  };
}

/** The key IDs of a JWKS, for the `jwks.kids.*` fields. */
export function kidsOf(jwks: Jwks): string[] {
  return jwks.keys.map((jwk) => jwk.kid);
}

/** The kids added to and removed from `previous` to get `next`. */
export function kidChanges(previous: Jwks, next: Jwks): LogFields {
  const before = new Set(kidsOf(previous));
  const after = new Set(kidsOf(next));
  return {
    'jwks.kids.current': [...after],
    'jwks.kids.added': [...after].filter((kid) => !before.has(kid)),
    'jwks.kids.removed': [...before].filter((kid) => !after.has(kid)),
  };
}

/** Errors whose messages this package writes, or Secrets Manager writes without echoing secret values. */
function hasSafeMessage(error: unknown): error is Error {
  return (
    error instanceof JwksValidationError ||
    error instanceof JwkOptionsMismatchError ||
    error instanceof RotationStateError ||
    error instanceof SecretsManagerServiceException
  );
}

/**
 * `error.type`, plus `error.message` for errors whose messages are safe to log.
 * Other messages, such as a cryptography library's, might echo its input.
 * No stack trace is logged.
 */
export function errorFields(error: unknown): LogFields {
  return {
    'error.type': error instanceof Error ? error.name : typeof error,
    'error.message': hasSafeMessage(error) ? error.message : undefined,
  };
}
