import { ResourceNotFoundException } from '@aws-sdk/client-secrets-manager';
import {
  ECS_VERSION,
  errorFields,
  kidChanges,
  logEvent,
  rotationFields,
} from '../../../src/assets/lambda/logger';
import { RotationStateError } from '../../../src/assets/lambda/rotation-error';
import { JwksValidationError, type Jwks } from '../../../src/shared/jwks';

const TRACE_HEADER_ENV = '_X_AMZN_TRACE_ID';

function capture(): () => Record<string, unknown>[] {
  const written: string[] = [];
  jest.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    written.push(String(chunk));
    return true;
  });
  return () => written.map((line) => JSON.parse(line) as Record<string, unknown>);
}

const jwks = (...kids: string[]): Jwks => ({ keys: kids.map((kid) => ({ kid })) }) as unknown as Jwks;

afterEach(() => {
  jest.restoreAllMocks();
  delete process.env[TRACE_HEADER_ENV];
  delete process.env.AWS_LAMBDA_FUNCTION_NAME;
});

test('writes one newline-terminated ECS JSON record', () => {
  process.env.AWS_LAMBDA_FUNCTION_NAME = 'rotation';
  const write = jest.spyOn(process.stdout, 'write').mockReturnValue(true);
  logEvent('create_secret', 'success', 'hello', { 'jwks.kids.current': ['a'] });
  const line = String(write.mock.calls[0][0]);
  expect(line.endsWith('\n')).toBe(true);
  expect(JSON.parse(line)).toEqual({
    '@timestamp': expect.any(String),
    'log.level': 'info',
    message: 'hello',
    'ecs.version': ECS_VERSION,
    'service.name': 'rotation',
    'cloud.provider': 'aws',
    'cloud.region': 'us-east-1',
    'event.category': ['configuration'],
    'event.type': ['change'],
    'event.action': 'create_secret',
    'event.outcome': 'success',
    'jwks.kids.current': ['a'],
  });
});

test('a value containing line breaks and quotes stays on one line', () => {
  const write = jest.spyOn(process.stdout, 'write').mockReturnValue(true);
  const arn = 'x\r\n{"forged":true}';
  logEvent('create_secret', 'success', 'a\nb', { 'aws.secretsmanager.secret.arn': arn });
  const output = String(write.mock.calls[0][0]);
  expect(output.trimEnd().split('\n')).toHaveLength(1);
  const record = JSON.parse(output) as Record<string, unknown>;
  expect(record).toMatchObject({ message: 'a\nb', 'aws.secretsmanager.secret.arn': arn });
  expect(record).not.toHaveProperty('forged');
});

test('a failure is logged at error level with the error event type', () => {
  const logged = capture();
  logEvent('test_secret', 'failure', 'nope');
  expect(logged()[0]).toMatchObject({ 'log.level': 'error', 'event.type': ['error'] });
});

test('adds the X-Ray trace ID from the trace header, and omits it without one', () => {
  const logged = capture();
  logEvent('start_function', 'success', 'a');
  process.env[TRACE_HEADER_ENV] =
    'Root=1-5e6722a7-cc2xmpl46db7ae0aaa9cd4e0;Parent=53995c3f42cd8ad8;Sampled=1';
  logEvent('start_function', 'success', 'b');
  const [without, withTrace] = logged();
  expect(without).not.toHaveProperty('aws.xray.trace.id');
  expect(withTrace['aws.xray.trace.id']).toBe('1-5e6722a7-cc2xmpl46db7ae0aaa9cd4e0');
});

test('rotationFields takes the account from the secret ARN, and tolerates other ids', () => {
  const arn = 'arn:aws:secretsmanager:eu-west-1:123456789012:secret:jwks-AbCdEf';
  expect(rotationFields('createSecret', arn, 't1')).toMatchObject({
    'event.id': 't1',
    'cloud.account.id': '123456789012',
    'aws.secretsmanager.rotation.step': 'createSecret',
  });
  expect(rotationFields('createSecret', 'jwks', 't1')['cloud.account.id']).toBeUndefined();
});

test('kidChanges lists the current, added and removed kids', () => {
  expect(kidChanges(jwks('a', 'b', 'c'), jwks('b', 'c', 'd'))).toEqual({
    'jwks.kids.current': ['b', 'c', 'd'],
    'jwks.kids.added': ['d'],
    'jwks.kids.removed': ['a'],
  });
});

test.each([
  ['a validation error', new JwksValidationError('kids must be unique')],
  ['a rotation state error', new RotationStateError('unknown_step', 'Unknown rotation step x')],
  ['a Secrets Manager error', new ResourceNotFoundException({ message: 'gone', $metadata: {} })],
])('errorFields includes the message of %s', (_name, error) => {
  expect(errorFields(error)).toEqual({ 'error.type': error.name, 'error.message': error.message });
});

test('errorFields omits the message of any other error, and handles non-errors', () => {
  expect(errorFields(new TypeError('echoes input'))).toEqual({
    'error.type': 'TypeError',
    'error.message': undefined,
  });
  expect(errorFields('oops')).toEqual({ 'error.type': 'string', 'error.message': undefined });
});
