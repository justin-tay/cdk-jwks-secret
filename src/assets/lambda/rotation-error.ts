/** Why a rotation cannot proceed, as reported in the `event.reason` field of a `validate_rotation` event. */
export type RotationStateReason =
  | 'rotation_disabled'
  | 'version_not_found'
  | 'version_not_pending'
  | 'unknown_step';

/**
 * A rotation request that is inconsistent with the secret's state. The message
 * is written by this package, so it is safe to log.
 */
export class RotationStateError extends Error {
  constructor(
    public readonly reason: RotationStateReason,
    message: string,
  ) {
    super(message);
    this.name = 'RotationStateError';
  }
}
