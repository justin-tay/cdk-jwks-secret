# How rotation works

Rotating keys is easy; rotating them without breaking anyone is the hard part,
because two parties cache keys:

- **The OpenID Connect server caches your client's JWKS** (fetched from its
  `jwks_uri`). It can only verify a signature, or encrypt to you, with a key
  it has already cached.
- **Your server caches the secret.** For a while after a rotation it may still
  sign with the previous key, or receive tokens encrypted to it.

`JwksSecret` keeps up to 3 keys and moves each one through a fixed lifecycle,
one step per rotation (every 28 days by default), so that neither cache ever
needs a key that is missing.

In the timelines below, `*` marks a key that still has its private part.

## Signing keys (`sig`)

| Day | Keys in the secret | Published | Your server signs with |
| --- | ------------------ | --------- | ---------------------- |
| 0   | `[A*, B*]`         | A, B      | A                      |
| 28  | `[A, B*, C*]`      | A, B, C   | B                      |
| 56  | `[B, C*, D*]`      | B, C, D   | C                      |
| 84  | `[C, D*, E*]`      | C, D, E   | D                      |

Each key goes through three stages:

1. **Next:** added at the end and published, but not used yet. It spends a
   whole rotation interval in the JWKS, so the OpenID Connect server has
   cached it before its first use.
2. **Signing:** the first key with a private part.
3. **Retired:** its private part is removed, but it stays published for one
   more interval, so assertions signed by a server still holding the previous
   secret keep verifying. At the next rotation it is dropped.

Day 0 is the exception: both keys are new, so the OpenID Connect server has
not cached either of them. That doesn't matter for a new client, because the
server fetches a client's JWKS the first time it needs it.

## Encryption keys (`enc`)

| Day | Keys in the secret | Published | Your server decrypts with |
| --- | ------------------ | --------- | ------------------------- |
| 0   | `[A*, B*]`         | A, B      | A, B                      |
| 28  | `[A*, B*, C*]`     | B, C      | A, B, C                   |
| 56  | `[B*, C*, D*]`     | C, D      | B, C, D                   |

Here the OpenID Connect server chooses which published key to encrypt to, so
the rule is reversed: a key is **unpublished one interval before its private
part is deleted**. During that interval the server can no longer pick it from
a fresh JWKS, but anything it encrypted to it from a cached JWKS still
decrypts. Every key in the secret keeps its private part; your server decrypts
with whichever key the JWE's `kid` names.

## Timing rules

The lifecycle only works if rotations are far enough apart:

- **Rotation interval > the OpenID Connect server's JWKS cache lifetime.**
  Otherwise a `sig` key can start signing before the server has cached it,
  and an `enc` key can be deleted while the server still encrypts to it.
- **Rotation interval > how long your server caches the secret.** See
  [Using the keys](using-the-keys.md).
- **Don't rotate twice within the OpenID Connect server's JWKS cache
  lifetime.** Each rotation moves every key one stage on, so two quick
  rotations skip the waiting periods above: a `sig` key starts signing moments
  after it was published, and an `enc` key is deleted moments after it was
  unpublished.

Watch out for rotations you don't trigger on purpose. The construct creates the
schedule with `rotateImmediatelyOnUpdate`, which is what initialises the
secret at deployment, but it also means that **any change to the schedule
(e.g. `rotationScheduleProps.automaticallyAfter`) rotates immediately**. A single extra rotation after a
normal interval is fine; one shortly after another rotation, such as a manual
`rotate-secret` or a second schedule change, is not.

## What the rotation Lambda does

Secrets Manager calls the Lambda once for each step of a rotation, with a
`ClientRequestToken` identifying the new, pending version of the secret. Steps
can be retried, so each one is safe to run more than once.

| Step           | What it does                                                                                                                                                  |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `createSecret` | Unless the pending version already exists, reads the current JWKS, computes the next one (initialising an empty secret with 2 keys) and stores it as pending. |
| `setSecret`    | Nothing: there is no other system to update, since the OpenID Connect server fetches the public keys itself.                                                  |
| `testSecret`   | Checks the pending JWKS (see below). A failure stops the rotation.                                                                                            |
| `finishSecret` | Makes the pending version current (moves the `AWSCURRENT` label to it).                                                                                       |

`testSecret` checks that the pending JWKS:

- is well-formed: 2 or 3 keys, each `kid` unique and equal to the key's
  RFC 7638 thumbprint, RSA keys of at least 2048 bits
- follows the layout above, with no private members left on a retired `sig` key
- matches the configured key options
- is exactly the rotation of the current JWKS: the kept keys unchanged and in
  order, the retired `sig` key stripped of its private part, and one new key

The Lambda logs key ids only, never key material.

## When a rotation fails

A failed rotation never changes the current secret: your server and the
OpenID Connect server carry on with the existing keys. The error is in the
rotation Lambda's log group, and the secret's `LastRotatedDate` stays at the
last successful rotation. Once the cause is fixed, rotate again with
`aws secretsmanager rotate-secret --secret-id <arn>`. If Secrets Manager
reports that a previous rotation isn't complete, first remove the `AWSPENDING`
label from the failed version (its id is in `describe-secret` output):

```sh
aws secretsmanager update-secret-version-stage --secret-id <arn> --version-stage AWSPENDING --remove-from-version-id <version-id>
```

## Changing the key options

The key options (`use`, `algorithm`, `curve`, `rsaModulusLength`) can't be
changed on an existing secret. If they no longer match the keys in the secret,
`createSecret` fails with an error listing the differences. To change them,
create a new `JwksSecret` (a new construct id), register its JWKS with the
OpenID Connect server, and switch your server over to it.

## See also

- [README](../README.md): props, including the supported algorithms, and
  the AWS resources it creates
- [Using the keys](using-the-keys.md): serving the JWKS and signing or
  decrypting with the keys
