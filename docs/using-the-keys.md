# Using the keys in your server

Your server reads the secret, serves the public keys from its JWKS endpoint
(registered as the client's `jwks_uri` with the OpenID Connect server) and uses
the private keys. See [How rotation works](how-rotation-works.md) for why the
rules below are what they are.

## Requirements

1. **Read the `AWSCURRENT` version of the secret.** Grant access with
   `jwksSecret.grantRead(role)`.
2. **Re-read it periodically.** Rotation changes the keys; cache the secret for
   at most a fraction of the rotation interval (e.g. an hour).
3. **Handle an uninitialised secret.** Until the first rotation completes,
   shortly after the stack is deployed, the secret is `{"keys":[]}`.
4. **Never serve private members.** Remove `d`, `p`, `q`, `dp`, `dq`, `qi`
   (and `oth`) from every published key.

### `sig` keys (e.g. `private_key_jwt`)

- **Publish:** every key in the secret, public members only.
- **Sign with:** the first key that has `d`. Put its `kid` and `alg` in the JWS
  header.

### `enc` keys

- **Publish:** every key, except the first one when there are 3 keys. Public
  members only.
- **Decrypt with:** the key whose `kid` matches the JWE header. Every key in the
  secret has its private part.
- **Re-read the secret on an unknown `kid`.** A rotation publishes a new key
  straight away, so the OpenID Connect server may encrypt to it before your
  server's cached copy of the secret has it. Re-read the secret once and try
  again before rejecting the JWE. (Signing keys don't need this: a new `sig`
  key isn't used for a whole rotation interval.)

## Helpers (JavaScript / TypeScript)

The rules above are implemented in `cdk-jwks-secret/jwks`, which does not
depend on the AWS CDK or the AWS SDK:

```ts
import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { parseJwks, selectDecryptionKey, selectSigningKey, toPublicJwks } from 'cdk-jwks-secret/jwks';

const client = new SecretsManagerClient({});
const { SecretString } = await client.send(
  new GetSecretValueCommand({ SecretId: process.env.JWKS_SECRET_ARN }),
);
const jwks = parseJwks(SecretString!); // validates structure and kids

// JWKS endpoint (both sig and enc)
const body = JSON.stringify(toPublicJwks(jwks));

// sig: private_key_jwt client assertion
const signingKey = selectSigningKey(jwks); // { kid, alg, ...private JWK }

// enc: decrypt a JWE
const decryptionKey = selectDecryptionKey(jwks, protectedHeader.kid);
```

`selectSigningKey` throws on an uninitialised secret or `enc` keys;
`selectDecryptionKey` returns `undefined` for an unknown `kid`, which is when to
re-read the secret, and throws on `sig` keys. `toPublicJwks` returns `{"keys":[]}` for an uninitialised secret.

## Other languages

Implement the two rules for your key use:

```
sig:  publish = keys.map(publicMembers)
      signingKey = first key with "d"

enc:  publish = (keys.length == 3 ? keys[1..] : keys).map(publicMembers)
      decryptionKey = key with matching "kid" (re-read the secret once if none)
```

The key use is the `use` member of any key; all keys in a secret share it.

## Signing and encryption keys on one `jwks_uri`

A client registers a single `jwks_uri`, so a client that both signs (e.g.
`private_key_jwt`) and decrypts (e.g. encrypted ID tokens) serves the keys of
two secrets, one with `use: 'sig'` and one with `use: 'enc'`, in one JWKS.
Apply each secret's rule and concatenate the keys:

```ts
const jwksList = [sigSecretString, encSecretString].map(parseJwks);
const body = JSON.stringify({ keys: jwksList.flatMap((jwks) => toPublicJwks(jwks).keys) });
```

The OpenID Connect server tells the keys apart by their `use`. The example app
in [`bin/`](../bin) serves its two secrets this way.
