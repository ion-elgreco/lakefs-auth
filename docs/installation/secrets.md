# Secrets

Three secrets exist in a lakefs-auth setup: the shared secret that ties lakeFS and both servers together, an
optional separate key for stored access key secrets, and the OIDC client secret.

## Where each value goes

One random string, the shared secret, goes into all three services. A second string, the encryption key, goes
into lakefs-authz only. `openssl rand -hex 32` makes each one.

<div class="grid" markdown>

```yaml title="lakeFS config.yaml"
auth:
  encrypt:
    secret_key: "<shared secret>"
```

```ini title="lakefs-authz environment"
LAKEFS_AUTHZ_SECRET_KEY=<shared secret>
LAKEFS_AUTHZ_ENCRYPTION_KEY=<encryption key>
```

```ini title="lakefs-authn environment"
LAKEFS_AUTHN_SECRET_KEY=<shared secret>
```

</div>

## What each one protects

The shared secret signs and verifies the tokens between the three services: the bearer token lakeFS mints for
lakefs-authz, and the session cookie lakefs-authn writes for the browser. Rotating it ends every session.

The encryption key encrypts the access key secrets that lakefs-authz stores. Only lakefs-authz encrypts
anything, so only it has this setting. Leave it unset and lakefs-authz encrypts with the shared secret
instead, which is why rotating the shared secret then makes every stored access key secret unreadable.

Set the encryption key before the first access key exists and keep it stable or rotate when needed separately
from the secret key.

## Rotate the shared secret

With the encryption key set, you can rotate the shared secret in two steps:

1. Set the same new value in lakeFS `auth.encrypt.secret_key`, in `LAKEFS_AUTHZ_SECRET_KEY` on lakefs-authz,
   and in `LAKEFS_AUTHN_SECRET_KEY` on lakefs-authn.
2. Restart the three services. Browser sessions end and users log in again. Stored access keys keep working.

## The OIDC client secret

lakefs-authn reads the client secret from `--oidc-client-secret`, or from the file named by
`--oidc-client-secret-file` when the flag is unset. The file form lets a setup job or a secret manager hand the
value over through a mounted volume. Leave both unset for a public client.

When the identity provider rotates the client secret, restart lakefs-authn with the new value. Sessions that
already exist keep working, because the session cookie is signed with the shared secret, not with the client
secret.
