# lakefs-authz

The lakeFS authorization server. It implements `api/authorization.yml` of lakeFS 1.86.0 on PostgreSQL and
stores users, groups, policies, and access keys. lakeFS evaluates the policies itself and uses this server as
its store, which gives open-source lakeFS multi-user RBAC.

The [Installation](https://ion-elgreco.github.io/lakefs-auth/latest/installation/) pages show how to run it with Docker Compose or Helm.

## Configuration

Every flag has a `LAKEFS_AUTHZ_*` environment variable. Boolean flags take a value, so
`LAKEFS_AUTHZ_RUN_MIGRATIONS=false` and `--run-migrations false` both work.

<details class="note" markdown="1">
<summary>Server</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--listen` | `LAKEFS_AUTHZ_LISTEN` | `0.0.0.0:8002` | Address the server binds to. |
| `--base-path` | `LAKEFS_AUTHZ_BASE_PATH` | `/api/v1` | Path prefix of every route. Must match the suffix of lakeFS `auth.api.endpoint`. |
| `--request-timeout` | `LAKEFS_AUTHZ_REQUEST_TIMEOUT` | `30s` | Server-side timeout per request. lakeFS has no client timeout toward this server. |
| `--cors-allow-origins` | `LAKEFS_AUTHZ_CORS_ALLOW_ORIGINS` | empty | Browser origins that may call the API, comma separated. Empty sends no CORS headers; `*` allows any origin. |
| `--metrics-listen` | `LAKEFS_AUTHZ_METRICS_LISTEN` | unset | Address for the Prometheus `/metrics` endpoint, for example `0.0.0.0:9090`. Unset keeps it off. |
| `--builder-listen` | `LAKEFS_AUTHZ_BUILDER_LISTEN` | unset | Address for the policy builder page, for example `127.0.0.1:8080`. Unset keeps it off. Callers act with their own lakeFS session cookie. |
| `--lakefs-endpoint` | `LAKEFS_AUTHZ_LAKEFS_ENDPOINT` | unset | lakeFS API endpoint with its version prefix, for example `http://lakefs:8000/api/v1`. Lets the policy builder offer live names. It stores no credential: each call forwards the caller's own lakeFS session cookie, so lakeFS decides what they may see. |
| `--log-level` | `LAKEFS_AUTHZ_LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, or `trace`. |
| `--log-format` | `LAKEFS_AUTHZ_LOG_FORMAT` | `text` | `text` for people, `json` for log pipelines. |

</details>

<details class="note" markdown="1">
<summary>Access from lakeFS</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--secret-key` | `LAKEFS_AUTHZ_SECRET_KEY` | none | The lakeFS `auth.encrypt.secret_key`. Verifies the bearer token lakeFS mints and, without `--encryption-key`, encrypts credential secrets. With `--api-token` set it only encrypts, so one of `--secret-key` and `--encryption-key` is always required. |
| `--api-token` | `LAKEFS_AUTHZ_API_TOKEN` | none | Static bearer token, the same value as lakeFS `auth.api.token`. Compared in constant time. When set, it is the only token accepted; give lakefs-authn the same value in `--authz-token`. |
| `--disable-auth` | `LAKEFS_AUTHZ_DISABLE_AUTH` | `false` | Accepts every request without a bearer token. Development only; logs a warning at startup. |

</details>

<details class="note" markdown="1">
<summary>Database</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--database-url` | `LAKEFS_AUTHZ_DATABASE_URL` | required | PostgreSQL connection string. |
| `--database-max-connections` | `LAKEFS_AUTHZ_DATABASE_MAX_CONNECTIONS` | `10` | Size of the connection pool. |
| `--run-migrations` | `LAKEFS_AUTHZ_RUN_MIGRATIONS` | `true` | Runs the embedded migrations at startup. Set `false` when a separate job owns the schema. |
| `--token-cleanup-interval` | `LAKEFS_AUTHZ_TOKEN_CLEANUP_INTERVAL` | `5m` | How often expired claimed token ids are deleted. |

</details>

<details class="note" markdown="1">
<summary>Setup and stored secrets</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--bootstrap-file` | `LAKEFS_AUTHZ_BOOTSTRAP_FILE` | none | YAML file with policies, groups, and users to create when they are missing. See the bootstrap page. |
| `--encryption-key` | `LAKEFS_AUTHZ_ENCRYPTION_KEY` | the secret key | Source of the key that encrypts stored access key secrets. Set it from the start and keep it stable; see the Notes below. |

</details>

## Notes

- **Bearer token.** With an empty lakeFS `auth.api.token`, lakeFS mints an HS256 token from the shared secret
  and `--secret-key` verifies it. To use a static token instead, set the same value in lakeFS `auth.api.token`
  and in `--api-token`. A configured static token switches the shared-secret token off, because lakeFS then
  never mints one; the shared secret still serves credential encryption.
- **Credential encryption.** Access key secrets are stored encrypted with AES-256-GCM under a key derived from
  `--encryption-key`, or from `--secret-key` when that flag is unset. Set `--encryption-key` from the start to
  rotate the lakeFS secret later without losing stored secrets. See
  [Secrets](https://ion-elgreco.github.io/lakefs-auth/latest/installation/secrets/).
- **Repeated creates.** A create of a user, group, or policy that already exists with the same content answers
  201 with the stored row, so a repeated lakeFS setup succeeds, for example after a reset of the lakeFS metadata
  without a reset of this database. A duplicate with different content, such as a policy with other statements,
  answers 409.
- **Health.** `GET /api/v1/healthcheck` answers 204 without a token and without touching the database. lakeFS
  calls it and `GET /config/version` at startup and stops on a failure. `GET /readyz`, at the root, pings the
  database and answers 200 or 503; it is the readiness probe.
- **Bootstrap and existing users.** A bootstrap entry for a user that already exists applies its groups,
  policies, and credentials only when the row is the same identity, that is, the `external_id` matches. A
  name that an identity provider login took first makes the bootstrap fail, so that the entry never
  decorates a stranger's account.
- **Not implemented.** `POST /auth/users` with `invite: true` answers 400, because this server sends no email.
  Password changes answer 501; lakeFS does not call that route in the supported configuration. The external
  principal routes are served, although lakefs-authn does not offer the login through them yet.
