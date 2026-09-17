# Operations

What to watch and what to expect once the servers run.

## Health checks

| Server | Endpoint | Answer |
|---|---|---|
| lakefs-authz | `GET /api/v1/healthcheck` | 204 when the process runs |
| lakefs-authz | `GET /readyz` | 200 when the database answers, 503 otherwise |
| lakefs-authn | `GET /healthz` | 200 when the process runs |
| lakefs-authn | `GET /readyz` | 200 after OIDC discovery succeeded, 503 until then |

Use `/healthcheck` and `/healthz` as liveness probes and `/readyz` as the readiness probe of both servers. The
`/readyz` routes live at the root, outside the API base path, and need no bearer token. A lakefs-authz replica
whose database is unreachable leaves the Service until the database is back. Until discovery succeeds, the
login routes of lakefs-authn answer 503 too, and the log line `OpenID Connect discovery failed, retrying`
carries the cause, for example a wrong issuer.

## Logs

Both servers log through `tracing` as text or JSON, selected with `--log-format`. They honour the
`X-Request-ID` header that lakeFS forwards, so one request can be followed across lakeFS and both servers. They
never log tokens, secrets, authorization codes, or cookie values.

## Metrics

Both servers expose Prometheus metrics, but only when you give them an address:
`--metrics-listen 0.0.0.0:9090`, or `LAKEFS_AUTHZ_METRICS_LISTEN` and `LAKEFS_AUTHN_METRICS_LISTEN`. The
endpoint gets its own listener, so put it on a port that only your monitoring reaches and never on the API
address. The Helm chart wires it through `authz.metrics.enabled` and `authn.metrics.enabled`, which add a
`metrics` port to the Service for a ServiceMonitor to target.

Every route of both servers reports these:

| Metric | Type | Labels |
| --- | --- | --- |
| `lakefs_auth_http_requests_total` | counter | `method`, `route`, `status` |
| `lakefs_auth_http_request_duration_seconds` | histogram | `method`, `route` |
| `lakefs_auth_http_requests_in_flight` | gauge | none |

The `route` label is the matched route pattern, such as `/api/v1/auth/users/{userId}`, never the request URI.
A user name therefore cannot turn into a label value, and the series count stays bounded. A request that
matches no route is labelled `<unmatched>`, and a method outside the nine standard verbs is labelled
`<other>`. A request whose client went away before the response was ready is counted with
`status="cancelled"`.

Each server adds its own:

| Metric | Type | Labels | Server |
| --- | --- | --- | --- |
| `lakefs_authn_browser_logins_total` | counter | `outcome` | lakefs-authn |
| `lakefs_authn_oidc_discovery_total` | counter | `outcome` | lakefs-authn |
| `lakefs_authz_db_connections` | gauge | `state` | lakefs-authz |

Two of these answer the questions that come up first. A rising
`lakefs_authn_oidc_discovery_total{outcome="failure"}` means the identity provider is unreachable, so logins
are about to stop. A `lakefs_authz_db_connections{state="idle"}` pinned at zero while `in_use` sits at the pool
maximum means the database has become the bottleneck.

## Timeouts and caching

lakeFS has no client timeout toward either server, so both enforce their own: 30 seconds by default,
`--request-timeout` on each. lakeFS caches credentials, users, and effective policies for 20 seconds
(`auth.cache.*`), so a change in lakefs-authz takes up to that long to apply. Disable the cache in tests.

## Database

lakefs-authz runs its embedded migrations at start unless `--run-migrations false`. The migrations run inside a database lock, so several replicas can start at the same time. Back the database up like any PostgreSQL database. Access key secrets are stored encrypted, so the
database alone does not reveal them; see [Secrets](installation/secrets.md).

## Upgrades and restarts

Both servers stop on SIGTERM and finish in-flight requests first, so a rolling restart loses no request. A
restart of lakefs-authz re-applies the [bootstrap file](installation/bootstrap.md) and adds what is missing. A
restart of lakefs-authn ends no session, because sessions live in the cookie.
