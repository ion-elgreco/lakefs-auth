# lakefs-authn

The lakeFS authentication server. It implements `api/authentication.yml` of lakeFS and turns an OIDC login into a
lakeFS session, for browsers through `/oidc/login` and for the lakeFS SDKs through the token login. The
[authentication flows](https://ion-elgreco.github.io/lakefs-auth/latest/authn-flows/) page shows how each login
works.

The [Installation](https://ion-elgreco.github.io/lakefs-auth/latest/installation/) pages show how to run it with Docker Compose or Helm.

## Configuration

Every flag has a `LAKEFS_AUTHN_*` environment variable. Boolean flags take an explicit value, so
`LAKEFS_AUTHN_GROUP_MAP_STRICT=false` works.

<details class="note" markdown="1">
<summary>Server</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--listen` | `LAKEFS_AUTHN_LISTEN` | `0.0.0.0:8001` | Address the server binds to. |
| `--public-url` | `LAKEFS_AUTHN_PUBLIC_URL` | required | External base URL of this server. The redirect URI is `<public-url>/oidc/callback`, and an `https` scheme makes the cookie `Secure`. |
| `--api-base-path` | `LAKEFS_AUTHN_API_BASE_PATH` | `/api/v1` | Path prefix of the lakeFS authentication API routes. Must match the suffix of lakeFS `auth.authentication_api.endpoint`. |
| `--request-timeout` | `LAKEFS_AUTHN_REQUEST_TIMEOUT` | `30s` | Server-side ceiling per request, so a hung identity provider or authorization server cannot pin a connection. |
| `--metrics-listen` | `LAKEFS_AUTHN_METRICS_LISTEN` | unset | Address for the Prometheus `/metrics` endpoint, for example `0.0.0.0:9090`. Unset keeps it off. |
| `--log-level` | `LAKEFS_AUTHN_LOG_LEVEL` | `info` | `error`, `warn`, `info`, `debug`, or `trace`. |
| `--log-format` | `LAKEFS_AUTHN_LOG_FORMAT` | `text` | `text` for people, `json` for log pipelines. |

</details>

<details class="note" markdown="1">
<summary>lakeFS and lakefs-authz</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--secret-key` | `LAKEFS_AUTHN_SECRET_KEY` | required | The lakeFS `auth.encrypt.secret_key`. Signs the session cookie and the login token. |
| `--authz-url` | `LAKEFS_AUTHN_AUTHZ_URL` | required | Base URL of lakefs-authz, including `/api/v1`. |
| `--authz-token` | `LAKEFS_AUTHN_AUTHZ_TOKEN` | none | Static bearer token for lakefs-authz, the same value as its `--api-token`. Without it the server mints the lakeFS internal token from the shared secret. |

</details>

<details class="note" markdown="1">
<summary>Identity provider</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--oidc-issuer` | `LAKEFS_AUTHN_OIDC_ISSUER` | required | Issuer URL. Discovery appends `/.well-known/openid-configuration` and compares the advertised issuer byte for byte. |
| `--oidc-client-id` | `LAKEFS_AUTHN_OIDC_CLIENT_ID` | required | Client id registered at the identity provider. |
| `--oidc-client-secret` | `LAKEFS_AUTHN_OIDC_CLIENT_SECRET` | none | Client secret. Leave it unset for a public client. |
| `--oidc-client-secret-file` | `LAKEFS_AUTHN_OIDC_CLIENT_SECRET_FILE` | none | File with the client secret, read at startup when `--oidc-client-secret` is unset. For mounted secrets. |
| `--oidc-scopes` | `LAKEFS_AUTHN_OIDC_SCOPES` | `openid,profile,email` | Scopes requested at login. Add the scope that carries the groups claim when you use one. |
| `--oidc-validate-claims` | `LAKEFS_AUTHN_OIDC_VALIDATE_CLAIMS` | empty | Claims that must match before a login is accepted, as `key=value,key=value`, for example `hd=example.com`. The value is compared exactly against the flattened claim, so an array matches as `a,b`; an item without `=` continues the value before it, so `aud=lakefs,other` expects the array `["lakefs", "other"]`. |
| `--discovery-refresh-interval` | `LAKEFS_AUTHN_DISCOVERY_REFRESH_INTERVAL` | `1h` | How often the provider metadata and signing keys are refreshed. |
| `--discovery-min-refresh-interval` | `LAKEFS_AUTHN_DISCOVERY_MIN_REFRESH_INTERVAL` | `60s` | Shortest gap between two refreshes triggered by an unknown signing key. |
| `--discovery-timeout` | `LAKEFS_AUTHN_DISCOVERY_TIMEOUT` | `10s` | Timeout of one request to the identity provider: discovery, the JWKS, and the authorization code exchange. |

</details>

<details class="note" markdown="1">
<summary>Users and groups</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--username-claim` | `LAKEFS_AUTHN_USERNAME_CLAIM` | `preferred_username,email,sub` | Claims tried in order for the lakeFS username of a new user. |
| `--friendly-name-claim` | `LAKEFS_AUTHN_FRIENDLY_NAME_CLAIM` | `name` | Claim used as the display name. |
| `--persist-friendly-name` | `LAKEFS_AUTHN_PERSIST_FRIENDLY_NAME` | `true` | Stores the display name in lakefs-authz and refreshes it at every login. |
| `--auth-source` | `LAKEFS_AUTHN_AUTH_SOURCE` | `oidc` | Value stored as the `source` of the users this server creates. |
| `--auto-provision` | `LAKEFS_AUTHN_AUTO_PROVISION` | `true` | Creates a lakeFS user at the first login of an unknown identity. With `false` only users that already exist can sign in, for example the ones a bootstrap file creates with their `external_id`. |
| `--initial-groups` | `LAKEFS_AUTHN_INITIAL_GROUPS` | `Developers` | Groups a new user joins when no groups claim resolves. They must exist in lakefs-authz. |
| `--groups-claim` | `LAKEFS_AUTHN_GROUPS_CLAIM` | none | Claim that lists the user's groups, as a string list or a comma separated string. |
| `--group-map` | `LAKEFS_AUTHN_GROUP_MAP` | empty | Renames provider groups to lakeFS groups, as `idp-name=lakefs-name,...`. |
| `--group-map-strict` | `LAKEFS_AUTHN_GROUP_MAP_STRICT` | `true` | Drops groups that the map does not mention; when none is left the user joins no group. With `false`, unmapped groups keep their provider name. |

</details>

<details class="note" markdown="1">
<summary>Browser session</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--session-ttl` | `LAKEFS_AUTHN_SESSION_TTL` | `168h` | Lifetime of the session cookie. The cookie format caps it at 30 days. |
| `--cookie-secure` | `LAKEFS_AUTHN_COOKIE_SECURE` | from `--public-url` | `true` when the public URL uses `https`. Set it only to override that. |
| `--cookie-domain` | `LAKEFS_AUTHN_COOKIE_DOMAIN` | none | `Domain` attribute of the session cookie, for a cookie shared across subdomains. |
| `--post-login-redirect-url` | `LAKEFS_AUTHN_POST_LOGIN_REDIRECT_URL` | `/` | Where the browser goes after login when `next` is absent. A relative `next` is resolved against it, so use the absolute lakeFS URL when lakeFS is on another origin. |
| `--post-logout-redirect-url` | `LAKEFS_AUTHN_POST_LOGOUT_REDIRECT_URL` | `/auth/login` | Where the browser goes after logout. |
| `--allowed-redirect-hosts` | `LAKEFS_AUTHN_ALLOWED_REDIRECT_HOSTS` | empty | Origins that an absolute `next` URL may point at, as `host`, `host:port`, or `scheme://host[:port]`. A bare host matches the default port only. Relative paths are always allowed. |
| `--rp-initiated-logout` | `LAKEFS_AUTHN_RP_INITIATED_LOGOUT` | `false` | Sends the browser to the provider `end_session_endpoint` on logout, so the provider session ends too. |

</details>

<details class="note" markdown="1">
<summary>SDK login</summary>

| Flag | Environment variable | Default | Comment |
|---|---|---|---|
| `--state-is-pkce-verifier` | `LAKEFS_AUTHN_STATE_IS_PKCE_VERIFIER` | `true` | For the SDK login: the lakeFS client sends the PKCE verifier in `state`. |
| `--sts-allowed-redirect-uris` | `LAKEFS_AUTHN_STS_ALLOWED_REDIRECT_URIS` | empty | Allow list for the `redirect_uri` of the SDK login. Empty refuses every SDK login. A loopback entry without a port, such as `http://127.0.0.1/callback`, matches any port; other entries match exactly. |

</details>

## How a login becomes a user

A login identifies a lakeFS user by the `sub` claim of the ID token. The first login creates that user with a
username from `--username-claim` and puts it in `--initial-groups`, which must already exist in lakefs-authz.
Later logins do not sync the user again, so a group you change in lakeFS stays as you set it.

Set `--groups-claim` to take the groups from the identity provider instead, and `--group-map` to rename them
to lakeFS group names. Set `--auto-provision false` to create no users at all; then every user needs an entry
with an `external_id` in the lakefs-authz bootstrap file.

The [authentication flows](https://ion-elgreco.github.io/lakefs-auth/latest/authn-flows/) page shows the
sequence and the edge cases.
