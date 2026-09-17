# Installation

lakefs-auth runs as two containers next to lakeFS: lakefs-authz with a PostgreSQL database, and lakefs-authn.
This page lists what every setup needs. Then follow the [Docker](docker.md) or the [Helm](helm.md) page.

## Before you begin

- **lakeFS** 1.86 or newer, and a PostgreSQL database for lakefs-authz.
- **One host name for lakeFS and lakefs-authn.** Browsers scope cookies by host, so the `/oidc/` prefix of the
  lakeFS URL must reach lakefs-authn. Both setups do that with a reverse proxy or an Ingress rule.
- **An OIDC client.** Register a client at the identity provider with the redirect URI
  `<lakeFS URL>/oidc/callback`. Keep the issuer URL exactly as the provider advertises it, the client id, and
  the client secret.
- **A decision: the lakeFS default roles or your own.** With `auth.ui_config.rbac: internal` the lakeFS setup
  creates the groups Admins, SuperUsers, Developers, and Viewers with their policies. With `external` lakeFS
  creates nothing, so a [bootstrap file](bootstrap.md) on lakefs-authz must seed the policies, the groups, the
  admin user, and its access key. Decide before the first start, because the lakeFS setup runs once.
- **A shared secret.** One random string that lakeFS, lakefs-authz, and lakefs-authn all use.
  `openssl rand -hex 32` makes one. [Secrets](secrets.md) explains what it protects and how to rotate it.
- **Optional, for the [policy builder](../tools/policy-builder.md).** It signs you in with the lakeFS session
  cookie, so serve it from the lakeFS host name. Its own port needs no setup: a cookie set by
  `lakefs.example.com` also reaches `lakefs.example.com:8080`. Its own host name does: give lakefs-authn
  `--cookie-domain .example.com` so the cookie reaches `authz.example.com` as well.

## What lakeFS needs

Both setups give lakeFS the same settings:

```yaml title="config.yaml"
auth:
  encrypt:
    secret_key: "<shared secret>"
  api:
    endpoint: http://authz:8002/api/v1          # lakefs-authz, base path included
  authentication_api:
    endpoint: http://authn:8001/api/v1          # lakefs-authn, base path included
  ui_config:
    rbac: internal                              # or external, see the decision above
    fallback_login_url: /oidc/login
    fallback_login_label: "Sign in with SSO"
    logout_url: /oidc/logout
    login_cookie_names: [internal_auth_session]
email_subscription:
  enabled: false                                # skip the welcome page before the setup wizard
```

The Docker page passes them as environment variables. The Helm page passes them through the lakeFS chart.

Two more settings decide how the lakeFS setup runs, so choose them now. Without them, lakeFS shows a welcome
page that asks for an email address and a country, and then the setup wizard. `email_subscription.enabled:
false` above removes the welcome page; as an environment variable it reads
`LAKEFS_EMAIL_SUBSCRIPTION_ENABLED=false`. To skip the wizard as well, set `LAKEFS_INSTALLATION_USER_NAME`,
`LAKEFS_INSTALLATION_ACCESS_KEY_ID`, and `LAKEFS_INSTALLATION_SECRET_ACCESS_KEY`, and lakeFS runs the setup
itself at start.

## After the install

1. Check the servers. `GET /api/v1/healthcheck` on lakefs-authz answers 204. `GET /readyz` on lakefs-authn
   answers 200 once it has reached the identity provider, and 503 with the reason in its log until then.
2. Complete the lakeFS setup wizard, unless the installation variables above already ran the setup at start.
   It runs once, and with `rbac: internal` it creates the groups Admins, SuperUsers, Developers, and Viewers,
   their policies, and the admin user in lakefs-authz. With `rbac: external` no wizard appears, because the
   bootstrap file already created all of that.
3. Open lakeFS and click **Sign in with SSO**. The first login creates the user in lakefs-authz and adds it to
   the Developers group.

