# lakefs-auth

[Documentation](https://ion-elgreco.github.io/lakefs-auth/) · [Issues](https://github.com/ion-elgreco/lakefs-auth/issues)

Two Rust servers that give open-source [lakeFS](https://lakefs.io) multi-user RBAC and OIDC single sign-on:

- **lakefs-authz** implements the lakeFS authorization API (`api/authorization.yml`). It stores users, groups,
  policies, and access keys in PostgreSQL. lakeFS evaluates policies itself and uses this server as the store.
- **lakefs-authn** implements the lakeFS authentication API (`api/authentication.yml`) with OIDC. It runs the
  browser login, provisions the user in lakefs-authz, and hands lakeFS a session cookie. It also serves the token
  login that the lakeFS SDKs use (the lakeFS `sts/login` operation).

Open-source lakeFS ships the clients for both APIs but no server. In its default mode it stores one user only.

## Install

The [Installation](https://ion-elgreco.github.io/lakefs-auth/latest/installation/) pages cover a Docker Compose setup
(`examples/docker`) and the Helm chart (`deploy/helm/lakefs-auth`).

## lakeFS configuration

```yaml
auth:
  encrypt:
    secret_key: "<shared secret, identical in lakeFS, lakefs-authz, and lakefs-authn>"
  api:
    endpoint: http://authz:8002/api/v1        # lakefs-authz, base path included
  authentication_api:
    endpoint: http://authn:8001/api/v1        # lakefs-authn, base path included
  ui_config:
    rbac: internal                             # lakeFS runs its own setup against lakefs-authz
    fallback_login_url: /oidc/login            # link shown on the lakeFS login page
    fallback_login_label: "Sign in with SSO"
    logout_url: /oidc/logout
    login_cookie_names: [internal_auth_session]
```

Browsers scope cookies by host, so in production a reverse proxy on the lakeFS host must route the `/oidc/`
prefix to lakefs-authn. Ports do not isolate cookies, which is why the compose example works without a proxy.


## Local demo

The demo needs Docker, [just](https://just.systems), `cargo-zigbuild`, and `zig`
(see [Container images](#container-images)).

```bash
just demo-up      # cross-compiles both servers, builds their images, and starts the stack
just demo-smoke   # logs in through OIDC without a browser and calls lakeFS with the resulting cookie
```

Then open <http://localhost:8000> and click **Sign in with SSO**. Sign in as `admin` / `admin` for the
lakeFS `Admins` group, or as `user` / `user` for `Developers`. The stack also serves the
[policy builder](docs/tools/policy-builder.md) on <http://localhost:8080>, filled with the real repository,
user, and group names that your session may see. Stop with `just demo-down`.
