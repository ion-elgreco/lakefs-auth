# Helm

The `lakefs-auth` chart installs lakefs-authz and lakefs-authn. lakeFS itself comes from the
[lakeFS chart](https://github.com/treeverse/charts), and PostgreSQL from your platform.

## Before you begin

- A Kubernetes cluster, `kubectl`, and `helm` 3.8 or newer for OCI registries.
- A PostgreSQL database that the cluster can reach.
- The items from [Installation](index.md): the OIDC client and the shared secret.
- Optional: `helmfile` 1.0 or newer, to install both charts with one command. See
  [Both charts with helmfile](#both-charts-with-helmfile).

## 1. Create the Secrets

The chart reads every secret from a Secret that you manage. The key `auth_encrypt_secret_key` is also the
default of the lakeFS chart, so one Secret serves both charts.

```bash
kubectl create namespace lakefs
kubectl -n lakefs create secret generic lakefs-shared-secret \
  --from-literal=auth_encrypt_secret_key="$(openssl rand -hex 32)"
kubectl -n lakefs create secret generic lakefs-authz-database \
  --from-literal=database-url='postgres://authz:<password>@postgres.example.internal:5432/authz'
kubectl -n lakefs create secret generic lakefs-oidc \
  --from-literal=client-secret='<client secret>'
```

## 2. Install the chart

```yaml title="lakefs-auth-values.yaml"
sharedSecret:
  existingSecret: lakefs-shared-secret
authz:
  database:
    existingSecret: lakefs-authz-database
authn:
  publicUrl: https://lakefs.example.com
  oidc:
    issuer: https://idp.example.com/realms/lakefs
    clientId: lakefs
    clientSecret:
      existingSecret: lakefs-oidc
  # Routes https://lakefs.example.com/oidc/ to lakefs-authn. lakeFS keeps its own Ingress for /.
  ingress:
    enabled: true
    className: nginx
    host: lakefs.example.com
    tls:
      enabled: true
      secretName: lakefs-tls
```

With the Gateway API instead of an Ingress, attach an HTTPRoute to your Gateway. It matches the `/oidc` prefix
by default:

```yaml title="lakefs-auth-values.yaml"
authn:
  httpRoute:
    enabled: true
    parentRefs:
      - name: public
        namespace: gateway-system
    hostnames: [lakefs.example.com]
```

```bash
helm install lakefs-auth oci://ghcr.io/ion-elgreco/charts/lakefs-auth \
  --version <version> --namespace lakefs --values lakefs-auth-values.yaml
kubectl -n lakefs rollout status deploy/lakefs-authz
kubectl -n lakefs rollout status deploy/lakefs-authn
```

`<version>` is a release from the [releases page](https://github.com/ion-elgreco/lakefs-auth/releases).
lakefs-authn becomes ready once it has reached the identity provider. Until then
`kubectl -n lakefs logs deploy/lakefs-authn` shows why not.

## 3. Point lakeFS at the servers

With the lakeFS chart, reuse the shared Secret and add the auth settings to `lakefsConfig`. Enable its Ingress
for `/` on the same host, and configure its database and object store as the lakeFS documentation describes.

```yaml title="lakefs-values.yaml"
existingSecret: lakefs-shared-secret
lakefsConfig: |
  auth:
    api:
      endpoint: http://lakefs-authz.lakefs.svc:8002/api/v1
    authentication_api:
      endpoint: http://lakefs-authn.lakefs.svc:8001/api/v1
    ui_config:
      rbac: internal
      fallback_login_url: /oidc/login
      fallback_login_label: "Sign in with SSO"
      logout_url: /oidc/logout
      login_cookie_names: [internal_auth_session]
  email_subscription:
    enabled: false
```

```bash
helm repo add lakefs https://charts.lakefs.io
helm upgrade --install lakefs lakefs/lakefs --namespace lakefs --values lakefs-values.yaml
```

Then continue with [After the install](index.md#after-the-install).

<details class="note" id="both-charts-with-helmfile" markdown="1">
<summary>Both charts with helmfile</summary>

[helmfile](https://helmfile.readthedocs.io/) declares the two releases in one file. One command then does
step 2 and step 3 together, in that order, with the host name written once.

Step 1 stays as it is. helmfile reads the Secrets, it does not create them.

The file name ends with `.gotmpl`. helmfile 1.0 renders `{{ ... }}` only in a file with that extension, and
reads a plain `helmfile.yaml` as literal YAML.

```yaml title="helmfile.yaml.gotmpl"
environments:
  default:
    values:
      # The one host that serves lakeFS on `/` and lakefs-authn on `/oidc`.
      - host: lakefs.example.com
        namespace: lakefs
        # A release from https://github.com/ion-elgreco/lakefs-auth/releases.
        lakefsAuthVersion: <version>
---
repositories:
  - name: lakefs
    url: https://charts.lakefs.io
  - name: lakefs-auth
    url: ghcr.io/ion-elgreco/charts
    oci: true

releases:
  - name: lakefs-auth
    namespace: {{ .Values.namespace }}
    chart: lakefs-auth/lakefs-auth
    version: {{ .Values.lakefsAuthVersion }}
    # Hold the install until lakefs-authz and lakefs-authn are ready.
    wait: true
    values:
      - lakefs-auth-values.yaml
      - authn:
          publicUrl: https://{{ .Values.host }}
          ingress:
            host: {{ .Values.host }}

  - name: lakefs
    namespace: {{ .Values.namespace }}
    chart: lakefs/lakefs
    version: <lakefs chart version>
    needs:
      - {{ .Values.namespace }}/lakefs-auth
    values:
      - lakefs-values.yaml
      - ingress:
          enabled: true
          ingressClassName: nginx
          hosts:
            - host: {{ .Values.host }}
              paths: ["/"]
          tls:
            - secretName: lakefs-tls
              hosts: ["{{ .Values.host }}"]
```

The two values files are the ones from step 2 and step 3. Drop `authn.publicUrl` and `authn.ingress.host` from
`lakefs-auth-values.yaml`, because helmfile sets them from `host`. Keep the rest: the Secret names, the OIDC
client, and `lakefsConfig` with the two endpoints. The lakeFS chart also needs its own `database` and
`blockstore` settings in `lakefsConfig`.

!!! note "The `---` is part of the syntax"

    helmfile renders the file in two passes, so `environments` and `releases` need their own YAML documents.
    In one document it stops with "environments and releases cannot be defined within the same YAML part".

`needs` installs lakefs-auth before lakeFS, and `wait: true` holds that install until both Deployments are
ready. The order matters: lakeFS checks the lakefs-authz health endpoint at start and stops when it fails.
Write the `needs` entry as `<namespace>/<release>`, because both releases name a namespace.

```bash
helm plugin install https://github.com/databus23/helm-diff
helmfile diff
helmfile apply
```

`helmfile apply` shows the change and installs it, and it needs the helm-diff plugin. `helmfile sync` installs
without the plugin and without the diff. `helmfile destroy` removes both releases and leaves the Secrets.

</details>

## Values

A complete file, with the Secret names from step 1 and one host name. The chart's `values.yaml` documents
every value, including the ones this file leaves at its default.

```yaml title="lakefs-auth-values.yaml"
sharedSecret:
  existingSecret: lakefs-shared-secret     # the Secret from step 1
  secretKey: auth_encrypt_secret_key       # its key, and the default of the lakeFS chart

authz:
  replicas: 2
  database:
    existingSecret: lakefs-authz-database  # holds the PostgreSQL connection string
    secretKey: database-url
  encryptionKey:
    existingSecret: lakefs-authz-encryption-key   # keeps stored access keys readable
    secretKey: encryption-key                     # across a rotation of the shared secret
  metrics:
    enabled: true                          # adds a `metrics` port for a ServiceMonitor
  # The bootstrap file itself, written inline. The chart puts it in a ConfigMap and
  # mounts it. Every row below is created at each start when it is missing.
  bootstrap: |
    version: 1
    policies:
      - name: FSFullAccess
        statement:
          - effect: allow
            action: ["fs:*"]
            resource: "*"
    groups:
      - id: DataTeam
        description: Data team
        policies: [FSFullAccess]

authn:
  replicas: 2
  publicUrl: https://lakefs.example.com    # the lakeFS URL; the redirect URI adds /oidc/callback
  oidc:
    issuer: https://idp.example.com/realms/lakefs   # exactly as the provider advertises it
    clientId: lakefs
    clientSecret:
      existingSecret: lakefs-oidc          # omit for a public client
      secretKey: client-secret
    scopes: openid,profile,email,groups    # `groups` carries the claim below
  groupsClaim: groups                      # the claim that lists the provider groups
  groupMap: lakefs-admins=Admins,lakefs-users=DataTeam   # provider group = lakeFS group;
                                                         # Admins exists with rbac: internal
  initialGroups: DataTeam                  # used when the claim resolves to nothing
  sessionTtl: 24h                          # cookie lifetime; the default is 168h
  rpInitiatedLogout: true                  # logout ends the provider session too
  metrics:
    enabled: true
  ingress:
    enabled: true                          # routes /oidc on the lakeFS host to this server
    className: nginx
    host: lakefs.example.com
    tls:
      enabled: true
      secretName: lakefs-tls
```

Both servers also take `image`, `resources`, `podAnnotations`, and `extraEnv`, which passes any flag the chart
does not model through its environment variable.

Two topics have their own page: the Secrets that hold these values on [Secrets](secrets.md), and the bootstrap
content on [Bootstrap file](bootstrap.md).
