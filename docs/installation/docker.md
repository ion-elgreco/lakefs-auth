# Docker

A single-host setup with Docker Compose: PostgreSQL, lakefs-authz, lakefs-authn, lakeFS, and nginx in front,
so that lakeFS and the `/oidc/` prefix share one host name. The files live in
[`examples/docker`](https://github.com/ion-elgreco/lakefs-auth/tree/main/examples/docker) in the repository.

## 1. Settings

Copy `.env.example` to `.env` and fill it in. `LAKEFS_URL` is the address users open; with TLS on the proxy it
starts with `https`.

```ini title=".env.example"
--8<-- "examples/docker/.env.example"
```

## 2. Compose file

The two servers run from the release images as a non-root user, with a read-only root filesystem and no
capabilities. lakeFS keeps its metadata and its data in a volume; see the lakeFS documentation for a database
and an object store.

```yaml title="docker-compose.yml"
--8<-- "examples/docker/docker-compose.yml"
```

## 3. Reverse proxy

nginx sends `/oidc/` to lakefs-authn and everything else to lakeFS, and passes `Set-Cookie` through, which
the login callback needs. To serve TLS, terminate it here and set `LAKEFS_URL` to the `https` address.

```nginx title="nginx.conf"
--8<-- "examples/docker/nginx.conf"
```

## 4. Start

```bash
docker compose up -d
curl -s -o /dev/null -w '%{http_code}\n' http://localhost/api/v1/healthcheck   # 204: lakeFS through the proxy
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8001/readyz          # 200: lakefs-authn reached the provider
```

Then continue with [After the install](index.md#after-the-install).
