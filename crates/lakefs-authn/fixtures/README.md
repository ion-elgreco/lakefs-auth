# Session cookie fixtures

`sessions.json` pins the byte format of the lakeFS session cookie `internal_auth_session`: a gorilla
`sessions.CookieStore` cookie (HMAC-SHA256, no encryption) around a Go gob map whose `token` entry is an HS256
JWT with `iss: auth`, `aud: login`, and `sub` set to the lakeFS username. `gen.go` produces it with the real
gorilla libraries. The unit tests assert that the Rust encoder reproduces those bytes exactly and that cookies
from a real `sessions.CookieStore` decode.

Regenerate it from the repository root:

```bash
docker run --rm -u $(id -u):$(id -g) -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod \
  -e GOFLAGS=-mod=mod -v "$PWD/crates/lakefs-authn/fixtures:/out" -w /out golang:1.24 \
  sh -c 'go mod tidy && go run gen.go > sessions.json'
```
