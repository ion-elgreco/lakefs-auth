set shell := ["bash", "-uc"]

# Cargo profile for the recipes. Defaults to `dev` for fast local iteration;
# CI sets PROFILE=ci which selects [profile.ci] (incremental off so sccache
# works, deps at opt-level=3), and the release workflow sets PROFILE=release.

profile := env_var_or_default("PROFILE", "dev")

# Cargo's `dev` profile outputs to `target/<triple>/debug/`; every other
# profile (release, ...) outputs to `target/<triple>/<profile>/`.

profile_dir := if profile == "dev" { "debug" } else { profile }

# Image architecture: the host's by default, `ARCH=amd64 just build-images` to cross-build.

host_arch := if arch() == "aarch64" { "arm64" } else { "amd64" }
image_arch := env_var_or_default("ARCH", host_arch)
linux_target := if image_arch == "arm64" { "aarch64-unknown-linux-gnu" } else { "x86_64-unknown-linux-gnu" }

# Tag of the locally built images; also their version label.

tag := env_var_or_default("TAG", "dev")

_default:
    just --list

# Format check and clippy with warnings denied (what CI runs)
lint:
    cargo fmt --all --check
    cargo clippy --profile {{ profile }} --workspace --all-targets --all-features -- -D warnings

# Unit and mock tests, no Docker
test:
    cargo test --profile {{ profile }} --workspace

# Store conformance suite on PostgreSQL (DATABASE_URL, or a testcontainer)
test-pg:
    cargo test --profile {{ profile }} -p lakefs-authz --features pg-tests --test store_conformance

# Integration tests that start lakeFS and ferriskey containers
test-docker:
    cargo test --profile {{ profile }} -p lakefs-authz --features pg-tests --test e2e_lakefs -- --ignored --nocapture
    cargo test --profile {{ profile }} -p lakefs-authn --features docker-tests --test ferriskey -- --test-threads=1 --nocapture
    cargo test --profile {{ profile }} -p lakefs-authn --features docker-tests --test lakefs_e2e -- --ignored --nocapture

# === Container images ===

# Cross-compile both servers for Linux with cargo-zigbuild (no Docker)
cross-compile target=linux_target:
    cargo zigbuild --locked --profile {{ profile }} --target {{ target }} -p lakefs-authn -p lakefs-authz

# Cross-compile, then build lakefs-authn:<tag> and lakefs-authz:<tag> from deploy/docker/Dockerfile.*
build-images: cross-compile
    #!/usr/bin/env bash
    set -euo pipefail
    # The Dockerfiles only package a prebuilt binary, so the build context is a
    # staging directory that holds nothing else. The release workflow does the same.
    revision=$(git rev-parse HEAD 2>/dev/null || echo unknown)
    build_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    rm -rf deploy/docker/staging
    mkdir -p deploy/docker/staging
    cp target/{{ linux_target }}/{{ profile_dir }}/lakefs-authn target/{{ linux_target }}/{{ profile_dir }}/lakefs-authz deploy/docker/staging/
    for bin in lakefs-authn lakefs-authz; do
        docker build --platform linux/{{ image_arch }} \
            --file "deploy/docker/Dockerfile.${bin#lakefs-}" \
            --build-arg "VERSION={{ tag }}" \
            --build-arg "REVISION=${revision}" \
            --build-arg "BUILD_DATE=${build_date}" \
            --tag "${bin}:{{ tag }}" \
            deploy/docker/staging
    done
    rm -rf deploy/docker/staging
    echo "==> built lakefs-authn:{{ tag }} and lakefs-authz:{{ tag }} (linux/{{ image_arch }}, {{ profile }} profile)"

# === Compose demo (examples/compose) ===

# Build the images, start lakeFS + both servers + ferriskey, and wait until they answer
demo-up: build-images
    #!/usr/bin/env bash
    set -euo pipefail
    cd examples/compose
    # `up -d` returns after the bootstrap job completed: authn depends on it with
    # condition service_completed_successfully.
    docker compose up -d || { docker compose logs --no-log-prefix bootstrap; exit 1; }
    docker compose logs --no-log-prefix bootstrap | tail -n 8
    echo "==> waiting for lakefs-authn and lakeFS"
    a=""; l=""
    for _ in $(seq 1 90); do
        a=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8001/readyz || true)
        l=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/api/v1/healthcheck || true)
        [ "$a" = "200" ] && [ "$l" = "204" ] && break
        sleep 2
    done
    echo "lakefs-authn ready: ${a:-?}   lakeFS healthy: ${l:-?}"
    echo
    echo "lakeFS:            http://localhost:8000  (click 'Sign in with SSO')"
    echo "  SSO admin:       admin / admin   (lakeFS group Admins)"
    echo "  SSO developer:   user / user     (lakeFS group Developers)"
    echo "lakeFS admin key:  AKIAJADMINADMINADMIQ / ${LAKEFS_ADMIN_SECRET:-bGFrZWZzLWF1dGgtZGVtby1hZG1pbi1zZWNyZXQw}  (user lakefs-installation)"
    echo "lakeFS repository: demo, stored in RustFS at s3://lakefs/demo"
    echo "RustFS S3 API:     http://localhost:9000  (${RUSTFS_ACCESS_KEY:-rustfsadmin} / ${RUSTFS_SECRET_KEY:-rustfsadmin})"
    echo "policy builder:    http://localhost:8080"
    echo "metrics:           http://localhost:9091/metrics (authz), http://localhost:9092/metrics (authn)"
    echo "ferriskey console: http://localhost:5555  (admin / admin)"
    echo "stop:              just demo-down"

# Log in through OIDC without a browser and call lakeFS with the resulting session cookie
demo-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
    need curl; need jq
    REALM=${REALM:-lakefs}
    CLIENT_ID=${CLIENT_ID:-lakefs}
    DEMO_USER=${DEMO_USER:-user}
    DEMO_PASSWORD=${DEMO_PASSWORD:-user}
    LAKEFS=http://localhost:8000
    AUTHN=http://localhost:8001
    IDP=http://localhost:3333
    JAR=$(mktemp)
    trap 'rm -f "$JAR"' EXIT

    echo "==> waiting for lakeFS"
    for _ in $(seq 1 60); do
        code=$(curl -s -o /dev/null -w '%{http_code}' "$LAKEFS/api/v1/healthcheck" || true)
        [ "$code" = "204" ] && break
        sleep 2
    done
    [ "$code" = "204" ] || { echo "lakeFS is not healthy (last status $code)" >&2; exit 1; }
    echo "lakeFS healthy; setup state: $(curl -fsS "$LAKEFS/api/v1/setup_lakefs" | jq -r .state)"

    echo "==> waiting for lakefs-authn discovery"
    for _ in $(seq 1 60); do
        code=$(curl -s -o /dev/null -w '%{http_code}' "$AUTHN/readyz" || true)
        [ "$code" = "200" ] && break
        sleep 2
    done
    [ "$code" = "200" ] || { echo "lakefs-authn is not ready (last status $code); see: docker compose -f examples/compose/docker-compose.yml logs authn" >&2; exit 1; }

    echo "==> starting OIDC login at lakefs-authn"
    AUTH_URL=$(curl -s -o /dev/null -w '%{redirect_url}' -c "$JAR" -b "$JAR" "$AUTHN/oidc/login?next=/repositories")
    [ -n "$AUTH_URL" ] || { echo "no redirect from /oidc/login" >&2; exit 1; }

    echo "==> authenticating at ferriskey without a browser"
    curl -s -o /dev/null -c "$JAR" -b "$JAR" "$AUTH_URL"
    LOGIN=$(curl -fsS -c "$JAR" -b "$JAR" -X POST "$IDP/realms/$REALM/login-actions/authenticate?client_id=$CLIENT_ID" \
        -H 'Content-Type: application/json' -d "{\"username\":\"$DEMO_USER\",\"password\":\"$DEMO_PASSWORD\"}")
    CALLBACK=$(echo "$LOGIN" | jq -r '.url // empty')
    [ -n "$CALLBACK" ] || { echo "ferriskey login did not return a callback url: $LOGIN" >&2; exit 1; }

    echo "==> completing the callback"
    read -r code target < <(curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' -c "$JAR" -b "$JAR" "$CALLBACK")
    [ "$code" = "302" ] || [ "$code" = "303" ] || { echo "callback returned $code" >&2; exit 1; }
    case "$target" in
        "$LAKEFS"/*) echo "callback redirects to $target" ;;
        *) echo "callback redirects to $target instead of $LAKEFS/..." >&2; exit 1 ;;
    esac
    grep -q internal_auth_session "$JAR" || { echo "no internal_auth_session cookie was set" >&2; exit 1; }

    echo "==> calling lakeFS with the session cookie"
    ME=$(curl -fsS -b "$JAR" "$LAKEFS/api/v1/user")
    echo "$ME" | jq .
    # lakeFS answers an anonymous request with an empty user, so an empty id is a failure.
    echo "$ME" | jq -e '.user.id | length > 0' >/dev/null || { echo "lakeFS did not accept the session cookie" >&2; exit 1; }
    echo "OK: lakeFS accepted the SSO session for $(echo "$ME" | jq -r .user.id)"

# Stop the demo and delete its volumes
demo-down:
    cd examples/compose && docker compose down -v

# === Documentation (zensical + mike) ===

# Regenerate the action catalog inside the policy builder page (docs/ symlinks to it)
sync-catalog:
    cargo run -q --profile {{ profile }} -p lakefs-authz --example sync-catalog

# Regenerate docs/assets/policy-builder.png; run it whenever the builder page changes
docs-screenshot chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome":
    #!/usr/bin/env bash
    set -euo pipefail
    [ -x "{{ chrome }}" ] || { echo "no Chrome at {{ chrome }}; pass chrome=/path/to/chrome" >&2; exit 1; }
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    # A copy with the dark media query disabled and one example statement filled
    # in, so the shot matches the light documentation theme and shows real output.
    python3 - "$work" <<'EOF'
    import sys
    page = open("crates/lakefs-authz/assets/policy-builder.html").read()
    page = page.replace("@media (prefers-color-scheme: dark)", "@media (prefers-color-scheme: never-match)", 1)
    boot = """
    <script>
    document.getElementById("policy-name").value = "DataTeamRaw";
    statements = [];
    const a = newStatement();
    a.actions = new Set(["fs:ReadObject","fs:WriteObject","fs:DeleteObject"]);
    realignKind(a); a.fields = { repository: "warehouse", path: "raw/*" };
    statements.push(a);
    draw();
    </script>
    """
    open(sys.argv[1] + "/index.html", "w").write(page.replace("</body>", boot + "</body>"))
    EOF
    # Job control is off in a non-interactive shell, so the PID is tracked
    # explicitly; `kill %1` would leave the server running and block the port.
    (cd "$work" && exec python3 -u -m http.server 0 --bind 127.0.0.1) >"$work/log" 2>&1 &
    server=$!
    trap 'rm -rf "$work"; kill "$server" 2>/dev/null || true' EXIT
    port=""
    for _ in $(seq 1 40); do
        port=$(sed -n 's/.*port \([0-9]*\).*/\1/p' "$work/log" 2>/dev/null | head -1)
        [ -n "$port" ] && break
        sleep 0.25
    done
    [ -n "$port" ] || { echo "the preview server never reported a port" >&2; exit 1; }
    curl -fsS -o /dev/null --retry 20 --retry-delay 1 --retry-all-errors "http://127.0.0.1:$port/"
    "{{ chrome }}" --headless --disable-gpu --no-sandbox --hide-scrollbars \
        --window-size=1360,880 --force-device-scale-factor=2 --virtual-time-budget=3000 \
        --screenshot=docs/assets/policy-builder.png "http://127.0.0.1:$port/" 2>/dev/null
    echo "==> wrote docs/assets/policy-builder.png"

# Build the documentation site into site/
docs-build: sync-catalog
    uvx zensical build

# Serve the documentation with live reload
docs-serve: sync-catalog
    uvx zensical serve

# squidfunk's fork of mike, pinned to a specific commit (zensical's
# versioning provider expects fixes that haven't landed in upstream yet).
# Bump when zensical updates its versioning guidance.

mike_pkg := "git+https://github.com/squidfunk/mike.git@2d4ad799442f4592db8ad53b179bfb33db8c69ac"

# Deploy a versioned docs build. push="--push" is the default for CI; pass push="" for a local dry-run that only touches the local gh-pages branch
docs-deploy version push="--push":
    uvx --from "{{ mike_pkg }}" --with zensical mike deploy {{ push }} --update-aliases {{ version }} latest

# Set the `latest` alias as the default: installs the root redirect from `/` to `/latest/` (idempotent, once per release)
docs-set-default push="--push":
    uvx --from "{{ mike_pkg }}" --with zensical mike set-default {{ push }} latest

# === Helm chart (deploy/helm/lakefs-auth) ===

# Lint the chart and run its unit tests (needs the helm-unittest plugin)
test-helm:
    helm lint deploy/helm/lakefs-auth --strict --values deploy/helm/lakefs-auth/tests/values/base.yaml
    helm unittest deploy/helm/lakefs-auth
