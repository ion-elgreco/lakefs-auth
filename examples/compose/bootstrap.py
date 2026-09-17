#!/usr/bin/env python3
"""Idempotent ferriskey bootstrap for the compose demo.

Creates the realm, the confidential client with its redirect URIs, and the demo
user, then writes the client secret to SECRET_FILE for lakefs-authn. Safe to run
on every `docker compose up`: existing objects are reused, and a client whose
secret is unknown is recreated so that the file and the provider always agree.
Uses only the Python standard library.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

IDP = os.environ.get("IDP_URL", "http://ferriskey-api:3333").rstrip("/")
REALM = os.environ.get("REALM", "lakefs")
CLIENT_ID = os.environ.get("CLIENT_ID", "lakefs")
DEMO_USER = os.environ.get("DEMO_USER", "user")
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "user")
# A second identity that lands in the lakeFS Admins group. lakefs-authn maps it
# there from the preferred_username claim; see LAKEFS_AUTHN_GROUP_MAP.
DEMO_ADMIN = os.environ.get("DEMO_ADMIN", "admin")
DEMO_ADMIN_PASSWORD = os.environ.get("DEMO_ADMIN_PASSWORD", "admin")
AUTHN_PUBLIC_URL = os.environ.get("AUTHN_PUBLIC_URL", "http://localhost:8001").rstrip("/")
LAKEFS_URL = os.environ.get("LAKEFS_URL", "http://localhost:8000").rstrip("/")
SECRET_FILE = os.environ.get("SECRET_FILE", "/secrets/oidc_client_secret")
ADMIN_USER = os.environ.get("IDP_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("IDP_ADMIN_PASSWORD", "admin")


def log(message):
    print(f"bootstrap: {message}", flush=True)


def request(method, path, body=None, token=None, form=None):
    url = f"{IDP}{path}"
    headers = {"Accept": "application/json"}
    data = None
    if form is not None:
        data = "&".join(f"{k}={v}" for k, v in form.items()).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            text = response.read().decode()
            return response.status, (json.loads(text) if text.strip() else None)
    except urllib.error.HTTPError as error:
        text = error.read().decode(errors="replace")
        try:
            return error.code, json.loads(text)
        except ValueError:
            return error.code, {"message": text}


def items(payload):
    """List endpoints answer either a bare list or {"data": [...]}."""
    if isinstance(payload, dict):
        payload = payload.get("data", [])
    return payload or []


def wait_ready():
    for _ in range(120):
        try:
            status, _ = request("GET", "/health/ready")
            if status == 200:
                return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    sys.exit("ferriskey never became ready")


def admin_token():
    status, body = request(
        "POST",
        "/realms/master/protocol/openid-connect/token",
        form={"grant_type": "password", "client_id": "admin-cli", "username": ADMIN_USER, "password": ADMIN_PASSWORD},
    )
    if status != 200 or not body or "access_token" not in body:
        sys.exit(f"admin password grant failed: {status} {body}")
    return body["access_token"]


def ensure_realm(token):
    status, body = request("POST", "/realms", {"name": REALM, "display_name": "lakeFS"}, token)
    if status in (200, 201):
        log(f"created realm {REALM}")
    else:
        log(f"realm {REALM} already exists ({status})")


def find_client(token):
    status, body = request("GET", f"/realms/{REALM}/clients", token=token)
    if status != 200:
        return None
    for client in items(body):
        if client.get("client_id") == CLIENT_ID:
            return client
    return None


def create_client(token):
    status, body = request(
        "POST",
        f"/realms/{REALM}/clients",
        {
            "name": CLIENT_ID,
            "client_id": CLIENT_ID,
            "client_type": "confidential",
            "public_client": False,
            "protocol": "openid-connect",
            "enabled": True,
            "service_account_enabled": False,
            "direct_access_grants_enabled": False,
            "oauth_device_code_grant_enabled": False,
        },
        token,
    )
    if status not in (200, 201) or not body:
        sys.exit(f"creating client {CLIENT_ID} failed: {status} {body}")
    secret = body.get("secret") or body.get("client_secret")
    if not secret:
        sys.exit(f"the created client carries no secret: {body}")
    return body["id"], secret


def existing_secret():
    try:
        with open(SECRET_FILE, encoding="utf-8") as handle:
            value = handle.read().strip()
            return value or None
    except OSError:
        return None


def ensure_client(token):
    """Returns (client uuid, secret) with the secret guaranteed to match the provider."""
    client = find_client(token)
    if client is None:
        uuid, secret = create_client(token)
        log(f"created client {CLIENT_ID}")
        return uuid, secret
    secret = existing_secret()
    if secret:
        log(f"client {CLIENT_ID} exists and the secret file is present")
        return client["id"], secret
    status, body = request("GET", f"/realms/{REALM}/clients/{client['id']}/client-secret", token=token)
    if status == 200 and body:
        for key in ("secret", "client_secret", "value"):
            if body.get(key):
                log(f"client {CLIENT_ID} exists; read its secret from the provider")
                return client["id"], body[key]
    log(f"client {CLIENT_ID} exists but its secret is unknown; recreating it")
    request("DELETE", f"/realms/{REALM}/clients/{client['id']}", token=token)
    uuid, secret = create_client(token)
    return uuid, secret


def register_urls(token, uuid):
    for uri in (f"{AUTHN_PUBLIC_URL}/oidc/callback", f"{AUTHN_PUBLIC_URL}/sts/callback"):
        request("POST", f"/realms/{REALM}/clients/{uuid}/redirects", {"value": uri, "enabled": True}, token)
    request(
        "POST",
        f"/realms/{REALM}/clients/{uuid}/post-logout-redirects",
        {"value": f"{LAKEFS_URL}/auth/login", "enabled": True},
        token,
    )


def ensure_password_policy(token):
    """The demo password is short, so relax the realm minimum to fit it.

    ferriskey rejects a password below the realm minimum, which starts at eight
    characters. A demo trades that strength for a password you can type.
    """
    minimum = max(1, min(len(DEMO_PASSWORD), len(DEMO_ADMIN_PASSWORD)))
    status, body = request("PUT", f"/realms/{REALM}/password-policy", {"min_length": minimum}, token)
    if status not in (200, 201, 204):
        sys.exit(f"relaxing the password policy to {minimum} characters failed: {status} {body}")
    log(f"password policy minimum is {minimum} characters")


def ensure_user(token, username, password, firstname, lastname):
    status, body = request(
        "POST",
        f"/realms/{REALM}/users",
        {
            "username": username,
            "firstname": firstname,
            "lastname": lastname,
            "email": f"{username}@example.com",
            "email_verified": True,
        },
        token,
    )
    user_id = None
    if status in (200, 201) and body:
        user_id = (body.get("data") or body).get("id")
        log(f"created user {username}")
    if not user_id:
        status, body = request("GET", f"/realms/{REALM}/users", token=token)
        for user in items(body):
            if user.get("username") == username:
                user_id = user["id"]
                log(f"user {username} already exists")
                break
    if not user_id:
        sys.exit(f"could not create or find user {username}: {status} {body}")
    status, body = request(
        "PUT",
        f"/realms/{REALM}/users/{user_id}/reset-password",
        {"value": password, "temporary": False, "credential_type": "password"},
        token,
    )
    if status not in (200, 201, 204):
        sys.exit(f"setting the password of {username} failed: {status} {body}")


def write_secret(secret):
    directory = os.path.dirname(SECRET_FILE)
    os.makedirs(directory, exist_ok=True)
    tmp = f"{SECRET_FILE}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(secret)
    os.chmod(tmp, 0o644)
    os.replace(tmp, SECRET_FILE)
    log(f"wrote the client secret to {SECRET_FILE}")


def main():
    wait_ready()
    token = admin_token()
    ensure_realm(token)
    uuid, secret = ensure_client(token)
    register_urls(token, uuid)
    ensure_password_policy(token)
    ensure_user(token, DEMO_USER, DEMO_PASSWORD, "Demo", "User")
    ensure_user(token, DEMO_ADMIN, DEMO_ADMIN_PASSWORD, "Demo", "Admin")
    write_secret(secret)
    log("done")


if __name__ == "__main__":
    main()
