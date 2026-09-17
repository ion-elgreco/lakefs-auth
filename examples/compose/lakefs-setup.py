#!/usr/bin/env python3
"""Idempotent lakeFS bootstrap for the compose demo.

Creates the RustFS bucket that holds the repository data, then creates the lakeFS
repository on top of it. The bucket request is signed with AWS Signature Version 4
and the lakeFS request uses the installation credentials over HTTP basic auth.
Safe to run on every `docker compose up`: an existing bucket and an existing
repository are left as they are. Uses only the Python standard library.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

S3_ENDPOINT = os.environ.get("S3_ENDPOINT", "http://rustfs:9000").rstrip("/")
S3_ACCESS_KEY = os.environ.get("S3_ACCESS_KEY", "rustfsadmin")
S3_SECRET_KEY = os.environ.get("S3_SECRET_KEY", "rustfsadmin")
S3_REGION = os.environ.get("S3_REGION", "us-east-1")
BUCKET = os.environ.get("BUCKET", "lakefs")

LAKEFS_URL = os.environ.get("LAKEFS_URL", "http://lakefs:8000").rstrip("/")
LAKEFS_ACCESS_KEY = os.environ.get("LAKEFS_ACCESS_KEY", "")
LAKEFS_SECRET_KEY = os.environ.get("LAKEFS_SECRET_KEY", "")
REPOSITORY = os.environ.get("REPOSITORY", "demo")
DEFAULT_BRANCH = os.environ.get("DEFAULT_BRANCH", "main")
SAMPLE_DATA = os.environ.get("SAMPLE_DATA", "true").lower() in ("1", "true", "yes")

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def log(message):
    print(f"lakefs-setup: {message}", flush=True)


# --- RustFS -----------------------------------------------------------------


def sign(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def signing_key(datestamp):
    key = sign(f"AWS4{S3_SECRET_KEY}".encode(), datestamp)
    key = sign(key, S3_REGION)
    key = sign(key, "s3")
    return sign(key, "aws4_request")


def s3_request(method, path):
    """One SigV4 signed request with an empty body. Returns (status, body text)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    host = urllib.parse.urlsplit(S3_ENDPOINT).netloc

    canonical_headers = f"host:{host}\nx-amz-content-sha256:{EMPTY_SHA256}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join([method, path, "", canonical_headers, signed_headers, EMPTY_SHA256])

    scope = f"{datestamp}/{S3_REGION}/s3/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    signature = hmac.new(signing_key(datestamp), string_to_sign.encode(), hashlib.sha256).hexdigest()

    headers = {
        "x-amz-content-sha256": EMPTY_SHA256,
        "x-amz-date": amz_date,
        "Authorization": (
            f"AWS4-HMAC-SHA256 Credential={S3_ACCESS_KEY}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        ),
    }
    request = urllib.request.Request(f"{S3_ENDPOINT}{path}", data=b"", method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status, response.read().decode(errors="replace")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace")


def wait_for_rustfs():
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"{S3_ENDPOINT}/health", timeout=5) as response:
                if response.status == 200:
                    return
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    sys.exit("RustFS never became ready")


def ensure_bucket():
    # S3 answers 200 to a PUT on a bucket you already own, so probe first to keep
    # the log honest about what this run actually did.
    status, _ = s3_request("HEAD", f"/{BUCKET}")
    if status == 200:
        log(f"bucket {BUCKET} already exists")
        return
    status, body = s3_request("PUT", f"/{BUCKET}")
    if status in (200, 204):
        log(f"created bucket {BUCKET}")
        return
    if status == 409 or "BucketAlreadyOwnedByYou" in body or "BucketAlreadyExists" in body:
        log(f"bucket {BUCKET} already exists")
        return
    sys.exit(f"creating bucket {BUCKET} failed: {status} {body}")


# --- lakeFS -----------------------------------------------------------------


def lakefs_request(method, path, body=None):
    url = f"{LAKEFS_URL}/api/v1{path}"
    credentials = base64.b64encode(f"{LAKEFS_ACCESS_KEY}:{LAKEFS_SECRET_KEY}".encode()).decode()
    headers = {"Accept": "application/json", "Authorization": f"Basic {credentials}"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode()
            return response.status, (json.loads(text) if text.strip() else None)
    except urllib.error.HTTPError as error:
        text = error.read().decode(errors="replace")
        try:
            return error.code, json.loads(text)
        except ValueError:
            return error.code, {"message": text}


def wait_for_lakefs():
    for _ in range(120):
        try:
            with urllib.request.urlopen(f"{LAKEFS_URL}/api/v1/healthcheck", timeout=5) as response:
                if response.status in (200, 204):
                    return
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    sys.exit("lakeFS never became healthy")


def wait_for_admin():
    """The installation setup runs at lakeFS start, so the admin key may lag the health check."""
    for _ in range(60):
        status, body = lakefs_request("GET", "/user")
        if status == 200:
            return
        if status in (401, 403):
            time.sleep(2)
            continue
        sys.exit(f"the lakeFS admin credentials were rejected: {status} {body}")
    sys.exit("the lakeFS admin credentials never became usable")


def ensure_repository():
    status, _ = lakefs_request("GET", f"/repositories/{REPOSITORY}")
    if status == 200:
        log(f"repository {REPOSITORY} already exists")
        return
    status, body = lakefs_request(
        "POST",
        "/repositories",
        {
            "name": REPOSITORY,
            "storage_namespace": f"s3://{BUCKET}/{REPOSITORY}",
            "default_branch": DEFAULT_BRANCH,
            "sample_data": SAMPLE_DATA,
        },
    )
    if status in (200, 201):
        log(f"created repository {REPOSITORY} on s3://{BUCKET}/{REPOSITORY}")
        return
    if status == 409:
        log(f"repository {REPOSITORY} already exists")
        return
    sys.exit(f"creating repository {REPOSITORY} failed: {status} {body}")


def main():
    if not LAKEFS_ACCESS_KEY or not LAKEFS_SECRET_KEY:
        sys.exit("LAKEFS_ACCESS_KEY and LAKEFS_SECRET_KEY are required")
    wait_for_rustfs()
    ensure_bucket()
    wait_for_lakefs()
    wait_for_admin()
    ensure_repository()
    log("done")


if __name__ == "__main__":
    main()
