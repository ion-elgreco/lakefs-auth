# Authentication flows

lakefs-authn implements the lakeFS authentication API and the browser side of the OIDC login. lakeFS never talks
OIDC itself. It reads a session cookie for browsers and calls lakefs-authn for the STS code exchange.

## Browser login

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant L as lakeFS
    participant A as lakefs-authn
    participant I as Identity provider
    participant Z as lakefs-authz

    B->>L: Open the login page
    L-->>B: Link "Sign in with SSO" to /oidc/login
    B->>A: GET /oidc/login?next=...
    A-->>B: Set the flow cookie, redirect to the provider
    B->>I: Authorization request with PKCE, state, and nonce
    I-->>B: Redirect to /oidc/callback?code&state
    B->>A: GET /oidc/callback
    A->>I: Exchange the code, verify the ID token
    A->>Z: Find the user by external id, create it on a miss
    A-->>B: Set internal_auth_session, redirect to next
    B->>L: Request with the session cookie
    L->>Z: Load the user
    L-->>B: Page
```

The callback checks three things before it creates a session:

- `state` matches the flow cookie. The comparison runs in constant time.
- The code exchange uses the PKCE verifier from the flow cookie.
- The ID token has a valid signature, issuer, audience, expiry, and nonce.

The session cookie holds a lakeFS login token. lakefs-authn signs it with the shared secret in the format lakeFS
uses, so lakeFS verifies it without a call back. The flow cookie lives 10 minutes. The session lives
`--session-ttl`, 7 days by default.

## User provisioning

Every login resolves to one lakeFS user:

```mermaid
flowchart TD
    S[ID token verified] --> F{"User with external_id = sub?"}
    F -->|yes| R["Keep the username and groups,<br>refresh the friendly name"]
    F -->|no| N["Derive the username from --username-claim"]
    N --> T{"Username taken by another identity?"}
    T -->|yes| E["Refuse the login with 401"]
    T -->|no| C["Create the user with source oidc<br>and external id sub"]
    C --> G["Add the groups from --groups-claim,<br>or --initial-groups when the claim is absent"]
    R --> D[Done]
    G --> D
```

The server never binds an existing account to a new identity. With `--auto-provision false` the "no" branch
refuses the login instead of creating a user, so every account must exist before its first login. A group
assignment that fails after the create deletes the user again, so the next login retries the whole create.

## Logout

```mermaid
flowchart LR
    B["GET /oidc/logout"] --> C[Clear the session and flow cookies]
    C --> Q{"RP-initiated logout on and<br>end_session_endpoint advertised?"}
    Q -->|yes| P[Redirect to the provider logout]
    Q -->|no| U["Redirect to --post-logout-redirect-url"]
```

The provider logout receives the client id, the post-logout redirect URI, and the ID token hint.

## SDK login with an identity provider code

A program can log in without a browser session through the lakeFS operation `POST /api/v1/sts/login`. lakeFS
names it after the AWS Security Token Service, because it trades an identity provider code for a lakeFS token.
The lakeFS SDKs implement it: `lakefs.client.from_web_identity(code, state, redirect_uri, ttl_seconds)` in
Python, and `stsLogin` in the experimental API of the Java and Rust clients. lakectl does not use it.

The SDK runs the OIDC login itself and receives an authorization code from the identity provider. It posts the
code to lakeFS, lakeFS forwards it to lakefs-authn, and the SDK receives a lakeFS token with the requested
lifetime. From then on the SDK calls lakeFS with that token, as it would with an access key. lakefs-authn
redeems the code only when the `redirect_uri` is on `--sts-allowed-redirect-uris`; the list is empty by
default, so the SDK login is off until the operator lists the redirect URIs of the SDK clients.

```mermaid
sequenceDiagram
    autonumber
    participant C as SDK client
    participant I as Identity provider
    participant L as lakeFS
    participant A as lakefs-authn
    participant Z as lakefs-authz

    C->>I: Login with PKCE, the verifier travels in state
    I-->>C: code and state
    C->>L: POST /api/v1/sts/login with code, state, redirect_uri
    L->>A: POST /api/v1/sts/login without an auth header
    A->>I: Exchange the code with code_verifier = state
    A->>Z: Find the user by external id, create it on a miss
    A-->>L: claims, every value as a string
    L->>Z: Find the user by external id
    L-->>C: lakeFS token with the requested lifetime
```

## Deployment

Browsers scope cookies by host. lakefs-authn must answer on the lakeFS host under the `/oidc/` prefix, usually
through a reverse proxy rule. The [Docker](installation/docker.md#3-reverse-proxy) and
[Helm](installation/helm.md#2-install-the-chart) pages show it. A local setup with lakeFS on port 8000 and lakefs-authn on port 8001 needs no proxy, because ports do
not isolate cookies.

Set `--oidc-issuer` to the exact issuer the provider advertises. Discovery fails on any difference, including a
trailing slash.
