# Preventing OAuth Authentication Vulnerabilities

OAuth's security model has almost no mandatory protections built into the specification itself — the spec defines the flow but leaves nearly every security decision to the implementer. This means vulnerabilities emerge on both sides of the relationship: a perfectly implemented client application is still at risk if the OAuth provider has a weak `redirect_uri` validator, and a correctly configured provider cannot compensate for a client that omits the `state` parameter or leaks authorization codes via `Referer` headers. RFC 9700 (published January 2025) is now the authoritative security best-practice document for OAuth 2.0, replacing the older threat model in RFC 6819. 

**Fundamental principle: The entire OAuth security model depends on two guarantees — that the authorization code can only be delivered to the legitimate client application (enforced by `redirect_uri` validation), and that it can only be used by the legitimate client application (enforced by `client_secret` or PKCE). Every major OAuth vulnerability is a bypass of one of these two guarantees.**

***

## For OAuth Service Providers (Authorization Servers)

### `redirect_uri` Validation

```
The redirect_uri is the highest-impact single parameter in all of OAuth.
If an attacker can control where the authorization code is delivered,
they own the account regardless of every other protection in place.

─────────────────────────────────────────────────────────────────────────────
DO: Exact byte-for-byte string comparison
─────────────────────────────────────────────────────────────────────────────
Registered URI:    https://client-app.com/callback
Incoming request:  https://client-app.com/callback       ✓ MATCH  → allow
Incoming request:  https://client-app.com/callback/      ✗ MISMATCH → reject
Incoming request:  https://CLIENT-APP.COM/callback       ✗ MISMATCH → reject (case)
Incoming request:  https://client-app.com/callback?foo=1 ✗ MISMATCH → reject

Why trailing slash matters:
  Registered: https://client-app.com/callback
  Requested:  https://client-app.com/callback/../evil     ← path traversal
  After normalisation: https://client-app.com/evil        ← wrong destination
  → Exact match before normalisation prevents this ✓

─────────────────────────────────────────────────────────────────────────────
DO NOT: Pattern matching, prefix matching, or wildcards
─────────────────────────────────────────────────────────────────────────────
Vulnerable pattern check: startsWith("https://client-app.com")
  Attacker submits: https://client-app.com.attacker.com/callback  ✓ PASSES ✗
  Attacker submits: https://client-app.com/callback@attacker.com  ✓ PASSES ✗

Vulnerable wildcard: https://client-app.com/*
  Attacker submits: https://client-app.com/evil              ✓ PASSES ✗

Vulnerable subdomain wildcard: https://*.client-app.com/callback
  Attacker submits: https://attacker.client-app.com/callback ✓ PASSES ✗
  If attacker controls ANY subdomain (via subdomain takeover, open redirect,
  XSS on subdomain): code delivered to attacker ✓

─────────────────────────────────────────────────────────────────────────────
Correct implementation (pseudo-code):
─────────────────────────────────────────────────────────────────────────────
def validate_redirect_uri(client_id, requested_uri):
    registered_uris = db.get_registered_uris(client_id)

    # Exact byte-for-byte comparison — no normalisation before comparison
    if requested_uri in registered_uris:
        return True

    # reject BEFORE any processing of the request
    raise OAuthError("invalid_request",
                     "redirect_uri does not match any registered URI")

    # NEVER:
    # - requested_uri.startswith(registered_uri)  ← prefix attack
    # - re.match(registered_pattern, requested_uri) ← regex bypass
    # - URL-decode then compare                   ← double-encoding bypass
    # - Compare after stripping fragment (#)      ← fragment injection

─────────────────────────────────────────────────────────────────────────────
Additional redirect_uri controls:
─────────────────────────────────────────────────────────────────────────────
✓ Allow ONLY HTTPS scheme in redirect URIs (except localhost for native apps)
  → Prevents code interception over unencrypted HTTP
✓ Reject redirect URIs with user-info components (https://x@evil.com/path)
✓ Reject redirect URIs with open redirects (/redirect?url=https://attacker.com)
✓ Reject localhost / loopback URIs in production client registrations
  (allowed only for native app local redirect: http://127.0.0.1:[port]/callback)
✓ When redirect_uri omitted in auth request: use the sole registered URI
   (only if exactly ONE URI is registered; otherwise reject)
✓ Re-validate redirect_uri at /token endpoint matches the original auth request value
   → Prevents code injection into the wrong redirect URI
```

### `state` Parameter Enforcement

```python
# ── SERVER-SIDE: Enforce state parameter ─────────────────────────────────────

# Step 1: Require state in all authorization requests
def handle_authorization_request(request):
    if not request.params.get('state'):
        # RFC 9700: state SHOULD be required by authorization servers
        # In practice: require it as a hard policy
        raise OAuthError("invalid_request",
                         "state parameter is required")

    # Store the state value associated with the requesting client
    # For validation after user consent:
    session['pending_state'] = request.params['state']
    session['pending_client_id'] = request.params['client_id']
    # ...


# Step 2: Return EXACT state value in authorization response
def issue_authorization_code(client_id, scope, redirect_uri, state):
    code = generate_secure_random_code()
    db.store_code(code, client_id, scope, redirect_uri)
    # Return state unchanged — do NOT modify, truncate, or re-encode it
    return redirect(f"{redirect_uri}?code={code}&state={state}")


# Step 3: Bind state value to session on the CLIENT SIDE (enforced by client)
# The server cannot enforce session binding — that is the client's responsibility.
# But server should document that state MUST be session-bound.


# ── WHAT GOOD state GENERATION LOOKS LIKE (CLIENT RESPONSIBILITY) ─────────────

import os, hashlib, hmac

# Method 1: Opaque random token (simplest, most common)
state = os.urandom(32).hex()         # 64 hex chars = 256 bits of entropy
session['oauth_state'] = state

# Method 2: HMAC of session cookie (cryptographically bound to session)
secret_key = app.config['SECRET_KEY']
session_id = session.get('session_id').encode()
state = hmac.new(secret_key.encode(), session_id, hashlib.sha256).hexdigest()
# → Even if attacker knows the algorithm, they can't forge a valid state
#   without knowing the session ID AND the secret key

# Method 3: Encrypted state with application context (for SPAs)
import json
from cryptography.fernet import Fernet
f = Fernet(SECRET_KEY)
state_data = {'nonce': os.urandom(16).hex(),
              'redirect_after': '/dashboard',
              'user_agent': request.user_agent.string}
state = f.encrypt(json.dumps(state_data).encode()).decode()
# → Carries app context securely AND is unguessable ✓
# → After OAuth callback: decrypt to get nonce + redirect destination


# ── VALIDATION AT /callback ────────────────────────────────────────────────────
def handle_callback(request):
    received_state = request.params.get('state')
    stored_state = session.pop('oauth_state', None)    # pop = single use ✓

    if not received_state or not stored_state:
        abort(400, "Missing state parameter")

    # Timing-safe comparison (prevents timing oracle attacks)
    if not hmac.compare_digest(received_state, stored_state):
        abort(400, "State mismatch — possible CSRF attack")
        # Log this event: potential CSRF or code injection in progress

    # Only now proceed to exchange code for token
    exchange_code_for_token(request.params['code'])
```

### Token and Scope Validation on the Resource Server

```python
# ── RESOURCE SERVER: validate every incoming API request ─────────────────────

def validate_access_token(token, request):
    token_info = introspect_token(token)   # call authorization server's /introspect

    # 1. Token must be active (not expired or revoked)
    if not token_info['active']:
        raise HTTPError(401, "Token is invalid or expired")

    # 2. Token must have been issued to the client making this request
    # (prevents token substitution attacks)
    if token_info['client_id'] != request.client_id:
        raise HTTPError(403, "Token was issued to a different client")

    # 3. Token scope must cover the operation being requested
    granted_scopes = set(token_info['scope'].split())
    required_scopes = get_required_scopes(request.path, request.method)
    if not required_scopes.issubset(granted_scopes):
        raise HTTPError(403,
            f"Insufficient scope: requires {required_scopes}, "
            f"token has {granted_scopes}")

    return token_info


# ── SCOPE DOWNGRADE PREVENTION ─────────────────────────────────────────────────
# Attacker may request a token with scope=read, then try to use it for write operations.
# Never infer permissions from token structure alone — always check scope at the resource.

# ── TOKEN BINDING (advanced, RFC 8705) ────────────────────────────────────────
# Bind access token to the client's TLS certificate (mutual TLS)
# → Stolen token useless without matching TLS client cert
# → Most applicable in high-security API environments
```

***

## For OAuth Client Applications

### Complete `state` Parameter Implementation

```python
# ── CLIENT-SIDE: Generate and validate state ──────────────────────────────────

# /login endpoint: initiate OAuth flow
def initiate_oauth_login():
    # Generate cryptographically strong random state
    state = secrets.token_urlsafe(32)    # 43 chars of URL-safe base64 = 256 bits

    # Store in server-side session (NOT in a cookie alone — session is server-side)
    session['oauth_state'] = state
    session['oauth_timestamp'] = time.time()    # expire stale states after 10 mins

    auth_url = (
        f"https://oauth-provider.com/auth"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid%20profile%20email"
        f"&state={state}"
    )
    return redirect(auth_url)


# /callback endpoint: validate state BEFORE processing code
def oauth_callback():
    # Check for OAuth error responses first
    if 'error' in request.args:
        abort(400, f"OAuth error: {request.args['error']}")

    received_state = request.args.get('state', '')
    stored_state = session.get('oauth_state', '')
    stored_timestamp = session.get('oauth_timestamp', 0)

    # State must be present and match
    if not hmac.compare_digest(received_state, stored_state):
        abort(400, "Invalid state — CSRF attempt detected")

    # State must not be stale (prevent replay of old states)
    if time.time() - stored_timestamp > 600:    # 10 minute expiry
        abort(400, "OAuth state expired — please try again")

    # Clear state from session (single-use enforcement)
    session.pop('oauth_state', None)
    session.pop('oauth_timestamp', None)

    # NOW safe to exchange the authorization code
    code = request.args.get('code')
    exchange_code_for_token(code)
```

### Sending `redirect_uri` to BOTH `/authorization` AND `/token`

```python
# ── WHY BOTH ENDPOINTS NEED redirect_uri ─────────────────────────────────────
# Authorization server ties the issued code to the redirect_uri used in /auth.
# /token endpoint MUST verify: redirect_uri in token request == redirect_uri at /auth.
# If /token doesn't receive redirect_uri: some servers skip the check.
# → Attacker who intercepted code can use it at /token WITHOUT matching redirect_uri.

# WRONG (only sends to /auth):
auth_url = f"{PROVIDER}/auth?...&redirect_uri={REDIRECT_URI}"
token_response = requests.post(f"{PROVIDER}/token", data={
    'grant_type': 'authorization_code',
    'code': code,
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET
    # ← no redirect_uri here → vulnerable
})

# CORRECT (sends to both):
auth_url = f"{PROVIDER}/auth?...&redirect_uri={REDIRECT_URI}"
token_response = requests.post(f"{PROVIDER}/token", data={
    'grant_type': 'authorization_code',
    'code': code,
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'redirect_uri': REDIRECT_URI          # ← MUST match what was used in /auth ✓
})
```

### PKCE for Mobile, Native, and SPA Clients

```python
# ── WHY PKCE IS REQUIRED FOR PUBLIC CLIENTS ───────────────────────────────────
# Mobile apps / native desktop apps: client_secret cannot be kept private
# (decompile the APK/binary → secret extracted trivially)
# SPA apps: client_secret in JavaScript = public secret
# → Without client_secret, anyone who intercepts the code can exchange it
# → PKCE replaces client_secret with a per-request one-time proof ✓

import hashlib, base64, os, re

def generate_pkce_pair():
    # code_verifier: 43–128 URL-safe characters (RFC 7636 §4.1)
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
    # Verify it matches: [A-Za-z0-9\-._~]{43,128}
    assert re.match(r'^[A-Za-z0-9\-._~]{43,128}$', code_verifier)

    # code_challenge: BASE64URL(SHA256(ASCII(code_verifier)))
    digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

    return code_verifier, code_challenge

code_verifier, code_challenge = generate_pkce_pair()
session['code_verifier'] = code_verifier    # stored securely; never sent in URL


# Authorization request (includes challenge):
auth_url = (
    f"{PROVIDER}/auth"
    f"?client_id={CLIENT_ID}"
    f"&redirect_uri={REDIRECT_URI}"
    f"&response_type=code"
    f"&scope=openid%20profile"
    f"&state={state}"
    f"&code_challenge={code_challenge}"     # ← sent in URL (public — just a hash)
    f"&code_challenge_method=S256"          # ← always S256, never plain
)


# Token request (includes verifier):
token_response = requests.post(f"{PROVIDER}/token", data={
    'grant_type': 'authorization_code',
    'code': authorization_code,
    'client_id': CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'code_verifier': session.pop('code_verifier')   # ← sent here (never in URL)
    # NO client_secret for public clients
})

# Authorization server validates: SHA256(code_verifier) == stored code_challenge
# → Intercepted code useless without the code_verifier (held only in attacker-inaccessible session)
# → code_verifier never appears in a URL → not in browser history, not in Referer headers ✓

# ⚠ NEVER use code_challenge_method=plain:
# plain: code_challenge == code_verifier (no hashing)
# → An attacker who sees the challenge (in the URL) has the verifier directly ✓
# → S256 is the only secure option
```

### Preventing Authorization Code Leakage via `Referer`

```http
# ── THE PROBLEM: Referer header leaks the authorization code ─────────────────
# After OAuth callback: user lands on:
# https://client-app.com/callback?code=a1b2c3d4&state=ae13d489bd00e3c24

# If /callback page includes ANY external resources (images, scripts, analytics):
# Browser sends:
GET /image.png HTTP/1.1
Host: cdn.third-party.com
Referer: https://client-app.com/callback?code=a1b2c3d4&state=ae13d489bd00e3c24
                                                ↑ CODE LEAKED TO CDN ✓

# Even if the code is used and invalidated, if the CDN logs Referer:
# → Third party has a record of valid authorization codes
# → If invalidation is slow (race condition): code usable by CDN operator ✓

# ── FIXES: Multiple layers of protection ─────────────────────────────────────

# Fix 1: Set Referrer-Policy header on /callback response
HTTP/1.1 302 Found
Location: /dashboard
Referrer-Policy: no-referrer
# → Browser sends no Referer header for ANY subsequent requests from this page ✓

# Fix 2: Use Referrer-Policy meta tag if you control the page HTML
<meta name="referrer" content="no-referrer">

# Fix 3: Immediately redirect away from the code-bearing URL
# /callback receives code → processes it → IMMEDIATELY redirects to /dashboard
# User's browser never renders a full page at /callback → no external resource loading ✓
def oauth_callback():
    code = request.args['code']
    # Process code...
    token = exchange_code_for_token(code)
    session['user_id'] = get_user_from_token(token)
    # Redirect to clean URL with no OAuth params
    return redirect('/dashboard', code=302)    # ← no external content loaded on /callback ✓

# Fix 4: Never include authorization code in dynamically generated JS files
# WRONG:
app.get('/app.js', (req, res) => {
    res.send(`var authCode = "${req.query.code}";`);  // ← code in a JS file
    // If attacker embeds: <script src="https://client-app.com/app.js?code=STOLEN"></script>
    // → Their page executes and extracts the authCode ✓ → code stolen via XSSI ✓
})

# CORRECT: Never put sensitive URL parameters into JS files served by your app

# Fix 5: Replace URL parameters in browser history after processing
window.history.replaceState({}, document.title, '/dashboard');
// → Removes ?code=...&state=... from browser history after processing ✓
# (Client-side, but prevents code appearing in browser history for extended period)
```

***

## ID Token / JWT Validation Checklist

```python
# ── COMPLETE ID TOKEN VALIDATION (OpenID Connect) ─────────────────────────────
import time
import hmac as hmac_lib
import requests
from jose import jwt, jwk
from jose.exceptions import JWTError, ExpiredSignatureError

def validate_id_token(id_token, nonce, client_id, issuer):
    # 1. Fetch current public keys (cache with TTL, refresh on kid mismatch)
    jwks_uri = f"{issuer}/.well-known/openid-configuration"
    oidc_config = requests.get(jwks_uri).json()
    jwks = requests.get(oidc_config['jwks_uri']).json()

    try:
        # 2. Decode and verify signature
        #    algorithms: EXPLICITLY list allowed algorithms — NEVER use ["*"] or omit
        #    aud: MUST match your client_id
        #    issuer: MUST match the expected OpenID provider
        claims = jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256", "ES256"],   # ← NEVER include "none"
            audience=client_id,              # ② aud check ✓
            issuer=issuer                    # ① iss check ✓
        )
        # jwt.decode() automatically validates exp ③ and iat ④

        # 5. Validate nonce (replay attack prevention)
        if not hmac_lib.compare_digest(claims.get('nonce', ''), nonce):
            raise ValueError("Nonce mismatch — potential replay attack")

        # 6. Validate auth_time if max_age was specified in auth request
        if 'auth_time' in claims:
            max_age = session.get('requested_max_age', float('inf'))
            if time.time() - claims['auth_time'] > max_age:
                raise ValueError("User authentication is too old — re-auth required")

        # 7. Use sub as primary user identifier (NOT email — email can change)
        user_id = claims['sub']            # stable, unique per provider
        email = claims.get('email')        # informational only
        email_verified = claims.get('email_verified', False)

        if email and not email_verified:
            # Do NOT use unverified email for identity matching
            # (attacker could register same unverified email at attacker's provider)
            email = None

        return {'sub': user_id, 'email': email, 'claims': claims}

    except ExpiredSignatureError:
        raise HTTPError(401, "ID token has expired")
    except JWTError as e:
        raise HTTPError(401, f"Invalid ID token signature: {e}")
```

***

## Consolidated Prevention Checklist

### OAuth Provider Requirements

```
REDIRECT_URI:
  ✓ Store explicit URI whitelist per client_id (not patterns, not wildcards)
  ✓ Exact byte-for-byte comparison before URL normalisation
  ✓ HTTPS required for all redirect URIs (except localhost for native apps)
  ✓ Re-validate at /token that redirect_uri matches value used at /auth
  ✓ Reject URIs with user-info, open redirects, or path traversal sequences

STATE:
  ✓ Require state parameter (reject requests without it, or strongly warn)
  ✓ Return exact state value unchanged in authorization response
  ✓ Document that state must be session-bound (client responsibility)

TOKENS:
  ✓ Issue short-lived access tokens (< 1 hour recommended)
  ✓ Implement token introspection (/introspect) for resource servers
  ✓ Support token revocation (/revoke) for logout and breach response
  ✓ Verify client_id at resource server matches token's issued-to client
  ✓ Enforce scope checks on every resource server request

PKCE:
  ✓ Support PKCE (RFC 7636) — required in OAuth 2.1 for ALL clients
  ✓ Require PKCE for public clients (no client_secret)
  ✓ Reject code_challenge_method=plain; accept only S256

DYNAMIC REGISTRATION (if supported):
  ✓ Require authentication for /registration endpoint (bearer token or client cert)
  ✓ Validate / restrict logo_uri, jwks_uri, sector_identifier_uri to HTTPS
  ✓ Do not fetch user-supplied URIs on the server without SSRF protection
  ✓ Implement allowlist or SSRF filter for any server-side URI fetching

DEPRECATE:
  ✗ Implicit grant type (RFC 9700: deprecated) — migrate to code + PKCE  [web:216]
  ✗ Resource Owner Password Credentials grant — deprecated in OAuth 2.1
  ✗ Unencrypted redirect URIs (HTTP) in production
```

### OAuth Client Requirements

```
MUST IMPLEMENT:
  ✓ state parameter — always, even though optional in spec
  ✓ PKCE — always for public clients (SPAs, mobile, native apps)
  ✓ redirect_uri in BOTH /auth AND /token requests
  ✓ HTTPS-only for all redirect_uris
  ✓ ID token full validation (alg, iss, aud, exp, nonce — all seven checks)
  ✓ Referrer-Policy: no-referrer on /callback response
  ✓ Immediate redirect from /callback (clear code from URL)

MUST NOT:
  ✗ Include authorization code in dynamically generated JS files
  ✗ Log authorization codes or access tokens to application logs
  ✗ Use email as primary identity key without email_verified: true check
  ✗ Store client_secret in mobile app binary or client-side JavaScript
  ✗ Accept id_token with alg: none
  ✗ Skip any of the seven ID token validation steps
  ✗ Reuse state values across sessions (single-use enforcement)
  ✗ Trust access tokens without verifying they were issued for your client_id

MONITORING:
  ✓ Log and alert on state mismatches at /callback (CSRF in progress)
  ✓ Log and alert on authorization code reuse attempts (code injection)
  ✓ Monitor for anomalous token usage (unexpected scopes, unusual client_ids)
  ✓ Implement token revocation on logout (call /revoke for access + refresh tokens)
```
