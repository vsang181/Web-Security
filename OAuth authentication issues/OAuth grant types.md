# OAuth Grant Types

OAuth 2.0 defines the rules for how a third-party client application can be granted limited access to a user's resources on another service — without the user ever sharing their password with the client. The grant type is the specific protocol flow that determines *how* that delegation happens: which parties talk to each other, over which channels, and what credentials are exchanged at each step. From a security perspective, the grant type you choose fundamentally determines your attack surface — the authorization code flow keeps the most sensitive tokens out of the browser entirely, while the implicit flow exposes them via URL fragments where they can be intercepted, logged, and replayed. 

**Fundamental principle: OAuth separates the act of authorising access (user consent, handled by the OAuth server) from the act of obtaining the token (handled by the client). The security of each grant type depends entirely on how well the token is protected during that second act — and that is where nearly all OAuth vulnerabilities are found.**

***

## Core Roles and Terminology

```
OAuth 2.0 Parties:
─────────────────────────────────────────────────────────────────────────────
Resource Owner:          The user whose data is being accessed (e.g., you)
Client Application:      The third-party app requesting access (e.g., a job site
                         wanting to read your LinkedIn profile)
OAuth Authorization Server: Issues access tokens after authenticating the user
                             and obtaining consent (e.g., accounts.google.com)
Resource Server:         Hosts the protected user data; validates access tokens
                         (may be same server as authorization server, or separate)
                         (e.g., api.google.com)

What OAuth is NOT:
  ✗ An authentication protocol (it delegates authorisation, not identity)
  ✓ When used for login (OpenID Connect), authentication is LAYERED ON TOP of OAuth
  → Many vulnerabilities arise from treating OAuth as authentication when it isn't

Token types:
  Authorization Code:   Short-lived, single-use code exchanged for an access token
                        → Travels through the browser (URL parameter) but is useless
                          alone — requires client_secret to exchange
  Access Token:         The credential used to call the resource server API
                        → Bearer token: whoever holds it can use it
                        → Should NEVER travel through the browser in code flow
  Refresh Token:        Long-lived token used to obtain new access tokens silently
                        → Only present in code flow, never implicit flow
  ID Token:             OpenID Connect extension — JWT containing user identity
                        → Separate from the access token; used for login

Scopes (what access is being requested):
  scope=contacts                                     (custom provider scope)
  scope=contacts.read                                (custom provider scope)
  scope=openid profile email                         (OpenID Connect standard scopes)
  scope=https://www.googleapis.com/auth/gmail.readonly  (URI-format scope)
```

***

## Authorization Code Grant Type (Recommended for Web Apps)

The authorization code flow is the most secure grant type because the access token never passes through the browser. The browser carries only a short-lived, single-use authorization *code*, and the actual token exchange happens over a direct server-to-server channel using a pre-shared `client_secret`. 

```
Authorization Code Flow — Complete Sequence:
─────────────────────────────────────────────────────────────────────────────

  [BROWSER]         [CLIENT APP]        [AUTH SERVER]       [RESOURCE SERVER]
      │                   │                    │                    │
  ①  │ Click "Sign in    │                    │                    │
      │ with [Provider]"  │                    │                    │
      │──────────────────►│                    │                    │
  ②  │ Redirect to       │ Builds auth URL    │                    │
      │ /authorization    │───────────────────►│                    │
      │◄──────────────────│                    │                    │
  ③  │ GET /authorization?...                  │                    │
      │────────────────────────────────────────►                    │
  ④  │ Login page / consent screen             │                    │
      │◄────────────────────────────────────────                    │
  ⑤  │ User logs in, clicks "Allow"            │                    │
      │────────────────────────────────────────►                    │
  ⑥  │ 302 → /callback?code=AUTHCODE&state=... │                    │
      │◄────────────────────────────────────────                    │
  ⑦  │ GET /callback?code=AUTHCODE&state=...   │                    │
      │──────────────────►│                    │                    │
  ⑧  │                   │ POST /token         │                    │
      │                   │ (server-to-server) │                    │
      │                   │───────────────────►│                    │
  ⑨  │                   │ {"access_token":..} │                    │
      │                   │◄───────────────────│                    │
  ⑩  │                   │ GET /userinfo        │                    │
      │                   │    Authorization: Bearer [token]        │
      │                   │────────────────────────────────────────►│
  ⑪  │                   │ {"username":"carlos","email":...}        │
      │                   │◄────────────────────────────────────────│
  ⑫  │ Logged in ✓       │                    │                    │
      │◄──────────────────│                    │                    │

Legend: [BROWSER] steps are visible to attacker/network. Steps ⑧–⑪ are NOT.
```

### Step 1: Authorization Request

```http
# Client application redirects user's browser to OAuth provider:

GET /authorization?client_id=12345
                  &redirect_uri=https://client-app.com/callback
                  &response_type=code
                  &scope=openid%20profile%20email
                  &state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com

# Parameter breakdown:
# ─────────────────────────────────────────────────────────────────────────────
# client_id:      Identifies the client app (registered with OAuth provider)
#                 PUBLIC value — not a secret
#                 → If you intercept this, you know which client app is involved
#
# redirect_uri:   Where to send the authorization code AFTER consent
#                 MUST match the pre-registered URI exactly (ideally)
#                 → #1 target for exploitation (redirect_uri manipulation)
#
# response_type:  "code" → tells server to use authorization code flow
#                 (implicit flow uses response_type=token)
#
# scope:          What access is being requested
#                 "openid" → required for OpenID Connect (login use case)
#                 "profile" → basic user info (name, picture, etc.)
#                 "email" → email address
#                 → Always check if scope can be ESCALATED in the token request
#
# state:          Unguessable random value tied to current browser session
#                 → CSRF protection for the /callback endpoint
#                 → If absent: CSRF attack possible → account takeover via code injection
#                 → If present but not validated: same vulnerability
#                 → Value should be: crypto.randomUUID() or equivalent

# ── SECURITY OBSERVATION ─────────────────────────────────────────────────────
# This request is visible to:
#   ✓ The user's browser
#   ✓ The OAuth provider's server
#   ✓ Any network observer (URL params in GET request)
# The client_id and scopes are public here — that's expected and safe.
# The state value MUST be unpredictable and session-bound.
```

### Steps 2–3: User Login and Consent → Authorization Code

```http
# After user logs in and clicks "Allow", OAuth server redirects:
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com

# The authorization code ("a1b2c3d4e5f6g7h8"):
#   - Short-lived (typically 5–10 minutes)
#   - Single-use (invalidated after one exchange attempt)
#   - Useless alone (requires client_secret to exchange for token)
#   - Tied to: the specific client_id, redirect_uri, and scope

# State validation (MUST perform on /callback):
# 1. Extract state from query parameter: "ae13d489bd00e3c24"
# 2. Compare to state stored in user's session when auth was initiated
# 3. Match → proceed. Mismatch → abort (CSRF attack in progress).

# ── SECURITY NOTE: Code travels through browser → exposed to ─────────────────
#   ✓ Browser address bar (briefly visible)
#   ✓ Referrer header (if page redirects elsewhere)
#   ✓ Server access logs at client-app.com
#   ✓ Browser history
# → This is WHY code alone is useless: it still requires client_secret to exchange
# → But: if redirect_uri is manipulated, code is sent to attacker's server ✓
```

### Steps 4–5: Token Exchange (Server-to-Server Back-Channel)

```http
# Client app server directly contacts the OAuth server (NOT via browser):

POST /token HTTP/1.1
Host: oauth-authorization-server.com
Content-Type: application/x-www-form-urlencoded

client_id=12345
&client_secret=SECRET_KEY_HERE
&redirect_uri=https://client-app.com/callback
&grant_type=authorization_code
&code=a1b2c3d4e5f6g7h8

# client_secret:  Pre-shared secret between client app and OAuth provider
#                 → PRIVATE — never sent to browser, never in URLs
#                 → Proves this token request actually comes from the registered client
#                 → If leaked: attacker can exchange any intercepted code themselves
#
# redirect_uri:   Must match exactly what was sent in the original auth request
#                 → OAuth server validates this to prevent code interception
#
# grant_type:     "authorization_code" → tells /token endpoint which flow this is

# ── OAuth server response ─────────────────────────────────────────────────────
{
    "access_token":  "z0y9x8w7v6u5",     ← the actual credential for API calls
    "token_type":    "Bearer",            ← how to send it: Authorization: Bearer ...
    "expires_in":    3600,                ← valid for 1 hour (typical)
    "scope":         "openid profile email",
    "refresh_token": "abc123refresh",     ← optional: get new access tokens silently
    "id_token":      "eyJhbG..."          ← JWT with user identity (OpenID Connect)
}

# ── THIS EXCHANGE IS INVISIBLE TO ────────────────────────────────────────────
#   ✓ The user's browser
#   ✓ Network observers
#   ✓ Attacker who intercepted the authorization code
# → Even if attacker has the code, they cannot exchange it without client_secret
```

### Steps 6–7: API Call and Resource Grant

```http
# Client app calls resource server with the access token:

GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5

# Response:
{
    "sub":      "user-id-12345",          ← subject: unique user identifier
    "username": "carlos",
    "email":    "carlos@carlos-montoya.net",
    "name":     "Carlos Montoya",
    "picture":  "https://..."
}

# Client app creates a session for "carlos" → user is logged in ✓
```

***

## Implicit Grant Type (Legacy — Largely Deprecated)

The implicit flow trades security for simplicity: the access token is returned directly in the URL fragment after consent, with no code exchange step and no `client_secret` required. This made it popular for single-page apps and native apps that cannot store secrets, but it fundamentally exposes the token to the browser environment. 

```
Implicit Flow — Complete Sequence:
─────────────────────────────────────────────────────────────────────────────

  [BROWSER]         [CLIENT SPA]        [AUTH SERVER]       [RESOURCE SERVER]
      │                   │                    │                    │
  ①  │ Click "Sign in"   │                    │                    │
      │──────────────────►│                    │                    │
  ②  │ Redirect to /auth  │                    │                    │
      │────────────────────────────────────────►                    │
  ③  │ Login + Consent                         │                    │
      │◄────────────────────────────────────────                    │
  ④  │ 302 → /callback#access_token=TOKEN&...  │                    │
      │◄────────────────────────────────────────                    │
      │ ↑ Token in URL FRAGMENT (#) — NOT sent in HTTP requests
      │   BUT: visible to JavaScript on the page
  ⑤  │ JS extracts token from window.location.hash               │
      │──────────────────►│                    │                    │
  ⑥  │                   │ GET /userinfo                            │
      │                   │    Authorization: Bearer TOKEN         │
      │                   │────────────────────────────────────────►│
  ⑦  │                   │ {"username":"carlos","email":...}        │
      │                   │◄────────────────────────────────────────│
  ⑧  │ Logged in ✓       │                    │                    │
      │◄──────────────────│                    │                    │

CRITICAL DIFFERENCES FROM CODE FLOW:
  ✗ No authorization code (code → token exchange step eliminated)
  ✗ No client_secret (nothing to authenticate the client app with)
  ✗ No back-channel (ALL communication goes through browser)
  ✗ Token in URL fragment → exposed to JavaScript, browser history, Referer
  ✗ No refresh tokens (implicit flow tokens typically cannot be refreshed)
  ✓ Simpler (2 fewer steps)
  ✓ No server-side component required (works in pure client-side SPAs)
```

### Steps 1–3: Authorization Request and Access Token Grant

```http
# Authorization request (differs only in response_type):
GET /authorization?client_id=12345
                  &redirect_uri=https://client-app.com/callback
                  &response_type=token         ← "token" instead of "code"
                  &scope=openid%20profile
                  &state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com

# After user consents, OAuth server responds with:
HTTP/1.1 302 Found
Location: https://client-app.com/callback
          #access_token=z0y9x8w7v6u5          ← TOKEN IN FRAGMENT
          &token_type=Bearer
          &expires_in=5000
          &scope=openid%20profile
          &state=ae13d489bd00e3c24

# ── URL FRAGMENT (#) BEHAVIOUR ────────────────────────────────────────────────
# Browser behaviour: fragment (#access_token=...) is NOT sent in HTTP requests.
# → Server at /callback never receives the token in the request
# → Fragment is ONLY accessible to JavaScript running on the page
#
# JavaScript extracts it:
const params = new URLSearchParams(window.location.hash.substring(1));
const accessToken = params.get('access_token');    // "z0y9x8w7v6u5"

# ── WHERE THE TOKEN IS EXPOSED ────────────────────────────────────────────────
# Fragment appears in:
#   ✓ Browser address bar (user can see it, screenshot risk)
#   ✓ Browser history (stored locally)
#   ✓ Any JavaScript executing on the page (XSS can steal it trivially)
#   ✓ Referer header (if page includes external resources, fragment may leak)
#   ✗ Server logs (fragment not sent in HTTP requests — only partial protection)
#
# ── SECURITY RISKS ────────────────────────────────────────────────────────────
# Token leakage via Referer:
#   If /callback loads images or scripts from third-party servers,
#   the Referer header includes the full URL (some browsers include fragment):
#   Referer: https://client-app.com/callback#access_token=z0y9x8w7v6u5
#   → Third-party server receives the token ✓
#
# Token leakage via open redirect on /callback:
#   If attacker redirects /callback to their own domain:
#   /callback?next=https://attacker.com
#   Browser redirects to attacker.com with fragment still intact:
#   https://attacker.com#access_token=z0y9x8w7v6u5
#   → Attacker's JavaScript reads window.location.hash → token captured ✓
#
# XSS interaction:
#   Any XSS vulnerability on the domain can access window.location.hash
#   → Access token stolen → attacker makes API calls on victim's behalf ✓
#   In code flow, XSS cannot steal the access token (never in browser JS context)
```

### Steps 4–5: API Call (Via Browser)

```http
# API call made from browser JavaScript (unlike code flow where server calls):
GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5

# This request is made from the user's browser:
# → Visible to browser extensions
# → Visible to any XSS payload on the page
# → Logged in browser network console
# → Potentially visible to a network proxy/observer
```

***

## PKCE Extension (Authorization Code + Public Clients)

When a client application cannot safely store a `client_secret` (native mobile apps, SPAs), PKCE (Proof Key for Code Exchange, RFC 7636) provides equivalent protection for the code flow without a static secret. 

```
PKCE Flow (Authorization Code without client_secret):
─────────────────────────────────────────────────────────────────────────────

Step 1: Client generates a random code_verifier and derives code_challenge:
  code_verifier  = random 43–128 character string
                   (e.g., "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
  code_challenge = BASE64URL(SHA256(code_verifier))
                   (e.g., "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")

Step 2: Authorization request (includes code_challenge):
  GET /authorization?...
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256

Step 3: Token request (includes code_verifier):
  POST /token
  ...
  code=AUTHCODE
  &code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
  ← No client_secret needed

Server validates: SHA256(code_verifier) == stored code_challenge ✓
→ Only the party that generated code_verifier can complete the exchange
→ If attacker intercepts the code: they don't have code_verifier → useless

Why this matters:
  ✗ Without PKCE: intercepted code → attacker exchanges it (no secret needed for public clients)
  ✓ With PKCE:    intercepted code → useless (code_verifier never travels in URL)

OAuth 2.1 status: PKCE is REQUIRED for ALL clients (including confidential) [web:188]
```
