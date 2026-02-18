# CORS and the Access-Control-Allow-Origin Header

The `Access-Control-Allow-Origin` (ACAO) response header is the centrepiece of the CORS protocol — the single most important header in the entire CORS specification, because it is the instruction a server sends to a browser declaring which external origins are permitted to read its responses, forming the controlled relaxation mechanism that allows the modern web's cross-origin API architectures to function while preserving the same-origin policy's core protections. Understanding every dimension of how this header works, what values it accepts, what restrictions apply to those values, how preflight checks interact with it, and crucially what it does NOT protect against, is essential both for implementing CORS correctly and for identifying the misconfigurations that transform it from a security mechanism into a vulnerability.

The central principle: **the ACAO header is a server-to-browser instruction, not a server-to-server restriction — it controls what browsers allow JavaScript to read, not what requests reach the server**.

## What is the Access-Control-Allow-Origin Header?

### Function and purpose

**How ACAO fits into the browser security model:**

```
Without CORS:
Browser has SOP: JavaScript on origin-A cannot read responses from origin-B

The problem this creates:
Frontend: https://app.company.com
API:       https://api.company.com
→ Completely different origins (different subdomain)
→ SOP blocks JavaScript from reading API responses
→ The application cannot work!

CORS solution:
api.company.com responds with:
Access-Control-Allow-Origin: https://app.company.com

Browser decision process:
1. JavaScript on app.company.com makes fetch to api.company.com
2. Browser adds: Origin: https://app.company.com to request
3. Browser receives response from api.company.com
4. Browser checks: Does ACAO match the requesting origin?
   ACAO: https://app.company.com
   Origin: https://app.company.com
   → MATCH! JavaScript may read the response.
5. JavaScript on app.company.com gets access to response body ✓

If no ACAO or mismatched ACAO:
4. Browser checks: Does ACAO match?
   ACAO: (absent) or https://other.com
   Origin: https://app.company.com
   → NO MATCH. Browser blocks JavaScript from reading response ✗
```

**ACAO header anatomy:**

```http
Single trusted origin (most secure for authenticated APIs):
Access-Control-Allow-Origin: https://app.company.com

Wildcard (public, unauthenticated APIs only):
Access-Control-Allow-Origin: *

Null (avoid — exploitable):
Access-Control-Allow-Origin: null

Multiple origins in one header (NOT supported by any browser):
Access-Control-Allow-Origin: https://app.com, https://admin.com  ← INVALID

Wildcard subdomain (NOT valid — browsers reject this syntax):
Access-Control-Allow-Origin: https://*.company.com  ← INVALID

The CORS spec only allows ONE of:
- A single specific origin
- *
- null
(Servers that need multiple origins must dynamically set the header)
```

## Simple Cross-Origin Requests

### The basic CORS exchange

**Step-by-step browser and server interaction:**

```http
Step 1: JavaScript on normal-website.com initiates request
fetch('https://robust-website.com/data', { mode: 'cors' });

Step 2: Browser automatically adds Origin header
GET /data HTTP/1.1
Host: robust-website.com
Origin: https://normal-website.com    ← Browser adds automatically
Accept: application/json
Connection: keep-alive

Step 3: Server processes request and responds with ACAO header
HTTP/1.1 200 OK
Content-Type: application/json
Access-Control-Allow-Origin: https://normal-website.com  ← Server grants access
Content-Length: 42

{"key": "value", "data": "response content"}

Step 4: Browser compares Origin against ACAO
Origin sent:  https://normal-website.com
ACAO returned: https://normal-website.com
→ EXACT MATCH → JavaScript permitted to read response ✓

Step 5: If NO match:
Origin sent:  https://normal-website.com
ACAO returned: https://other-website.com (or absent)
→ MISMATCH → Browser blocks JavaScript access ✗
→ "CORS error: No 'Access-Control-Allow-Origin' header present"
→ .then() callback never fires with response data
```

**What the browser actually blocks:**

```javascript
// The request still reaches the server regardless of CORS!
// The server still processes it and returns a response!
// CORS only controls whether JavaScript can READ that response.

fetch('https://robust-website.com/data')
  .then(response => {
      // This .then() is where the browser enforces CORS
      // If ACAO doesn't match → error thrown here
      // The HTTP request itself already completed on the server
      return response.json();
  })
  .then(data => {
      // If CORS blocked: never reaches here
      console.log(data);
  })
  .catch(error => {
      // CORS failure appears here as a TypeError
      console.error('CORS error:', error);
      // "TypeError: Failed to fetch" or "CORS policy blocked access"
  });
```

**Origin header — key facts:**

```
The Origin header:
- Added automatically by browsers on cross-origin requests
- Cannot be set/modified by JavaScript (unlike other headers)
  fetch('/path', { headers: { 'Origin': 'fake' } })
  → Browser ignores the developer-specified Origin
  → Uses actual page origin instead
  → Prevents forging Origin headers from browser context

- Only sent on cross-origin requests (not same-origin)
- Contains: scheme + hostname + port (no path, query, or fragment)
  Page: https://app.example.com/user/profile?tab=settings
  Origin header: https://app.example.com  (just the origin, not full URL)

- Also sent on same-origin POST requests in some browsers
- Null for: file://, sandboxed iframes with data: URIs, some redirects
```

## CORS with Credentials

### Access-Control-Allow-Credentials header

**Why credentials require special handling:**

```
Default fetch() / XHR behaviour — NO credentials:
fetch('https://api.example.com/data')
→ Request sent WITHOUT cookies
→ Request sent WITHOUT Authorization header
→ Server sees unauthenticated request

The server can respond: Access-Control-Allow-Origin: *
→ Anyone can read this response (it's unauthenticated anyway)

With credentials (cookies, Authorization):
fetch('https://api.example.com/data', { credentials: 'include' })
→ Browser sends victim's session cookies
→ Server generates authenticated response (contains private data!)
→ If ANY origin could read this → catastrophic data theft

CORS requires explicit opt-in for credentialed cross-origin reads:
Server must include BOTH:
  Access-Control-Allow-Origin: https://specific-origin.com  (NOT wildcard!)
  Access-Control-Allow-Credentials: true
```

**HTTP exchange with credentials:**

```http
Request with credentials included:
GET /data HTTP/1.1
Host: robust-website.com
Origin: https://normal-website.com
Cookie: JSESSIONID=abc123def456       ← Session cookie included
Authorization: Bearer eyJhbGci...     ← Auth header included

Server response permitting credentialed read:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://normal-website.com   ← Specific origin!
Access-Control-Allow-Credentials: true                    ← Credentials allowed!
Content-Type: application/json

{"username": "alice", "privateData": "sensitive content"}

Browser decision:
1. Is ACAO a specific matching origin (not wildcard)? YES
2. Is ACAC: true present? YES
→ JavaScript can read authenticated response ✓
```

**The wildcard + credentials restriction:**

```http
This combination is FORBIDDEN by the CORS specification:
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

Browser behaviour:
Even if server returns both these headers together:
→ Browser IGNORES the response
→ Treats it as a CORS failure
→ JavaScript cannot read the response

Why the spec forbids it:
If ANY origin (*) could read credentialed responses:
→ Any website could silently steal authenticated data
→ Every user visiting any page would have their data exposed
→ The wildcard + credentials combination would be
  universally catastrophic

What servers do instead (often insecurely):
"I need multiple origins AND credentials"
"The spec won't allow wildcard + credentials"
"So I'll dynamically reflect whatever Origin is sent"
→ This is the root cause of the most common CORS vulnerability!
```

**Credentials mode in JavaScript:**

```javascript
// Three credentials modes:

// 1. 'omit' — never send cookies/auth (not useful for authenticated endpoints)
fetch('https://api.example.com/data', { credentials: 'omit' });

// 2. 'same-origin' — DEFAULT: send credentials only for same-origin
fetch('https://api.example.com/data');
// Same as: fetch(..., { credentials: 'same-origin' })
// Cross-origin requests: no cookies sent

// 3. 'include' — always send cookies/auth even cross-origin
fetch('https://api.example.com/data', { credentials: 'include' });
// Requires: ACAO specific + ACAC: true

// XMLHttpRequest equivalent:
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;  // Equivalent to credentials: 'include'
xhr.open('GET', 'https://api.example.com/data');
xhr.send();
```

## Wildcards and Their Restrictions

### When `*` is valid vs. dangerous

**Wildcard ACAO — permitted use cases:**

```
Access-Control-Allow-Origin: *

Meaning: Any origin can read this response

Legitimate uses:
✓ Public CDN serving fonts, icons, images
✓ Open public API (no authentication, no sensitive data)
✓ Public data APIs (weather, maps, open datasets)
✓ Static assets intended for cross-origin use

Not permitted with wildcard:
✗ Endpoints requiring authentication
✗ Endpoints setting cookies
✗ Endpoints returning user-specific data
✗ Any endpoint where: Access-Control-Allow-Credentials: true

Security rule:
Access-Control-Allow-Origin: *  is only safe when:
The response contains NOTHING that would be harmful
if read by any random website on the internet
```

**Invalid wildcard syntax — browser rejection:**

```http
These are all INVALID and browsers reject them:

Subdomain wildcard (NOT supported):
Access-Control-Allow-Origin: https://*.example.com
→ Browser treats this as invalid
→ No cross-origin access granted
→ Developers wanting "all subdomains" must dynamically set the header

Multiple origins in one header (NOT supported):
Access-Control-Allow-Origin: https://app.com https://admin.com
Access-Control-Allow-Origin: https://app.com, https://admin.com
→ Both invalid — no browser supports multiple values

Port wildcard (NOT supported):
Access-Control-Allow-Origin: https://example.com:*
→ Invalid syntax

Path specificity (NOT supported — origin only, no path):
Access-Control-Allow-Origin: https://example.com/specific-path
→ CORS only works at origin level, path ignored in ACAO
→ Access-Control-Allow-Origin: https://example.com grants access
   to ALL paths on example.com

Only valid values:
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: https://example.com   (specific origin)
Access-Control-Allow-Origin: null                  (avoid — exploitable)
```

**Why "all subdomains" requires dynamic origin handling:**

```javascript
// Developer problem:
// I need to allow ALL subdomains of my company to access this API
// But CORS doesn't support: Access-Control-Allow-Origin: https://*.company.com

// Solution developers use (SECURE version):
app.use((req, res, next) => {
    const origin = req.headers.origin;

    if (origin) {
        try {
            const url = new URL(origin);
            // Secure: parse hostname, check exact suffix
            if (url.protocol === 'https:' &&
                (url.hostname === 'company.com' ||
                 url.hostname.endsWith('.company.com'))) {
                res.setHeader('Access-Control-Allow-Origin', origin);
                res.setHeader('Access-Control-Allow-Credentials', 'true');
                res.setHeader('Vary', 'Origin');  // Critical!
            }
        } catch {
            // Invalid origin — no CORS headers set
        }
    }
    next();
});

// Solution developers use (INSECURE version — common vulnerability):
app.use((req, res, next) => {
    const origin = req.headers.origin;
    // BUG: No validation — reflects ANY origin!
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});
```

## Preflight Checks

### When and why preflight is triggered

**Preflight protects legacy resources from unexpected requests:**

```
Historical context:
Before CORS existed: cross-origin requests were either
  - Blocked entirely (XHR), or
  - Only simple GET/POST via HTML forms
  → Servers designed under assumption: complex requests = same-origin

CORS introduced: ability to make PUT, DELETE, PATCH + custom headers cross-origin
Legacy servers didn't expect these cross-origin!
Preflight = "check before acting" for requests that could
affect servers that never expected cross-origin access

Preflight triggers when request is "non-simple":
Any method other than: GET, POST, HEAD
→ PUT, DELETE, PATCH, CONNECT, TRACE, OPTIONS → triggers preflight

Content-Type other than:
→ text/plain
→ application/x-www-form-urlencoded
→ multipart/form-data
Any other Content-Type (e.g., application/json) → triggers preflight

Any custom request headers:
→ X-Custom-Header, Authorization (in some cases)
→ Any header not in the "safelisted" list → triggers preflight

Simple requests (NO preflight):
GET / POST / HEAD
+ Only safelisted headers
+ Only simple Content-Types
→ Go directly to the server
→ Server response with ACAO controls browser access
```

**Full preflight exchange:**

```http
Step 1: Browser detects non-simple request
JavaScript wants to send:
PUT /data HTTP/1.1
Content-Type: application/json
Special-Request-Header: value123

Step 2: Browser automatically sends OPTIONS preflight FIRST:
OPTIONS /data HTTP/1.1
Host: some-website.com
Origin: https://normal-website.com
Access-Control-Request-Method: PUT           ← "I want to use PUT"
Access-Control-Request-Headers: Special-Request-Header  ← "I want to use this header"
Connection: keep-alive
Content-Length: 0

Step 3: Server responds to preflight:
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS    ← Permitted methods
Access-Control-Allow-Headers: Special-Request-Header ← Permitted headers
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240                         ← Cache for 240 seconds

Step 4: Browser evaluates preflight response
Is my origin (https://normal-website.com) in ACAO? YES
Is my method (PUT) in Access-Control-Allow-Methods? YES
Is my header (Special-Request-Header) in Access-Control-Allow-Headers? YES
→ All checks pass → Proceed with actual request ✓

Step 5: Browser sends the actual PUT request
PUT /data HTTP/1.1
Host: some-website.com
Origin: https://normal-website.com
Content-Type: application/json
Special-Request-Header: value123
Cookie: session=TOKEN

{"action": "update", "value": "new_value"}

Step 6: Server processes PUT, responds normally
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"status": "updated"}

Step 7: Browser checks ACAO in final response
→ Matches origin → JavaScript reads response ✓
```

**Preflight caching with Access-Control-Max-Age:**

```http
Access-Control-Max-Age: 240
→ Browser caches this preflight result for 240 seconds
→ Same-origin requests to same endpoint skip preflight for 240s
→ Reduces network overhead for frequent cross-origin calls

Browser limits:
Chrome: max 7200 seconds (2 hours)
Firefox: max 86400 seconds (24 hours)
Setting a very high value reduces preflight overhead significantly
for frequently accessed endpoints

Access-Control-Max-Age: 0
→ Forces fresh preflight on every request
→ Useful during development / debugging CORS issues
```

**Preflight failure scenarios:**

```http
If preflight response does NOT include the requested method:
OPTIONS /data → Response:
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: GET, POST
(PUT not listed!)
→ Browser blocks the actual PUT request
→ "CORS preflight did not succeed"

If preflight response does NOT include the requested header:
OPTIONS /data → Response:
Access-Control-Allow-Origin: https://normal-website.com
Access-Control-Allow-Methods: PUT
(Special-Request-Header not in Access-Control-Allow-Headers!)
→ Browser blocks the actual request
→ Custom header stripped or request blocked

Common cause of CORS errors in development:
Server handles GET/POST but forgets to handle OPTIONS method!
OPTIONS returns 404 or 405 → preflight fails → appears as CORS error
→ Actually a server routing issue, not a CORS configuration issue
```

**Performance impact of preflight:**

```
Each preflighted request = 2 HTTP round-trips:
Round trip 1: OPTIONS preflight → preflight response
Round trip 2: Actual request → actual response

Performance implications:
Each preflight adds latency (one full network round-trip)
High-frequency API calls: doubled network overhead!

Mitigation strategies:
1. Use Access-Control-Max-Age to cache preflight results
   (Browser won't repeat preflight until cache expires)

2. Design APIs to use simple requests where possible:
   GET for reads, POST with form-encoded data
   Avoids triggering preflight entirely

3. Server-sent events or WebSockets for high-frequency data
   These don't trigger preflight checks

4. HTTP/2 multiplexing reduces preflight overhead
   Multiple requests share same connection
```

## The ACAO and Vary Header Interaction

### Preventing cache poisoning via Vary: Origin

```http
Problem without Vary: Origin:

Request 1 (from trusted origin):
GET /api/data HTTP/1.1
Origin: https://trusted-app.com

Server response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://trusted-app.com
Content-Type: application/json
{"sensitiveData": "value"}

← CDN or shared cache stores this response!

Request 2 (from attacker's origin):
GET /api/data HTTP/1.1
Origin: https://attacker.com

CDN/cache serves cached response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://trusted-app.com  ← FROM CACHE!
{"sensitiveData": "value"}

Browser: "ACAO is trusted-app.com, attacker.com doesn't match"
→ Attacker can't read. But... 
→ Cache now serving wrong ACAO header is a misconfiguration risk
→ With some CDN configurations, attacker COULD be served 
   a response with ACAO: https://attacker.com cached from their own earlier request

Solution:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://trusted-app.com
Vary: Origin                    ← Cache this response per unique Origin value!
→ Each distinct Origin value gets its own cache entry
→ Eliminates ACAO cache poisoning risk
```

```javascript
// Always set Vary: Origin when dynamically generating ACAO:
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');  // Essential when ACAO is dynamic!
    }
    next();
});

// When ACAO is static (e.g., always *), Vary: Origin not needed
// But when ACAO varies per origin value → always set Vary: Origin
```

## Does CORS Protect Against CSRF?

### A critical and common misconception 

**Why CORS does NOT prevent CSRF:**

```
Common developer misconception:
"We configured CORS to only allow our frontend domain"
"Therefore cross-origin requests from other sites are blocked"
"Therefore we're protected against CSRF"

Why this is WRONG:

CORS only restricts:
Whether browsers allow JavaScript to READ cross-origin responses

CORS does NOT restrict:
Whether requests are SENT to the server at all!

CSRF exploits the SENDING, not the reading:

Classic CSRF (HTML form):
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to" value="ATTACKER">
</form>
<script>document.forms[0].submit();</script>

This form submission:
→ IS cross-origin (attacker.com → bank.com)
→ Sends with victim's bank.com cookies
→ DOES NOT trigger CORS checks (HTML form submission, not XHR/fetch)
→ CORS is completely irrelevant to this attack!
→ Server processes the transfer!

CORS is only checked when:
JavaScript (XHR/fetch) makes requests and wants to READ the response
HTML forms, img tags, script tags: bypass CORS entirely!
```

**CORS misconfiguration makes CSRF WORSE, not better:**

```
Scenario: Poorly configured CORS (reflects any Origin)

Without CORS misconfiguration:
Attacker CAN make requests cross-origin (CSRF via forms)
Attacker CANNOT read responses (SOP blocks)
→ Attacker can perform actions but cannot read data
→ CSRF but no data theft

With CORS misconfiguration (arbitrary Origin reflected):
Attacker CAN make requests cross-origin (CSRF via fetch with credentials)
Attacker CAN read responses (CORS misconfiguration allows)
→ Attacker can perform actions AND steal response data
→ CSRF PLUS data exfiltration!

Example: CSRF to steal CSRF token (chained attack)
// Step 1: Steal the CSRF token via CORS misconfiguration
const accountPage = await fetch('https://vulnerable.com/account', {
    credentials: 'include'
});
const html = await accountPage.text();  // CORS lets us read this!
const csrfToken = html.match(/csrf_token.*?value="([^"]+)"/) [portswigger](https://portswigger.net/web-security/cors);

// Step 2: Use stolen CSRF token for CSRF attack
await fetch('https://vulnerable.com/change-email', {
    method: 'POST',
    credentials: 'include',
    body: `email=attacker@evil.com&csrf_token=${csrfToken}`
});

// CORS misconfiguration enabled CSRF to bypass CSRF token protection!
```

**What CORS and CSRF protection each cover:**

```
CSRF attacks:
→ Attacker makes requests cross-site (forms, img, script, etc.)
→ Goal: trigger state changes on authenticated user's behalf
→ Does NOT need to read responses
→ Defence: CSRF tokens, SameSite cookies
→ CORS does NOT help here

CORS vulnerabilities:
→ Attacker makes cross-origin requests AND reads responses
→ Goal: steal authenticated data (API keys, tokens, private info)
→ Requires JavaScript (fetch/XHR)
→ Defence: Strict CORS configuration (specific ACAO + no dynamic reflection)
→ CSRF tokens do NOT help here (tokens are in the response attacker reads!)

Overlap (CORS misconfiguration enables enhanced CSRF):
→ Attacker uses CORS vulnerability to steal CSRF token
→ Uses stolen token to bypass CSRF protection
→ Performs state-changing actions that even CSRF tokens normally block
→ Defence: Fix CORS misconfiguration AND use SameSite cookies
```

## Complete CORS Header Reference

### All CORS-related headers

**Request headers (browser → server):**

```http
Origin: https://requesting-site.com
→ Which origin is making the request
→ Automatically added by browser
→ Cannot be overridden by JavaScript

Access-Control-Request-Method: PUT
→ Preflight only: which HTTP method the actual request will use

Access-Control-Request-Headers: Content-Type, X-Custom-Header
→ Preflight only: which non-simple headers the request will include
```

**Response headers (server → browser):**

```http
Access-Control-Allow-Origin: https://trusted.com | *
→ Which origin(s) can read this response
→ Most critical CORS header

Access-Control-Allow-Credentials: true
→ Whether credentialed requests are allowed
→ Cannot be combined with ACAO: *

Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
→ Preflight only: permitted HTTP methods
→ Tells browser which methods to allow in actual request

Access-Control-Allow-Headers: Content-Type, Authorization, X-Custom-Header
→ Preflight only: permitted request headers
→ Tells browser which custom headers are allowed

Access-Control-Max-Age: 86400
→ Preflight only: seconds to cache preflight result
→ Reduces preflight overhead for subsequent requests

Access-Control-Expose-Headers: X-Total-Count, X-Page-Size
→ Which response headers JavaScript can access
→ By default: only basic safelisted headers accessible
→ Custom headers must be explicitly exposed via this header
```

**Access-Control-Expose-Headers example:**

```javascript
// Server sets:
// Access-Control-Expose-Headers: X-Total-Count, X-Request-ID

// Now JavaScript CAN read these headers:
const response = await fetch('https://api.example.com/items', {
    credentials: 'include'
});
const totalCount = response.headers.get('X-Total-Count');    // ✓ Accessible
const requestId = response.headers.get('X-Request-ID');     // ✓ Accessible
const customHeader = response.headers.get('X-Not-Exposed'); // ✗ Returns null

// Without Access-Control-Expose-Headers:
// Only these safelisted headers accessible via JavaScript:
// Cache-Control, Content-Language, Content-Length,
// Content-Type, Expires, Last-Modified, Pragma
```
