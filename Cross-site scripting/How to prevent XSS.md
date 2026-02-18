# How to Prevent XSS

XSS prevention is not a single technique but a layered defense strategy built on two fundamental pillars: encoding data on output and validating input on arrival—with encoding being the most critical because it transforms potentially dangerous characters into their harmless representations at the exact point where data enters a specific HTML, JavaScript, CSS, or URL context. The central insight of effective XSS prevention is that the same user input may be safe in one rendering context but dangerous in another—angle brackets are dangerous in HTML element contexts but harmless inside properly encoded JavaScript strings, and single quotes are dangerous in JavaScript strings but irrelevant in numeric attribute values—which means security controls must be applied at output time when the context is known, not at input time when the final rendering destination is unclear. A defense-in-depth approach combines context-aware output encoding as the primary control, strict input validation as a secondary filter, sanitization libraries like DOMPurify when allowing HTML is unavoidable, security-aware template engines and frameworks that encode by default, and Content Security Policy as a last line of defense that limits damage even when injection vulnerabilities exist, because relying on any single mechanism creates exploitable gaps that attackers routinely find and abuse. 

The core principle: **encode data at the point of output, using the encoding method appropriate for the specific rendering context.**

## The Two Pillars of XSS Defense

### Overview

```
Defense Layer 1: Encode data on output (PRIMARY)
- Apply at output time, not input time
- Context-aware encoding
- Different encoding for each context
- Cannot be bypassed by encoding tricks

Defense Layer 2: Validate input on arrival (SECONDARY)
- Allowlist-based validation
- Reject clearly invalid input early
- Reduces attack surface
- Complements, doesn't replace encoding

Defense Layer 3: Sanitize when HTML required
- Only when users must submit HTML
- Use trusted libraries (DOMPurify)
- Never implement manually

Defense Layer 4: Use safe frameworks/templates
- Auto-escaping template engines
- Security-aware JavaScript frameworks
- Reduces human error

Defense Layer 5: Content Security Policy
- Last line of defense
- Mitigates successful XSS injection
- Restricts what injected code can do
```

## Encoding Data on Output

### Why encode at output, not input? 

```
WRONG: Encode at input time
User submits: O'Brien
Stored as: O&#39;Brien
Used in HTML: O&#39;Brien    ✓ Safe in HTML
Used in SQL: O&#39;Brien     ✗ Wrong (double encoded)
Used in email: O&#39;Brien   ✗ Wrong (shows as &#39;)
Used in JSON: "O&#39;Brien"  ✗ Wrong format
Used in Excel: O&#39;Brien   ✗ Wrong in spreadsheet

CORRECT: Encode at output time (just before rendering)
User submits: O'Brien
Stored as: O'Brien (raw)
Rendered in HTML: O&#39;Brien  ✓ HTML-encoded when shown
Used in SQL: O\'Brien          ✓ SQL-escaped when queried
Used in email: O'Brien         ✓ Raw for email
Used in JSON: "O'Brien"        ✓ Raw for JSON

Conclusion:
Encoding at input corrupts data for other uses
Encoding at output applies correct format for each destination
```

### HTML context encoding

**When:** User-controllable data appears as text content inside HTML elements

**What to encode:**

```html
<!-- Characters that enable HTML injection -->
& → &amp;   (must be first to avoid double-encoding)
< → &lt;
> → &gt;
" → &quot;
' → &#x27;  (or &apos; in HTML5)
/ → &#x2F;  (helps close HTML tags)

<!-- Example: User input "Alice <admin>" -->

UNSAFE (no encoding):
<div>Welcome Alice <admin></div>
Browser interprets: <admin> as HTML tag

SAFE (HTML encoded):
<div>Welcome Alice &lt;admin&gt;</div>
Browser displays: Welcome Alice <admin>  (literal text)
```

**Encoding scope:**

```html
<!-- Minimum required: < > " ' & -->

<h1>Hello, <?php echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8'); ?></h1>

<!-- Example transformations: -->
Input: <script>alert(1)</script>
Output: &lt;script&gt;alert(1)&lt;/script&gt;
Rendered: <script>alert(1)</script>  (displays as text, not executed)

Input: " onclick="alert(1)
Output: &quot; onclick=&quot;alert(1)
Rendered: " onclick="alert(1)  (literal text)

Input: O'Brien
Output: O&#x27;Brien
Rendered: O'Brien  (correct display)
```

### HTML attribute context encoding

**When:** User data appears inside HTML attribute values

**Key requirements:**

```html
<!-- ALWAYS quote attribute values -->
UNSAFE (unquoted):
<input value=USER_INPUT>
Attack: ?x=onmouseover=alert(1) space is separator
Result: <input value=x onmouseover=alert(1)>

SAFE (quoted + encoded):
<input value="USER_INPUT">
Attack payload gets encoded: &quot; breaks quote attempt

<!-- Inside double-quoted attributes -->
Input: " onmouseover="alert(1)
Encoded: &quot; onmouseover=&quot;alert(1)
Result: <input value="&quot; onmouseover=&quot;alert(1)">  ✓ Safe

<!-- Inside single-quoted attributes -->
Input: ' onclick='alert(1)
Encoded: &#x27; onclick=&#x27;alert(1)
Result: <input value='&#x27; onclick=&#x27;alert(1)'>  ✓ Safe

<!-- Best practice: Always double-quote, encode both quote types -->
<input type="text" value="<?= htmlspecialchars($val, ENT_QUOTES, 'UTF-8') ?>">
```

**Dangerous attribute values (URL-based attributes):**

```html
<!-- href, src, action, formaction, data -->
<!-- HTML-encoding alone insufficient for javascript: URLs! -->

UNSAFE:
<a href="<?= htmlspecialchars($url, ENT_QUOTES, 'UTF-8') ?>">

Input: javascript:alert(1)
HTML-encoded: javascript:alert(1)  (no special chars to encode!)
Result: <a href="javascript:alert(1)">  ✗ Still dangerous

SAFE: Validate URL scheme BEFORE encoding
if (filter_var($url, FILTER_VALIDATE_URL) && preg_match('/^https?:/i', $url)) {
    echo '<a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '">';
} else {
    echo '<a href="#">'; // Default safe value
}
```

**Dangerous attributes to avoid populating with user data:**

```html
<!-- Event handlers - NEVER put user data here -->
<div onclick="USER_INPUT">         <!-- XSS even with encoding -->
<img onerror="USER_INPUT">         <!-- XSS even with encoding -->
<a onmouseover="USER_INPUT">       <!-- XSS even with encoding -->

<!-- Only safe if encoded, but risky -->
<a href="USER_INPUT">              <!-- Validate URL scheme first -->
<form action="USER_INPUT">         <!-- Validate URL scheme first -->
<img src="USER_INPUT">             <!-- Validate URL scheme first -->

<!-- Never safe regardless of encoding -->
<script>USER_INPUT</script>        <!-- ALWAYS DANGEROUS -->
<style>USER_INPUT</style>          <!-- ALWAYS DANGEROUS -->
<div style="USER_INPUT">           <!-- ALWAYS DANGEROUS -->
```

### JavaScript string context encoding

**When:** User data appears inside a JavaScript string literal

**Critical rule:** Unicode-escape all non-alphanumeric characters 

```javascript
// HTML entity encoding is NOT enough in JavaScript context!

// Example: Data in JavaScript string
<script>
var userName = "USER_INPUT";
</script>

// Input: ";alert(1);//
// HTML-encoded: &quot;;alert(1);//
// JavaScript sees: "&quot;;alert(1);//"  

// HTML encoding doesn't affect JavaScript interpretation!
// &quot; is still a string terminator in JavaScript!
// Result: var userName = "&quot;;  (closes string) alert(1);// "
// alert(1) executes!

// CORRECT: Unicode-escape non-alphanumeric characters
// Input: ";alert(1);//
// Unicode-escaped: \u0022\u003balert(1)\u003b\u002f\u002f

// JavaScript string with Unicode escapes:
var userName = "\u0022\u003balert(1)\u003b\u002f\u002f";
// JavaScript sees literal characters, not code
// Result: variable contains the literal string ";alert(1);//

// Key characters to encode:
< → \u003c
> → \u003e
& → \u0026
' → \u0027
" → \u0022
/ → \u002f
\ → \u005c
; → \u003b
( → \u0028
) → \u0029
```

**Line terminators (special case):**

```javascript
// Unicode line terminators break JavaScript strings
// Must be explicitly escaped:

U+2028 (Line Separator)    → \u2028
U+2029 (Paragraph Separator) → \u2029

// These characters end JavaScript string literals
// even without a backslash or quote character!

// Example vulnerability:
var msg = "USER_INPUT";
// Input contains U+2028 (line separator)
// JavaScript sees:
var msg = "text with
";  // String terminated!
// Syntax error or XSS depending on what follows
```

### URL context encoding

**When:** User data forms part of a URL**** 

```javascript
// URL encoding converts characters to %XX format

// Characters that need URL encoding:
Spaces → %20
< → %3C
> → %3E
" → %22
' → %27
= → %3D
& → %26
? → %3F
/ → %2F
# → %23

// PHP:
$encoded = rawurlencode($userInput);  // Encodes everything except unreserved chars
<a href="/search?q=<?= rawurlencode($query) ?>">

// JavaScript:
const encoded = encodeURIComponent(userInput);
const url = '/search?q=' + encodeURIComponent(query);

// Python:
from urllib.parse import quote
encoded = quote(user_input)

// Important: URL encoding ≠ HTML encoding
// Need BOTH when URL in HTML attribute:
<a href="/search?q=<?= htmlspecialchars(rawurlencode($query), ENT_QUOTES, 'UTF-8') ?>">
```

### CSS context encoding

**When:** User data appears inside CSS styles

```css
/* CSS context is dangerous even with proper encoding */

/* User data in CSS values */
<div style="color: USER_INPUT;">

/* Attack: CSS expression (IE) */
Input: expression(alert(1))
Result: <div style="color: expression(alert(1));">  ✗ XSS in IE

/* Attack: URL-based XSS */
Input: red; background: url('javascript:alert(1)')
Result: <div style="color: red; background: url('javascript:alert(1)');">  ✗ XSS

/* CSS encoding: Use \HH format */
< → \3C
> → \3E
& → \26
' → \27
" → \22

/* Recommendation: Avoid user data in CSS */
/* Use pre-defined classes instead: */
<div class="color-<?= htmlspecialchars($userColor) ?>">  /* Validate against allowlist */
```

### Multi-layer encoding

**When multiple contexts stack (e.g., JavaScript inside HTML):**

```html
<!-- Event handler contains JavaScript string: TWO CONTEXTS -->
<a href="#" onclick="doSearch('USER_INPUT')">

Context 1 (innermost): JavaScript string context
Context 2 (outer): HTML attribute context

Encoding order (innermost first):
1. Unicode-escape for JavaScript: ' → \u0027
2. HTML-encode for attribute: & → &amp; etc.

Example:
Input: '; alert(document.domain);//

Step 1: Unicode escape (JavaScript context)
\u0027\u003b alert(document.domain)\u003b\u002f\u002f

Step 2: HTML encode (HTML attribute context)
\u0027\u003b alert(document.domain)\u003b\u002f\u002f
(no special HTML chars in Unicode escapes, no change needed)

Result:
<a href="#" onclick="doSearch('\u0027\u003b alert(document.domain)\u003b\u002f\u002f')">

JavaScript interprets:
doSearch(''; alert(document.domain);//') 
→ Literal string, no XSS ✓
```

**Wrong order causes XSS:**

```html
<!-- Wrong: HTML encode first, then Unicode escape -->
Input: '; alert(document.domain);//

Step 1: HTML encode: &#x27;; alert(document.domain);//

Step 2: Try Unicode escape: &#x27;; alert(document.domain);//
(HTML entity isn't Unicode-escaped)

Result:
<a onclick="doSearch('&#x27;; alert(document.domain);//')">

Browser HTML-decodes attribute: '
JavaScript sees: doSearch(''; alert(document.domain);//')
Breaks out of string: '' → empty string, alert executes!

WRONG: HTML decode happens before JavaScript execution
CORRECT: Unicode-escape first (JavaScript), then HTML-encode (attribute)
```

## Validating Input on Arrival

### Principles of input validation 

```
Validation goals:
1. Reject input that cannot possibly be legitimate
2. Apply before processing/storing data
3. Reduce attack surface (doesn't replace encoding)
4. Catch attacks early in processing chain

What to validate:
- Expected data types (number, email, URL, date)
- Length constraints (min/max)
- Format patterns (regex)
- Allowed character sets
- Business logic constraints (valid range, valid status)
```

### Allowlist vs. blacklist validation 

**Always prefer allowlists (whitelists):**

```javascript
// BLACKLIST (avoid):
function validateInput(input) {
    const blacklist = ['<', '>', '"', "'", 'javascript:', 'data:', 'vbscript:'];
    return !blacklist.some(bad => input.toLowerCase().includes(bad));
}

Problems with blacklists:
✗ Attackers discover and bypass missing entries
✗ New attack vectors not in list (e.g., new protocols)
✗ Obfuscation bypasses: java\tscript: or java&#58;script
✗ Encoding bypasses: %3Cscript%3E, \u003cscript\u003e
✗ Must maintain as new attacks emerge
✗ Easy to miss edge cases

// ALLOWLIST (preferred):
function validateProtocol(url) {
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false; // Invalid URL
    }
}

Benefits:
✓ Explicitly allows only known-safe values
✓ Unknown/new attacks automatically blocked
✓ Simpler logic: allow X, deny everything else
✓ Not defeated by obfuscation (must match exact pattern)
✓ Easier to maintain and verify
```

**Practical validation examples:**

```javascript
// URL validation - allowlist protocols
function validateUrl(url) {
    try {
        const parsed = new URL(url);
        
        // Allowlist: Only http and https
        const allowedProtocols = ['http:', 'https:'];
        if (!allowedProtocols.includes(parsed.protocol)) {
            return null; // Reject javascript:, data:, vbscript:, etc.
        }
        
        return url;
    } catch {
        return null; // Not a valid URL at all
    }
}

// Integer validation
function validateInteger(input) {
    const num = parseInt(input, 10);
    if (isNaN(num) || num.toString() !== input.trim()) {
        return null; // Not a valid integer
    }
    return num;
}

// Alphanumeric validation
function validateAlphanumeric(input) {
    const pattern = /^[a-zA-Z0-9]+$/;
    if (!pattern.test(input)) {
        return null;
    }
    return input;
}

// Email validation
function validateEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!pattern.test(email)) {
        return null;
    }
    return email;
}

// Name validation (letters, spaces, hyphens, apostrophes)
function validateName(name) {
    const pattern = /^[a-zA-Z\s\-']{1,100}$/;
    if (!pattern.test(name)) {
        return null;
    }
    return name;
}

// Usage
const url = validateUrl(req.query.redirect);
if (!url) {
    return res.status(400).send('Invalid URL');
}
// Now safe to encode and use
```

**Block, don't sanitize:**

```javascript
// WRONG: Attempt to clean invalid input
function sanitizeInput(input) {
    return input.replace(/</g, '').replace(/>/g, '').replace(/script/gi, '');
}

Why this fails:
Input: <sCrIpT>alert(1)</sCrIpT>
After replace(/script/gi, ''): <sCrIpT>alert(1)</sCrIpT>
→ Still dangerous! Case replacement incomplete

Input: <<script>script>alert(1)<</script>/script>
After replace(/script/gi, ''): <<>alert(1)</>
→ Becomes: <> which may still cause issues

// CORRECT: Block invalid input outright
function validateName(input) {
    if (!/^[a-zA-Z\s]{1,50}$/.test(input)) {
        throw new ValidationError('Name must be letters and spaces only');
    }
    return input;
}
```

## Allowing Safe HTML (When Unavoidable)

### The HTML sanitization problem 

```
Why user-submitted HTML is dangerous:
- Must allow some tags: <b>, <i>, <p>, <a>, <img>
- Must block dangerous tags: <script>, <iframe>
- Must block dangerous attributes: onclick, onerror, href="javascript:"
- Browser quirks and inconsistencies create edge cases
- Mutation XSS: Safe HTML modified by browser to unsafe HTML
- New attack vectors discovered regularly

Why manual implementation fails:
- Browser parser quirks create exploitable edge cases
- Mutation XSS bypasses tag-based filtering
- Attribute-based attacks on allowed tags
- Encoding variations bypassing blacklists
- SVG, MathML, and namespace attacks
- Context-dependent parsing differences

Solution: Use established, actively maintained library
```

### DOMPurify sanitization library 

**The recommended client-side HTML sanitizer:**

```html
<!-- Installation -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.6/purify.min.js"></script>

<!-- NPM -->
npm install dompurify
```

**Basic usage:**

```javascript
import DOMPurify from 'dompurify';

// Dangerous user HTML
const userHTML = '<b>Bold text</b><script>alert("XSS")</script><img src=x onerror=alert(1)>';

// Sanitize
const cleanHTML = DOMPurify.sanitize(userHTML);
// Result: '<b>Bold text</b><img src="x">'  (script removed, onerror stripped)

// Now safe to assign to innerHTML
document.getElementById('comment').innerHTML = cleanHTML;

// Bad practice (even with DOMPurify):
document.getElementById('comment').innerHTML = userHTML;  // Never do this
```

**DOMPurify configuration:**

```javascript
// Allow only specific tags
const clean = DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li']
});

// Allow only specific attributes
const clean = DOMPurify.sanitize(dirty, {
    ALLOWED_TAGS: ['a', 'img'],
    ALLOWED_ATTR: ['href', 'src', 'alt', 'title']
});

// Remove specific tags entirely (including content)
const clean = DOMPurify.sanitize(dirty, {
    FORBID_TAGS: ['style'],
    FORBID_ATTR: ['style']
});

// Force all links to be safe
const clean = DOMPurify.sanitize(dirty, {
    FORCE_BODY: true,
    ADD_ATTR: ['target']  // Allow target="_blank"
});

// Custom hook to enforce https links
DOMPurify.addHook('afterSanitizeAttributes', function(node) {
    if (node.tagName === 'A') {
        const href = node.getAttribute('href');
        if (href && !/^https?:/.test(href)) {
            node.removeAttribute('href');  // Remove non-http(s) hrefs
        }
        node.setAttribute('rel', 'noopener noreferrer');  // Security for target="_blank"
    }
});
```

**What DOMPurify handles:**

```javascript
// Script tags
DOMPurify.sanitize('<script>alert(1)</script>');
// → '' (removed entirely)

// Event handlers
DOMPurify.sanitize('<img src=x onerror=alert(1)>');
// → '<img src="x">' (onerror stripped)

// javascript: URLs
DOMPurify.sanitize('<a href="javascript:alert(1)">click</a>');
// → '<a>click</a>' (href removed)

// data: URLs
DOMPurify.sanitize('<img src="data:text/html,<script>alert(1)</script>">');
// → '<img>' (data: src removed)

// SVG XSS
DOMPurify.sanitize('<svg><use href="data:image/svg+xml,<svg id=\'x\'><script>alert(1)</script></svg>#x"></use></svg>');
// → Safe SVG (dangerous content removed)

// Nested XSS
DOMPurify.sanitize('<<img src=x onerror=alert(1)>//');
// → '' or safe version

// Mutation XSS patterns
// DOMPurify double-parses to catch mutation XSS
```

**Server-side sanitization (Node.js):**

```javascript
// DOMPurify requires DOM environment
// Use jsdom for server-side

const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function sanitizeHTML(dirty) {
    return DOMPurify.sanitize(dirty, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
        ALLOWED_ATTR: ['href', 'title', 'rel'],
        ADD_ATTR: ['target']
    });
}

// Express route
app.post('/comment', express.json(), (req, res) => {
    const rawComment = req.body.comment;
    const safeComment = sanitizeHTML(rawComment);
    db.comments.insert({ content: safeComment, authorId: req.user.id });
    res.redirect('/comments');
});
```

**Important caveats:**

```
DOMPurify limitations:
✗ Not perfect: Security vulnerabilities discovered periodically
✗ Requires browser environment (or jsdom on server)
✗ Bypasses found through browser quirks
✗ Sanitized HTML can still be confusing to users

Best practices:
✓ Monitor DOMPurify GitHub for security updates
✓ Update regularly (security patches)
✓ Use restrictive ALLOWED_TAGS configuration
✓ Don't allow style attributes
✓ Test with new XSS vectors periodically
✓ Consider markdown-to-HTML as alternative
```

### Markdown as safer alternative

```javascript
// Allow markdown input, convert to safe HTML
// Users write: **bold** *italic* [link](https://example.com)
// Converted to: <strong>bold</strong> <em>italic</em> <a href="...">link</a>

// Node.js with marked + DOMPurify
const marked = require('marked');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

function renderMarkdown(markdownInput) {
    // Convert markdown to HTML
    const rawHTML = marked.parse(markdownInput);
    
    // Sanitize the generated HTML (defense in depth)
    return DOMPurify.sanitize(rawHTML);
}

// Still sanitize even though marked is generally safe
// Marked can have vulnerabilities too
```

## Preventing XSS Using Template Engines

### Server-side templates 

**Template engines provide auto-escaping by default:**

**Jinja2 (Python/Flask):**

```python
# Enable autoescaping (required for HTML safety)
from jinja2 import Environment, PackageLoader, select_autoescape

env = Environment(
    loader=PackageLoader("myapp"),
    autoescape=select_autoescape(['html', 'xml'])  # Enable for HTML/XML
)

# Template: greeting.html
# <h1>Hello, {{ user.name }}</h1>
# <!-- Jinja2 automatically HTML-encodes user.name -->

# Input: user.name = "<script>alert(1)</script>"
# Output: <h1>Hello, &lt;script&gt;alert(1)&lt;/script&gt;</h1>
# Display: Hello, <script>alert(1)</script>  (as text)

# Explicit escaping when autoescape may be disabled:
{{ user.name | e }}        <!-- Force HTML escaping -->
{{ user.name | escape }}   <!-- Same as | e -->

# To render trusted HTML (use with caution!)
{{ trusted_html | safe }}  <!-- Don't use with user input! -->
{% autoescape false %}{{ trusted_html }}{% endautoescape %}
```

**Warning: Bypassing auto-escape:**

```python
# DANGEROUS: Marking user input as safe
user_input = request.args.get('name')
return render_template('page.html', name=Markup(user_input))  # ✗ XSS!

# DANGEROUS: Concatenating into template string
template = Template("Hello, " + user_input)  # Server-side template injection!

# SAFE: Passing raw value to template
return render_template('page.html', name=user_input)  # Auto-escaped ✓
```

**Twig (PHP):**

```php
<?php
// Twig auto-escapes by default in HTML templates
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

$loader = new FilesystemLoader('/path/to/templates');
$twig = new Environment($loader, [
    'autoescape' => 'html'  // Enable HTML auto-escaping
]);

// In Twig template: greeting.html
// <h1>Hello, {{ user.firstname }}</h1>
// Auto-escaped automatically

// Explicit context-aware escaping:
{{ user.firstname | e('html') }}       // HTML context
{{ user.url | e('url') }}              // URL context
{{ user.style | e('css') }}            // CSS context
{{ user.jsvar | e('js') }}             // JavaScript context
{{ user.attr | e('html_attr') }}       // HTML attribute context

// Bypass (only for trusted content!):
{{ trusted_html | raw }}   // Don't use with user input!
```

**Freemarker (Java):**

```java
// FreeMarker with auto-escaping
Configuration cfg = new Configuration(Configuration.VERSION_2_3_31);
cfg.setOutputEncoding("UTF-8");

// Enable auto-escaping for HTML output
cfg.setAutoEscapingPolicy(Configuration.ENABLE_IF_DEFAULT_AUTO_ESCAPING_POLICY);
cfg.setOutputFormat(HTMLOutputFormat.INSTANCE);

// Template: greeting.ftlh (note .ftlh extension for HTML auto-escaping)
// <h1>Hello, ${user.firstName}</h1>
// Auto-escaped for HTML

// Manual escaping:
${user.firstName?html}   // HTML encoding
${user.url?url}          // URL encoding
${user.js?js_string}     // JavaScript string encoding

// Mark as safe (trusted HTML only):
${trustedHTML?no_esc}   // Disable escaping
```

### React (JavaScript) 

```jsx
// React auto-escapes JSX expressions by default
function UserProfile({ user }) {
    // SAFE: JSX auto-escapes (HTML-encodes)
    return (
        <div>
            <h1>Hello, {user.name}</h1>
            <p>{user.bio}</p>
        </div>
    );
}

// Input: user.name = "<script>alert(1)</script>"
// Rendered HTML: <h1>Hello, &lt;script&gt;alert(1)&lt;/script&gt;</h1>
// Display: Hello, <script>alert(1)</script>  (as text, not executed)

// DANGEROUS: dangerouslySetInnerHTML bypasses auto-escaping
function DangerousComponent({ userHtml }) {
    return (
        // ✗ Only for trusted, sanitized content!
        <div dangerouslySetInnerHTML={{ __html: userHtml }} />
    );
}

// SAFE: Use DOMPurify with dangerouslySetInnerHTML
import DOMPurify from 'dompurify';

function SafeHtmlComponent({ userHtml }) {
    const cleanHtml = DOMPurify.sanitize(userHtml, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p']
    });
    
    return (
        // ✓ Sanitized before setting
        <div dangerouslySetInnerHTML={{ __html: cleanHtml }} />
    );
}

// Other unsafe patterns in React:
const url = userInput;
<a href={url}>Click</a>  // Dangerous! Allows javascript: URLs

// Safe URL handling in React:
function SafeLink({ url, children }) {
    // Validate URL before rendering
    const isSafe = /^https?:/.test(url);
    return isSafe ? <a href={url}>{children}</a> : <span>{children}</span>;
}
```

### Vue.js (JavaScript)

```html
<!-- Vue auto-escapes template expressions -->
<template>
    <!-- SAFE: {{ }} auto-escapes HTML -->
    <div>Hello, {{ user.name }}</div>
    <!-- Input: <script>alert(1)</script> -->
    <!-- Rendered: <div>Hello, &lt;script&gt;alert(1)&lt;/script&gt;</div> -->
    
    <!-- DANGEROUS: v-html bypasses escaping -->
    <div v-html="user.bioHTML"></div>  <!-- Only for trusted content -->
    
    <!-- SAFE: v-html with sanitization -->
    <div v-html="sanitizedBio"></div>
</template>

<script>
import DOMPurify from 'dompurify';

export default {
    computed: {
        sanitizedBio() {
            return DOMPurify.sanitize(this.user.bio);
        }
    }
};
</script>
```

## Preventing XSS in PHP

### HTML context in PHP 

```php
<?php
/**
 * CORRECT: htmlentities with ENT_QUOTES and UTF-8
 * Three required arguments:
 * 1. The input string
 * 2. ENT_QUOTES - encode both single AND double quotes
 * 3. 'UTF-8' - character encoding
 */

// Basic usage:
echo htmlentities($input, ENT_QUOTES, 'UTF-8');

// HTML5 extended entities (recommended):
echo htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// Using in templates:
?>
<html>
<head><title><?= htmlspecialchars($pageTitle, ENT_QUOTES, 'UTF-8') ?></title></head>
<body>
    <h1>Hello, <?= htmlspecialchars($name, ENT_QUOTES, 'UTF-8') ?></h1>
    <input type="text" name="search" value="<?= htmlspecialchars($search, ENT_QUOTES, 'UTF-8') ?>">
    <p><?= htmlspecialchars($content, ENT_QUOTES, 'UTF-8') ?></p>
</body>
</html>

<?php
// Encoding reference:
// htmlspecialchars converts:
// & → &amp;
// < → &lt;
// > → &gt;
// " → &quot;
// ' → &#039; (with ENT_QUOTES)

// htmlentities converts all applicable characters to HTML entities
// More comprehensive but similar for XSS purposes

// Short form (create helper function):
function h($str) {
    return htmlspecialchars($str, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Usage:
echo "<h1>Hello, " . h($name) . "</h1>";
// Or in templates: <?= h($name) ?>
```

### JavaScript context in PHP 

```php
<?php
/**
 * PHP doesn't have built-in JavaScript Unicode escaping
 * Must implement custom jsEscape function
 */

function jsEscape($str) {
    $output = '';
    $str = mb_str_split($str, 1, 'UTF-8');
    
    foreach ($str as $char) {
        $chrNum = mb_ord($char, 'UTF-8');
        
        // Handle Unicode line terminators (critical!)
        if ($chrNum === 0x2028) {
            $output .= '\u2028';
            continue;
        }
        if ($chrNum === 0x2029) {
            $output .= '\u2029';
            continue;
        }
        
        // Escape all non-alphanumeric ASCII characters
        if ($chrNum < 128 && !ctype_alnum($char) && $char !== ' ' && $char !== '.') {
            $output .= sprintf('\\u%04x', $chrNum);
        } else {
            $output .= $char;
        }
    }
    
    return $output;
}

// Usage examples:

// Inside <script> block - JavaScript string context
?>
<script>
var username = '<?php echo jsEscape($_GET['username']); ?>';
var message = "<?php echo jsEscape($_POST['message']); ?>";
</script>

<?php
// Inside event handler attribute - TWO CONTEXTS
// Step 1: jsEscape (JavaScript context, innermost)
// Step 2: htmlspecialchars (HTML attribute context, outer)
?>
<a href="#" onclick="setName('<?= htmlspecialchars(jsEscape($name), ENT_QUOTES, 'UTF-8') ?>')">
<?php
// Example:
// Input: '; alert(1);//
// After jsEscape: \u0027\u003b alert(1)\u003b\u002f\u002f
// After htmlspecialchars: \u0027\u003b alert(1)\u003b\u002f\u002f (no HTML-special chars)
// Result: onclick="setName('\u0027\u003b alert(1)\u003b\u002f\u002f')"  ✓ Safe
```

### URL context in PHP

```php
<?php
// For URL parameters:
$safeParam = rawurlencode($userInput);
echo '<a href="/search?q=' . $safeParam . '">';

// For full URLs (validate scheme first):
function buildSafeUrl($userUrl) {
    $allowedSchemes = ['http', 'https'];
    
    $parsed = parse_url($userUrl);
    if (!$parsed || !in_array($parsed['scheme'] ?? '', $allowedSchemes)) {
        return '#'; // Default safe URL
    }
    
    return htmlspecialchars($userUrl, ENT_QUOTES, 'UTF-8');
}

echo '<a href="' . buildSafeUrl($redirect) . '">';
```

## Preventing XSS in JavaScript (Client-Side)

### HTML encoding in JavaScript 

```javascript
/**
 * JavaScript has no built-in HTML encoder
 * Create helper function for HTML context encoding
 */

function htmlEncode(str) {
    return String(str).replace(/[^\w. ]/gi, function(c) {
        return '&#' + c.charCodeAt(0) + ';';
    });
}

// More comprehensive version using DOM API:
function htmlEncode(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// Explicit character mapping (most reliable):
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Usage:
document.getElementById('message').innerHTML = htmlEncode(userInput);

// Better alternative - use textContent instead:
document.getElementById('message').textContent = userInput;
// textContent treats everything as text, no encoding needed!
```

### JavaScript Unicode encoding 

```javascript
/**
 * For JavaScript string contexts
 * Unicode-escape all non-alphanumeric characters
 */

function jsEscape(str) {
    return String(str).replace(/[^\w. ]/gi, function(c) {
        return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
    });
}

// Usage in dynamic script generation:
document.write('<script>x="' + jsEscape(untrustedValue) + '";<\/script>');

// More practical usage - building JavaScript in strings:
const safeValue = jsEscape(userInput);
const script = `var userPref = "${safeValue}";`;

// Example:
// Input: "; alert(1); var x = "
// After jsEscape: \u0022\u003b alert(1)\u003b var x \u003d \u0022
// JavaScript sees literal string: "; alert(1); var x = "
```

**Better approach - avoid inline JavaScript entirely:**

```javascript
// Instead of injecting data into JavaScript:
// AVOID:
echo "<script>var userId = " . $userId . ";</script>";

// USE data attributes (always HTML-encode the value):
echo '<div id="app" data-user-id="' . htmlspecialchars($userId, ENT_QUOTES, 'UTF-8') . '">';

// Read safely in JavaScript:
const userId = document.getElementById('app').dataset.userId;

// Or use JSON for complex data:
echo '<script>var config = ' . json_encode($config, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) . ';</script>';

// JSON_HEX_* flags encode < > ' " & in JSON output
// Prevents XSS when embedding JSON in HTML
```

### Safe DOM manipulation patterns

```javascript
// SAFE patterns for DOM manipulation:

// 1. textContent (safest - treats as literal text)
element.textContent = userInput;  // Always safe

// 2. createTextNode
const textNode = document.createTextNode(userInput);
element.appendChild(textNode);  // Always safe

// 3. setAttribute for non-URL attributes
element.setAttribute('class', userInput);  // Safe for class, id, etc.
element.setAttribute('data-value', userInput);  // Safe for data attributes

// 4. createElement with textContent
function createComment(text, author) {
    const div = document.createElement('div');
    div.className = 'comment';
    
    const authorEl = document.createElement('strong');
    authorEl.textContent = author;  // Safe ✓
    
    const textEl = document.createElement('p');
    textEl.textContent = text;  // Safe ✓
    
    div.appendChild(authorEl);
    div.appendChild(textEl);
    return div;
}

// UNSAFE patterns to avoid:
element.innerHTML = userInput;    // ✗ Parses HTML
element.outerHTML = userInput;    // ✗ Parses HTML
document.write(userInput);        // ✗ Parses HTML
eval(userInput);                  // ✗ Executes code
setTimeout(userInput, 0);         // ✗ Executes code (string form)
new Function(userInput)();        // ✗ Executes code
```

## Preventing XSS in jQuery 

### jQuery selector safety

```javascript
// HISTORY: jQuery vulnerability with location.hash

// Old pattern (VULNERABLE in old jQuery):
$(window).on('hashchange', function() {
    var element = $(location.hash);  // ✗ Rendered as HTML in old jQuery
    element[0].scrollIntoView();
});

// Attack: URL fragment containing HTML
// /#<img src=x onerror=alert(1)>
// Old jQuery interpreted hash as HTML → XSS!

// PATCHED IN JQUERY: Current jQuery checks for # prefix
// $(location.hash) → Only renders as HTML if starts with <

// But: Still dangerous if user controls full input:
$(userInput);  // If userInput = "<img src=x onerror=alert(1)>"
                // jQuery renders as HTML!

// SAFE: Escape before using in jQuery selector
function jsEscape(str) {
    return String(str).replace(/[^\w. ]/gi, function(c) {
        return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
    });
}

// If user must provide selector:
$(jsEscape(userInput));  // Escape first

// Better: Don't allow user input in selectors
// Use IDs/classes you control:
$('#user-' + sanitizedId);  // Validate ID is alphanumeric first
```

### jQuery DOM manipulation safety

```javascript
// UNSAFE jQuery patterns:
$(selector).html(userInput);    // ✗ Parses HTML, allows XSS
$(selector).append(userInput);  // ✗ Parses HTML, allows XSS
$(selector).prepend(userInput); // ✗ Parses HTML, allows XSS
$(selector).after(userInput);   // ✗ Parses HTML, allows XSS
$(selector).before(userInput);  // ✗ Parses HTML, allows XSS
$.parseHTML(userInput);         // ✗ Parses HTML, allows XSS

// SAFE jQuery alternatives:
$(selector).text(userInput);    // ✓ Treats as text, encodes HTML
$(selector).val(userInput);     // ✓ Sets form value safely

// When HTML rendering needed:
import DOMPurify from 'dompurify';
$(selector).html(DOMPurify.sanitize(userInput));  // ✓ Sanitize first

// Safe anchor href:
const safeUrl = /^https?:/.test(url) ? url : '#';
$('#link').attr('href', safeUrl);  // ✓ Validated URL

// Creating elements safely:
const $div = $('<div/>').text(userInput);  // ✓ text() is safe
$container.append($div);
```

## CSP as Last Line of Defense 

### Defense-in-depth with CSP

```http
/* XSS prevention layers:
 * Layer 1: Output encoding (primary)
 * Layer 2: Input validation (secondary)
 * Layer 3: Sanitization libraries (when HTML needed)
 * Layer 4: Secure frameworks (auto-escaping)
 * Layer 5: CSP (last resort - limits XSS damage)
 */

Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';

What this provides:
- default-src 'self': Resources from same origin only
- script-src 'self': Scripts from same origin only (blocks external XSS payloads)
- object-src 'none': No plugin-based attacks
- frame-src 'none': No clickjacking via frames
- base-uri 'none': No base tag injection

If XSS injection still occurs:
- Inline scripts blocked (no 'unsafe-inline')
- External script loading blocked
- Attacker cannot load tools from external domains
- Attack surface significantly reduced
```

### Recommended complete CSP:

```http
Content-Security-Policy:
    default-src 'none';
    script-src 'nonce-RANDOM' 'strict-dynamic';
    style-src 'nonce-RANDOM';
    img-src 'self';
    font-src 'self';
    connect-src 'self';
    form-action 'self';
    frame-ancestors 'none';
    base-uri 'none';

Implementation (Node.js):
```

```javascript
const crypto = require('crypto');

app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'none'; ` +
        `script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
        `style-src 'nonce-${nonce}'; ` +
        `img-src 'self'; ` +
        `font-src 'self'; ` +
        `connect-src 'self'; ` +
        `form-action 'self'; ` +
        `frame-ancestors 'none'; ` +
        `base-uri 'none';`
    );
    next();
});
```
