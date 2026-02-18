# Same-Origin Policy (SOP)

The same-origin policy (SOP) is one of the most fundamental security mechanisms in web browsers — a critical boundary that prevents malicious websites from reading data belonging to other websites, forming the cornerstone of web security upon which nearly every other browser-enforced protection is built. Without it, any webpage a user visits could silently read their emails, private messages, banking data, and session information from every other site they are authenticated to, simply by making JavaScript requests to those services and reading the responses. The SOP achieves this by restricting JavaScript on one origin from reading responses or accessing data that originates from a different origin — while still allowing cross-origin requests to be sent and cross-origin resources to be embedded, creating a carefully balanced set of rules that enables the modern web to function while preventing the most dangerous forms of cross-site data theft.

The core principle: **browsers allow cross-origin requests to be sent, but block JavaScript from reading cross-origin responses — the SOP is about controlling read access, not request sending**.

## What Defines an Origin?

### Origin = scheme + domain + port

**All three components must match for same-origin:**

```
Origin components:
1. URI Scheme:   http  or  https  (or others: ftp, file, etc.)
2. Domain:       normal-website.com
3. Port:         80 (http default), 443 (https default), or explicit

Full origin of: http://normal-website.com/example/example.html

Scheme: http
Domain: normal-website.com
Port:   80 (implied by http)
```

**Same-origin comparison table:**

```
Base URL: http://normal-website.com/example/example.html

URL Accessed                              | Same Origin? | Reason
------------------------------------------|--------------|------------------------
http://normal-website.com/example/        | YES          | Same scheme, domain, port
http://normal-website.com/example2/       | YES          | Same scheme, domain, port
https://normal-website.com/example/       | NO           | Different scheme AND port
http://en.normal-website.com/example/     | NO           | Different subdomain
http://www.normal-website.com/example/    | NO           | Different subdomain
http://normal-website.com:8080/example/   | NO           | Different port
http://normal-website.co.uk/example/      | NO           | Different domain (eTLD)
http://attacker.com/example/              | NO           | Entirely different domain
```

**Implied ports:**

```
Port is often inferred from scheme:
http  → implied port 80
https → implied port 443
ftp   → implied port 21

http://example.com   = http://example.com:80   (same origin)
https://example.com  = https://example.com:443 (same origin)
http://example.com   ≠ https://example.com     (different scheme + port)
http://example.com   ≠ http://example.com:8080 (different port)
```

**Internet Explorer exception (legacy):**

```
IE historically did NOT include port in origin comparison:
http://normal-website.com/page  and  http://normal-website.com:8080/page
→ IE treated these as same origin!

All other browsers: different port = different origin
IE exception created exploitable inconsistencies in cross-browser apps
Modern IE/Edge now follows the standard
```

## Why the Same-Origin Policy is Necessary

### What the web would look like without SOP

**The attack scenario without SOP:**

```
User is authenticated to:
- Gmail (session cookie for mail.google.com)
- Facebook (session cookie for facebook.com)
- Online banking (session cookie for bank.com)

User visits: http://malicious-website.com

Without SOP, JavaScript on malicious-website.com could:

// Read all Gmail emails
fetch('https://mail.google.com/mail/u/0/#inbox')
  .then(r => r.text())
  .then(emails => sendToAttacker(emails));

// Read Facebook messages
fetch('https://www.facebook.com/messages/')
  .then(r => r.text())
  .then(messages => sendToAttacker(messages));

// Read bank account balance
fetch('https://bank.com/account/dashboard')
  .then(r => r.text())
  .then(data => sendToAttacker(data));

// Transfer money
fetch('https://bank.com/transfer', {
    method: 'POST',
    body: 'amount=10000&to=ATTACKER'
});

SOP makes all of these .then() blocks fail:
→ The requests CAN be sent
→ The responses CANNOT be read by cross-origin JavaScript
→ Data theft via reading responses is prevented
```

**Why cookie automatic sending makes SOP critical:**

```
When browser makes request to bank.com:
→ Browser automatically includes all bank.com cookies
→ Including: session=VICTIM_AUTH_TOKEN
→ Server generates AUTHENTICATED response
→ Response contains victim's personal data

Without SOP:
→ Attacker's JavaScript reads that authenticated response
→ Full account access from any malicious page

With SOP:
→ Request sent (with cookies) → Response received by browser
→ JavaScript on malicious-website.com CANNOT read the response
→ Data stays protected
```

## How SOP is Implemented

### Cross-origin loading vs. cross-origin reading

**The key distinction browsers enforce:**

```
Cross-origin resource LOADING (generally PERMITTED):
✓ <img src="https://other.com/image.jpg">       — Image loads and displays
✓ <script src="https://other.com/script.js">    — Script loads and executes
✓ <link href="https://other.com/style.css">     — Stylesheet applies
✓ <video src="https://other.com/video.mp4">     — Video plays
✓ <iframe src="https://other.com/page.html">    — Page renders
✓ <form action="https://other.com/submit">      — Form submits

Cross-origin resource READING via JavaScript (BLOCKED):
✗ Reading pixel data from cross-origin <canvas> image
✗ Reading response body of cross-origin fetch/XHR
✗ Reading cross-origin iframe's DOM content
✗ Reading cross-origin window's document content
✗ Accessing cross-origin response headers (without CORS)

The pattern:
Browser happily loads/embeds/sends cross-origin resources
JavaScript code cannot INSPECT or READ those cross-origin resources
```

**Practical examples:**

```javascript
// Loading an image cross-origin: ALLOWED
const img = new Image();
img.src = 'https://other.com/avatar.jpg';
document.body.appendChild(img);  // Image displays ✓

// Trying to READ that image's pixels: BLOCKED
const canvas = document.createElement('canvas');
canvas.getContext('2d').drawImage(img, 0, 0);
canvas.toDataURL();  // SecurityError: Tainted canvas! ✗

// Making a cross-origin fetch: request SENT
fetch('https://bank.com/account-data');  // Request reaches server ✓

// Reading the response: BLOCKED (without CORS)
fetch('https://bank.com/account-data')
  .then(r => r.json())  // Blocked unless CORS allows it ✗
  .then(data => console.log(data));  // Never reaches here ✗

// Including an iframe from another origin: ALLOWED
const iframe = document.createElement('iframe');
iframe.src = 'https://other.com/page';
document.body.appendChild(iframe);  // Page loads in iframe ✓

// Reading the iframe's content: BLOCKED
iframe.contentDocument.body.innerHTML;  // DOMException ✗
```

### SOP exceptions and nuances

**Objects writable but not readable cross-domain:**

```javascript
// location.href — can SET it (navigate), cannot READ it cross-origin
const popup = window.open('https://other.com');

// CAN write: navigate the popup
popup.location.href = 'https://other.com/page2';  // Allowed (navigation) ✓

// CANNOT read: where is the popup currently?
console.log(popup.location.href);  // SecurityError ✗
console.log(popup.document.title); // SecurityError ✗

// location.replace — CAN be called cross-domain
popup.location.replace('https://other.com/page3');  // Allowed ✓
```

**Objects readable but not writable cross-domain:**

```javascript
// window.length — number of frames, readable cross-origin
const popup = window.open('https://other.com');
console.log(popup.length);  // Readable: number of frames ✓
popup.length = 5;           // Cannot set cross-origin ✗

// window.closed — is the window closed?
console.log(popup.closed);  // Readable ✓
popup.closed = true;        // Cannot set ✗

// These properties reveal minimal, non-sensitive info
// Hence readable cross-origin for legitimate functionality
```

**Functions callable cross-domain:**

```javascript
// Window management functions — callable cross-origin
const popup = window.open('https://other.com');
popup.close();   // Close the window ✓
popup.blur();    // Remove focus ✓
popup.focus();   // Give focus ✓

// These allow basic window management without exposing content
```

**postMessage — controlled cross-origin communication:**

```javascript
// Sending a message cross-origin: ALLOWED with postMessage
const iframe = document.getElementById('cross-origin-iframe');

// Sender (parent page at https://parent.com):
iframe.contentWindow.postMessage(
    { type: 'request', data: 'hello' },
    'https://trusted-iframe.com'  // Target origin — security check!
);

// Receiver (inside iframe at https://trusted-iframe.com):
window.addEventListener('message', function(event) {
    // ALWAYS validate origin before processing!
    if (event.origin !== 'https://parent.com') {
        return;  // Reject unexpected messages
    }
    console.log('Received:', event.data);
    event.source.postMessage({ type: 'response', data: 'world' },
                               event.origin);
});

// postMessage provides a controlled channel for cross-origin communication
// without breaking SOP — data shared only through explicit message passing
// not by directly accessing cross-origin DOM/data
```

### Cookies and the relaxed SOP

**Cookie scope is broader than SOP — a common source of confusion:**

```
SOP for JavaScript:
http://app.example.com and http://api.example.com
= Different origins (different subdomain)
= JavaScript on app.example.com CANNOT read api.example.com responses

BUT cookies use a different (older, broader) scoping model:
Set-Cookie: session=TOKEN; Domain=.example.com
→ Accessible to: ALL subdomains of example.com!
→ app.example.com receives this cookie
→ api.example.com receives this cookie
→ mail.example.com receives this cookie

Why this exists:
Cookies predate the modern SOP
Legacy requirements for single sign-on across subdomains
www.example.com and shop.example.com sharing auth cookie

Security implication:
XSS on any subdomain → cookie theft across entire eTLD+1
Cookie scope doesn't respect strict origin boundaries
```

**Partial cookie security mitigations:**

```http
HttpOnly flag: Prevents JavaScript from reading cookies
Set-Cookie: session=TOKEN; HttpOnly; Secure; SameSite=Strict

HttpOnly effect:
document.cookie  → Does NOT include HttpOnly cookies
XSS cannot steal HttpOnly session cookies via document.cookie
(They are still sent in HTTP requests — just not readable by JS)

Secure flag: Cookie only sent over HTTPS
→ Prevents network interception

SameSite: Restricts cross-site cookie sending
→ Limits CSRF attacks (covered in SameSite guides)

Domain scoping — use narrower scope when possible:
Set-Cookie: session=TOKEN; Domain=app.example.com; HttpOnly; Secure
→ Only app.example.com gets this cookie
→ Not accessible to other subdomains
→ Limits blast radius of subdomain compromise
```

### Relaxing SOP with document.domain

**The document.domain mechanism:**

```javascript
// Scenario: Two related pages need to share data
// marketing.example.com wants to access example.com content

// Without document.domain:
// Different subdomains = different origins = SOP blocks access

// With document.domain (LEGACY MECHANISM):

// On marketing.example.com:
document.domain = 'example.com';

// On example.com:
document.domain = 'example.com';

// Now both origins are treated as example.com for SOP purposes
// Cross-subdomain DOM access becomes possible:
// marketing.example.com iframe can read example.com's document

// Restriction: Can only set to a suffix of current hostname
// marketing.example.com CAN set: document.domain = 'example.com' ✓
// marketing.example.com CANNOT set: document.domain = 'attacker.com' ✗
// marketing.example.com CANNOT set: document.domain = 'com' ✗
//   (Modern browsers block setting to bare TLDs)
```

**Historical TLD attack (now blocked):**

```
Old browser behaviour (now prevented):
site-a.com sets: document.domain = 'com'
site-b.com sets: document.domain = 'com'
→ Both now "same origin" (com)
→ ANY site on .com could read any other .com site's DOM!

Modern browsers:
→ Block setting document.domain to TLD or eTLD
→ Must be an actual subdomain of the current hostname
→ Both sides must actively opt in

Current status of document.domain:
→ Deprecated in modern browsers (Chrome 106+, Firefox considering)
→ Chrome now requires both frames to have same-origin by default
→ Feature flag/header needed to enable it
→ Avoid using document.domain in new applications
→ Use postMessage for cross-subdomain communication instead
```

**Secure alternative to document.domain:**

```javascript
// INSTEAD OF: document.domain relaxation
// USE: postMessage for intentional cross-origin communication

// Parent page (example.com):
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://marketing.example.com') return;

    if (event.data.type === 'requestData') {
        // Explicitly share only what's needed
        event.source.postMessage({
            type: 'response',
            data: { publicInfo: 'shared data here' }
        }, event.origin);
    }
});

// Iframe page (marketing.example.com):
window.parent.postMessage({ type: 'requestData' }, 'https://example.com');
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://example.com') return;
    console.log('Received:', event.data);
});

// postMessage:
// ✓ Explicit data sharing (only what you send)
// ✓ Origin validation possible
// ✓ No relaxation of SOP isolation
// ✓ Supported in all modern browsers
// ✓ Not deprecated
```

## SOP and Its Relationship to Other Mechanisms

### SOP alone is not sufficient — why CORS exists

```
The gap SOP creates in modern applications:

Legitimate need:
SPA frontend: https://app.company.com
REST API:     https://api.company.com
→ Frontend MUST read API responses to function
→ SOP blocks this: different subdomain = different origin!

Solution: CORS (Cross-Origin Resource Sharing)
→ Server explicitly declares: "This origin may read my responses"
→ Browser enforces that declaration
→ Controlled relaxation of SOP for legitimate use cases

Without CORS: API-based architectures impossible under strict SOP
With CORS misconfigured: SOP's protections undermined (see CORS guide)
```

### SOP and CSRF

```
Important distinction:
SOP does NOT prevent CSRF!

CSRF works because:
→ SOP does NOT block CROSS-ORIGIN REQUESTS from being SENT
→ SOP only blocks JavaScript from READING cross-origin RESPONSES
→ A form submission from attacker.com to bank.com:
  → Request sent WITH cookies (SOP doesn't stop this)
  → Attacker's JS cannot read the response (SOP blocks this)
  → But the ACTION was performed — CSRF succeeded!

CSRF is a one-way attack:
→ Attacker SENDS requests (SOP allows)
→ Attacker cannot READ responses (SOP blocks)
→ But state changes (transfer, email change) don't need response reading

CORS misconfiguration enables two-way attacks:
→ Attacker SENDS requests AND READS responses
→ Data exfiltration becomes possible (requires CORS miconfig)

This is why:
SOP prevents data reading but not action taking → CSRF tokens needed
CORS controls which origins can read → must be configured strictly
```
