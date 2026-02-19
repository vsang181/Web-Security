# Preventing Prototype Pollution

No single technique eliminates prototype pollution entirely — the correct approach is layered defence at multiple levels: block dangerous keys at the input boundary, freeze or seal prototype objects so they cannot be modified even if a merge runs, eliminate gadgets by removing the inheritance relationship from sensitive objects, and prefer data structures that don't walk the prototype chain at all. Each layer independently reduces attack surface; together they make exploitation practically impossible.

**Fundamental principle: Prototype pollution has two halves — a *source* (the path that writes to `Object.prototype`) and a *gadget* (the property the application later reads from an object that inherits the pollution). A complete defence must address both: even if you cannot block every source, eliminating gadgets makes the vulnerability unexploitable. Even if you cannot eliminate every gadget, blocking sources prevents pollution from occurring in the first place.**

***

## Layer 1: Input Sanitisation (Stopgap — Not Sufficient Alone)

```javascript
// ── ALLOWLIST (most robust form of key sanitisation) ──────────────────────────
// Explicitly define which keys are permitted — reject everything else.
// Best used on narrow, well-defined APIs where the key set is known.

const ALLOWED_USER_KEYS = new Set(['firstName', 'lastName', 'email', 'theme']);

function safeMergeAllowlist(target, source) {
    for (const key of Object.keys(source)) {   // Object.keys = own enumerable only
        if (!ALLOWED_USER_KEYS.has(key)) {
            continue;                            // reject any unexpected key ✓
        }
        target[key] = source[key];
    }
}
// Advantage: __proto__, constructor, prototype all rejected by default ✓
// Disadvantage: requires knowing all valid keys in advance → impractical for
//               generic utilities (deep merge, lodash-style assign, etc.)


// ── BLOCKLIST (common — but must block ALL pollution vectors) ─────────────────
// Reject known dangerous keys. Easier to implement but harder to get right.

function safeMergeBlocklist(target, source) {
    for (const key of Object.keys(source)) {
        // Must block ALL three prototype pollution paths:
        if (key === '__proto__')   continue;     // direct prototype accessor
        if (key === 'constructor') continue;     // constructor.prototype path
        if (key === 'prototype')   continue;     // direct prototype property

        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            safeMergeBlocklist(target[key], source[key]);   // ← RECURSE safely
        } else {
            target[key] = source[key];
        }
    }
}

// ── CRITICAL: use Object.keys(), NOT for...in ─────────────────────────────────
// for...in iterates own + INHERITED enumerable properties → leaks prototype props
// Object.keys() returns ONLY own enumerable properties → safe ✓

const polluted = {};
Object.prototype.evil = 'payload';

for (const k in polluted)       console.log(k); // "evil" ← leaks prototype ✗
for (const k of Object.keys(polluted)) console.log(k); // nothing ← safe ✓


// ── WHY BLOCKLISTS FAIL WITHOUT ALL THREE PATHS ───────────────────────────────

// WEAK blocklist (blocks only __proto__):
function weakFilter(key) { return key !== '__proto__'; }
// BYPASS: constructor[prototype][isAdmin]=true
//   → "constructor" passes filter → "prototype" passes → Object.prototype polluted ✓

// WEAK blocklist (single-pass string stripping):
function weakStrip(key) { return key.replace('__proto__', ''); }
// BYPASS: __pro__proto__to__
//   → after strip: __proto__ → pollution succeeds ✓
// Fix: use a loop or regex until the string stabilises:
function robustStrip(key) {
    let prev;
    do {
        prev = key;
        key = key.replace(/__proto__|constructor|prototype/g, '');
    } while (key !== prev);
    return key;
}
```

***

## Layer 2: Freeze or Seal the Prototype (Block All Sources)

```javascript
// ── Object.freeze(): makes the prototype completely immutable ─────────────────
// Properties cannot be added, removed, or modified.
// Any attempt to modify is silently ignored in sloppy mode,
// throws TypeError in strict mode.

Object.freeze(Object.prototype);

// Proof: any pollution attempt silently fails
Object.prototype.evil = 'payload';   // silently ignored
({}).evil;                            // undefined ✓

Object.assign(Object.prototype, { evil: 'payload' }); // TypeError in strict mode ✓

// Recursive freeze (protects the full chain):
function deepFreeze(obj) {
    Object.getOwnPropertyNames(obj).forEach(name => {
        const value = obj[name];
        if (typeof value === 'object' && value !== null) {
            deepFreeze(value);
        }
    });
    return Object.freeze(obj);
}
deepFreeze(Object.prototype);   // freeze the root ✓


// ── Object.seal(): prevents adding/removing properties, allows value changes ──
// Less restrictive than freeze — use if libraries legitimately add to prototypes.

Object.seal(Object.prototype);
Object.prototype.evil = 'payload';  // silently ignored (cannot add new properties) ✓
Object.prototype.toString = () => 'hacked';  // allowed (existing property, value change)
// → seal is a reasonable compromise if freeze breaks legitimate library behaviour


// ── When to prefer seal over freeze ──────────────────────────────────────────
// Some polyfills and libraries add methods to built-in prototypes at runtime.
// Object.freeze() would break these.
// Object.seal() prevents new pollution while allowing existing modifications.
// For maximum security in production apps: use freeze and test thoroughly.


// ── Placement: early initialisation is critical ───────────────────────────────
// Freeze MUST be called before any user-controlled input is processed.
// Best practice: make it the FIRST line of your entry point.

// server.js or index.js:
'use strict';
Object.freeze(Object.prototype);     // ← FIRST LINE before any require() ✓
const express = require('express');
// ...


// ── Limitation: does not protect non-Object.prototype chains ─────────────────
// Attacker can still pollute Array.prototype, Function.prototype, etc.
// if those are not frozen:
Object.freeze(Object.prototype);     // protected
Object.freeze(Array.prototype);      // also protect array operations
Object.freeze(Function.prototype);   // also protect function operations
```

***

## Layer 3: Eliminate Gadgets via `Object.create(null)`

```javascript
// ── Create objects with null prototype = no inheritance chain at all ──────────
// These objects cannot inherit ANYTHING from Object.prototype —
// even if the prototype is polluted, null-prototype objects are immune.

const safeConfig = Object.create(null);
// Object.getPrototypeOf(safeConfig) === null
// safeConfig.__proto__ === undefined (no prototype accessor)
// safeConfig.toString === undefined (no inherited methods)

// Pollution has NO effect:
Object.prototype.evil = 'payload';
safeConfig.evil;                   // undefined ✓ — no prototype chain to walk

// ── Practical usage ───────────────────────────────────────────────────────────

// Safe dictionary / lookup table:
const lookup = Object.create(null);
lookup['userId_123'] = { role: 'user' };
lookup['userId_456'] = { role: 'admin' };
// → Even if Object.prototype.role = 'admin' is polluted:
//   lookup['userId_999'].role → TypeError (key doesn't exist) — not 'admin' ✓

// Safe options object (eliminates gadgets):
const options = Object.create(null);
options.theme = 'dark';
options.fontSize = 16;
// → transport_url pollution: options.transport_url === undefined ✓
//   (not inherited, genuinely absent)

// ── Caveats: what you lose without a prototype ────────────────────────────────
const obj = Object.create(null);
obj.toString();               // TypeError: obj.toString is not a function
JSON.stringify(obj);          // works fine ✓ (JSON doesn't use prototype methods)
obj instanceof Object;        // false (no prototype chain)
'key' in obj;                 // works fine ✓ (checks own properties)
Object.keys(obj);             // works fine ✓

// Solution for when prototype methods ARE needed:
// → Only use Object.create(null) for config/options/data objects
// → Not for objects that need to be passed to APIs expecting prototype methods
// → For those, use Map instead (see Layer 4)


// ── Setting prototype to null on existing objects ─────────────────────────────
const existingObj = { key: 'value' };
Object.setPrototypeOf(existingObj, null);
// → existingObj now has null prototype
// → No longer inherits from Object.prototype ✓
// → Use sparingly: setPrototypeOf is slow (deoptimises JS engine's hidden class)
// → Better to use Object.create(null) from the start
```

***

## Layer 4: Use Prototype-Safe Data Structures

```javascript
// ── Map: key-value storage immune to prototype confusion ─────────────────────
// Map.get() ONLY returns properties set via Map.set() — it never walks the chain.
// dot notation on a Map CAN still return prototype-inherited values,
// but Map's own API (.get(), .has(), .set()) is completely safe.

Object.prototype.evil = 'polluted';
const config = new Map();
config.set('transport_url', 'https://normal-website.com');
config.set('theme', 'dark');

// SAFE access via Map API:
config.get('evil');              // undefined ✓ (not in the Map's own data)
config.get('transport_url');     // 'https://normal-website.com' ✓
config.has('evil');              // false ✓
config.has('transport_url');     // true ✓

// UNSAFE access via dot notation (still walks prototype chain):
config.evil;                     // 'polluted' ✗ (inherited from Object.prototype)
// → ALWAYS use .get() and .has(), never dot notation for Map lookups ✓


// ── Set: value storage immune to prototype confusion ─────────────────────────
Object.prototype.evil = 'polluted';
const permissions = new Set();
permissions.add('read');
permissions.add('write');

permissions.evil;                // 'polluted' ✗ (dot notation — still inherits)
permissions.has('evil');         // false ✓ (Set's own method — safe)
permissions.has('read');         // true ✓

// Use .has() for membership checks, never 'in' or dot access on Sets ✓


// ── Map vs Object: when to use each ──────────────────────────────────────────
//
//                     Plain Object {}    Map              Object.create(null)
// ─────────────────────────────────────────────────────────────────────────────
// Prototype pollution immune?    No       Via .get()/.has()  Yes (completely)
// Inherits prototype methods?    Yes      Yes (Map methods)  No
// Keys of any type?              String   Any type           String
// Ordered iteration?             No       Yes (insertion)    No
// JSON serialisable?             Yes      No (manual)        Yes
// Best for:                   Simple   Computed/dynamic     Config/options
//                             configs  key sets             data dicts


// ── WeakMap: same safety for object-keyed associations ───────────────────────
// When keys are objects (not strings), WeakMap provides safe storage:
const safeCache = new WeakMap();
safeCache.set(requestObject, { userId: 123 });
safeCache.get(requestObject);    // { userId: 123 } ✓
// → Cannot be polluted via __proto__ since keys must be objects ✓
```

***

## Layer 5: Dependency and Library Hardening

```javascript
// ── Update vulnerable libraries immediately ───────────────────────────────────
// Many high-severity prototype pollution CVEs are in common npm packages:
//
// Library           CVE                   Fix version
// ─────────────────────────────────────────────────────────────────────────────
// lodash            CVE-2019-10744        ≥ 4.17.12   (_.merge, _.defaultsDeep)
// jQuery            CVE-2019-11358        ≥ 3.4.0     ($.extend deep merge)
// express           (json spaces gadget)  ≥ 4.17.4
// minimist          CVE-2020-7598         ≥ 1.2.3     (CLI arg parser)
// qs                CVE-2022-24999        ≥ 6.10.3    (query string parser)
// set-value         CVE-2019-10747        ≥ 3.0.1

// ── Audit dependencies regularly ─────────────────────────────────────────────
npm audit                         // lists known vulnerabilities
npm audit fix                     // auto-upgrades patchable deps
npx snyk test                     // deeper analysis including prototype pollution

// ── Use Node.js --disable-proto flag (deployment hardening) ──────────────────
// Removes or disables __proto__ at the runtime level:
node --disable-proto=delete server.js    // __proto__ removed entirely from all objects
node --disable-proto=throw server.js     // accessing __proto__ throws TypeError

// NOTE: this does NOT protect against constructor.prototype pollution path
// → Still necessary to block "constructor" and "prototype" keys in merge functions ✓

// ── Content Security Policy (CSP) for client-side gadget mitigation ───────────
// Even if client-side pollution succeeds, a strong CSP limits what sinks are exploitable:
Content-Security-Policy:
  script-src 'self' https://trusted-cdn.com;   // blocks arbitrary script.src ✓
  default-src 'self';
  object-src 'none';

// Defeats: transport_url gadget (can't load script from attacker.com) ✓
// Does NOT defeat: inline event handlers (onerror, etc.) unless unsafe-inline blocked
// Add: script-src 'self' 'nonce-...' to also block inline scripts ✓
```
