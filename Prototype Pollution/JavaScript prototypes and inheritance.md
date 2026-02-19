# JavaScript Prototypes and Inheritance

JavaScript's inheritance model is fundamentally different from class-based languages like Java or Python. Rather than defining a class blueprint and instantiating objects from it, JavaScript uses a *prototypal* model — every object is linked directly to another object called its prototype, and properties are inherited by walking this chain at runtime. Understanding this model precisely is what makes prototype pollution attacks possible: the attacker doesn't exploit a bug in a specific function, they exploit the language's own property resolution mechanism.

**Fundamental principle: In JavaScript, property lookup is not a compile-time or class-time operation — it happens at runtime, on every access, by walking the prototype chain. This means that if an attacker can plant a property anywhere on that chain *before* the engine walks it, the application code will find and use it as if it were a legitimate value.**

***

## Objects in JavaScript

```javascript
// ── Everything in JavaScript is (effectively) an object ──────────────────────

// Object literal: explicitly declares properties as key:value pairs
const user = {
    username: "wiener",
    userId: 1234,
    isAdmin: false
};

// Property access: dot notation or bracket notation (equivalent)
user.username          // "wiener"
user['username']       // "wiener"  ← bracket notation allows dynamic keys

// Methods: properties whose value is a function
const user2 = {
    username: "wiener",
    greet: function() {
        return `Hello, ${this.username}`;
    },
    // Shorthand method syntax (ES6):
    logout() {
        console.log("Logged out");
    }
};
user2.greet();         // "Hello, wiener"

// ── "Almost everything is an object" — what this means in practice ─────────
typeof {}          // "object"
typeof []          // "object"   ← arrays are objects with numeric keys
typeof function(){} // "function" — but functions are also objects (have properties)
typeof "string"    // "string"   — primitives are NOT objects...
typeof 1           // "number"
typeof true        // "boolean"

// ...BUT primitives are AUTO-BOXED into wrapper objects when you access properties:
"hello".toUpperCase()    // works! "hello" temporarily becomes a String object
(1).toFixed(2)           // works! 1 temporarily becomes a Number object
// → The wrapper object inherits from String.prototype / Number.prototype ✓
// → After the property access, the wrapper is discarded (primitives are immutable)
```

***

## What Is a Prototype?

```javascript
// ── Every object has a hidden [[Prototype]] link ──────────────────────────────

// Built-in prototypes for each data type:
let myObject  = {};   Object.getPrototypeOf(myObject);   // Object.prototype
let myString  = "";   Object.getPrototypeOf(myString);   // String.prototype
let myArray   = [];   Object.getPrototypeOf(myArray);    // Array.prototype
let myNumber  = 1;    Object.getPrototypeOf(myNumber);   // Number.prototype
let myFunc    = function(){}; Object.getPrototypeOf(myFunc); // Function.prototype

// ── Why prototypes exist: shared method storage ───────────────────────────────

// INEFFICIENT (without prototypes): every string object stores its own copy of methods
const s1 = { value: "hello", toLowerCase: function(){ ... } };
const s2 = { value: "world", toLowerCase: function(){ ... } };  // duplicated!

// EFFICIENT (with prototypes): methods defined ONCE on the prototype, shared by all
String.prototype.toLowerCase = function() { ... };  // defined once
const s1 = "hello";   s1.toLowerCase();  // ← inherited from String.prototype ✓
const s2 = "world";   s2.toLowerCase();  // ← same method, zero duplication ✓

// ── The prototype relationship (visualised) ────────────────────────────────────

//  myArray  ──[[Prototype]]──►  Array.prototype  ──[[Prototype]]──►  Object.prototype  ──►  null
//  ["a","b"]                    [push, pop, map,                       [toString,
//                                filter, reduce,                        hasOwnProperty,
//                                indexOf, ...]                          valueOf, ...]

//  myString  ──[[Prototype]]──►  String.prototype  ──[[Prototype]]──►  Object.prototype  ──►  null
//  "hello"                       [toLowerCase,                         [toString,
//                                 toUpperCase,                          hasOwnProperty, ...]
//                                 trim, split, ...]

//  myObject  ──[[Prototype]]──►  Object.prototype  ──►  null
//  {}                            [toString, hasOwnProperty,
//                                 valueOf, isPrototypeOf, ...]
```

***

## How Property Inheritance Works at Runtime

```javascript
// ── Property lookup algorithm (runtime, every access) ─────────────────────────

// Step 1: Does the object itself have the property as an OWN property?
//         → Yes: return it immediately (own property wins)
//         → No: go to Step 2

// Step 2: Does the object's prototype have the property?
//         → Yes: return it
//         → No: go to the prototype's prototype (repeat)

// Step 3: Continue up the chain until Object.prototype
//         → If found: return it
//         → If Object.prototype doesn't have it: return undefined (chain ends at null)

// ── Concrete example ──────────────────────────────────────────────────────────

const user = { username: "wiener", userId: 1234 };

// Step 1: user.username → user has own property "username" → "wiener" ✓ (stops here)

// Step 2: user.toString() →
//   user has own "toString"? No
//   user.__proto__ (Object.prototype) has "toString"? Yes → [Function: toString] ✓

// Step 3: user.nonExistent →
//   user has own "nonExistent"? No
//   Object.prototype has "nonExistent"? No
//   Object.prototype.__proto__ === null → end of chain → undefined ✓

// ── OWN properties vs INHERITED properties ────────────────────────────────────

const obj = { ownProp: "I am own" };

// hasOwnProperty: checks ONLY own properties (does not walk the chain)
obj.hasOwnProperty('ownProp');      // true  ← directly on obj
obj.hasOwnProperty('toString');     // false ← inherited, not own
obj.hasOwnProperty('__proto__');    // false ← special accessor, not own

// 'in' operator: checks the ENTIRE chain (own + inherited)
'ownProp' in obj;                   // true
'toString' in obj;                  // true  ← found on Object.prototype ✓
'nonExistent' in obj;               // false ← not anywhere in chain

// for...in: iterates ALL enumerable properties (own + inherited)
// → This is why unsafe merge functions using for...in are vulnerable:
//   they iterate inherited properties including attacker-injected ones ✓
for (const key in obj) {
    console.log(key);  // logs inherited enumerable props too
}

// Object.keys(): ONLY own enumerable properties (safe for merge functions)
Object.keys(obj);  // ["ownProp"]   ← inherited properties excluded ✓
```

***

## The Prototype Chain in Full Detail

```javascript
// ── Walking the complete chain for a string ───────────────────────────────────

const username = "wiener";

username.__proto__                  // String.prototype
username.__proto__.__proto__        // Object.prototype
username.__proto__.__proto__.__proto__  // null  ← top of the chain

// ── Walking the complete chain for an array ───────────────────────────────────

const arr = [1, 2, 3];

arr.__proto__                       // Array.prototype
arr.__proto__.__proto__             // Object.prototype
arr.__proto__.__proto__.__proto__   // null

// ── Walking the complete chain for a custom object ────────────────────────────

function Animal(name) {
    this.name = name;               // own property
}
Animal.prototype.speak = function() {   // method on prototype
    return `${this.name} makes a sound`;
};

function Dog(name, breed) {
    Animal.call(this, name);        // inherit own property
    this.breed = breed;             // own property
}
Dog.prototype = Object.create(Animal.prototype);  // set up prototype chain
Dog.prototype.constructor = Dog;

const rex = new Dog("Rex", "Labrador");

// rex's prototype chain:
// rex  ──►  Dog.prototype  ──►  Animal.prototype  ──►  Object.prototype  ──►  null

// Property resolution:
rex.name;    // "Rex"           ← own property (set by Animal.call)
rex.breed;   // "Labrador"      ← own property
rex.speak(); // "Rex makes a sound" ← found on Animal.prototype ✓
rex.toString(); // "[object Object]" ← found on Object.prototype ✓

// Visualised:
// rex { name:"Rex", breed:"Labrador" }
//   → Dog.prototype { constructor: Dog }
//     → Animal.prototype { speak: [Function] }
//       → Object.prototype { toString, hasOwnProperty, valueOf, ... }
//         → null
```

***

## Accessing and Modifying Prototypes

```javascript
// ── Three ways to access a prototype ─────────────────────────────────────────

const obj = { key: "value" };

// Method 1: __proto__ (de facto standard, legacy but universal browser support)
obj.__proto__                          // Object.prototype

// Method 2: Object.getPrototypeOf() (ES5+, recommended)
Object.getPrototypeOf(obj)             // Object.prototype

// Method 3: .constructor.prototype (works for most objects)
obj.constructor.prototype              // Object.prototype
// Note: constructor can be overwritten → less reliable than the above two

// ── __proto__ as a getter AND setter ─────────────────────────────────────────

// Reading the prototype:
const proto = obj.__proto__;           // reads [[Prototype]]

// Setting the prototype (reassignment):
const newProto = { customMethod() { return "custom"; } };
obj.__proto__ = newProto;              // sets [[Prototype]] to newProto
obj.customMethod();                    // "custom" ✓

// IMPORTANT: When you ASSIGN A PROPERTY to __proto__, not reassign __proto__ itself:
obj.__proto__.newProp = "planted";
// → This does NOT change obj's prototype
// → It MODIFIES the existing prototype object by adding newProp to it
// → ALL objects sharing this prototype now inherit newProp
// → THIS IS THE HEART OF PROTOTYPE POLLUTION ✓

// ── Chaining __proto__ to walk and modify the chain ──────────────────────────

const str = "hello";
str.__proto__              // String.prototype
str.__proto__.__proto__    // Object.prototype
str.__proto__.__proto__.polluted = "payload";
// → Object.prototype.polluted = "payload"
// → EVERY object in the runtime now inherits "polluted" ✓

// Verification:
const a = {};
const b = [];
const c = function(){};
console.log(a.polluted);   // "payload" ✓
console.log(b.polluted);   // "payload" ✓
console.log(c.polluted);   // "payload" ✓
```

***

## Modifying Built-in Prototypes

```javascript
// ── Legitimate prototype extension (historical pattern, now discouraged) ──────

// Before ES6 introduced String.prototype.trim():
String.prototype.removeWhitespace = function() {
    return this.replace(/^\s+|\s+$/g, '');
};

const searchTerm = "  example  ";
searchTerm.removeWhitespace();    // "example" ✓
// → All strings now have removeWhitespace ✓

// Why this was common practice:
// → Polyfills for older browsers (adding missing features like Array.prototype.map)
// → Utility methods shared across the entire codebase
// → "Monkey patching" third-party library behaviour

// Why this is NOW considered bad practice:
// → Name collisions: if the spec later adds a method with the same name
//   but slightly different behaviour → silent breakage
// → Prototype pollution vulnerability surface: any function that extends prototypes
//   could be exploited if it processes attacker-controlled input ✓
// → Unpredictable for...in iteration (adds enumerable properties to all objects)

// ── The modern alternative: utility functions or subclassing ─────────────────

// Instead of: String.prototype.removeWhitespace = ...
// Do this:
function removeWhitespace(str) {
    return str.replace(/^\s+|\s+$/g, '');
}

// Or use a class that extends String (ES6):
class SafeString extends String {
    removeWhitespace() {
        return this.valueOf().replace(/^\s+|\s+$/g, '');
    }
}

// ── What Object.prototype contains (the root of all inheritance) ──────────────

// Every object in JavaScript inherits ALL of these:
Object.getOwnPropertyNames(Object.prototype);
// [
//   "constructor",       ← reference to the Object constructor function
//   "__defineGetter__",  ← legacy
//   "__defineSetter__",  ← legacy
//   "hasOwnProperty",    ← checks if property is own (not inherited)
//   "__lookupGetter__",  ← legacy
//   "__lookupSetter__",  ← legacy
//   "isPrototypeOf",     ← checks if object is in another's prototype chain
//   "propertyIsEnumerable", ← checks if property is enumerable
//   "toString",          ← "[object Object]" by default
//   "valueOf",           ← returns the primitive value of the object
//   "__proto__",         ← the getter/setter for the prototype link
//   "toLocaleString"     ← locale-aware string conversion
// ]

// Prototype pollution target: Object.prototype
// → It is at the TOP of every object's chain
// → Polluting it affects every single object in the JavaScript runtime ✓
// → No object is immune unless it was created with Object.create(null):
const safe = Object.create(null);
Object.getPrototypeOf(safe);   // null — no prototype chain at all ✓
safe.toString;                 // undefined (no inherited methods) ✓
// → Safe objects like this are immune to prototype pollution
```

***

## Why This Directly Enables Prototype Pollution

```javascript
// ── The inheritance model creates the attack surface ─────────────────────────

// Normal application code:
const config = {};     // empty object → inherits from Object.prototype
const adminStatus = config.isAdmin;   // undefined (not set)
// → Application logic: if (!adminStatus) → not admin ✓

// After pollution:
Object.prototype.isAdmin = true;      // planted on prototype

// Same application code, same config object, no modification to config:
const adminStatus = config.isAdmin;   // TRUE (inherited from polluted prototype!)
// → config.hasOwnProperty('isAdmin') === false → own property NOT set
// → But config.isAdmin === true → inherited ✓
// → Application logic: if (!adminStatus) → ... admin access granted ✓ ← bypass!

// Key insight: application developers assume that if they never wrote
// config.isAdmin = true, then config.isAdmin is undefined.
// Prototype pollution breaks this assumption WITHOUT touching the config object.

// ── The three conditions for a successful gadget ──────────────────────────────

// Condition 1: Property must NOT be an own property of the target object
config.isAdmin = true;                // ← attacker cannot exploit this as a gadget
                                      //    own property shadows the prototype ✓

// Condition 2: Object must inherit from the polluted prototype
const safeObj = Object.create(null); // ← no prototype → immune to Object.prototype pollution
safeObj.isAdmin;                     // undefined ← safe ✓

// Condition 3: The property must flow into a dangerous operation (sink)
eval(config.callback);               // ← dangerous: eval with prototype-inherited value ✓
script.src = config.transport_url;   // ← dangerous: script injection ✓
exec(cmd, config);                   // ← dangerous: command execution with polluted options ✓
```
