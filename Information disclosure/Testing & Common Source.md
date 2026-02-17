# How to find and exploit information disclosure vulnerabilities

Information disclosure is everywhere: in responses, headers, error behavior, and “forgotten” endpoints. The goal during testing is to **collect**, **diff**, and **search** at scale so you don’t miss small leaks that later unlock bigger bugs.

> Only test systems you own or have explicit permission to assess.

## Testing workflow (map → provoke → diff → expand)

Use the same repeatable loop for every target:

1) **Map**: Build an inventory of routes, parameters, and response types.  
2) **Provoke**: Send “slightly wrong” input to force edge-case handling.  
3) **Diff**: Compare responses (status, length, timing, headers, body structure).  
4) **Expand**: Use what you learned (framework hints, endpoints, IDs) to widen coverage.

What to record for every interesting finding:
- Full request + full response (headers + body).
- Status code, response length, timing.
- Any stack traces, file paths, internal hostnames, query fragments, versions, keys/tokens.

## Fuzzing and response diffing 

Fuzzing for info leaks is mostly about **unexpected types**, **boundary values**, and **format confusion**—not “exploit payloads”.

### Low-impact fuzz cases 

#### Type confusion
Try changing a parameter type and watch for different error paths:

```http
GET /api/orders?orderId=123
GET /api/orders?orderId=abc
GET /api/orders?orderId=true
GET /api/orders?orderId=null
GET /api/orders?orderId[]=1
GET /api/orders?orderId={"x":1}
```

JSON body variants:

```http
POST /api/orders
Content-Type: application/json

{"orderId":"not-a-number"}
```

```http
POST /api/orders
Content-Type: application/json

{"orderId":null}
```

```http
POST /api/orders
Content-Type: application/json

{"orderId":{"$gt":0}}
```

What you’re looking for:
- Stack traces, debug fields, “expected type” hints.
- Different status codes for “valid vs invalid” identifiers (enumeration).
- Error messages mentioning DB tables/columns, ORM model names, or internal services.

#### Boundary values
```http
GET /api/users?id=0
GET /api/users?id=-1
GET /api/users?id=999999999999
GET /api/users?id=2147483648
GET /api/users?id=9223372036854775808
```

#### Format confusion
Send “wrong” content types and malformed bodies to trigger verbose parsers:

```http
POST /api/profile
Content-Type: text/plain

{"name":"test"}
```

```http
POST /api/profile
Content-Type: application/json

{"name": "test"
```

```http
POST /api/profile
Content-Type: application/xml

<user><name>test</name></user>
```

#### Method confusion
Check how the app behaves on unsupported methods (often reveals routing details):

```bash
curl -i -X TRACE https://target.tld/
curl -i -X OPTIONS https://target.tld/api/
curl -i -X PUT https://target.tld/login
```

If TRACE is enabled, some servers echo the request back, which can expose internal headers added by proxies or gateways.

### Automate with curl + diff (quick local workflow)

Capture and compare “normal” vs “provoked” responses:

```bash
curl -s -D headers_ok.txt  https://target.tld/api/users?id=1   -o body_ok.txt
curl -s -D headers_bad.txt https://target.tld/api/users?id=abc -o body_bad.txt

diff -u headers_ok.txt headers_bad.txt | sed -n '1,200p'
diff -u body_ok.txt body_bad.txt | sed -n '1,200p'
```

Fast keyword search (responses saved to disk):

```bash
rg -n "Exception|Stack trace|Traceback|Fatal error|Warning:|SQLSTATE|ORA-|NullReference|DEBUG|password|secret|token|api[_-]?key" .
rg -n "BEGIN PRIVATE KEY|AKIA|Authorization:|Bearer " .
```

### Burp Intruder-style approach (what to configure)

When you have a parameter worth testing, automate high-volume probes and sort by differences:

- Payload positions: mark the parameter(s) you want to fuzz.
- Payload lists:
  - Types: `true`, `false`, `null`, `{}`, `[]`, `""`
  - Boundaries: `-1`, `0`, `1`, big integers
  - Strings: very long strings, Unicode, whitespace-only
  - Format breakers: malformed JSON fragments, invalid UTF-8 (if supported)
- Match rules: `Exception`, `Traceback`, `Stack`, `SQLSTATE`, `ORA-`, `DEBUG`, `key`, `token`, `secret`
- Extract rules:
  - `Set-Cookie` values (redact before sharing)
  - Version banners (`Server`, `X-Powered-By`)
  - Error codes/IDs (`correlationId`, `traceId`, `requestId`)

Tip: always sort results by **status**, **length**, and **time**. “One response that’s different” is often your lead.

## Common sources of information disclosure (with concrete checks)

### 1) Files for crawlers: `robots.txt` and `sitemap.xml`
These often reveal paths that aren’t linked in the UI.

```bash
curl -s https://target.tld/robots.txt | sed -n '1,200p'
curl -s https://target.tld/sitemap.xml | sed -n '1,200p'
```

What to extract:
- `Disallow:` directories (admin panels, backups, staging paths).
- Hidden endpoints that don’t appear in navigation.

### 2) Directory listings
If directory listing is enabled, it can expose:
- Temp files, crash dumps, backups, logs.
- Hidden resources not intended for users.

Manual checks:
- Visit suspected directories ending with `/` and observe if an index listing appears.
- Look for file patterns: `.log`, `.dmp`, `.dump`, `.bak`, `.old`, `.zip`, `.tar.gz`, `.sql`.

### 3) Developer comments and client-side artifacts
Common places:
- HTML comments: `<!-- TODO: ... -->`
- Inline scripts with debug toggles
- JS bundles and source maps

Check for source maps:
```bash
# If you see app.js, try app.js.map (only where authorized)
curl -i https://target.tld/static/app.js.map
```

Search client-side code for secrets-like patterns:
```bash
rg -n "api[_-]?key|secret|token|password|BEGIN PRIVATE KEY|AKIA|client_secret" ./static
```

### 4) Error messages (the biggest leak category)
Watch for:
- Framework names, template engines, DB type/version.
- File paths and line numbers.
- SQL fragments, table/column names.
- Debug flags, internal hostnames.

Examples of “too much”:
- Full stack trace returned to the browser
- Detailed SQL/ORM errors
- “Debug dump” objects (session, env, config)

### 5) Debug endpoints and diagnostics
Common mistakes:
- Debug mode enabled in production
- Profilers/toolbars exposed publicly
- Metrics endpoints unauthenticated
- API documentation UIs exposed (Swagger/OpenAPI)

What to look for:
- Build version, environment name (prod/stage/dev)
- Internal service URLs
- Credentials, tokens, encryption keys (worst case)
- Session variables and feature flags

### 6) User account pages and ID-based leaks (IDOR-adjacent)
Even when access control blocks “full page access”, partial components can leak.

Example risk pattern:
```http
GET /user/personal-info?user=carlos
```

If the app renders a component (email/API key) without checking that `user` matches the authenticated user, you may see other users’ data reflected on your page.

Things to test:
- Change `user` / `id` / `accountId` parameters.
- Compare behavior for “existing vs non-existing” IDs.
- Compare fields that load via separate API calls (often less protected).

### 7) Backup files and source disclosure
Common backup naming:
```text
/index.php~
/config.php.bak
/app.js.old
/settings.py.save
/db.sql
/backup.zip
```

The security impact is huge if it exposes:
- Hard-coded API keys
- Database credentials
- Internal endpoints
- Logic that enables other exploits

### 8) Insecure configuration (server/app)
Examples to validate:
- Verbose error pages enabled
- Debug mode enabled
- TRACE method enabled (echoing request data)
- Overly detailed security headers/banners
- Misconfigured caching (private data cached in shared proxies)

### 9) Version control exposure (`/.git/`)
If version control metadata is accessible, attackers can sometimes recover history/diffs and potentially secrets committed accidentally.

Defensive check:
- Ensure the web server denies dotfiles/directories.
- Ensure deployments never include `.git/`.

## “Engineering informative responses” (turn behavior into data)

Sometimes you can make the app *reveal more* by forcing it to process data in ways it wasn’t designed for:

- Trigger a parsing error in a specific subsystem:
  - JSON parser vs XML parser vs form parser
- Trigger a backend conversion error:
  - String → integer conversion
  - Date parsing failures
- Trigger template rendering errors (missing variable names)
- Trigger ORM mapping errors (unknown fields)

Example: forcing validation detail
```http
POST /api/payments
Content-Type: application/json

{"amount":"aaa","currency":"ZZZ","card":{"number":"x"}}
```

What you might get back (bad):
- Field-level validation messages revealing internal field names and constraints.
- Processor names (“StripeAdapter”, “LegacyBillingService”).
- Trace IDs that correlate with internal logs (useful for incident response, dangerous if exposed with too much context).

## Reporting severity (how to write a strong finding)

A useful structure:

- **What leaked**: exact field(s)/string(s)/file(s)/endpoint(s).  
- **Why it matters**: what capability it gives an attacker (ATO, fraud, pivoting, targeted exploit).  
- **Exploitability**: can it be accessed unauthenticated, at scale, or reliably?  
- **Blast radius**: single user vs all users, single endpoint vs global.  
- **Fix**: specific remediation steps (config + code).

Example severity mapping:
- Critical: secrets/credentials, reset tokens, private keys, payment data, session tokens.
- High: debug endpoints exposing internal systems, source code disclosure, detailed auth enumeration enabling credential attacks.
- Medium: framework versions + known vulnerable versions, directory listing revealing sensitive filenames.
- Low: harmless banners with no follow-on impact (still worth hardening).

## Prevention (OWASP-aligned practical controls)

### 1) Generic errors externally, detailed logs internally
- Return consistent, minimal error responses.
- Log full exception details server-side with access controls.
- Use correlation IDs for support without exposing stack traces.

Express (Node.js) error middleware:
```js
app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  console.error({ id, err }); // server-side only
  res.status(500).json({ error: "Request failed", requestId: id });
});
```

Flask (Python) generic handler:
```python
@app.errorhandler(Exception)
def handle_error(e):
    app.logger.exception("Unhandled exception")
    return {"error": "Request failed"}, 500
```

ASP.NET Core production exception handler:
```csharp
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error");
}
```

### 2) Disable debug/diagnostic features in production
- Debug toolbars off
- Profilers not publicly reachable
- Metrics/admin endpoints behind auth + network restrictions

### 3) Lock down static hosting
- Disable directory listing.
- Deny dotfiles and backup extensions.
- Restrict or remove source maps in production.

Nginx examples:
```nginx
autoindex off;
server_tokens off;

location ~ /\. { deny all; }
location ~* \.(bak|old|swp|zip|tar|gz|7z|~|map)$ { deny all; }
```

### 4) Secrets management (don’t ship secrets to clients)
- Never embed secrets in JS/mobile apps/HTML.
- Use a secret store and inject at runtime.
- Rotate secrets on suspected exposure.
- Use scoped keys (least privilege) so leaks have limited impact.

### 5) Consistent responses to prevent enumeration
- Same status codes for auth failures.
- Same error messages.
- Avoid timing differences (no quick exits).

### 6) CI/build hygiene
Automate checks to prevent “leak artifacts” from shipping:
- Secret scanning on commits and build artifacts.
- Block `.git/`, backups, logs, dumps, `.env`, source maps (if undesired).
- Fail builds if production config enables debug/verbose errors.

### 7) Logging and monitoring
- Redact sensitive fields (passwords, tokens, Authorization headers).
- Alert on requests for suspicious artifacts (`/.git/`, backups, debug endpoints).
- Track spikes in 4xx/5xx patterns and unusual endpoint discovery behavior.
