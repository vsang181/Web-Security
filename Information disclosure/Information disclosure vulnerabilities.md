# Information disclosure vulnerabilities (information leakage)

Information disclosure is when a website unintentionally reveals sensitive information to users (including unauthenticated visitors).  
Leaks can be direct (secrets/personal data) or indirect (technical details that reduce attacker effort and enable follow-on exploits).

## What can be leaked
- User data: usernames, email addresses, addresses, order history, account IDs, financial details, session identifiers.
- Business data: internal documents, pricing rules, discount logic, private reports, partner data.
- Technical details: framework versions, internal hostnames/IPs, directory structure, API routes, database table/column names, stack traces, feature flags, cloud metadata.

## Where to look (common leak sources)

### 1) Error handling
Verbose errors often reveal stack traces, source file paths/line numbers, query fragments, internal service names, and sometimes environment variables.

Example: overly verbose JSON error response
```json
{
  "error": "NullReferenceException",
  "message": "Object reference not set to an instance of an object",
  "path": "C:\\app\\Controllers\\CheckoutController.cs:142",
  "sql": "SELECT * FROM Users WHERE email='...'"
}
```

### 2) Debug / diagnostic endpoints
- Debug toolbars, profiling endpoints, actuator/status endpoints.
- Swagger/OpenAPI UIs exposing internal APIs.
- Metrics endpoints (hostnames, queue names, build info).
- GraphQL introspection enabled in production.

### 3) Static files and misconfigured hosting
- Directory listing enabled.
- Backup files in web root: `.bak`, `.old`, `.swp`, `.zip`, `.tar.gz`, `~`.
- Source maps published (`.map`) exposing client-side source.
- `.git/` or `.svn/` accidentally exposed.
- Temporary uploads stored under publicly accessible paths.

Example: backup naming patterns worth checking
```text
/.config.php.bak
/app.js.old
/index.php~
/db.sql
/backup.zip
```

### 4) Client-side leaks
- API keys and secrets embedded in JS (or mobile apps).
- Internal endpoints/hostnames in bundles.
- Comments in HTML/JS revealing TODOs, credentials, or hidden paths.

### 5) Inconsistent responses (enumeration leaks)
Subtle differences can reveal whether a resource exists or a user is valid:
- Status codes (`404` vs `403` vs `200`)
- Response size/body differences
- Redirect behavior
- Response timing

Common examples:
- Username enumeration on login/register/reset flows.
- Object existence leaks (e.g., `/invoice/12345` behaves differently for valid vs invalid IDs).

### 6) Headers and metadata
- `Server`, `X-Powered-By`, framework-specific headers.
- Detailed caching headers revealing shared cache behavior.
- `Set-Cookie` attributes exposing session handling weaknesses.

Example: header hardening targets
```text
Server: nginx/1.18.0
X-Powered-By: Express
X-AspNet-Version: 4.0.30319
```

## How to find information disclosure (practical workflow)

### 1) Passive collection (low-noise)
- Browse normally and capture traffic.
- Inspect HTML/JS for comments, endpoints, keys, and source maps.
- Review response headers everywhere (login, errors, static assets, APIs).

Quick checklist:
- “View source” on key pages.
- Check `.map` files for major JS bundles.
- Search responses for: `key`, `token`, `secret`, `password`, `AKIA`, `BEGIN PRIVATE KEY`, `Authorization`.

If you’re saving responses locally, quick grep examples:
```bash
rg -n "AKIA|BEGIN PRIVATE KEY|Authorization:|api[_-]?key|secret|token|password" ./captures
rg -n "Exception|Stack trace|Traceback|NullReferenceException|SQLSTATE|ORA-" ./captures
```

### 2) Error-driven discovery
Trigger safe, low-impact errors and compare responses:
- Invalid types (string instead of number)
- Missing required fields
- Unsupported HTTP methods
- Unexpected content types

You’re looking for:
- Stack traces, debug fields
- Internal IDs
- Query fragments
- File paths

### 3) Content and behavior diffing
Try the same request with small variations:
- Existing vs non-existing IDs
- Valid vs invalid usernames
- Authenticated vs unauthenticated
- Different roles/accounts

Track:
- Status codes
- Response lengths
- Key phrases
- Latency differences

### 4) File and path discovery (defensive testing)
Focus on “likely-to-exist” files and misconfig indicators:
- `robots.txt`, `sitemap.xml`
- Common backups and temp files
- Known framework paths (only where authorized)

## Assessing severity (what matters most)
Information disclosure is highest severity when it:
- Exposes credentials/secrets (API keys, private keys, DB creds, session tokens).
- Exposes personal/regulated data (payment details, national IDs, medical info).
- Enables account takeover (reset tokens, session identifiers, auth bypass hints).
- Enables exploitation of known vulnerabilities (exact versions + exposed attack surface).
- Reveals internal network/infrastructure that enables pivoting.

Strong write-up pattern:
- “What leaked” + “what an attacker can do with it” + “how far it scales”.

## Prevention (best practices that reduce leaks)

### 1) Make “sensitive” explicit
Define what counts as sensitive (secrets, tokens, internal URLs, build info, user data, logs), then bake it into:
- Code review checklists
- Secure coding guidelines
- CI policies (secret scanning, debug toggles)

### 2) Use generic error messages externally
- Return minimal user-facing errors.
- Log detailed errors server-side (with access control).
- Ensure consistent responses across auth flows (avoid enumeration signals).

API error pattern (good)
```json
{ "error": "Request failed" }
```

### 3) Disable debug/diagnostics in production
- Turn off debug toolbars and verbose exception pages.
- Protect admin/diagnostic endpoints with strong auth + network restrictions.
- Remove or restrict API docs UIs in production.

### 4) Secure configuration defaults
Web server:
- Disable directory listing.
- Minimize version banners.
- Don’t serve dotfiles, backups, or repo metadata.

Nginx examples
```nginx
autoindex off;
server_tokens off;

location ~ /\. { deny all; }
location ~* \.(bak|old|swp|zip|tar|gz|7z|~)$ { deny all; }
```

### 5) Secrets management (don’t let secrets reach clients)
- Never ship secrets in JS, mobile apps, or HTML.
- Keep secrets in server-side secret stores / environment injection.
- Rotate secrets if exposure is suspected.
- Use scoped keys (least privilege) so a leak has limited blast radius.

### 6) Build-time and repo hygiene
- Strip developer comments where appropriate.
- Scan repos and build artifacts for secrets.
- Prevent source maps from being published publicly (or restrict access).
- Ensure backup artifacts and CI outputs never land in web root.

### 7) Logging and monitoring
- Redact sensitive fields in logs (passwords, tokens, Authorization headers).
- Alert on suspicious requests for backups, repo metadata, and debug endpoints.
- Track spikes in 4xx/5xx patterns that suggest probing.
