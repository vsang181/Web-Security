# Insecure direct object references (IDOR)

IDOR (Insecure Direct Object Reference) is an access control flaw where a user can access or modify an object (record/file/resource) by changing an identifier the application trusts (ID, filename, UUID, account number). It most often enables horizontal privilege escalation (other users’ data) and sometimes becomes vertical escalation if the targeted object belongs to an admin or unlocks privileged actions.

## What IDOR is (and isn’t)
IDOR happens when the server uses attacker-controllable input to look up an object and returns/changes it **without** verifying the requester is allowed to access that specific object. A “hard-to-guess” identifier (UUID/GUID) is not a fix if the app ever leaks it, or if access control checks are missing.

Common direct references:
- Database records: `?customer_number=132355`, `/api/invoices/12345`, `{"userId":456}`.
- Static files: `/static/12144.txt`, `/uploads/invoice_123.pdf`, `/download?file=report-2025.csv`.

## Where IDOR shows up (patterns + examples)
Look for any endpoint where the client supplies an identifier that maps to a sensitive object.

### Database object reference (classic)
```http
GET /customer_account?customer_number=132355 HTTP/1.1
Cookie: session=...
```
If the server does something like:
```sql
SELECT * FROM customers WHERE customer_number = :customer_number;
```
and returns results without checking ownership/tenant/role, then changing `customer_number` can expose other customers.

### API object reference (path, query, JSON)
```http
GET /api/orders/381 HTTP/1.1
Cookie: session=...
```

```http
GET /api/orders?orderId=381 HTTP/1.1
Cookie: session=...
```

```http
POST /api/orders/view HTTP/1.1
Content-Type: application/json
Cookie: session=...

{"orderId":381}
```

### Static file reference (incrementing or guessable filenames)
```http
GET /static/12144.txt HTTP/1.1
```
If these transcripts contain sensitive content and are served without authZ checks, you can often enumerate by adjusting the number.

### Indirect “almost IDOR” references
- `?filename=` download endpoints: often combine IDOR with path traversal if validation is weak.
- Multi-tenant apps: `?tenantId=...` or `X-Tenant: ...` headers; if user can switch tenant context, that’s frequently catastrophic.

## How to test and exploit IDOR (practical workflow)
IDOR testing is mostly “object-level authorization testing”: same endpoint, different object.

### 1) Build an object map
Identify object types and their identifiers:
- Users: `userId`, `username`, `uuid`
- Accounts: `accountId`, `customer_number`
- Orders/invoices: `orderId`, `invoiceId`
- Documents/messages: `docId`, `messageId`, `attachmentId`, filenames

Capture at least:
- One object you own (known-good)
- One object you don’t own (learned via UI, references, emails, shared links, search, logs, or predictable IDs)

### 2) Swap identifiers everywhere (not just GET)
Test read and write operations; write endpoints are often worse.

Read tests:
```http
GET /api/invoices/1001
GET /api/invoices/1002
```

Write tests:
```http
PUT /api/shipping-addresses/55
Content-Type: application/json

{"addressLine1":"Changed by attacker"}
```

Delete tests:
```http
DELETE /api/payment-methods/9
```

State-change tests (often overlooked):
```http
POST /api/users/123/disable-mfa
POST /api/orders/381/cancel
POST /api/invoices/1002/refund
```

### 3) Don’t trust “blocked” responses until you verify no leakage
Even if you get a redirect or error, check:
- Response body contains partial data
- Response headers leak info (IDs, filenames, debug fields)
- Timing differs for “exists vs doesn’t exist” (enumeration)
- Side effects still happen (e.g., cancel/refund processed but response says “unauthorized”)

### 4) Enumerate IDs safely (when authorized)
If identifiers are numeric and sequential:
- Increment/decrement by 1
- Try ranges and observe differences in status/length
- Use concurrency carefully (avoid causing harm)

If identifiers are UUIDs:
- Hunt for leaks: links, page source, JS, API responses, logs, messages, reviews, “shared with you” pages.
- Check whether the app returns UUIDs for other users in listing endpoints you can access.

### 5) Test “secondary” parameters and parameter pollution
Sometimes the app authorizes based on one parameter but fetches using another.

Example:
```http
GET /api/documents?docId=10&userId=me
```
Try:
- Duplicate parameters: `docId=10&docId=11`
- Mixed sources: path + query + body
- Alternate names: `id`, `doc_id`, `documentId`

### 6) Check object relationships (ReBAC-style rules)
In real apps, authorization is often relationship-based:
- Owner
- Same organization/tenant
- Assigned agent
- Member of project/team
So test edge relationships: removed member, suspended user, invited-not-accepted, read-only role.

## Why IDOR happens (and common “false fixes”)
The underlying cause is almost always “lookup first, authorize later” or “authorize generically, not per object”.

Frequent false fixes:
- “We use UUIDs now”: UUIDs reduce guessing, but don’t replace authorization.
- “The UI doesn’t show the link”: hiding links is not a server-side control.
- “We check user is logged in”: authentication is not authorization.
- “We validate the ID is numeric”: input validation doesn’t ensure permission.
- “We only expose static files”: static hosting bypasses your app-layer authZ unless you design for it.

How IDOR turns into vertical escalation:
- You IDOR into an admin’s account record, API key, or password reset token.
- You IDOR into privileged actions (approve refunds, change roles, access audit logs).
- You IDOR into configuration objects that affect system behavior (feature flags, pricing rules).

## Preventing IDOR (secure design + code examples)
The fix is consistent **server-side object-level authorization** with deny-by-default behavior.

### 1) Enforce object-level checks on every request
Pseudocode:
```text
obj = loadObject(id)
if obj is null: return 404
if !can(currentUser, action, obj): return 403 (or 404 to hide existence)
perform action
```

Ownership check example:
```text
if obj.ownerId != currentUser.id and !currentUser.hasRole("ADMIN"):
  deny
```

Tenant check example:
```text
if obj.tenantId != currentUser.tenantId:
  deny
```

### 2) Prefer “scoped queries” (authorize by construction)
Instead of:
```sql
SELECT * FROM invoices WHERE invoice_id = :id;
```
Use:
```sql
SELECT * FROM invoices
WHERE invoice_id = :id
  AND owner_user_id = :current_user_id;
```
Or for multi-tenant:
```sql
SELECT * FROM invoices
WHERE invoice_id = :id
  AND tenant_id = :current_tenant_id;
```
This reduces the chance a developer forgets a separate permission check.

### 3) Centralize authorization logic (policy layer)
Avoid scattered `if (user.isAdmin)` checks in controllers. Use a single policy mechanism so every endpoint follows the same pattern.

Node/Express (middleware pattern):
```js
function canViewInvoice(user, invoice) {
  return invoice.tenantId === user.tenantId &&
         (invoice.ownerId === user.id || user.roles.includes("FINANCE"));
}

app.get("/api/invoices/:id", async (req, res) => {
  const invoice = await db.invoices.findById(req.params.id);
  if (!invoice) return res.sendStatus(404);
  if (!canViewInvoice(req.user, invoice)) return res.sendStatus(403);
  res.json(invoice);
});
```

Django (queryset scoping):
```python
from django.http import Http404

def invoice_view(request, invoice_id):
    qs = Invoice.objects.filter(tenant=request.user.tenant)
    try:
        invoice = qs.get(id=invoice_id, owner=request.user)
    except Invoice.DoesNotExist:
        raise Http404()
    return JsonResponse(invoice.to_dict())
```

Spring-style concept (service-layer authorization):
```java
Invoice invoice = invoiceRepo.findById(id).orElseThrow(NotFound::new);
if (!policy.canView(principal, invoice)) throw new Forbidden();
```

### 4) Secure file access (don’t rely on “static” for sensitive files)
If a file is sensitive, don’t serve it directly from a public static directory with a guessable name.

Safer patterns:
- Store files outside public web root; serve via an authenticated download endpoint that authorizes access then streams the file.
- Use short-lived signed URLs only after authorization (and scope them to one object/user if possible).
- Ensure caching headers don’t allow shared caches to store private content.

Example: authenticated download endpoint (conceptual)
```http
GET /download?documentId=9911
-> server checks ownership/tenant, then streams bytes
```

### 5) Normalize and validate identifiers (but don’t confuse with authZ)
Do:
- Validate format (numeric bounds, UUID format, length)
- Reject weird encodings early
- Rate limit high-volume object lookups to slow enumeration

But remember: these are guardrails, not the permission check.

### 6) Testing and process controls
- Add automated tests that assert forbidden access across users/roles (authorization matrix tests).
- Add “negative tests” for ID swapping in CI for key object types.
- Log and alert on patterns: many 403/404s with sequential IDs, repeated access attempts across many objects.
