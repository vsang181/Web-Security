# Business logic vulnerabilities (application logic flaws)

Business logic vulnerabilities are flaws in the design and implementation of an application that allow attackers to manipulate legitimate functionality to achieve unintended goals. Unlike technical vulnerabilities like SQLi or XSS, logic flaws exploit the application's intended features in ways developers never anticipated. These vulnerabilities often bypass security controls entirely because the application is working "as coded" but not "as intended."

Logic flaws are particularly dangerous because automated scanners rarely detect them—they require human understanding of business rules, workflows, and attacker motivations.

> Only test systems you own or are explicitly authorized to assess.

## What are business logic vulnerabilities? (concept)

### The distinction from technical vulnerabilities

**Technical vulnerabilities:** Break security controls through malicious input
- SQL injection: `' OR '1'='1`
- XSS: `<script>alert(1)</script>`
- Path traversal: `../../../etc/passwd`

**Logic vulnerabilities:** Abuse legitimate functionality through unexpected workflows
- Purchase items for negative price
- Transfer money to yourself and recipient simultaneously
- Apply discount codes multiple times
- Skip payment verification steps
- Manipulate quantity to overflow and wrap to negative

### Key characteristics

**1) Application works "correctly" but produces wrong results:**
```python
# Code functions perfectly but logic is flawed
def apply_discount(price, discount_percent):
    discount = price * (discount_percent / 100)
    return price - discount

# Problem: No validation on discount_percent
# Attacker sends: discount_percent=150
# Result: price - (price * 1.5) = negative price
```

**2) Assumptions about user behavior are violated:**
```python
# Developer assumes: Users always proceed step-by-step
# Reality: Attackers jump directly to final step
@app.route('/checkout/step1')  # Select items
@app.route('/checkout/step2')  # Enter shipping
@app.route('/checkout/step3')  # Enter payment
@app.route('/checkout/complete')  # Finalize order - NO VALIDATION!
```

**3) Edge cases not considered:**
```python
# Developer assumes: Quantity is positive
# Reality: Attacker sends negative quantity
def add_to_cart(product_id, quantity):
    item = get_product(product_id)
    cart.total += item.price * quantity  # What if quantity is -10?
```

### Why they're dangerous

- **Bypass all security controls** (firewall, WAF, authentication all passed)
- **Difficult to detect** (no malicious payload signatures)
- **Unique to each application** (no generic exploit patterns)
- **High business impact** (financial loss, fraud, data breach)
- **Often trivial to exploit** (just change a number in request)

## How business logic vulnerabilities arise

### Root cause 1: Flawed assumptions

**Assumption: Users follow the intended workflow**
```
Reality: Attackers skip steps, repeat steps, or go backwards
```

**Assumption: Input values are reasonable**
```
Reality: Negative numbers, zero, extremely large values, null
```

**Assumption: Client-side validation is sufficient**
```
Reality: Attackers bypass browser entirely with Burp Suite
```

**Assumption: Authenticated users are trustworthy**
```
Reality: Authenticated users can be malicious
```

**Assumption: State is maintained correctly**
```
Reality: Race conditions, concurrent requests, session manipulation
```

### Root cause 2: Incomplete validation

**Example - Price validation:**
```python
# Only checks for negative, but not zero
def validate_price(price):
    if price < 0:
        return False
    return True

# Attacker sets price=0, gets items free
```

**Example - Quantity validation:**
```python
# Checks minimum but not maximum
def validate_quantity(qty):
    if qty < 1:
        return False
    return True

# Attacker sets qty=999999999, causes integer overflow
```

### Root cause 3: Trust in client-side controls

**Vulnerable pattern:**
```html
<!-- Client-side only validation -->
<form onsubmit="return validatePrice()">
    <input type="hidden" name="price" value="100" readonly>
    <input type="number" name="quantity" min="1" max="10">
</form>

<script>
function validatePrice() {
    let price = document.querySelector('[name="price"]').value;
    if (price < 0) {
        alert("Invalid price");
        return false;
    }
    return true;
}
</script>
```

**Exploitation:**
```http
POST /purchase HTTP/1.1

price=-50&quantity=100
```

Client-side validation bypassed completely.

### Root cause 4: Complex systems with unclear interactions

```
Component A assumes Component B validates input
Component B assumes Component A validates input
Result: Nobody validates input
```

## Common business logic vulnerability patterns

### 1) Excessive trust in client-side data

#### Vulnerability: Hidden field manipulation

**Scenario:** E-commerce site stores price in hidden form field.

**Vulnerable code:**
```html
<form action="/purchase" method="POST">
    <input type="hidden" name="product_id" value="123">
    <input type="hidden" name="price" value="1000.00">
    <input type="number" name="quantity" value="1">
    <button>Buy Now</button>
</form>
```

```python
@app.route('/purchase', methods=['POST'])
def purchase():
    product_id = request.form['product_id']
    price = float(request.form['price'])  # Trusted from client!
    quantity = int(request.form['quantity'])
    
    total = price * quantity
    charge_customer(total)
    return "Purchase complete"
```

**Exploitation:**
```http
POST /purchase HTTP/1.1

product_id=123&price=0.01&quantity=1
```

Result: $1000 product purchased for $0.01.

**Real-world impact:**
- Financial loss (items sold below cost)
- Inventory manipulation
- Accounting discrepancies

#### Vulnerability: Cookie-based privilege escalation

**Vulnerable code:**
```python
@app.route('/admin')
def admin_panel():
    is_admin = request.cookies.get('admin')
    
    if is_admin == 'true':  # Trusted from cookie!
        return render_admin_panel()
    else:
        return "Access denied", 403
```

**Exploitation:**
```http
GET /admin HTTP/1.1
Cookie: admin=true
```

Result: Admin access without proper authentication.

### 2) Failing to handle unconventional input

#### Vulnerability: Negative quantity

**Vulnerable code:**
```python
def add_to_cart(product_id, quantity):
    product = get_product(product_id)
    
    # No validation on quantity sign
    cart_total = product.price * quantity
    session['cart_total'] += cart_total
```

**Exploitation:**
```http
POST /cart/add HTTP/1.1

product_id=123&quantity=-10
```

**What happens:**
```
Product price: $100
Quantity: -10
Cart total: $100 * -10 = -$1000
New balance: $0 + (-$1000) = -$1000
```

Customer gets paid $1000 to "buy" the product!

#### Vulnerability: Integer overflow

**Vulnerable code:**
```python
def calculate_total(quantity, price):
    # Both stored as 32-bit signed integers
    return quantity * price

# Max value: 2,147,483,647
```

**Exploitation:**
```
quantity = 2,147,483,647
price = 2
Result: 4,294,967,294 (overflow wraps to negative)
Actual value stored: -2 (or 0 depending on language)
```

Customer orders massive quantity for free.

#### Vulnerability: Special values (null, empty, zero)

**Vulnerable code:**
```python
def apply_shipping_cost(cart_total, country):
    if country == 'US':
        shipping = 10
    elif country == 'International':
        shipping = 50
    
    return cart_total + shipping

# What if country is None, '', or missing?
```

**Exploitation:**
```http
POST /checkout HTTP/1.1

cart_total=100&country=
```

If `country` is empty and not in if/elif, shipping is never added!

### 3) Inconsistent security controls

#### Vulnerability: Unauthenticated API endpoint

**Web UI flow (secure):**
```
1. Login required
2. View profile
3. Click "Change Email"
4. Submit new email with CSRF token
5. Verify old password
```

**API endpoint (insecure):**
```python
@app.route('/api/update-email', methods=['POST'])
def update_email():
    user_id = request.json.get('user_id')
    new_email = request.json.get('email')
    
    # No authentication check!
    # No password verification!
    
    update_user_email(user_id, new_email)
    return {'success': True}
```

**Exploitation:**
```http
POST /api/update-email HTTP/1.1
Content-Type: application/json

{"user_id": 123, "email": "attacker@evil.com"}
```

Result: Account takeover without authentication.

### 4) Flawed workflows and state management

#### Vulnerability: Bypassing payment verification

**Intended workflow:**
```
Step 1: Add items to cart
Step 2: Enter shipping address
Step 3: Enter payment details
Step 4: Payment processor validates card
Step 5: Complete order
```

**Vulnerable implementation:**
```python
@app.route('/checkout/step5-complete')
def complete_order():
    cart = session.get('cart')
    
    # Assumes payment was already verified in step 4
    # No check if step 4 actually happened!
    
    process_order(cart)
    return "Order complete!"
```

**Exploitation:**
```http
# Skip steps 3-4 entirely
POST /checkout/step1  # Add items
POST /checkout/step2  # Enter shipping
POST /checkout/step5-complete  # Jump to completion
```

Result: Free items, payment never processed.

#### Vulnerability: Race condition in money transfer

**Vulnerable code:**
```python
def transfer_money(from_account, to_account, amount):
    # Step 1: Check balance
    if get_balance(from_account) >= amount:
        # Step 2: Deduct from sender
        time.sleep(0.1)  # Simulate processing delay
        deduct_balance(from_account, amount)
        
        # Step 3: Add to recipient
        add_balance(to_account, amount)
```

**Exploitation (concurrent requests):**
```python
# Send 10 simultaneous requests
import threading

def exploit():
    transfer_money(attacker_account, victim_account, 1000)

threads = [threading.Thread(target=exploit) for _ in range(10)]
for t in threads:
    t.start()
```

**What happens:**
```
Balance: $1000

Request 1: Check balance ($1000 >= $1000) ✓
Request 2: Check balance ($1000 >= $1000) ✓
Request 3: Check balance ($1000 >= $1000) ✓
...
All pass the check before any deduction occurs!

Result: $1000 transferred 10 times from account with only $1000
```

### 5) Domain-specific logic flaws

#### Vulnerability: Coupon code stacking

**Intended behavior:** One discount code per order.

**Vulnerable code:**
```python
def apply_discount(cart_total, discount_codes):
    for code in discount_codes:
        discount = get_discount(code)
        cart_total = cart_total * (1 - discount)
    
    return cart_total
```

**Exploitation:**
```http
POST /checkout HTTP/1.1

cart_total=1000&discount_codes[]=SAVE10&discount_codes[]=SAVE10&discount_codes[]=SAVE10
```

**Result:**
```
Original: $1000
After 1st code: $1000 * 0.9 = $900
After 2nd code: $900 * 0.9 = $810
After 3rd code: $810 * 0.9 = $729
```

Or using array manipulation to apply same code multiple times.

#### Vulnerability: Loyalty points manipulation

**Scenario:** Earn 1 point per $1 spent, redeem 100 points for $10 credit.

**Vulnerable code:**
```python
def complete_purchase(cart_total):
    points_earned = int(cart_total)
    user.points += points_earned
    
    charge_customer(cart_total)

def redeem_points(points_to_redeem):
    credit = (points_to_redeem / 100) * 10
    user.points -= points_to_redeem
    user.account_credit += credit
```

**Exploitation:**
```
1. Purchase item for -$100 (negative price manipulation)
2. Get charged -$100 (receives money)
3. Earn -100 points (loses points)
4. Redeem -100 points:
   - Points to redeem: -100
   - Credit: (-100 / 100) * 10 = -$10
   - User points: current - (-100) = current + 100
   - User credit: current + (-$10) = current - $10

Wait, that's wrong. Let me recalculate:

Actually, if negative quantity:
1. Add -10 items at $100 each = -$1000
2. Pay -$1000 (receive $1000)
3. Earn -1000 points? 

Or simpler: Return items for refund, keep points
```

#### Vulnerability: Subscription cancellation bypass

**Business rule:** Cancel subscription = lose access immediately.

**Vulnerable code:**
```python
@app.route('/subscription/cancel')
def cancel_subscription():
    user.subscription_end_date = datetime.now()
    user.subscription_status = 'cancelled'
    
    # But access check only looks at end_date
    return "Subscription cancelled"

@app.route('/premium-content')
def premium_content():
    if user.subscription_end_date > datetime.now():
        return render_premium_content()
```

**Exploitation:**
```
1. Subscribe for 1 year (end_date = today + 365 days)
2. Immediately cancel (status = 'cancelled')
3. Access premium content (end_date still in future!)
```

Result: One day of payment, one year of access.

### 6) Parameter tampering

#### Vulnerability: User ID in request

**Vulnerable code:**
```python
@app.route('/profile/update', methods=['POST'])
def update_profile():
    user_id = request.form['user_id']  # From form field!
    name = request.form['name']
    email = request.form['email']
    
    update_user(user_id, name, email)
    return "Profile updated"
```

**Exploitation:**
```http
POST /profile/update HTTP/1.1

user_id=1&name=Admin&email=attacker@evil.com
```

Result: Update admin account instead of own account.

#### Vulnerability: Privilege escalation via role parameter

**Vulnerable code:**
```python
@app.route('/user/create', methods=['POST'])
def create_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form.get('role', 'user')  # Default to 'user'
    
    # No validation on role!
    create_new_user(username, password, role)
```

**Exploitation:**
```http
POST /user/create HTTP/1.1

username=attacker&password=pass123&role=admin
```

Result: Self-promoted to admin.

## Testing methodology for logic flaws

### Phase 1: Understand the application

**Map all functionality:**
- User registration and authentication
- Password reset
- Profile management
- Shopping cart and checkout
- Payment processing
- Loyalty/rewards programs
- Subscriptions
- Admin functions

**Identify business rules:**
- What are the intended workflows?
- What constraints exist (price, quantity, limits)?
- What assumptions are being made?
- What's the "happy path" vs edge cases?

### Phase 2: Identify trust boundaries

**Ask:**
- What data comes from the client?
- What client-side validation exists?
- Is there corresponding server-side validation?
- What happens if I bypass client-side checks?

**Common trust issues:**
- Prices in hidden fields
- User IDs in forms
- Privileges in cookies
- Quantities with client-side limits
- Discounts calculated client-side

### Phase 3: Test boundary values

**For every numeric input:**
```
- Zero (0)
- Negative (-1, -999999)
- Very large (999999999, 2147483647)
- Decimal where integer expected (1.5, 0.5)
- Non-numeric ('abc', '<script>', null)
```

**For every workflow:**
```
- Skip steps (go from step 1 to step 5)
- Repeat steps (apply discount twice)
- Go backwards (step 3 → step 1 → step 3)
- Concurrent execution (race conditions)
```

### Phase 4: Manipulate parameters systematically

**Test every parameter:**
```http
Original:
POST /purchase
product_id=123&price=100&quantity=1&discount=10&user_id=456

Tests:
- product_id=1 (access other products)
- price=0 (free items)
- price=-100 (get paid)
- quantity=0 (divide by zero?)
- quantity=-10 (negative total)
- discount=100 (100% off)
- discount=999 (infinite discount)
- user_id=1 (admin account)
```

### Phase 5: Look for state management issues

**Test scenarios:**
- Multiple browser tabs (concurrent actions)
- Back button after completing action
- Refresh/replay requests
- Session expiration mid-workflow
- Logout during transaction

## Real-world exploitation examples

### Example 1: Negative pricing vulnerability

**Target:** Online store

**Discovery:**
```http
POST /cart/add HTTP/1.1

product_id=123&quantity=5
Response: "5 items added, total: $500"
```

**Test negative quantity:**
```http
POST /cart/add HTTP/1.1

product_id=123&quantity=-5
Response: "Cart total: -$500"
```

**Exploitation workflow:**
```
1. Add expensive item with negative quantity (-10 × $1000 = -$10,000)
2. Add cheap item with positive quantity (1 × $1 = $1)
3. Cart total: -$10,000 + $1 = -$9,999
4. Checkout and "pay" negative amount
5. Receive $9,999 credit to payment method
```

### Example 2: Workflow bypass

**Target:** Premium content site

**Intended flow:**
```
/register → /subscribe → /payment → /access-content
```

**Test direct access:**
```http
GET /access-content HTTP/1.1
Cookie: session=abc123

Response: 403 Forbidden
```

**Test intermediate step:**
```http
GET /payment?plan=free HTTP/1.1

Response: "Payment processed" (no actual payment!)
```

**Then:**
```http
GET /access-content HTTP/1.1

Response: 200 OK (premium content accessible!)
```

### Example 3: Race condition in vote limiting

**Target:** Voting/polling application

**Business rule:** One vote per user

**Vulnerable code:**
```python
def submit_vote(user_id, candidate_id):
    # Check if already voted
    if has_voted(user_id):
        return "Already voted"
    
    # Record vote (delay simulates database write)
    time.sleep(0.1)
    record_vote(user_id, candidate_id)
    mark_as_voted(user_id)
```

**Exploitation:**
```python
import threading
import requests

def vote():
    requests.post('/vote', data={'candidate_id': 123})

# Send 100 simultaneous requests
threads = [threading.Thread(target=vote) for _ in range(100)]
for t in threads:
    t.start()
```

All 100 requests pass the `has_voted()` check before any complete, resulting in 100 votes from one user.

### Example 4: Coupon code manipulation

**Target:** E-commerce checkout

**Intended:** One coupon per order

**Test:**
```http
POST /cart/apply-coupon HTTP/1.1

code=SAVE20

Response: "20% discount applied"
```

**Test multiple applications:**
```http
POST /cart/apply-coupon HTTP/1.1

code=SAVE20

POST /cart/apply-coupon HTTP/1.1

code=SAVE20

POST /cart/apply-coupon HTTP/1.1

code=SAVE20
```

If each request succeeds, 20% discount applied three times:
```
$100 × 0.8 = $80
$80 × 0.8 = $64
$64 × 0.8 = $51.20
```

Or test array manipulation:
```http
POST /cart/apply-coupon HTTP/1.1

code[]=SAVE20&code[]=SAVE20&code[]=SAVE20
```

## Prevention strategies

### 1) Never trust client-side data

**Bad:**
```python
price = request.form['price']  # From hidden field
```

**Good:**
```python
product_id = request.form['product_id']
price = get_product_price(product_id)  # From database
```

### 2) Validate all inputs server-side

```python
def validate_quantity(qty):
    if not isinstance(qty, int):
        raise ValueError("Quantity must be integer")
    
    if qty < 1:
        raise ValueError("Quantity must be positive")
    
    if qty > 100:
        raise ValueError("Quantity exceeds maximum")
    
    return qty
```

### 3) Implement state validation

```python
# Track workflow state
session['checkout_stage'] = 1

@app.route('/checkout/step2')
def checkout_step2():
    if session.get('checkout_stage') != 1:
        return redirect('/checkout/step1')
    
    # Process step 2
    session['checkout_stage'] = 2
```

### 4) Use database transactions for consistency

```python
def transfer_money(from_account, to_account, amount):
    with database.transaction():
        # Lock rows to prevent race conditions
        sender = Account.objects.select_for_update().get(id=from_account)
        
        if sender.balance < amount:
            raise InsufficientFunds()
        
        sender.balance -= amount
        sender.save()
        
        recipient = Account.objects.get(id=to_account)
        recipient.balance += amount
        recipient.save()
```

### 5) Implement idempotency for critical operations

```python
@app.route('/transfer', methods=['POST'])
def transfer():
    # Require unique transaction ID
    transaction_id = request.form['transaction_id']
    
    # Check if already processed
    if Transaction.objects.filter(id=transaction_id).exists():
        return "Transaction already processed"
    
    # Process transfer
    process_transfer(transaction_id, ...)
```

### 6) Enforce business rules at all layers

```python
# Database constraint
class Product(db.Model):
    price = db.Column(db.Decimal, CheckConstraint('price >= 0'))

# Application logic
def add_to_cart(product_id, quantity):
    if quantity < 1 or quantity > 100:
        raise ValueError("Invalid quantity")
    
    product = get_product(product_id)
    if product.price < 0:
        raise ValueError("Invalid product price")
```

### 7) Document assumptions and validate them

```python
def apply_discount(price, discount_percent):
    """
    Apply percentage discount to price.
    
    Assumptions:
    - price >= 0
    - 0 <= discount_percent <= 100
    - Result should never be negative
    
    Args:
        price: Original price in dollars (must be non-negative)
        discount_percent: Discount percentage (0-100)
    
    Returns:
        Discounted price (never negative)
    """
    # Validate assumptions
    assert price >= 0, "Price must be non-negative"
    assert 0 <= discount_percent <= 100, "Discount must be 0-100%"
    
    discounted = price * (1 - discount_percent / 100)
    
    # Ensure result matches assumptions
    assert discounted >= 0, "Discounted price became negative"
    
    return discounted
```
