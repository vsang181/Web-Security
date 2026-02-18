# How to secure authentication mechanisms

Authentication is the first line of defense for most applications, yet it's one of the most commonly exploited attack surfaces. Even small logic flaws, timing differences, or weak password policies can completely undermine security. This section covers proven practices to build robust authentication that resists brute-force attacks, credential stuffing, logic bypasses, and enumeration.

Securing authentication requires defense-in-depth: strong policies, secure implementation, proper multi-factor authentication, and protecting supplementary features like password reset.

## Core security principles (what matters most)

### 1) Protect credentials in transit and at rest

**Always use HTTPS for authentication:**
- Enforce HTTPS for ALL pages (not just login)
- Redirect HTTP → HTTPS automatically
- Use HSTS headers to prevent downgrade attacks
- Use strong TLS configuration (TLS 1.2+, disable weak ciphers)

**Example HSTS header:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Redirect HTTP to HTTPS (Nginx):**
```nginx
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

**Hash passwords properly:**
```python
# Good: bcrypt with salt
import bcrypt

password = b"user_password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt(rounds=12))

# Verify
if bcrypt.checkpw(password, hashed):
    print("Login successful")
```

Never:
- Store passwords in plaintext
- Use weak hashing (MD5, SHA1 without salt)
- Use weak salts or no salt
- Store passwords reversibly (encryption is not hashing)

**Use strong, modern algorithms:**
- **bcrypt** (industry standard, recommended)
- **Argon2** (modern, memory-hard, best for new systems)
- **PBKDF2** (acceptable fallback)
- **scrypt** (memory-hard alternative)

Avoid: MD5, SHA1, SHA256 (without salt/iterations), plain text

### 2) Prevent username enumeration

**Problem:** Different responses reveal whether username exists.

Vulnerable login endpoint:
```text
Username: admin, Password: wrong  → "Incorrect password"
Username: nonexistent, Password: wrong  → "User not found"
```

Attacker learns "admin" exists, focuses brute-force there.

**Solution: Identical generic errors**

Secure implementation:
```python
def login(username, password):
    user = db.get_user(username)
    
    # ALWAYS hash password even if user doesn't exist (timing consistency)
    if user:
        password_hash = user.password_hash
    else:
        # Use dummy hash to keep timing consistent
        password_hash = "$2b$12$dummy_hash_to_prevent_timing_attack"
    
    # Always check password
    if bcrypt.checkpw(password.encode(), password_hash.encode()):
        if user and user.is_active:
            return create_session(user)
    
    # SAME error message for all failures
    return "Invalid username or password", 401
```

**Key principles:**
- **Same error message** for wrong username, wrong password, locked account
- **Same HTTP status code** (401) for all auth failures
- **Same response time** (hash password even if user doesn't exist)
- Don't reveal existence via password reset ("If account exists, email sent")
- Don't expose usernames in public profiles, URLs, error messages

**Timing attack protection:**
```python
import secrets
import time

def constant_time_compare(a, b):
    # Use built-in constant-time comparison
    return secrets.compare_digest(a, b)

def login_with_timing_protection(username, password):
    start_time = time.time()
    
    # Your login logic here
    result = authenticate(username, password)
    
    # Add small random delay to prevent timing analysis
    time.sleep(secrets.randbelow(50) / 1000)  # 0-50ms jitter
    
    return result
```

### 3) Implement robust brute-force protection

**Multi-layered rate limiting:**

#### Account-level lockout (progressive delays):
```python
# Track failed attempts per account
failed_attempts = {}

def login(username, password):
    attempts = failed_attempts.get(username, 0)
    
    # Progressive delay based on attempts
    if attempts > 0:
        delay = min(2 ** attempts, 30)  # Exponential backoff, max 30 sec
        time.sleep(delay)
    
    if authenticate(username, password):
        failed_attempts[username] = 0
        return success()
    else:
        failed_attempts[username] = attempts + 1
        
        # Lock account after threshold
        if failed_attempts[username] >= 5:
            lock_account(username, duration=300)  # 5 min lockout
        
        return error("Invalid credentials")
```

#### IP-based rate limiting:
```python
from datetime import datetime, timedelta

ip_attempts = {}  # {ip: [(timestamp, username), ...]}

def check_ip_rate_limit(ip, username):
    now = datetime.now()
    cutoff = now - timedelta(minutes=15)
    
    # Clean old attempts
    if ip in ip_attempts:
        ip_attempts[ip] = [(t, u) for t, u in ip_attempts[ip] if t > cutoff]
    else:
        ip_attempts[ip] = []
    
    # Check rate
    recent_attempts = len(ip_attempts[ip])
    
    if recent_attempts >= 20:  # Max 20 attempts per 15 min
        return False, "Too many login attempts. Try again later."
    
    ip_attempts[ip].append((now, username))
    return True, None
```

#### CAPTCHA after threshold:
```python
def login(username, password, captcha_response=None):
    attempts = get_failed_attempts(username)
    
    # Require CAPTCHA after 3 failed attempts
    if attempts >= 3:
        if not captcha_response:
            return error("CAPTCHA required", captcha_needed=True)
        
        if not verify_captcha(captcha_response):
            return error("Invalid CAPTCHA")
    
    # Proceed with authentication
    return authenticate(username, password)
```

**Defense in depth strategies:**
- Account lockout (temporary, avoid permanent to prevent DoS)
- IP rate limiting (careful with proxies/NAT)
- CAPTCHA (after N failures)
- Device fingerprinting (flag unusual devices)
- Email alerts on failed attempts
- Multi-factor authentication (required after suspicious activity)

**Distributed brute-force protection:**
```python
# Track attempts across multiple IPs targeting same account
def check_distributed_attack(username):
    recent_ips = get_recent_ips_for_user(username, minutes=10)
    
    if len(recent_ips) > 5:  # Same user from 5+ different IPs
        lock_account(username, duration=600)
        alert_security_team(f"Distributed attack detected on {username}")
        return False
    
    return True
```

### 4) Enforce strong password policies (usable security)

**Bad password policies (frustrating but weak):**
- "Must be 8-16 characters" (why limit max?)
- "Must contain uppercase, lowercase, number, symbol" (leads to predictable patterns like `Password1!`)
- "Must change every 30 days" (leads to `Password1`, `Password2`, etc.)

**Better approach: Password strength meter**

```javascript
// Frontend: Real-time password strength feedback (using zxcvbn library)
const passwordInput = document.getElementById('password');
const strengthMeter = document.getElementById('strength');

passwordInput.addEventListener('input', function() {
    const result = zxcvbn(this.value);
    
    const strengthText = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'][result.score];
    strengthMeter.textContent = strengthText;
    strengthMeter.className = 'strength-' + result.score;
    
    // Show specific feedback
    if (result.feedback.warning) {
        document.getElementById('feedback').textContent = result.feedback.warning;
    }
    
    // Only allow strong passwords (score 3 or 4)
    document.getElementById('submit').disabled = result.score < 3;
});
```

Backend validation:
```python
from zxcvbn import zxcvbn

def validate_password(password):
    result = zxcvbn(password)
    
    if result['score'] < 3:  # Require at least "Strong"
        suggestions = result['feedback']['suggestions']
        return False, f"Password too weak. {', '.join(suggestions)}"
    
    return True, None
```

**Effective password requirements:**
- Minimum length: 12+ characters (longer is better)
- No maximum length (within reason, e.g., 128 chars)
- Check against breach databases (Have I Been Pwned API)
- Block common passwords ("password", "123456", "qwerty")
- Don't force frequent changes (causes weak, predictable patterns)
- Allow password managers (don't block paste)

**Check against breached passwords:**
```python
import hashlib
import requests

def check_pwned_password(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    # Query Have I Been Pwned API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    
    # Check if full hash appears in results
    for line in response.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return False, f"Password appears in {count} data breaches"
    
    return True, None
```

### 5) Verify logic thoroughly (avoid logic flaws)

**Common authentication logic flaws:**

#### Flaw 1: Incomplete validation
```python
# VULNERABLE: Only checks if user exists
def reset_password(username, new_password):
    user = db.get_user(username)
    if user:  # Missing token verification!
        user.password = hash_password(new_password)
        db.save(user)
        return "Password reset successful"
```

#### Flaw 2: Sequential checks (exploitable)
```python
# VULNERABLE: Can bypass MFA by manipulation
def login(username, password):
    user = authenticate(username, password)
    if not user:
        return error("Invalid credentials")
    
    session['user_id'] = user.id  # Session created BEFORE MFA!
    
    if user.mfa_enabled:
        redirect('/mfa-verify')  # Attacker can skip this
    else:
        redirect('/dashboard')
```

**Secure implementation:**
```python
def login(username, password):
    user = authenticate(username, password)
    if not user:
        return error("Invalid credentials")
    
    # Create temporary session (NOT logged in yet)
    session['pending_user_id'] = user.id
    session['auth_stage'] = 'password_verified'
    
    if user.mfa_enabled:
        redirect('/mfa-verify')
    else:
        # Only now create real session
        finalize_login(user)
        redirect('/dashboard')

def mfa_verify(code):
    # Check we're in correct stage
    if session.get('auth_stage') != 'password_verified':
        return error("Invalid request")
    
    user_id = session.get('pending_user_id')
    user = db.get_user(user_id)
    
    if verify_mfa(user, code):
        finalize_login(user)
        redirect('/dashboard')
    else:
        return error("Invalid MFA code")

def finalize_login(user):
    # Clear temporary session
    session.pop('pending_user_id', None)
    session.pop('auth_stage', None)
    
    # Create real authenticated session
    session['user_id'] = user.id
    session['logged_in'] = True
    session['login_time'] = time.time()
```

**Testing checklist for logic flaws:**
- [ ] Can I skip steps by manipulating URLs or session?
- [ ] Does every verification actually check something meaningful?
- [ ] Are checks enforced on the backend (not just frontend)?
- [ ] Can I reuse tokens/codes after they should expire?
- [ ] Does the state machine prevent skipping required steps?

### 6) Secure supplementary functionality

**Password reset is an authentication bypass vector:**

Vulnerable reset flow:
```python
# VULNERABLE: Predictable token
def request_reset(email):
    user = db.get_user(email)
    if user:
        token = hashlib.md5(user.email.encode()).hexdigest()  # Predictable!
        send_email(user.email, f"/reset?token={token}")

def reset_password(token, new_password):
    user = db.get_user_by_token(token)  # Token never expires!
    if user:
        user.password = hash_password(new_password)
```

**Secure reset implementation:**
```python
import secrets
from datetime import datetime, timedelta

def request_reset(email):
    user = db.get_user(email)
    
    # Always return same message (prevent enumeration)
    message = "If account exists, password reset email sent"
    
    if user:
        # Generate cryptographically secure token
        token = secrets.token_urlsafe(32)
        
        # Store with expiration
        db.store_reset_token(
            user_id=user.id,
            token=hash_token(token),  # Store hashed
            expires=datetime.now() + timedelta(hours=1)
        )
        
        # Invalidate old tokens
        db.invalidate_old_tokens(user.id)
        
        # Send email
        send_email(user.email, f"/reset?token={token}")
        
        # Log for security monitoring
        log_security_event('password_reset_requested', user.id)
    
    return message

def reset_password(token, new_password):
    # Hash token for lookup
    token_hash = hash_token(token)
    
    # Verify token exists, hasn't expired, hasn't been used
    reset_record = db.get_reset_token(token_hash)
    
    if not reset_record:
        return error("Invalid or expired reset link")
    
    if reset_record.expires < datetime.now():
        return error("Reset link has expired")
    
    if reset_record.used:
        return error("Reset link already used")
    
    # Validate new password
    valid, msg = validate_password(new_password)
    if not valid:
        return error(msg)
    
    # Reset password
    user = db.get_user(reset_record.user_id)
    user.password = hash_password(new_password)
    
    # Mark token as used
    reset_record.used = True
    db.save(reset_record)
    
    # Invalidate all sessions
    invalidate_all_sessions(user.id)
    
    # Log security event
    log_security_event('password_reset_completed', user.id)
    
    # Notify user
    send_email(user.email, "Your password was reset")
    
    return success("Password reset successful")
```

**Account registration security:**
```python
def register(username, email, password):
    # Check if user/email already exists (but don't reveal which)
    if db.user_exists(username) or db.email_exists(email):
        return error("Registration failed")  # Generic
    
    # Validate password
    valid, msg = validate_password(password)
    if not valid:
        return error(msg)
    
    # Require email verification
    verification_token = secrets.token_urlsafe(32)
    
    user = create_user(
        username=username,
        email=email,
        password=hash_password(password),
        verified=False,
        verification_token=hash_token(verification_token),
        verification_expires=datetime.now() + timedelta(hours=24)
    )
    
    send_verification_email(email, verification_token)
    
    return success("Check email to verify account")
```

### 7) Implement proper multi-factor authentication (MFA)

**What counts as "factors":**
- **Something you know:** Password, PIN, security questions
- **Something you have:** Phone, hardware token, authenticator app
- **Something you are:** Biometrics (fingerprint, face, voice)

**Not true MFA:**
- Email verification (same factor as password - "something you know")
- Security questions (weak "something you know")
- SMS to phone number used in registration (vulnerable to SIM swap)

**Better MFA implementations:**

#### TOTP (Time-based One-Time Password) - Recommended:
```python
import pyotp
import qrcode

def enable_mfa(user):
    # Generate secret
    secret = pyotp.random_base32()
    
    # Store encrypted secret
    user.mfa_secret = encrypt(secret)
    db.save(user)
    
    # Generate QR code for authenticator app
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email,
        issuer_name="YourApp"
    )
    
    qr = qrcode.make(totp_uri)
    return qr, secret

def verify_mfa(user, code):
    if not user.mfa_enabled:
        return False
    
    secret = decrypt(user.mfa_secret)
    totp = pyotp.TOTP(secret)
    
    # Verify code (allows 1 interval tolerance for clock drift)
    if totp.verify(code, valid_window=1):
        # Check if code was recently used (prevent replay)
        if is_code_recently_used(user.id, code):
            return False
        
        mark_code_used(user.id, code)
        return True
    
    return False
```

#### Hardware tokens (FIDO2/WebAuthn) - Most Secure:
```python
from webauthn import generate_registration_options, verify_registration_response

def register_security_key(user):
    options = generate_registration_options(
        rp_id="yourdomain.com",
        rp_name="Your App",
        user_id=user.id,
        user_name=user.email,
        user_display_name=user.username
    )
    
    # Store challenge
    session['webauthn_challenge'] = options.challenge
    
    return options

def verify_security_key_registration(user, credential):
    challenge = session.get('webauthn_challenge')
    
    verified = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_origin="https://yourdomain.com",
        expected_rp_id="yourdomain.com"
    )
    
    if verified:
        # Store credential
        store_webauthn_credential(user.id, verified.credential_id, verified.public_key)
        return True
    
    return False
```

**MFA backup codes:**
```python
def generate_backup_codes(user):
    codes = [secrets.token_hex(4) for _ in range(10)]
    
    # Store hashed codes
    user.backup_codes = [hash_code(code) for code in codes]
    db.save(user)
    
    return codes  # Display once to user

def verify_backup_code(user, code):
    code_hash = hash_code(code)
    
    if code_hash in user.backup_codes:
        # Remove used code
        user.backup_codes.remove(code_hash)
        db.save(user)
        return True
    
    return False
```

## Security monitoring and alerting

**Log authentication events:**
```python
def log_auth_event(event_type, user_id=None, ip=None, details=None):
    log_entry = {
        'timestamp': datetime.now(),
        'event': event_type,
        'user_id': user_id,
        'ip': ip,
        'user_agent': request.headers.get('User-Agent'),
        'details': details
    }
    
    security_log.write(log_entry)
    
    # Alert on suspicious activity
    if event_type in ['account_lockout', 'password_reset', 'mfa_disabled']:
        send_user_alert(user_id, event_type)
    
    # Alert security team on attacks
    if event_type in ['distributed_attack', 'credential_stuffing_detected']:
        alert_security_team(log_entry)
```

**Events to log:**
- Login success/failure
- Account lockouts
- Password changes/resets
- MFA enrollment/use/bypass attempts
- Session creation/destruction
- Privilege changes
- Suspicious patterns (impossible travel, credential stuffing)
