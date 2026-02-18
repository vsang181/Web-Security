# WebSockets

WebSockets are a bi-directional, full-duplex communications protocol initiated over HTTP that fundamentally change the client-server communication model from the traditional request-response cycle to a persistent, open channel where either party can send messages at any time without waiting for the other to initiate an exchange. Unlike standard HTTP where every interaction requires the client to initiate a request and wait for a server response, a WebSocket connection remains continuously open after the initial handshake, enabling the server to push data to the client the moment it becomes available — a capability that is essential for real-time applications like live financial data feeds, collaborative document editing, multiplayer games, live chat systems, and real-time dashboards where even small latency from polling would degrade the user experience significantly. Understanding how WebSocket connections are established, how messages flow through them, and how they differ fundamentally from HTTP in their security model is essential for any web security assessment, because the persistent, bidirectional nature of WebSockets introduces a distinct set of vulnerabilities — particularly cross-site WebSocket hijacking and message injection — that do not map cleanly onto the HTTP-centric security controls most developers are familiar with.

## HTTP vs. WebSockets — The Core Difference

### Traditional HTTP communication model

**How HTTP works — request/response cycle:**

```
Traditional HTTP interaction:
Client (Browser)                    Server
      │                                │
      │── GET /page HTTP/1.1 ─────────►│
      │                                │── Process request
      │◄─ HTTP/1.1 200 OK ────────────│
      │   [HTML response]              │
      │                                │
      │   (Transaction complete)       │
      │                                │
      │── GET /data HTTP/1.1 ─────────►│  ← New request required
      │                                │── Process new request
      │◄─ HTTP/1.1 200 OK ────────────│
      │   [JSON response]              │
      │                                │

Key characteristics:
✓ Stateless: each request is independent
✓ Client-initiated ONLY: server cannot push without a request
✓ Transactional: one request → one response → connection optionally reused
✓ Short-lived in nature (even with keep-alive)

Problem for real-time data:
Server has new data to show user...
Server CANNOT send it until client asks!

Workaround attempts:
→ Polling: client asks every N seconds ("Do you have new data?")
  → Wasteful: mostly empty responses, still delayed
→ Long polling: client asks, server holds response until data available
  → Better, but complex, still half-duplex, high server resource use
→ Server-Sent Events: server push, but client-to-server still HTTP
  → Unidirectional from server to client only
```

**WebSocket communication model:**

```
WebSocket interaction:
Client (Browser)                    Server
      │                                │
      │── HTTP Upgrade Request ────────►│  ← Initial HTTP handshake
      │◄─ 101 Switching Protocols ─────│  ← Server accepts upgrade
      │                                │
      │════════ WebSocket tunnel ════════│  ← Persistent open connection
      │                                │
      │── "user typed a message" ──────►│  ← Client sends anytime
      │                                │
      │◄── "new message from Alice" ───│  ← Server pushes anytime
      │                                │
      │◄── "stock price: £142.50" ─────│  ← Server pushes again
      │                                │
      │── "heartbeat ping" ────────────►│
      │◄── "heartbeat pong" ───────────│
      │                                │
      │   (Connection stays open...)   │

Key characteristics:
✓ Persistent: single connection stays open for the session duration
✓ Bidirectional: EITHER party sends whenever it has data
✓ Full-duplex: both sides can send simultaneously
✓ Low overhead: no HTTP headers on every message after handshake
✓ Low latency: server pushes data immediately, no polling delay
✓ Not transactional: messages are independent, no request-response pairing
```

**Comparison at a glance:**

```
Property               | HTTP                    | WebSocket
-----------------------|-------------------------|---------------------------
Connection lifecycle   | Short-lived per request | Persistent (long-lived)
Who initiates data     | Client only             | Either client or server
Communication model    | Request → Response      | Bi-directional messages
Message pairing        | Paired (req+resp)       | Independent (no pairing)
Protocol overhead      | Full HTTP headers       | Minimal frame headers
Latency for server push| High (requires poll)    | Near-zero (immediate push)
Connection setup       | Per request (or pool)   | Once per session
State across messages  | Stateless (or cookies)  | Stateful (open connection)
Suitable for           | CRUD APIs, web pages    | Real-time, streaming, chat
```

### When WebSockets are the right choice

**Real-world use cases where WebSockets excel:**

```
Financial data streaming:
→ Stock tickers, live prices, order book updates
→ Server pushes price changes the instant they occur
→ HTTP polling at 1-second intervals = 1-second delay minimum
→ WebSocket = millisecond delivery of price events

Live chat applications:
→ Messages must appear for all users in real time
→ Server receives message from Alice → immediately pushes to Bob
→ HTTP would require Bob to poll constantly

Collaborative tools (Google Docs, Figma, etc.):
→ Cursor positions, edits, presence indicators
→ Every keystroke must propagate to all connected users instantly
→ Only WebSockets provide the low-latency bidirectionality needed

Multiplayer games:
→ Player positions, game state, events
→ Sub-100ms latency essential
→ Bidirectional: client sends moves, server sends game state

Live monitoring dashboards:
→ System metrics, IoT sensor data, log streams
→ Server streams data continuously as it arrives
→ Client displays without any polling overhead

Push notifications (web):
→ Server notifies browser of events while user is on the page
→ "You have a new message", "Your order shipped"
→ Delivered instantly without client polling
```

## Establishing a WebSocket Connection

### The WebSocket handshake

**Initiating WebSocket from JavaScript:**

```javascript
// WebSocket constructor — initiates the handshake
var ws = new WebSocket("wss://normal-website.com/chat");
// wss:// = WebSocket Secure (over TLS) — always prefer this
// ws://  = WebSocket unencrypted — avoid on production

// With subprotocol specification:
var ws = new WebSocket("wss://normal-website.com/chat", "chat-v2");
// Subprotocol: application-level protocol negotiation
// Server must support the specified subprotocol

// Connection event handlers:
ws.onopen = function(event) {
    console.log("WebSocket connection established");
    ws.send("Hello, server!");
};

ws.onmessage = function(event) {
    console.log("Message from server:", event.data);
};

ws.onclose = function(event) {
    console.log("Connection closed:", event.code, event.reason);
    // Codes: 1000=normal, 1001=going away, 1006=abnormal, etc.
};

ws.onerror = function(event) {
    console.error("WebSocket error:", event);
};
```

**The HTTP upgrade handshake in detail:**

```http
Step 1: Client sends HTTP Upgrade request
(This is a standard HTTP/1.1 request with special headers)

GET /chat HTTP/1.1
Host: normal-website.com
Upgrade: websocket                              ← Request protocol upgrade
Connection: keep-alive, Upgrade                 ← Keep connection, then upgrade
Sec-WebSocket-Version: 13                       ← RFC 6455 version
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==    ← Random base64 nonce
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2  ← Auth cookies!
Origin: https://normal-website.com              ← SOP-related origin check
Sec-WebSocket-Protocol: chat                    ← Optional: requested subprotocol
Sec-WebSocket-Extensions: permessage-deflate    ← Optional: compression

Step 2: Server responds with 101 Switching Protocols
(This is the last HTTP response — after this, HTTP ends!)

HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=  ← Derived from client key
Sec-WebSocket-Protocol: chat                          ← Confirmed subprotocol
Sec-WebSocket-Extensions: permessage-deflate          ← Confirmed extensions

Step 3: Protocol switches from HTTP to WebSocket
→ The TCP connection that carried the HTTP handshake now carries WebSocket frames
→ No more HTTP — raw WebSocket framing from this point
→ Browser and server exchange binary WebSocket frames directly
→ Either side can send a frame at any time
```

**Understanding the handshake headers:**

```
Sec-WebSocket-Key:
→ Client generates a random 16-byte value
→ Base64-encoded: wDqumtseNBJdhkihL6PW7w==
→ Purpose: NOT for security/authentication
→ Purpose: To prevent caching proxies from accidentally establishing WebSocket
  (A random key ensures each handshake is unique)
→ The nonce proves this is a deliberate WebSocket upgrade, not a cached HTTP response

Sec-WebSocket-Accept (server's response):
→ Derived from: Base64(SHA1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
→ The GUID "258EAFA5..." is a constant defined in RFC 6455
→ Purpose: Proves server genuinely understands WebSocket protocol
  (Caching proxy would not know to compute this)
→ Provides protection against misconfigured servers accidentally accepting upgrade

Sec-WebSocket-Version: 13
→ Refers to RFC 6455 — the standardised WebSocket specification
→ Versions 1-12 were drafts; version 13 is the stable standard
→ Almost universally used; other versions are legacy/non-standard

Connection: keep-alive, Upgrade
→ "Upgrade" value tells intermediaries this is a protocol upgrade request
→ "keep-alive" ensures connection is maintained during upgrade

Upgrade: websocket
→ Specifies WHICH protocol to upgrade to (websocket, not HTTP/2, etc.)
→ Server MUST return Upgrade: websocket in response to confirm

101 Switching Protocols:
→ The one-time HTTP response that completes the handshake
→ After this response is sent/received, the connection is no longer HTTP
→ The socket is now a raw WebSocket pipe
```

**Handshake key derivation — verifying server compliance:**

```
Security mechanism for Sec-WebSocket-Accept:

Client sends:     Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==

Server computes:
1. Concatenate:   "wDqumtseNBJdhkihL6PW7w==" + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
2. SHA-1 hash:    SHA1("wDqumtseNBJdhkihL6PW7w==258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
3. Base64 encode: → "0FFP+2nmNIf/h+4BP36k9uzrYGk="

Server sends:     Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=

Client verifies:  Computes expected value, compares — match = valid server

Purpose:
Ensures the server ACTIVELY processed the WebSocket upgrade request
A cached HTTP response or misconfigured proxy would not produce the correct value
This is a protocol integrity check, NOT a security/authentication mechanism
Authentication still relies on session cookies/tokens sent during handshake
```

**wss:// vs. ws:// — why TLS matters:**

```
ws://  = WebSocket over plain TCP (unencrypted)
         Equivalent to http:// for regular web requests
         All messages visible to network observers
         Susceptible to:
         → Eavesdropping (message content visible)
         → Man-in-the-middle injection (attacker modifies messages)
         → Protocol downgrade attacks

wss:// = WebSocket over TLS (encrypted)
         Equivalent to https:// for regular web requests
         TLS handshake occurs BEFORE the WebSocket handshake
         Messages encrypted in transit
         Certificate validation provides server authentication

Always use wss:// in production:
→ Protects message confidentiality
→ Prevents injection by network intermediaries
→ Required when page is served over HTTPS
   (Mixed content: HTTPS page cannot open ws:// connection)
→ Modern browsers block ws:// from HTTPS origins

Connection establishment sequence for wss://:
1. TCP connection to server port (typically 443)
2. TLS handshake (certificate validation, key exchange)
3. WebSocket HTTP upgrade request (inside TLS tunnel)
4. Server responds 101 Switching Protocols
5. WebSocket frames exchanged inside TLS tunnel
```

## WebSocket Messages

### Message format and content

**Sending and receiving messages:**

```javascript
// Sending a simple text message:
ws.send("Peter Wiener");

// Sending structured data as JSON (most common in modern apps):
ws.send(JSON.stringify({
    type: "chat",
    user: "Alice",
    content: "Hello, world!",
    timestamp: Date.now()
}));

// Sending binary data (ArrayBuffer or Blob):
const buffer = new ArrayBuffer(4);
const view = new DataView(buffer);
view.setInt32(0, 12345);
ws.send(buffer);   // Binary message

// Setting binary message type:
ws.binaryType = 'arraybuffer';  // Receive as ArrayBuffer (default)
ws.binaryType = 'blob';         // Receive as Blob
```

**Receiving messages:**

```javascript
ws.onmessage = function(event) {
    // event.data can be:
    // - String (for text frames)
    // - ArrayBuffer (for binary frames, when binaryType='arraybuffer')
    // - Blob (for binary frames, when binaryType='blob')

    if (typeof event.data === 'string') {
        // Text message — common for JSON
        try {
            const parsed = JSON.parse(event.data);
            handleMessage(parsed);
        } catch {
            handleRawText(event.data);
        }
    } else if (event.data instanceof ArrayBuffer) {
        // Binary message
        const view = new DataView(event.data);
        handleBinaryData(view);
    }
};
```

**Real-world message formats:**

```javascript
// Chat application message (JSON):
{
    "user": "Hal Pline",
    "content": "I wanted to be a Playstation growing up...",
    "timestamp": "2026-02-18T22:00:00Z",
    "room": "general",
    "type": "message"
}

// Financial data feed message (JSON):
{
    "type": "price_update",
    "symbol": "AAPL",
    "price": 142.50,
    "change": +0.35,
    "volume": 12847693,
    "timestamp": 1708300800000
}

// Real-time notification:
{
    "type": "notification",
    "title": "New message",
    "body": "You have 3 unread messages",
    "priority": "high"
}

// Presence/status update:
{
    "type": "presence",
    "userId": "user_abc123",
    "status": "online",
    "lastSeen": null
}

// Error from server:
{
    "type": "error",
    "code": 4001,
    "message": "Invalid authentication token"
}

// Heartbeat/ping-pong (keepalive):
{ "type": "ping" }  // Client sends
{ "type": "pong" }  // Server replies
// (WebSocket protocol also has built-in ping/pong frames)
```

### WebSocket connection states

```javascript
// WebSocket readyState values:
ws.readyState === WebSocket.CONNECTING   // 0: Handshake in progress
ws.readyState === WebSocket.OPEN         // 1: Connection established, messages flowing
ws.readyState === WebSocket.CLOSING      // 2: Close handshake in progress
ws.readyState === WebSocket.CLOSED       // 3: Connection closed

// Safe message sending pattern:
function sendMessage(ws, data) {
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(data));
        return true;
    } else {
        console.warn('WebSocket not open, message queued');
        messageQueue.push(data);
        return false;
    }
}

// Graceful close:
ws.close(1000, "User logged out");
// Code 1000 = normal closure
// Triggers close handshake: client sends Close frame, server acknowledges
```

## Security Implications of WebSocket Design

### Why WebSockets require different security thinking

**Authentication at handshake — not per message:**

```
HTTP security model:
Each HTTP request independently carries authentication:
Authorization: Bearer TOKEN
Cookie: session=VALUE
→ Server validates on EVERY request
→ Token revocation immediately effective

WebSocket security model:
Authentication happens ONCE at handshake:
GET /chat HTTP/1.1
Cookie: session=VALUE   ← Only sent here, during HTTP upgrade

After handshake:
→ NO authentication headers on subsequent WebSocket messages
→ Session validity checked once at connection time
→ Token revocation may not affect existing open connections
→ Connection stays authenticated for its entire duration

Security implications:
→ Compromised session token = entire WebSocket session compromised
→ Server must validate session before upgrading to WebSocket
→ Consider periodic re-validation for long-lived connections
→ Implement application-level token refresh inside WebSocket messages
   if re-authentication during session is required
```

**Origin validation — critical security check:**

```
HTTP: Same-Origin Policy restricts cross-origin JavaScript reads
WebSockets: SOP does NOT prevent cross-origin WebSocket connections!

A page at https://attacker.com CAN:
new WebSocket('wss://victim.com/chat');
→ Browser sends the connection request
→ Browser INCLUDES victim.com session cookies in the handshake!
→ If server doesn't validate Origin: attacker steals authenticated connection!

This is Cross-Site WebSocket Hijacking (CSWSH):
1. Victim logged into victim.com (has session cookie)
2. Victim visits attacker.com
3. attacker.com's JavaScript opens: new WebSocket('wss://victim.com/ws')
4. Browser sends handshake with Origin: https://attacker.com
5. Handshake includes Cookie: session=VICTIM_SESSION
6. If server doesn't check Origin: connection established!
7. Attacker's JavaScript reads all messages from victim's session!

Defence: Always validate Origin header in WebSocket handshake server-side:
const allowedOrigins = ['https://app.example.com', 'https://www.example.com'];
if (!allowedOrigins.includes(req.headers.origin)) {
    ws.terminate();  // Reject connection!
}
```

**Message injection and validation:**

```
Unlike HTTP where each request is independently validated:
WebSocket messages arrive as raw data stream
Each message must be independently validated!

Common mistakes:
→ Trusting message content without validation (SQL injection via WebSocket)
→ Treating messages as authenticated just because connection was authenticated
→ Not sanitising message content before rendering in DOM (WebSocket XSS)
→ Not enforcing authorisation on individual message actions

Example vulnerable WebSocket handler (server-side):
ws.on('message', function(data) {
    const msg = JSON.parse(data);
    // DANGEROUS: Trusting msg.userId from client!
    db.query('SELECT * FROM messages WHERE userId = ' + msg.userId);
    // Client controls msg.userId → SQL injection!
});

Secure handler:
ws.on('message', function(data) {
    const msg = JSON.parse(data);
    // userId comes from authenticated session, NOT from message!
    const userId = session.userId;
    db.query('SELECT * FROM messages WHERE userId = ?', [userId]);
});
```

## WebSocket Handshake Security Headers Summary

**All handshake headers and their security relevance:**

```
Request header          | Security relevance
------------------------|------------------------------------------
Origin                  | SERVER must validate — prevents CSWSH
Sec-WebSocket-Key       | Prevents caching/proxy mistakes
Cookie                  | Carries authentication — HTTPS only!
Upgrade                 | Identifies protocol upgrade intent
Connection              | Must include 'Upgrade'

Response header         | Security relevance
------------------------|------------------------------------------
Sec-WebSocket-Accept    | Validates server understood WebSocket
101 Switching Protocols | Confirms successful upgrade

Post-handshake (inside WebSocket tunnel):
→ No further HTTP headers
→ All subsequent security must be at application level
→ Validate every message independently
→ Never trust message content as authoritative identity
→ Use session data from handshake for identity, not message payload
```
