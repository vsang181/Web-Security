# How to secure your authentication mechanisms

Authentication is security-critical and easy to get subtly wrong, so aim for **defense-in-depth**: multiple controls that fail safely if one layer is bypassed.

## Take care with user credentials

### Enforce HTTPS everywhere
- Serve the login page and all authenticated pages over TLS only.
- Redirect HTTP → HTTPS and enable HSTS so browsers stop attempting plaintext requests after the first secure visit.
- If you terminate TLS at a reverse proxy/load balancer, ensure internal hops are also protected (mTLS or private network controls) and that apps don’t trust spoofable forwarding headers.

Nginx: force HTTPS + HSTS
```nginx
server {
  listen 80;
  server_name example.com;
  return 301 https://$host$request_uri;
}

server {
  listen 443 ssl http2;
  server_name example.com;

  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

  # ... TLS config ...
}
```

### Avoid accidental credential disclosure
Audit for leakage paths that make brute force and enumeration easier:
- Public profiles that reveal usernames/emails.
- Email addresses in error pages, API responses, HTML comments, or client-side bundles.
- Logs containing credentials (request bodies, headers like `Authorization`, query strings).
- Third-party analytics capturing form fields.

Logging redaction examples (conceptual)
```text
Redact fields: password, new_password, current_password, otp, mfa_code, Authorization
Do not log: reset tokens, session IDs, remember-me tokens
```

## Don’t rely on users for security

Users will optimize for convenience. Build “secure by default” behaviors into the system.

### Password policy: prefer length + screening over complexity rules
Good modern controls:
- Enforce a minimum length (long passphrases beat “P@ssw0rd1!” patterns).
- Allow long passwords (do not silently truncate).
- Allow all characters (including whitespace and Unicode).
- Block common and breached passwords (credential reuse is the norm).
- Provide a strength meter so users can iterate quickly.

Client-side strength meter (example using zxcvbn-style scoring)
```html
<input id="password" type="password" autocomplete="new-password" />
<progress id="score" max="4" value="0"></progress>
<script>
  // pseudo: score = zxcvbn(password).score
  // set progress value to score
</script>
```

Server-side rules (example)
```text
Minimum length: 12 (or higher for high-risk apps)
Maximum length: >= 64
Reject: common passwords, breached passwords, organization-specific terms (company name, product name)
```

### Store and compare passwords safely
- Use a modern password hashing scheme (with per-password salts).
- Compare secrets using constant-time comparisons (or framework primitives).
- Cap maximum password input length to reduce DoS risk from extremely long inputs.

## Prevent username enumeration

Make “user exists” and “user doesn’t exist” indistinguishable at scale.

### Normalize responses across failure cases
- Same HTTP status code.
- Same response body shape/length (for JSON, same fields; for HTML, same template).
- Same error message text (character-for-character).
- Similar response timing (avoid quick exits).

Bad vs good examples
```text
Bad:
- "User does not exist"
- "Wrong password"
- "Account locked"

Good:
- "Login failed; invalid user ID or password."
```

### Avoid timing leaks
If you short-circuit when a user doesn’t exist, attackers can measure that difference.

Pseudo-code: avoid “quick exit”
```text
# Risky pattern
IF user_exists(username):
  verify_password(...)
  return error_if_invalid()
ELSE:
  return error()

# Better pattern (uniform work)
verify_password_for_username_or_dummy(username, password)
return error_if_invalid()
```

### Registration and password reset responses matter too
Apply the same generic-message rules to:
- Registration (“If this address is eligible, we’ll send a confirmation email.”)
- Password reset (“If that account exists, we’ll send reset instructions.”)

## Implement robust brute-force protection

Brute-force controls should slow automation without enabling easy denial-of-service.

### Layered anti-automation controls
Use a combination of:
- Per-account throttling (prevents distributed attacks across many IPs).
- Per-IP throttling (helps against single-source attacks).
- Device/session-level throttling (cookie/device fingerprint as an additional signal).
- Progressive challenges (CAPTCHA/step-up after a small number of failures).
- MFA (best control against password compromise).

Example policy (illustrative)
```text
Per account:
- After 5 failures in 10 minutes: add 2s delay
- After 10 failures: require CAPTCHA
- After 15 failures: temporary lockout with exponential backoff

Per IP:
- 50 login attempts / 5 minutes: throttle
- 200 / 5 minutes: block for 15 minutes
```

### Account lockout: avoid “lockout-as-DoS”
If you lock accounts too aggressively, attackers can lock out many users.
- Prefer exponential backoff over long fixed lockouts.
- Allow password reset even if the account is throttled/locked (with additional checks).
- Alert users on lockout events.

### Don’t trust spoofable IP headers
If you use `X-Forwarded-For` / `X-Real-IP`:
- Only honor them when set by your trusted edge proxy.
- Strip/overwrite these headers at the edge to prevent client spoofing.

## Triple-check verification logic (state machines, not pages)

Authentication bugs are often logic bugs, not crypto bugs.

### Treat authentication as a state machine
- “Password verified” is not the same as “fully authenticated” when MFA is enabled.
- Enforce checks server-side on every sensitive endpoint.

Conceptual states
```text
ANON -> PASSWORD_VERIFIED -> MFA_VERIFIED -> AUTHENTICATED
```

Rules to enforce:
- Only allow MFA verification endpoints in `PASSWORD_VERIFIED`.
- Deny access to authenticated resources until `MFA_VERIFIED`.

### Bind MFA challenges to the session/user
- Never rely on client-controlled values (hidden fields/cookies) to decide which account is being verified.
- OTP challenges should be attempt-limited, time-limited, and invalidated on success.

### Require reauthentication for sensitive actions
Before:
- Changing password/email/phone/MFA device
- Viewing secrets (API keys, recovery codes)
- High-risk actions (payment/shipping changes)

Require:
- Current password and/or step-up MFA
- CSRF protection for the action endpoint

## Don’t forget supplementary functionality

Attackers love the “side doors” because teams often secure login but neglect related flows.

### Remember-me / “keep me logged in”
If you implement persistent login:
- Use random high-entropy tokens (not username/timestamp/password-derived).
- Store only hashed tokens server-side.
- Rotate tokens on use.
- Provide revocation (“log out of all devices”).
- Protect cookies: `HttpOnly`, `Secure`, `SameSite`, narrow `Path`, reasonable `Max-Age`.

Cookie example (conceptual)
```http
Set-Cookie: remember_me=...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000
```

### Password reset
Secure reset flows should:
- Use single-use, high-entropy, time-limited tokens.
- Re-validate the token on both page load and form submit.
- Invalidate tokens immediately after success.
- Never email passwords (old or new) as a “solution”.
- Send notifications for reset events.

Reset token handling (conceptual)
```text
Store: hash(token), user_id, expires_at, used_at=null
Email: /reset?token=<raw token>
Verify: hash(token) matches AND not expired AND not used
```

### Host/header-dependent reset links
If you generate reset links using incoming headers:
- Use a configured canonical base URL instead of request headers.
- Validate/allow-list hostnames at the edge and app.

## Implement proper multi-factor authentication

### Use distinct factors
True MFA means different factor types (knowledge + possession, etc.).
- Email-based codes are often “knowledge factor twice” if email is protected by a password.
- SMS OTP is better than nothing, but it’s exposed to SIM swap and interception risks.
- Prefer authenticator apps, hardware keys, or modern phishing-resistant methods (e.g., WebAuthn/passkeys) for high-value accounts.

### Make MFA non-bypassable
- Enforce “MFA verified” server-side on every protected endpoint.
- Rate limit OTP verification and cap attempts per challenge.
- Secure enrollment, reset, and recovery flows with step-up authentication and alerts.

## Monitoring and incident readiness

Add detection so you know when you’re being attacked:
- Log failed logins, lockouts, MFA failures, password resets, and sensitive account changes.
- Alert on credential stuffing patterns (many accounts, few passwords), password spraying, and anomalous geo/device behavior.
- Build support playbooks for account takeover recovery (session revocation, token invalidation, forced password reset, MFA re-enrollment).
