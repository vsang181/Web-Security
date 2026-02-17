# Vulnerabilities in multi-factor authentication (MFA / 2FA)

Multi-factor authentication (MFA) requires users to prove their identity using multiple factors, typically “something you know” (password) plus “something you have” (device-generated or device-received code).  
MFA is generally more secure than password-only login, but weak implementations can be bypassed or brute-forced just like single-factor authentication.

## What “real” MFA means
MFA only provides the intended security benefit when it validates *different* factor types (knowledge + possession, or possession + inherence).  
A common pitfall is “two-step authentication” that verifies the *same* factor twice (for example, password + email OTP, where both are ultimately protected by knowledge of the email account credentials).

## 2FA token types and risk tradeoffs
Verification codes are usually provided via:
- Authenticator apps (TOTP): codes are generated on-device and are not transmitted over the network to reach the user, reducing interception risk.
- Hardware tokens (OTP token / keypad): purpose-built devices that generate codes locally.
- SMS OTP: codes are transmitted over the mobile network, which introduces additional risks (interception and SIM swapping).
- Email OTP: often weaker than it looks because compromise of email can collapse both login and “second factor.”

Practical implications:
- Prefer phishing-resistant MFA where possible (e.g., modern public-key-based authenticators such as WebAuthn/FIDO2) for high-value accounts.
- Treat SMS-based 2FA as higher risk and do not rely on it as your only “strong” control for privileged users.

## Common MFA implementation flaws

### 1) “2FA bypass” via incorrect state handling
A frequent design bug happens when the app treats a user as “logged in” after the password step and only *later* asks for a second factor.  
If “logged-in only” pages don’t explicitly enforce “MFA completed,” users (or attackers) may be able to skip the OTP page and access protected endpoints directly.

Defensive pattern:
- Use an explicit “partial authentication” state after step 1.
- Gate *all* sensitive routes on “fully authenticated” (password + MFA verified).
- Ensure server-side checks exist; client-side redirects or UI “wizards” don’t count.

Example (conceptual):
```text
State after password step:
- session.authenticated = true        # risky if treated as fully logged in
- session.mfa_verified = false

Correct enforcement:
- allow only /mfa/verify when mfa_verified=false
- deny all other authenticated routes until mfa_verified=true
```

### 2) Broken MFA binding (factor not tied to the right user/session)
Another common flaw is when the app decides *which account* is being verified using a client-controlled value (cookie, hidden field, request parameter) instead of binding it to the server-side session created at step 1.  
This can allow a user to authenticate with their own password, then “switch” the target account for the MFA verification step.

Insecure pattern (conceptual HTTP flow):
```http
POST /login/step1
username=attacker&password=...

Set-Cookie: account=attacker
GET /login/step2
Cookie: account=attacker

POST /login/step2
Cookie: account=victim
verification-code=......
```

Defensive pattern:
- Never trust a client-controlled “account” selector during MFA verification.
- Bind the MFA challenge to the server-side session established at step 1 (or to a one-time transaction ID stored server-side).
- Validate that the OTP is being checked for the *same principal* that passed the password step.

Secure pattern (conceptual):
```text
POST /login/step1 -> server creates session S for user U
- session.user_id = U
- session.mfa_challenge_id = random
- session.mfa_verified = false

POST /login/step2
- server reads session.user_id (not from cookies/params)
- server verifies OTP for that user + that challenge
```

### 3) Brute-forcing MFA codes (weak verification controls)
OTP values are often only 4–6 digits, which makes brute force feasible if the verification endpoint has weak protections.  
Logging the user out after N failures is not sufficient by itself if an attacker can repeatedly re-initiate the flow (or automate step 1 + step 2) and there’s no robust throttling.

Defensive controls that should exist on the MFA verification endpoint:
- Rate limit per account and per source (IP/device fingerprint/session), not just globally.
- Lockout/backoff after repeated failures (prefer short exponential backoff rather than long hard lockouts that can be abused for DoS).
- Enforce maximum attempts per challenge (invalidate the challenge after too many wrong codes).
- Ensure codes are single-use where applicable (especially backup codes and emailed magic codes).

### 4) Weak “remember this device” / trusted device flows
“Remember this device” can be helpful, but it becomes a bypass if implemented as a simple cookie flag that isn’t:
- cryptographically protected,
- bound to the specific device/browser,
- revocable, and
- scoped to a reasonable lifetime.

Defensive pattern:
- Treat “remembered device” as its own credential: store a server-side record, rotate identifiers, support revocation, and require reauth for sensitive actions even on remembered devices.

### 5) Insecure MFA enrollment and recovery
Attackers often target the *change* paths rather than the login path:
- Adding a new MFA device.
- Resetting MFA.
- Changing phone number/email used for OTP delivery.

Defensive pattern:
- Require step-up authentication (password + existing MFA) to change MFA settings.
- Use strong verification and cooldowns for recovery flows.
- Notify users of MFA changes through out-of-band channels and provide quick revocation.

### 6) SMS-specific risks (delivery factor weaknesses)
SMS OTP can be undermined by:
- SIM swapping (attacker takes over the phone number).
- Interception and social engineering at telecom providers.
- Weaknesses in the broader SMS ecosystem.

If SMS must be supported:
- Limit its use to lower-risk accounts or as a fallback with additional controls.
- Add alerts for phone number changes and suspicious OTP requests.

## How to test MFA safely (review checklist)
Use this as a structured checklist when reviewing an app’s MFA implementation:

- Access control: Can any authenticated endpoint be reached after step 1 but before step 2?
- Session state: Is there a clear “partially authenticated” state enforced server-side?
- Binding: Is the MFA verification tied to the step-1 session user, or can the target user be influenced by client input?
- Challenge lifecycle: Are OTP challenges time-bound, attempt-limited, and invalidated on success?
- Rate limiting: Are there per-account and per-source throttles on the OTP verification endpoint?
- Enumeration: Do MFA flows leak whether a username exists (messages, status codes, timing)?
- Enrollment/recovery: Are MFA changes protected by step-up auth and logged/alerted?
- Trusted devices: Are “remember device” tokens robust, revocable, and not simple boolean cookies?

## Hardening recommendations (what to implement)
- Prefer phishing-resistant MFA for high-value accounts (e.g., WebAuthn/FIDO2) and use authenticator apps/hardware tokens over SMS where feasible.
- Ensure MFA is enforced as an authorization gate (“MFA verified”) across all sensitive endpoints, not just as a UI step.
- Bind the second factor verification to the authenticated session/user from step 1, never to client-controlled identifiers.
- Apply strong throttling and attempt limits to OTP verification, and design lockouts to avoid enabling denial-of-service.
- Secure enrollment, reset, and recovery with step-up authentication, notifications, and audit logs.
- Keep responses consistent (messages/status/timing) to reduce enumeration and oracle behaviors.
