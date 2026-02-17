# Authentication vulnerabilities

Authentication vulnerabilities are usually critical because authentication sits directly on the boundary between the public internet and sensitive, authenticated functionality.  
If attackers can bypass or weaken authentication, they can often access protected data/features and gain additional internal attack surface for follow-on exploits.

## What is authentication?
Authentication is the process of verifying the identity of a user or client.  
Because websites are exposed to anyone with internet access, robust authentication is a foundational control in web application security.

### Common authentication factors
- Something you know (knowledge factor), e.g., password, PIN, security question answer.
- Something you have (possession factor), e.g., phone, hardware token, authenticator app.
- Something you are/do (inherence factor), e.g., biometrics or behavioral patterns.

## Authentication vs authorization
Authentication verifies *who* a user is.  
Authorization verifies *what* that authenticated user is allowed to do (permissions, roles, access scope).

Example:
- Authentication: “Is this really Carlos123?”
- Authorization: “Can Carlos123 view other users’ data or delete accounts?”

## How authentication vulnerabilities arise
Most authentication vulnerabilities fall into two broad categories:
- Weak protection against automated guessing: brute force, password spraying, and credential stuffing succeed because controls like rate limiting, lockouts, or MFA are missing or flawed.
- Logic flaws / poor implementation: broken authentication where attackers bypass checks due to unexpected flows, inconsistent validation, or trusting client-controlled state.

Even small logic issues tend to become security issues in authentication because the expected behavior is strict and attackers can iterate quickly.

## Impact
If an attacker compromises an account (by bypass or guessing), they gain everything that account can access.  
If the compromised account is privileged (admin/support), the attacker may gain full control over the application and potentially pivot into internal infrastructure; even low-privileged accounts can expose business data and unlock “internal-only” pages that enable higher-severity attacks.

## Where vulnerabilities commonly appear
A typical web authentication system is a collection of mechanisms—each can introduce its own weaknesses:
- Password-based login (username handling, password checks, brute-force protections, error messaging, session creation).
- Multi-factor authentication (OTP/TOTP verification, “remember this device” flows, MFA reset/recovery).
- Other mechanisms (magic links, passwordless, API keys, SSO glue code, device trust).
- Third-party auth (for example OAuth integrations; issues often come from incorrect assumptions about tokens/identity, misconfigured redirect URIs, and unsafe session binding).

## Making authentication robust (practical principles)
Treat authentication as a *system* (login + MFA + recovery + error handling + monitoring), then layer defenses so one failure doesn’t collapse the whole flow.

### Credential handling
- Enforce minimum password length; allow long passwords/passphrases (do not silently truncate).  
- Allow all characters (including whitespace/Unicode) and avoid “composition rules” that force specific character classes (these often harm usability and don’t reliably improve security).
- Use secure password storage (strong one-way hashing with a modern scheme) and constant-time comparisons during verification.
- Always protect login and authenticated pages with TLS; never accept credentials over plaintext HTTP.

### Prevent brute force and enumeration
- Use rate limiting / throttling on login and MFA verification endpoints (and any endpoint that proves identity).
- Implement lockout controls carefully: define a lockout threshold, observation window, and lockout duration; consider exponential backoff instead of fixed lockout durations.
- Keep login failure messages generic and consistent to reduce username enumeration via differences in text, status codes, redirects, or timing.

Example: avoid user-existence timing leaks (conceptual)
```text
# Risky: different work depending on whether the user exists
IF user_exists(username):
  hash = HASH(password)
  valid = check_store(username, hash)
  IF NOT valid: return "Invalid username or password"
ELSE:
  return "Invalid username or password"
```

```text
# Better: do uniform work for failure paths
hash = HASH(password)
valid = check_store(username, hash)
IF NOT valid: return "Invalid username or password"
```

### Secure “sensitive actions”
- Require reauthentication (password and/or step-up MFA) before sensitive changes like password resets, email changes, payment/shipping changes, and MFA device changes.
- Design recovery flows (forgot password / MFA reset) as high-risk entry points: ensure tokens are single-use, time-limited, bound to the right account, and don’t leak whether an account exists.

### Detection and response
- Log authentication failures, lockouts, and unusual patterns (e.g., many failures across many accounts, repeated MFA failures, impossible travel signals).
- Alert on suspicious patterns early; successful auth bypasses often look like “normal” logins unless you monitor context.
