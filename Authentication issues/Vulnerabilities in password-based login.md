# Vulnerabilities in password-based login

Password-based login relies on “something you know” (a secret password) as proof of identity, which means the application’s security is compromised if an attacker can obtain or guess valid credentials.  
This section covers common ways password logins fail in practice: brute-force and credential-based attacks, username enumeration, flawed brute-force protection, and risks in HTTP Basic authentication.

## Brute-force attacks (and why they work)
A brute-force attack is trial-and-error guessing of credentials, usually automated with wordlists and tooling to make a high volume of login attempts quickly.  
Attackers rarely guess “randomly”; they use patterns, public information, and human behavior to make educated guesses that are far more effective than raw randomness.

### Common automated attack types (useful for threat modeling)
- Brute force: Many passwords tried against one account.
- Credential stuffing: Known `username:password` pairs (from breaches elsewhere) tried against your login.
- Password spraying: One/few common passwords tried across many accounts.

## Brute-forcing usernames
Usernames are often easier to guess than passwords, especially when they follow a predictable format (email addresses, `firstname.lastname`, etc.) or when privileged accounts use obvious names like `admin` / `administrator`.

During review/auditing, look for places your app accidentally discloses valid usernames:
- Public profile pages (even if profile details are hidden, the profile identifier may match the login username).
- HTTP responses containing email addresses (error pages, support pages, JavaScript bundles, API responses).
- “High-privilege hints” (admin/support emails exposed in headers, logs, or UI text).

## Brute-forcing passwords (real-world patterns)
Password cracking difficulty depends heavily on password strength, but “strong password policy” can backfire when it pushes users into predictable variations.

Common human patterns that attackers exploit:
- “Policy crowbar” passwords: `mypassword` becomes `Mypassword1!`, `Myp4$$w0rd`, etc.
- Predictable rotation: `Password1!` → `Password2!`, `Password1?`, etc.

### Practical password controls (defensive)
If you’re improving a password-based system, focus on controls that make guessing harder without harming usability:

- Enforce a minimum length; treat short passwords as weak (especially without MFA).
- Allow long passwords/passphrases (plan for at least 64 characters).
- Do not silently truncate passwords (fail validation explicitly if you must enforce a maximum).
- Allow all characters (including whitespace and Unicode); avoid composition rules (forced upper/lower/special) because they often reduce usability without reliably improving security.
- Block common and previously breached passwords.
- Provide a password strength meter to guide users away from weak choices.
- Store passwords securely (strong one-way password hashing) and compare using safe, constant-time functions where possible.

## Username enumeration (how it happens)
Username enumeration is when an attacker can determine whether a username exists by observing differences in the application’s behavior.

This commonly appears in:
- Login flows (valid username + wrong password behaves differently from invalid username).
- Registration flows (revealing “username already taken” too directly).
- Password recovery flows (revealing whether an email/username exists).

### Enumeration signals to check
Look for any difference between “user exists” vs “user doesn’t exist” cases:

- Status codes  
  If most failed attempts return one status code, but a specific username returns another (e.g., 200 vs 401/403/302), that can leak validity.

- Error messages  
  Even tiny differences (“Invalid password” vs “Invalid username or password”, punctuation differences, spacing) can become a reliable oracle.

- Response time  
  A “quick exit” path (stop early if user doesn’t exist) often responds faster than the “user exists, now verify password” path. Attackers can amplify this by sending very long passwords so hashing/verification takes noticeably longer.

### Safer response strategy (pattern)
Keep error handling uniform across failure conditions:
- Same HTTP status code for failures.
- Same response body shape (HTML/JSON).
- Similar processing time (avoid quick exits when possible).

Pseudo-code example:

```text
# Risky: different work depending on whether the user exists
IF user_exists(username):
  password_hash = HASH(password)
  valid = check_store(username, password_hash)
  IF NOT valid:
    RETURN "Invalid user ID or password"
ELSE:
  RETURN "Invalid user ID or password"
```

```text
# Better: uniform work for failure paths
password_hash = HASH(password)
valid = check_store(username, password_hash)
IF NOT valid:
  RETURN "Invalid user ID or password"
```

### Generic error message examples
Incorrect (leaks info):
- `Login for user foo: invalid password.`
- `Login failed, invalid user ID.`
- `Login failed; account disabled.`

Correct (generic):
- `Login failed; invalid user ID or password.`

Apply the same principle to password recovery:
- Correct: `If that email address is in our database, we will send you an email to reset your password.`

## Flawed brute-force protection (design pitfalls)
Brute-force protection aims to slow automation and reduce the number of guesses an attacker can attempt. Common approaches include account lockout and rate limiting, but both are frequently implemented with bypassable logic or create new risks (like denial of service).

### Account lockout (and how to implement it safely)
Account lockout can help against targeted guessing on a single account, but it must be carefully designed.

Key design parameters:
- Lockout threshold: failed attempts before lockout.
- Observation window: time period those attempts must occur within.
- Lockout duration: how long the lockout lasts.

Practical recommendations:
- Track failed-attempt counters against the *account*, not only the source IP (IP-only controls are easy to evade at scale).
- Prefer exponential backoff (short initial lockouts that increase with repeated failures) over a fixed long lockout.
- Prevent lockout-as-DoS: attackers should not be able to trivially lock out many user accounts. Consider allowing password reset flows even if an account is locked, and add additional verification for unlock/recovery.
- Avoid lockout messages that reveal “account locked” vs “invalid login” if you’re trying to reduce enumeration.

### User rate limiting (IP-based throttling)
Rate limiting blocks or slows login attempts when too many requests occur in a short time window.

Typical unblock mechanisms:
- Automatic unblock after a cool-down period.
- Manual admin unblock.
- User completes a CAPTCHA after repeated failures.

Why IP-only rate limiting isn’t enough on its own:
- It can be bypassed by distributed sources (botnets, rotating egress, shared networks).
- It can cause collateral damage (NAT/shared IPs) and enable denial-of-service against legitimate users.

A stronger approach combines multiple signals:
- Per-account throttling + per-IP throttling.
- Device/session risk signals (new device, unusual location, unusual volume).
- CAPTCHA as a defense-in-depth control after a small number of failures (not necessarily on the first attempt).

## HTTP Basic authentication (why it’s risky)
HTTP Basic authentication uses an `Authorization` header containing a Base64-encoded `username:password` token that the browser automatically sends on subsequent requests:

```http
Authorization: Basic base64(username:password)
```

Why it’s generally considered insecure for modern web apps:
- Credentials are effectively replayed on every request (increasing exposure if transport protections are weak).
- Without strong transport protections (TLS everywhere + HSTS), credentials can be captured or altered via man-in-the-middle scenarios.
- Many implementations don’t include robust brute-force protections.
- It provides no built-in CSRF protection and doesn’t solve session security on its own.
- Exposed credentials may be reused by users across other systems, increasing impact.

If you must use it (legacy/internal use cases):
- Enforce TLS-only and HSTS.
- Add throttling/lockout controls at the gateway/app layer.
- Scope access tightly (least privilege) and prefer modern session-based auth for interactive web apps.

## Logging and monitoring (don’t skip this)
Authentication attacks often look like “normal” traffic unless you instrument and review the right events.

Log and monitor at minimum:
- Failed logins (reason should be internal-only; don’t expose it to the user).
- Account lockouts and unlocks.
- Password reset requests and completions.
- MFA challenges/failures (if used).
- High-risk changes (email/password changes) and reauthentication events.

Consider alerting on patterns:
- Many failures across many accounts (spraying).
- Many attempts on one account (targeted brute force).
- Successful login after many failures.
- Unusual geolocation/device changes.
