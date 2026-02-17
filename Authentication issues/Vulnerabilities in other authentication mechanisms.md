# Vulnerabilities in other authentication mechanisms

Beyond the primary login flow, “account management” features (remember-me, password reset, password change) regularly introduce high-impact vulnerabilities because they can bypass or replace normal authentication checks.  
Treat these endpoints as part of your authentication system and secure them to the same standard as the login page.

## Keeping users logged in (“Remember me”)
“Remember me” usually works by issuing a long-lived token stored in a persistent cookie; possession of this cookie can effectively bypass interactive login.  
The most common failures happen when tokens are predictable, derived from static values (username/timestamp), or (worst-case) include password material.

### Common weaknesses
- Predictable token construction (e.g., `username + timestamp`) enabling guessing/brute force.
- “Encoding” mistaken for encryption (Base64 provides no confidentiality).
- Reversible encryption used incorrectly (weak keys, shared secrets, poor key management).
- Hashing static values without a unique per-token salt, making offline guessing feasible if the algorithm is known.
- No rate limiting on token verification, allowing attackers to bypass login attempt limits by guessing tokens instead.
- Tokens not rotated or invalidated, enabling replay for long periods after compromise.

### Secure design pattern (recommended)
Use a **random, high-entropy** token and store only a server-side representation (preferably a hash), with rotation and revocation.

Selector + validator pattern (conceptual):
- Cookie stores: `selector.validator` (both random)
- DB stores: `selector`, `hash(validator)`, `user_id`, `expires_at`, `last_used`, `revoked`

Why this helps:
- Fast lookup by selector, but validator is never stored in plaintext.
- If DB leaks, attacker still can’t directly replay validators.
- Easy rotation: issue a new validator after each use.

Example (Python-like pseudocode):
```python
import os, hmac, hashlib, base64, time

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def hash_token(token: str) -> str:
    # Use a server-side secret "pepper" stored outside the DB if possible
    pepper = b"SERVER_SECRET_PEPPER"
    return hmac.new(pepper, token.encode(), hashlib.sha256).hexdigest()

selector  = b64url(os.urandom(9))      # short id for lookup
validator = b64url(os.urandom(33))     # high entropy secret

cookie_value = f"{selector}.{validator}"

store_in_db(
  selector=selector,
  validator_hash=hash_token(validator),
  user_id=user_id,
  expires_at=int(time.time()) + 60*60*24*30,  # e.g., 30 days
  revoked=False
)

set_cookie(
  name="remember_me",
  value=cookie_value,
  http_only=True,
  secure=True,
  same_site="Lax",   # consider "Strict" where UX allows
  path="/",
  max_age=60*60*24*30
)
```

Rotation on use (conceptual):
- If remember-me cookie is presented and valid, **rotate** validator (and optionally selector) and set a new cookie.
- If invalid, revoke that selector record and force full login.

Revocation events to implement:
- User logs out (“log out of all devices” option is ideal).
- Password change, MFA enrollment changes, email change.
- Suspicious activity detection.

## Resetting user passwords (high-risk by design)
Password reset is inherently dangerous because it replaces normal password authentication with an alternative proof mechanism.  
The safest implementations never send a user their current password and never email a persistent password.

### Unsafe patterns to avoid
- Sending the existing password (should be impossible with secure storage).
- Emailing a newly generated long-lived password.
- Reset links that identify the account directly (e.g., `reset?user=victim`) without a secret, unguessable token.
- Tokens that don’t expire, are reusable, or are not invalidated after use.
- Failing to validate the token again on final form submission (only validating on page load).

### Robust reset flow (recommended)
1. User submits identifier (email/username).
2. Application always responds generically (don’t reveal whether the account exists).
3. If account exists: generate a high-entropy, single-use reset token, store only a hash server-side, set short expiry.
4. Send reset link containing the token (HTTPS only).
5. On link open: validate token (exists, not expired, not used).
6. On form submit: **re-validate token** and reset the password; immediately invalidate token(s).
7. Notify the user via out-of-band channel that a reset occurred.

Token generation example (Node.js):
```js
import crypto from "crypto";

function newResetToken() {
  const token = crypto.randomBytes(32).toString("base64url"); // high entropy
  const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
  return { token, tokenHash };
}

// DB: store tokenHash, userId, expiresAt, usedAt=null
// Email link: https://app.example/reset-password?token=<token>
```

Reset form submission (server-side checks you should enforce):
- Token exists and matches stored hash.
- Not expired.
- Not previously used.
- Password meets policy.
- Reset action is rate limited.
- CSRF protections for the reset POST (don’t rely on the token alone as the only anti-CSRF control).

### Password reset poisoning (defensive notes)
If your app builds reset URLs dynamically using request headers (especially `Host` / forwarding headers), it may be possible for an attacker to influence where the reset link points.  
Hardening measures:
- Build absolute URLs from a configured canonical origin, not from inbound headers.
- Validate/allow-list `Host` and proxy forwarding headers at the edge.
- Prefer generating links using server-side configuration (e.g., `APP_BASE_URL`) and known routes.

## Changing user passwords
Password change endpoints often reuse the same credential verification logic as login, and can be vulnerable to the same classes of issues (brute force, enumeration, logic flaws).  
They become especially dangerous when the endpoint lets the requester choose the target username (even via a hidden field).

### Common weaknesses
- Target user is taken from request data (hidden input/cookie/param) rather than the authenticated session.
- Current password not required (or not re-verified) before changing to a new password.
- Missing step-up authentication for sensitive changes.
- No CSRF protection (attacker forces a logged-in victim to submit a password change).
- Weak rate limiting on “current password” attempts (enabling password guessing through the change-password endpoint).

### Secure design pattern (recommended)
- Identify the account to change using the server-side session principal only.
- Require current password (and consider step-up MFA) before allowing the change.
- Apply CSRF protection and rate limiting.
- Invalidate active sessions and remember-me tokens after password change (or at least rotate them).
- Notify the user of the change.

Example (conceptual server logic):
```text
POST /account/change-password

Require: user is authenticated
Require: CSRF token valid
target_user = session.user_id   # not from request
Verify: current_password matches target_user
Validate: new_password policy
Update: password hash
Revoke: all reset tokens, remember-me tokens, and (optionally) sessions for target_user
Audit log + user notification
```

## Testing checklist (quick audit)
- Remember-me:
  - Is the token random and high entropy (not derived from username/timestamp/password)?
  - Is it stored server-side and revocable/rotatable?
  - Are cookies `HttpOnly`, `Secure`, and `SameSite`?
  - Is there rate limiting on token verification?

- Password reset:
  - Do responses avoid account enumeration?
  - Are tokens single-use, short-lived, and validated on both GET (view) and POST (submit)?
  - Are links generated from a canonical configured origin (not request headers)?
  - Are resets logged and user-notified?

- Password change:
  - Is the target account determined from session, not request parameters?
  - Is current password (and/or step-up MFA) required?
  - Are CSRF and rate limiting enforced?
  - Are sessions/remember-me tokens rotated or revoked?
