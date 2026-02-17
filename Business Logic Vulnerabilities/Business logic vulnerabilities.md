# Business logic vulnerabilities (logic flaws)

Business logic vulnerabilities are flaws in an application’s **design or workflow rules** that let users trigger unintended behavior by interacting with features in ways developers didn’t anticipate. These issues aren’t “classic” injection bugs; they’re problems like missing state checks, trusting client-controlled values, incorrect assumptions about user intent, and broken validation across multi-step processes.

Because logic flaws depend on the application’s domain and rules (payments, discounts, roles, inventory, approvals), they’re hard to detect with automated scanners and often require manual testing and domain knowledge.

## What “business logic” means here
“Business logic” is the set of rules and constraints that define how the application is supposed to behave (even if the app isn’t a literal business). Logic flaws are also called:
- Application logic vulnerabilities
- Logic bugs (security-impacting)

A logic flaw usually appears when the app reaches an unexpected state (out-of-order steps, repeated steps, partial completion, mixed flows) and fails open instead of failing safe.

## How logic flaws arise
Logic flaws commonly come from flawed assumptions, including:
- Assuming users only interact via the browser UI (client-side validation is treated as “good enough”).
- Assuming requests happen in a fixed order (step 1 must happen before step 2).
- Assuming state is consistent across components (cart service, payment service, fulfilment service all agree).
- Assuming “this field can’t be modified” because it’s hidden, disabled, or “not in the UI”.
- Assuming concurrency won’t happen (double-submits, retries, race conditions, parallel sessions).
- Assuming testers/devs “know how it works” without documenting invariants and edge cases.

Complex systems amplify these issues: different teams own different services, each makes assumptions about the others, and the gaps become exploitable.

## Typical impact
Impact varies from low to critical, but unintended behavior can become high severity when it affects:
- Authentication/identity (bypass login, privilege escalation, account takeover paths).
- Authorization (accessing admin-only actions, horizontal privilege escalation).
- Money/credits/discounts (free purchases, negative totals, credit minting).
- Inventory/fulfillment (ordering out-of-stock items, duplicating refunds).
- Abuse/DoS (locking accounts, exhausting resources, breaking business operations).

Even if the attacker can’t profit directly, logic flaws can still harm the business (fraud, inventory disruption, reputational damage).

## Common examples (patterns to recognize)
These are categories you can map to your own app’s workflows.

### Workflow bypass / step skipping
The app assumes steps are completed in order, but doesn’t enforce it server-side.
- Accessing “confirmed order” pages without completing payment
- Triggering “ship order” without a successful authorization
- Completing password change without verifying current password

### Client-controlled “source of truth”
Security-critical values are accepted from the client instead of computed server-side.
- Price, currency, quantity, shipping cost, tax, discount amount
- `isAdmin`, `role`, `accountId`, `userId`, `mfaVerified`, `paid=true`
- “Trusting” hidden fields or local storage

Example (bad):
```json
POST /checkout
{
  "items": [{"sku":"ABC","qty":1,"unitPrice":0.01}],
  "total": 0.01,
  "shipping": 0
}
```

Better:
- Client sends only identifiers and quantities.
- Server looks up current prices, rules, and computes totals.

### Inconsistent state across endpoints
One endpoint validates a rule, another endpoint applies the action without re-checking.
- “Apply coupon” validates eligibility, but “place order” doesn’t re-validate coupon usage limits
- “Add to cart” checks stock, but “checkout” doesn’t re-check stock

### Race conditions (TOCTOU)
Two requests in parallel cause a state transition to happen twice.
- Double-spend gift cards / store credit
- Duplicate refunds
- Bypassing purchase limits (“only 1 per user”) by parallel checkout
- Reusing “one-time” tokens in parallel

Defensive patterns:
- Use database constraints/transactions where possible
- Idempotency keys for payment/refund endpoints
- Atomic “check-and-update” operations (single statement / transaction)

### Abuse of “edge” functionality
Attackers often target supplementary features:
- Returns/refunds, cancellations, chargeback flows
- Loyalty points, referral bonuses
- Support/admin tools, previews, “test mode”
- Password reset, email change, “remember device”
- Trial periods, coupons/promotions, shipping rules

### Weak validation of “sensible values”
Values are accepted but not sanity-checked.
- Negative quantities or totals
- Extremely large numbers (overflow / rounding issues)
- Invalid state transitions (refund before purchase)
- Nonce/token reuse

## How to test for logic flaws (practical method)
Logic testing is about mapping workflows and then breaking the assumptions.

### 1) Model the workflow and invariants
Write down:
- States: `Created -> PendingPayment -> Paid -> Fulfilled -> Refunded -> Closed`
- Allowed transitions (and who can do them)
- Invariants that must always hold:
  - “Total charged = sum(line items) + tax + shipping - discounts”
  - “Refund amount <= captured amount”
  - “User can only change their own email”
  - “MFA must be verified to access sensitive endpoints”

### 2) Try “unexpected but valid HTTP”
- Repeat requests (resubmits)
- Skip steps (call step N directly)
- Swap identifiers (change `accountId`, `orderId`, `userId`)
- Modify hidden fields / JSON fields
- Parallelize critical actions (race testing)
- Use multiple sessions/devices/browsers simultaneously

### 3) Look for mismatched validation
- Endpoint A validates; endpoint B assumes A was called
- Frontend validates; backend trusts it
- Service validates; downstream service doesn’t

### 4) Focus on “money and identity”
If time is limited, prioritize:
- Checkout/payment/refund/store credit
- Account management, password reset/change
- Role changes, admin functions, invitation flows

## Preventing business logic vulnerabilities (engineering practices)

### Make assumptions explicit and enforce them
- Document workflows (sequence diagrams/data flows) and note assumptions per step.
- Encode assumptions as server-side checks (don’t rely on UI).
- Fail safe: if state is unexpected, reject with a clear error and log it.

Example: state enforcement
```text
POST /ship-order
Require: order.state == PAID
Require: actor has role == FULFILLMENT
Else: deny + audit log
```

### Treat the server as the source of truth
- Compute totals, discounts, permissions, and state transitions server-side.
- Store authoritative values and derive from trusted data (DB/config), not from client payload.

### Validate “sensible” inputs (beyond type checks)
- Bounds checks (min/max quantities, totals, lengths)
- Reject negative numbers where nonsensical
- Validate enums/status transitions, not free-form strings
- Enforce currency/locale consistency

### Make workflows idempotent and race-safe
- Add idempotency keys to payment/refund/credit endpoints:
```http
Idempotency-Key: 6f7a9d2c-...
```
- Ensure “one-time” actions are enforced with atomic updates:
```text
UPDATE coupons
SET used = true, used_by = :user
WHERE code = :code AND used = false
```
- Use transactions/locking around balance/stock updates.

### Centralize authorization and state checks
- Don’t scatter “if admin” checks across handlers.
- Prefer shared authorization middleware/policies.
- Re-check authorization at every sensitive action endpoint.

### Log and monitor “impossible” paths
Logic exploitation often looks like legitimate feature use.
- Log invalid state transitions, repeated submissions, abnormal refund rates, coupon abuse patterns.
- Alert on spikes (many resets, many refunds, many failed transitions).
- Keep audit trails for state-changing actions (who, what, when, before/after).

### Improve review and test coverage
- Add unit tests for invariants and state transitions.
- Add integration tests that simulate:
  - step skipping
  - repeated submissions
  - concurrent requests
  - identifier swapping
- Use threat modeling per major workflow (checkout, account recovery, admin actions).

## Quick checklist
- Are all security-critical values computed server-side (price, discount, role, state)?
- Does every sensitive endpoint enforce:
  - correct authentication state (including MFA where required)?
  - correct authorization (role/ownership)?
  - correct workflow state (order/payment/refund state machine)?
- Are actions idempotent and safe under retries?
- Are race conditions prevented for balances/stock/tokens?
- Are errors/messages consistent (avoid leaking sensitive state)?
- Are “supporting” flows (reset/change/remember-me/refund) secured as strongly as login/checkout?
