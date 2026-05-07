# A06:2025 — Insecure Design

**OWASP Position:** #6 (down from #4 in 2021, as Supply Chain and Misconfig grew)
**Key distinction:** Implementation bugs (other categories) can be fixed; insecure design cannot — the required security controls were never built.

## What It Is

Flawed architectural and design decisions that create security risks regardless of implementation quality. Cannot be patched without rearchitecting — only caught early through threat modeling, secure design patterns, and security requirements.

## What to Look For

### Weak Password Recovery / Account Recovery
```bash
grep -rn "forgot.password\|reset.password\|recover.account\|security.question" \
  --include="*.{js,ts,py,php,rb}" .
```

Check the recovery flow:
- Does it use security questions? (NIST 800-63 recommends against them — multiple people can know the answers)
- Is the reset token time-limited (15–60 minutes max)?
- Is the reset token single-use?
- Is the user's current session invalidated after reset?

### Business Logic Flaws
These require understanding the application's domain. Look for:

**Rate limiting on business transactions:**
```bash
grep -rn "booking\|reservation\|purchase\|checkout\|order" --include="*.{js,ts,py,php}" .
# Verify high-value transactions have rate limiting, quantity caps, and anti-automation
```

**No bot / automation protection on critical flows:**
- Login, registration, checkout, booking — do they have CAPTCHA, rate limits, or bot detection?
- Can automated scripts create 1000 accounts in seconds?

**Missing business rule validation:**
```bash
# Negative quantity / price manipulation
grep -rn "quantity\|amount\|price\|total\|count" --include="*.{js,ts,py,php}" .
# Verify: quantity > 0, price >= expected minimum, total = sum of parts
```

**Concurrent request / race condition vulnerabilities:**
- Multiple simultaneous requests to claim a limited resource (voucher codes, limited stock)
- Fund transfer: debit, credit, log — is there a transaction/rollback?

### Missing Multi-Tier Validation
```bash
# Client-side-only validation (no server-side counterpart)
grep -rn "required\|maxLength\|pattern\|min=\|max=" --include="*.{jsx,tsx,html}" .
# For each client validation, verify a matching server-side check exists
```

### Tenant Isolation Weaknesses (Multi-Tenant Apps)
```bash
grep -rn "tenantId\|organizationId\|companyId\|workspaceId" --include="*.{js,ts,py,php}" .
# Verify every query is scoped: .eq('tenant_id', currentTenant)
# Test: can user from Tenant A access Tenant B's data by changing IDs?
```

### Insufficient Transport Layer Security Design
- Are sensitive operations (password change, payment) protected by re-authentication?
- Is 2FA step-up required for critical actions?

## Common Design Anti-Patterns

```javascript
// BAD: Security question for account recovery
const questions = ['What is your pet name?', 'Where were you born?'];
// Answers are guessable, findable via social media

// GOOD: Time-limited OTP to verified email/phone
const token = crypto.randomBytes(32).toString('hex');
await storeResetToken(userId, token, Date.now() + 15 * 60 * 1000); // 15 min
await sendResetEmail(userEmail, token);
```

```javascript
// BAD: Bulk booking without cap
async function bookSeats(userId, count, eventId) {
  await db.query('INSERT INTO bookings (user_id, event_id, seats) VALUES ($1, $2, $3)',
    [userId, eventId, count]); // count could be 600!
}

// GOOD: Business rule validation
async function bookSeats(userId, count, eventId) {
  if (count > MAX_SEATS_PER_BOOKING) throw new Error('Exceeds maximum seats per booking');
  const available = await getAvailableSeats(eventId);
  if (count > available) throw new Error('Not enough seats available');
  // Atomic insert with advisory lock to prevent race conditions
}
```

## Design Review Questions

When analyzing a codebase, ask these questions about critical flows:

1. **Authentication**: What happens if the email verification link is replayed? Can an attacker verify someone else's email?
2. **Password Reset**: Is the token time-limited? Single-use? Is the old password still valid until reset completes?
3. **Payment**: Can the price be manipulated client-side? Is final price validated server-side against the product database?
4. **Rate Limiting**: How many failed logins before lockout? How many accounts can one IP create per hour?
5. **Business Logic**: Can any numeric values be negative? What are the min/max bounds?
6. **Multi-tenancy**: Is tenant isolation enforced at the database query level, not just middleware?

## Prevention Checklist

- [ ] Password recovery uses time-limited, single-use tokens (not security questions)
- [ ] Reset tokens expire (≤ 60 minutes)
- [ ] High-value transactions have rate limiting and quantity caps
- [ ] Server-side validation mirrors all client-side validation
- [ ] Business rule limits enforced server-side (price, quantity, count)
- [ ] Multi-tenant queries explicitly scoped to current tenant at DB level
- [ ] Race conditions mitigated with transactions/locks for resource contention
- [ ] Re-authentication required for sensitive operations (password change, payment)
- [ ] Threat model exists or has been discussed for critical flows
- [ ] Integration tests cover misuse cases, not just happy paths
