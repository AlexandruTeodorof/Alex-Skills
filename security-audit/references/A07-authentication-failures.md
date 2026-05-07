# A07:2025 — Authentication Failures

**OWASP Position:** #7 (maintained from 2021)
**Incidence:** Max 15.80% per app; 1,120,673 occurrences; 7,147 CVEs; 36 CWEs

## What It Is

Failures that allow attackers to trick a system into recognizing an invalid or incorrect user as legitimate. Includes credential stuffing, weak passwords, broken session management, and ineffective MFA.

## What to Look For

### No Rate Limiting on Auth Endpoints
```bash
grep -rn "login\|signin\|auth\|password\|token" --include="*.{js,ts,py,php,rb}" . \
  | grep -i "route\|endpoint\|handler\|post\|controller"
# Then check if rate-limit middleware is applied to those routes
grep -rn "rateLimit\|rate.limit\|throttle\|slowDown\|limiter" --include="*.{js,ts,py,php}" .
```

### Weak / Default Password Policy
```bash
grep -rn "password.*length\|minLength\|min_length\|password.*validate\|password.*policy" \
  --include="*.{js,ts,py,php,rb}" .
# Check: minimum 8+ chars (NIST: 15+ recommended), no complexity requirements forcing weak passwords
# Check: not validated against known breached password lists
```

### Missing or Bypassable MFA
```bash
grep -rn "mfa\|totp\|2fa\|two.factor\|otp\|authenticator" --include="*.{js,ts,py,php}" .
# Is MFA enforced on all admin accounts?
# Is MFA fallback (backup codes) also rate-limited?
```

### Session Management Issues
```bash
# Session ID in URL
grep -rn "session.*url\|sessionId.*query\|PHPSESSID.*GET\|jsessionid" \
  --include="*.{js,ts,py,php}" .

# Session not invalidated after logout
grep -rn "signOut\|logout\|sign.out" --include="*.{js,ts,py,php}" .
# Verify the session is destroyed server-side, not just client-side cookie deletion

# No session regeneration after login
grep -rn "regenerate\|rotate.*session\|new.*session" --include="*.{js,ts,py,php}" .
# Session fixation: if sessionId doesn't change after auth, it's vulnerable
```

### JWT Issues
```bash
grep -rn "jwt\|jsonwebtoken\|jose\|pyjwt" --include="*.{js,ts,py}" .
```

Check:
- Algorithm explicitly set (`algorithm: 'HS256'` / `algorithm: ['HS256']`) — never `'none'`
- `jwt.verify()` used, not just `jwt.decode()`
- `aud` and `iss` claims validated
- Short expiry (≤ 15 min for access tokens; refresh tokens separate)
- Refresh token rotation implemented

```javascript
// BAD: no algorithm check, decode not verify
const payload = jwt.decode(token);

// BAD: algorithm none possible
jwt.verify(token, secret); // vulnerable to alg:none attack if not explicitly set

// GOOD: explicit algorithm, full verification
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'],
  audience: 'my-app',
  issuer: 'my-auth-server',
});
```

### Account Enumeration
```bash
grep -rn "user.*not.*found\|invalid.*email\|no.*account\|username.*incorrect" \
  --include="*.{js,ts,py,php,rb}" .
# Login/reset errors should say "Invalid username or password" — not which one is wrong
```

### Password Storage
```bash
# Look for password hashing implementations
grep -rn "bcrypt\|argon2\|scrypt\|pbkdf2\|hashpw\|password_hash" --include="*.{js,ts,py,php,rb}" .
# Verify bcrypt cost factor ≥ 12, argon2 used with recommended memory/iteration params
```

### Session Timeout
```bash
grep -rn "maxAge\|expires\|session.timeout\|SESSION_TIMEOUT\|cookie.*expires" \
  --include="*.{js,ts,py,php}" .
# Sessions should expire after inactivity (e.g., 15–60 min for sensitive apps)
# "Remember me" tokens should have bounded lifetime (e.g., 30 days max)
```

## Common Vulnerable Patterns

```javascript
// BAD: different error messages — reveals which field is wrong
if (!user) return res.status(401).json({ error: 'User not found' });
if (!validPassword) return res.status(401).json({ error: 'Wrong password' });

// GOOD: identical message
return res.status(401).json({ error: 'Invalid username or password' });
```

```javascript
// BAD: no rate limiting on login
app.post('/login', async (req, res) => {
  const user = await authenticate(req.body);
  ...
});

// GOOD: rate limited
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
app.post('/login', loginLimiter, async (req, res) => {
  ...
});
```

```python
# BAD: SHA-256 for password (fast hash, GPU-crackable)
import hashlib
hashed = hashlib.sha256(password.encode()).hexdigest()

# GOOD: argon2 (slow, memory-hard)
from argon2 import PasswordHasher
ph = PasswordHasher()
hashed = ph.hash(password)
```

## Prevention Checklist

- [ ] Rate limiting on `/login`, `/register`, `/forgot-password`, `/reset-password`
- [ ] MFA available (ideally required for admin accounts)
- [ ] Passwords: minimum 8 chars (NIST recommends 15+); validated against breached list
- [ ] No complexity rules that encourage weak passwords (no "must have uppercase+number+symbol")
- [ ] Password hashed with Argon2id, bcrypt (≥12), scrypt, or PBKDF2
- [ ] Session regenerated after login (prevent session fixation)
- [ ] Session invalidated server-side on logout
- [ ] Session ID never in URL
- [ ] Session expires after inactivity (admin apps: 15–30 min)
- [ ] JWT: explicit algorithm, `jwt.verify()` not `jwt.decode()`, `aud`/`iss` validated
- [ ] JWT: short expiry on access tokens; refresh token rotation
- [ ] Generic error messages on auth failure (no username/password distinction)
- [ ] Account lockout or progressive delay after repeated failures
- [ ] Single logout (SLO) if using SSO/OAuth — log out of all sessions
