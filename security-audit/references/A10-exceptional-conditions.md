# A10:2025 — Mishandling of Exceptional Conditions

**OWASP Position:** #10 (new category for 2025; replaces SSRF)
**Focus:** 24 CWEs — improper error handling, logic errors, failure scenarios
**Key CWEs:** CWE-209 (error exposing sensitive data), CWE-476 (NULL pointer dereference), CWE-636 (failing open)

## What It Is

Applications that don't prevent unusual situations, don't detect them when they happen, or respond poorly — leading to logic bugs, resource leaks, race conditions, fraudulent transactions, DoS, and silent security failures. "Failing open" (allowing access when an error occurs) is a critical subtype.

## What to Look For

### Exposed Stack Traces and Internal Details
```bash
# Express error handlers leaking stack
grep -rn "err\.stack\|error\.stack\|exception\.stack" --include="*.{js,ts,py,php}" .
grep -rn "res\.send(err\|res\.json(err\|response.*exception" --include="*.{js,ts,py,php}" .

# Django DEBUG
grep -rn "DEBUG\s*=\s*True" --include="*.py" --include="*.cfg" .

# Spring Boot
grep -rn "server\.error\.include-stacktrace" --include="*.{properties,yaml,yml}" .
```

### Failing Open (Access Granted on Error)
This is critical — if an auth/authorization check throws an exception, does it grant or deny?
```bash
grep -rn "try.*\|catch.*" --include="*.{js,ts,py,php}" . | head -50
# Manually review catch blocks in auth middleware and permission checks
```

Vulnerable vs. safe:
```javascript
// BAD: exception in auth check defaults to "allow" 
async function canAccess(userId, resourceId) {
  try {
    return await db.checkPermission(userId, resourceId);
  } catch (e) {
    return true; // DANGEROUS: error = grant access
  }
}

// GOOD: fail closed
async function canAccess(userId, resourceId) {
  try {
    return await db.checkPermission(userId, resourceId);
  } catch (e) {
    logger.error('Permission check failed', { userId, resourceId, error: e.message });
    return false; // Safe default: deny on error
  }
}
```

### Resource Leaks (DoS Vector)
```bash
# File handles not closed on exception
grep -rn "fs\.open\|fs\.createReadStream\|createWriteStream" --include="*.{js,ts}" .
# Verify finally block or .destroy() on error

# Database connections not released
grep -rn "db\.connect\|pool\.connect\|getConnection\|acquire" --include="*.{js,ts,py}" .
# Verify connection.release() / connection.end() in finally

# Temp files not cleaned up
grep -rn "tmp\|temp\|mktemp\|tmpfile\|NamedTemporaryFile" --include="*.{js,ts,py}" .
```

### Incomplete Transaction Rollback
```bash
grep -rn "BEGIN\|transaction\|START TRANSACTION\|commit\|rollback" --include="*.{js,ts,py,php,sql}" .
# Multi-step operations (debit + credit + log) should rollback completely on any failure
```

Vulnerable vs. safe:
```javascript
// BAD: partial failure leaves inconsistent state
async function transferFunds(fromId, toId, amount) {
  await debitAccount(fromId, amount);    // if this succeeds but next fails...
  await creditAccount(toId, amount);     // money lost
  await logTransaction(fromId, toId, amount);
}

// GOOD: atomic transaction
async function transferFunds(fromId, toId, amount) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [amount, fromId]);
    await client.query('UPDATE accounts SET balance = balance + $1 WHERE id = $2', [amount, toId]);
    await client.query('INSERT INTO transactions (from_id, to_id, amount) VALUES ($1, $2, $3)',
      [fromId, toId, amount]);
    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
```

### NULL / Undefined Dereference Without Check
```bash
# Optional chaining absent in critical paths
grep -rn "\.id\b\|\.userId\b\|\.email\b" --include="*.{js,ts}" . | head -30
# Verify values checked for null before use in auth/access paths
```

### Race Conditions in Resource Claims
```bash
grep -rn "check.*then.*use\|select.*then.*update\|available.*then.*book" \
  --include="*.{js,ts,py,php}" .
# Classic TOCTOU: check-then-act without atomic lock
# Pattern: SELECT available → UPDATE (another request changes state between)
```

### Unhandled Promise Rejections / Async Errors
```bash
# Unhandled async errors in Express (v4 requires explicit next(err))
grep -rn "async.*req.*res" --include="*.{js,ts}" . | head -20
# Each async route handler should have try/catch or use asyncHandler wrapper

# Global handler missing
grep -rn "process\.on.*unhandledRejection\|process\.on.*uncaughtException" --include="*.{js,ts}" .
```

### Missing Rate Limiting on Error-Prone Endpoints
```bash
grep -rn "rateLimit\|throttle\|limiter" --include="*.{js,ts}" .
# Endpoints that can trigger expensive operations (file uploads, report generation, email send)
# should be rate-limited to prevent DoS via exception storms
```

## Prevention Checklist

- [ ] Error handlers return generic messages to users; stack traces logged server-side only
- [ ] Auth/permission checks fail closed (deny on error, never grant)
- [ ] Database connections released in `finally` blocks
- [ ] File handles closed on exception (try/finally or using-statement)
- [ ] Multi-step mutations wrapped in database transactions with rollback
- [ ] Temp files cleaned up on error
- [ ] Async route handlers have try/catch or error wrapper
- [ ] Global unhandledRejection / uncaughtException handlers log and alert
- [ ] NULL/undefined checks before accessing properties in critical paths
- [ ] TOCTOU race conditions mitigated with atomic operations or advisory locks
- [ ] Rate limiting on expensive operations to prevent exception-storm DoS
- [ ] Repeated identical errors aggregated (alert on pattern, not every instance)
- [ ] Observability tooling (Sentry, Datadog, etc.) captures unhandled exceptions
