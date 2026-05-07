# A01:2025 — Broken Access Control

**OWASP Position:** #1 (maintained from 2021)
**Incidence:** 100% of tested applications had some form; 1.8M+ occurrences; 40 mapped CWEs

## What It Is

Access control enforces the policy that users cannot act outside their intended permissions. Failures allow attackers to access unauthorized functionality or data, modify or destroy data, or perform business functions beyond their role.

## What to Look For

### Missing Authorization Checks
```bash
# Find route handlers without auth middleware
grep -rn "router\.\(get\|post\|put\|delete\|patch\)" --include="*.js" --include="*.ts" .
# Then verify each one has auth guard above it
```

### Insecure Direct Object References (IDOR)
Look for patterns where user-supplied IDs are used without ownership verification:
```typescript
// VULNERABLE: uses ID from request without verifying ownership
const record = await db.query(`SELECT * FROM records WHERE id = ${req.params.id}`);

// SAFE: verifies the record belongs to the authenticated user
const record = await db.query(
  'SELECT * FROM records WHERE id = $1 AND user_id = $2',
  [req.params.id, req.user.id]
);
```

### CORS Misconfiguration
```bash
grep -rn "Access-Control-Allow-Origin" --include="*.{js,ts,py,php}" .
grep -rn "cors(" --include="*.{js,ts}" .
# Watch for: '*' or dynamic origin reflection without allowlist
```

### Privilege Escalation via Parameter Tampering
```bash
grep -rn "role\|isAdmin\|is_admin\|permission" --include="*.{js,ts,py,php}" .
# Check if role/permission values come from request body/params vs. server-side session
```

### Forced Browsing to Admin Routes
- Check if admin routes are protected beyond just hiding them from navigation
- Look for role checks on all admin API endpoints

### JWT / Token Manipulation
```bash
grep -rn "jwt\|decode\|verify" --include="*.{js,ts}" .
# Ensure jwt.verify() is called, not just jwt.decode()
# Check 'algorithm' parameter is not 'none'
```

## Common Vulnerable Patterns

```javascript
// BAD: No ownership check
app.delete('/api/posts/:id', auth, async (req, res) => {
  await Post.delete(req.params.id); // anyone can delete any post
});

// GOOD: Scoped to authenticated user
app.delete('/api/posts/:id', auth, async (req, res) => {
  const deleted = await Post.delete({ id: req.params.id, userId: req.user.id });
  if (!deleted) return res.status(403).send('Forbidden');
});
```

```javascript
// BAD: Admin check client-side only
if (user.isAdmin) renderAdminButton(); // UI-only guard, backend unprotected

// GOOD: Server-side check on every request
app.get('/admin/stats', requireAdmin, async (req, res) => { ... });
```

## Prevention Checklist

- [ ] Deny-by-default — all resources require explicit authorization
- [ ] Access control logic lives server-side; client side is UI only
- [ ] Record ownership verified on every read/write/delete (`.eq('user_id', userId)`)
- [ ] CORS origin allowlist, not wildcard `*` for credentialed requests
- [ ] Rate limiting on all API endpoints
- [ ] Session tokens invalidated server-side after logout
- [ ] Authorization failures logged and monitored
- [ ] Access control tested in unit/integration tests (not just happy path)
- [ ] JWT: `algorithm` explicitly set, `aud`/`iss` claims validated
