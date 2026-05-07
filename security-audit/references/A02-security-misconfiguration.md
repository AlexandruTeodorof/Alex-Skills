# A02:2025 — Security Misconfiguration

**OWASP Position:** #2 (up from #5 in 2021)
**Incidence:** 100% of applications; avg 3.00%; 719,000+ CWE occurrences

## What It Is

Security misconfiguration results from missing security hardening, improper cloud permissions, enabled unnecessary features, unchanged defaults, excessive error verbosity, or disabled security features in upgraded systems.

## What to Look For

### Default or Weak Credentials
```bash
grep -rn "admin\|password\|changeme\|default" --include="*.{env,yaml,yml,json,conf,config}" .
grep -rn "username.*admin\|password.*admin\|secret.*changeme" --include="*.{js,ts,py,php}" .
```

### Exposed Stack Traces and Debug Information
```bash
# Node.js / Express
grep -rn "res\.send(err\|res\.json(err\|console\.error(err" --include="*.{js,ts}" .
# Python
grep -rn "debug\s*=\s*True\|DEBUG\s*=\s*True" --include="*.py" --include="*.cfg" .
# Generic
grep -rn "display_errors\s*=\s*On\|stack.*trace.*true" --include="*.{php,ini,conf}" .
```

### Missing Security Headers
```bash
grep -rn "helmet\|Content-Security-Policy\|X-Frame-Options\|HSTS\|Strict-Transport-Security" \
  --include="*.{js,ts}" .
# If helmet (Node) or equivalent is missing, security headers are likely absent
```

### Unnecessary Features / Services Enabled
- Check for sample/test routes left in production code
- Check for debug endpoints (`/debug`, `/__debug__`, `/phpinfo`, `/admin/test`)
- Check for directory listing enabled in web server configs

### Cloud / Infrastructure Misconfig
```bash
# AWS-style config checks
grep -rn "\"*\"" --include="*.json" . | grep -i "Principal\|Action\|Resource"
# Look for S3 buckets set to public, overly permissive IAM policies
grep -rn "public-read\|public-read-write\|authenticated-read" --include="*.{json,yaml,yml,tf}" .
```

### Insecure Cookie Configuration
```bash
grep -rn "cookie\|session" --include="*.{js,ts}" .
# Missing: httpOnly: true, secure: true, sameSite: 'strict' or 'lax'
```

### Environment-Specific Settings in Production
```bash
grep -rn "NODE_ENV\|APP_ENV\|FLASK_ENV\|RAILS_ENV" --include="*.{js,ts,py,rb}" .
# Verify debug mode cannot be enabled in production
```

## Common Vulnerable Patterns

```javascript
// BAD: sends error details to client
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

// GOOD: generic message, log internally
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(500).json({ error: 'Internal server error' });
});
```

```javascript
// BAD: no security headers
const app = express();

// GOOD: helmet sets sane defaults
const app = express();
app.use(helmet());
```

## Prevention Checklist

- [ ] Repeatable hardening process (dev = staging = production configurations)
- [ ] Minimal platform — remove unused features, ports, samples, documentation
- [ ] Default credentials changed everywhere (databases, admin panels, services)
- [ ] Error messages generic to users; detailed errors logged server-side only
- [ ] Security headers set (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- [ ] Cloud storage/service permissions reviewed and restricted
- [ ] Environment configs reviewed as part of patch management
- [ ] Cookie flags: `httpOnly`, `secure`, `sameSite`
- [ ] No debug/test endpoints in production
- [ ] Automated config verification across environments
