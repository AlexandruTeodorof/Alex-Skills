# A09:2025 — Security Logging and Alerting Failures

**OWASP Position:** #9 (maintained, renamed from "Logging and Monitoring Failures" to emphasize alerting)
**Incidence:** Low CVE count (723) but high operational impact — breaches go undetected for years

## What It Is

The absence of comprehensive logging, monitoring, and alerting makes it impossible to detect attacks in progress, understand post-incident timelines, or meet regulatory requirements. Real-world breaches: 3.5M children's health records undetected for 7 years; airline breached for 10+ years; GDPR fine of £20M for 400K payment records exposed.

## What to Look For

### No Logging of Auth Events
```bash
grep -rn "login\|signin\|logout\|signout\|register\|signup" --include="*.{js,ts,py,php,rb}" .
# Verify each flow logs: who attempted, from what IP, success/failure, timestamp
grep -rn "logger\.\|log\.\|console\.\|logging\.\|winston\|pino\|bunyan" --include="*.{js,ts}" .
```

### No Logging of Authorization Failures
```bash
grep -rn "403\|forbidden\|unauthorized\|permission.*denied\|access.*denied" \
  --include="*.{js,ts,py,php,rb}" .
# Each should log: userId, resource attempted, timestamp, IP
```

### No Logging of High-Value Business Events
```bash
grep -rn "payment\|transfer\|delete.*account\|admin.*action\|export\|download" \
  --include="*.{js,ts,py,php,rb}" .
# These should have structured audit log entries
```

### Sensitive Data in Logs
```bash
# Password in logs
grep -rn "log.*password\|logger.*password\|console.*password\|print.*password" \
  --include="*.{js,ts,py,php,rb}" .

# PII in logs
grep -rn "log.*email\|log.*phone\|log.*ssn\|log.*credit.card\|log.*token" \
  --include="*.{js,ts,py,php,rb}" .
```

Vulnerable:
```javascript
// BAD: logs the full request body (may contain password, payment data)
logger.info('Login attempt', { body: req.body });

// GOOD: log only safe fields
logger.info('Login attempt', { username: req.body.username, ip: req.ip });
```

### Log Injection
```bash
# User input directly in log message without encoding
grep -rn "logger\..*req\.\|log\..*req\.\|console\..*req\." --include="*.{js,ts,py}" .
# If user input like "\n[CRITICAL] Admin logged in" reaches the log, it can fake log entries
```

Vulnerable vs. safe:
```javascript
// BAD: newlines in user input corrupt log structure
logger.info(`User action: ${req.body.action}`);

// GOOD: structured logging — user data is a field, not part of the message
logger.info('User action', { action: req.body.action, userId: req.user.id });
```

### No Structured / Machine-Parseable Logs
```bash
grep -rn "console\.log\b" --include="*.{js,ts}" . | wc -l
# High console.log usage suggests ad-hoc logging, not structured log management
# Check: is JSON structured logging used? (winston JSON format, pino, etc.)
```

### No Alerting / Monitoring Integration
```bash
grep -rn "sentry\|datadog\|newrelic\|cloudwatch\|grafana\|prometheus\|alertmanager\|pagerduty" \
  --include="*.{js,ts,py,php,json,yaml}" .
# No monitoring integration means breaches go undetected
```

### Missing Rate-Limit / Brute Force Detection
- Even if logging exists, is there automated alerting when login failures spike?
- Is there detection for credential stuffing patterns (many accounts, same IP)?

## Audit Log Requirements by Event Type

| Event | Required Log Fields |
|-------|-------------------|
| Login success/failure | userId/username, IP, user-agent, timestamp, result |
| Password reset | userId, IP, timestamp, token issued |
| Authorization failure | userId, resource, action, IP, timestamp |
| Admin action | adminId, action, target, before/after values, timestamp |
| High-value transaction | userId, amount, target, result, timestamp |
| Data export | userId, dataset, record count, timestamp |
| Account creation/deletion | actorId, targetId, IP, timestamp |
| Config change | adminId, setting, old value, new value, timestamp |

## Prevention Checklist

- [ ] All auth events logged (login success, failure, logout, lockout)
- [ ] Authorization failures logged with user + resource context
- [ ] High-value transactions have audit log entries
- [ ] No passwords, tokens, or payment data in logs
- [ ] No PII (email, phone, SSN) in logs (or pseudonymized)
- [ ] Structured/JSON logging — machine parseable
- [ ] Logs shipped to centralized log management (not just local files)
- [ ] Append-only audit logs with tamper protection
- [ ] Alerting configured for: repeated auth failures, authorization failures spike, anomalous access patterns
- [ ] Log injection prevented — user data as structured fields, not string interpolation
- [ ] Log retention policy defined and implemented (regulatory minimum, typically 90 days–2 years)
- [ ] Logs reviewed as part of incident response runbook
