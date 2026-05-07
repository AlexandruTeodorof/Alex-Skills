# A04:2025 — Cryptographic Failures

**OWASP Position:** #4 (down from #2 in 2021)
**Focus:** Absent or weak cryptography, compromised keys, implementation errors

## What It Is

Failures related to cryptography (or lack thereof) that expose sensitive data. Includes using weak/outdated algorithms, missing encryption at rest or in transit, hardcoded keys, weak password hashing, and poor key management.

## What to Look For

### Hardcoded Secrets and Keys
```bash
# Broad secret scan
grep -rn --include="*.{js,ts,py,php,rb,go,java,env,yaml,yml,json}" \
  -E "(password|passwd|secret|api_key|apikey|access_key|private_key|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]" \
  . --exclude-dir={node_modules,.git,dist,build,vendor}

# Check .env files committed to git history
git log --all --full-history -- "**/.env" "**/.env.*" 2>/dev/null | head -20

# AWS credentials
grep -rn "AKIA[0-9A-Z]{16}\|aws_access_key_id\|aws_secret_access_key" . \
  --exclude-dir={node_modules,.git}
```

### Weak Hashing Algorithms
```bash
# MD5 usage (broken for security purposes)
grep -rn "md5\|MD5\|createHash('md5')" --include="*.{js,ts,py,php,rb}" .

# SHA1 for passwords (insufficient)
grep -rn "sha1\|SHA1\|createHash('sha1')" --include="*.{js,ts,py,php,rb}" .

# Python: hashlib with weak algorithms
grep -rn "hashlib\.md5\|hashlib\.sha1" --include="*.py" .

# PHP: password_hash with PASSWORD_MD5
grep -rn "PASSWORD_MD5\|md5(\$" --include="*.php" .
```

### Passwords Stored Without Proper Hashing
```bash
# Looking for plain storage or weak hashing of passwords
grep -rn "password.*=.*req\.\|password.*=.*request\." --include="*.{js,ts,py,php}" .
# Verify bcrypt/argon2/scrypt is used, not md5/sha1/sha256 directly
grep -rn "bcrypt\|argon2\|scrypt\|pbkdf2" --include="*.{js,ts,py,php,rb}" .
```

### Missing TLS / HTTP Connections
```bash
# HTTP (not HTTPS) in URLs
grep -rn '"http://' --include="*.{js,ts,py,php,rb,go,java}" . \
  --exclude-dir={node_modules,test,__tests__,spec}
# Exclude localhost/127.0.0.1 results as those are expected in dev
```

### Weak Random Number Generation
```bash
# Non-cryptographic random for tokens/keys
grep -rn "Math\.random()\|random\.random()\|rand()" --include="*.{js,ts,py,php}" .
# For security purposes, use crypto.randomBytes() / secrets.token_hex() / openssl_random_pseudo_bytes()
```

### ECB Mode or Deprecated Crypto
```bash
grep -rn "ECB\|createCipher\b\|DES\|RC4\|3DES\|TripleDES" --include="*.{js,ts,py,php,rb}" .
# createCipher (deprecated Node.js) - no IV, vulnerable
# AES-ECB leaks block patterns
```

### Missing Certificate Validation
```bash
grep -rn "verify\s*=\s*False\|rejectUnauthorized\s*:\s*false\|InsecureRequestWarning\|DISABLE_SSL" \
  --include="*.{js,ts,py,php,rb}" .
```

## Common Vulnerable Patterns

```javascript
// BAD: MD5 for password (broken)
const hash = crypto.createHash('md5').update(password).digest('hex');

// BAD: SHA256 without salt (rainbow table vulnerable)
const hash = crypto.createHash('sha256').update(password).digest('hex');

// GOOD: bcrypt with salt rounds
const hash = await bcrypt.hash(password, 12);
```

```javascript
// BAD: Math.random() for tokens
const token = Math.random().toString(36).substring(2);

// GOOD: cryptographically secure
const token = crypto.randomBytes(32).toString('hex');
```

```python
# BAD: hardcoded secret
SECRET_KEY = "my-secret-key-123"

# GOOD: from environment
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY env var not set")
```

## Prevention Checklist

- [ ] No hardcoded secrets, API keys, or passwords in source code
- [ ] `.env` and secret files in `.gitignore`; check git history for past leaks
- [ ] Passwords hashed with Argon2id, bcrypt (≥12 rounds), scrypt, or PBKDF2-HMAC-SHA-512
- [ ] All sensitive data encrypted at rest
- [ ] TLS 1.2+ enforced; no HTTP for sensitive data; HSTS header set
- [ ] No MD5 / SHA1 for security purposes; use SHA-256+ for non-password hashing
- [ ] Cryptographic keys generated randomly; stored in environment or secrets manager (not source code)
- [ ] CSPRNG used for tokens: `crypto.randomBytes()`, `secrets.token_hex()`, etc.
- [ ] No ECB mode; use GCM or CBC with authenticated encryption
- [ ] Certificate validation not disabled (no `verify=False`, no `rejectUnauthorized: false`)
- [ ] Consider post-quantum cryptography migration path (PQC standards due by 2030)
