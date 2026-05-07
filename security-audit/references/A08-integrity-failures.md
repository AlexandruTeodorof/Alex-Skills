# A08:2025 — Software or Data Integrity Failures

**OWASP Position:** #8
**Distinction from A03:** A03 = supply chain (external dependencies); A08 = integrity verification failures at runtime — trusting unverified updates, unsigned code, insecure deserialization, and crossing untrusted boundaries

## What It Is

Failures to maintain integrity of software, code, and data artifacts in the running application. Includes auto-update without verification, loading plugins from untrusted CDNs, and deserializing attacker-controlled data.

## What to Look For

### Unsafe Deserialization
```bash
# Java
grep -rn "ObjectInputStream\|readObject\|deserialize\|fromXML\|XStream" \
  --include="*.java" .

# Python — unsafe deserialization functions
grep -rn "pickle\.loads\|pickle\.load\|marshal\.loads" --include="*.py" .

# yaml.load without Loader argument is unsafe — use yaml.safe_load() instead
grep -rn "yaml\.load(" --include="*.py" .

# PHP
grep -rn "unserialize(" --include="*.php" .

# Ruby
grep -rn "Marshal\.load\|YAML\.load(" --include="*.rb" .

# Node.js — dynamic function construction from untrusted strings
grep -rn "Function\s*(" --include="*.{js,ts}" . | grep -v "//\|Arrow\|Anonymous\|callback"
```

**Why dangerous:** `pickle.loads()` deserializes arbitrary Python objects — an attacker who controls the bytes can achieve Remote Code Execution. Same for Java's `ObjectInputStream`, PHP's `unserialize()`, and Ruby's `Marshal.load()`.

Safe alternatives:
```python
# SAFE: JSON for data exchange — only deserializes primitive types
import json
data = json.loads(user_supplied_string)

# SAFE: yaml.safe_load — restricts to basic types only
import yaml
data = yaml.safe_load(content)
```

```java
// SAFE: use JSON/protobuf instead of Java object serialization
// For Java 9+: ObjectInputFilter can whitelist allowed classes if Java deserialization is required
```

### Auto-Update Without Integrity Verification
```bash
# Check for update/download mechanisms
grep -rn "download\|auto.updat\|fetch.*install" \
  --include="*.{js,ts,py,sh,bash}" . | grep -v "node_modules\|\.git"

# Verify downloaded content has checksum/signature verification
grep -rn "sha256\|checksum\|verify.*signature\|gpg.*verify" --include="*.{sh,py,js}" .
```

### Untrusted CDN Resources Without Subresource Integrity (SRI)
```bash
# Script/link tags without integrity attribute
grep -rn '<script.*src=.*cdn\|<link.*href=.*cdn' --include="*.{html,ejs,hbs,blade.php}" .
# Each external CDN resource should have: integrity="sha384-..." crossorigin="anonymous"
```

**Vulnerable pattern:**
```html
<!-- No SRI — if CDN is compromised, attacker controls your JS -->
<script src="https://cdn.example.com/library.min.js"></script>
```

**Safe pattern:**
```html
<!-- SRI hash pins the exact file content — any modification fails the browser check -->
<script 
  src="https://cdn.example.com/library.min.js"
  integrity="sha384-abc123..."
  crossorigin="anonymous">
</script>
```

### Untrusted Cookie Data Used in Business Logic
```bash
# Base64-encoded objects in cookies (classic deserialization vector in Rails/Java/PHP)
grep -rn "cookie.*base64\|base64.*decode.*cookie\|request\.cookies" \
  --include="*.{js,ts,py,php,rb}" .
# Verify cookie data is HMAC-signed and never trusted directly for auth decisions
```

### Dynamic Code Construction from Data
```bash
# Building executable code from untrusted strings — serious code injection risk
grep -rn "Function\s*(" --include="*.{js,ts}" .
# Verify: is any user-supplied or external data passed as the function body string?
```

### Untrusted Third-Party Infrastructure
```bash
# Check if any domain redirects through external providers
grep -rn "proxy_pass\|CNAME\|forwarded.*to" --include="*.{conf,nginx.conf,yaml,yml}" .
# Auth cookies set on a parent domain propagate to all subdomains — verify subdomain trust boundaries
```

## CI/CD Pipeline Integrity

```bash
# GitHub Actions: third-party actions without SHA pinning
grep -rn "uses:" .github/workflows/*.yml 2>/dev/null | grep -v "actions/" | head -20
# Third-party actions should reference an immutable commit SHA, not a mutable tag
```

```yaml
# VULNERABLE: tag can be overwritten to point to malicious code
# - uses: some-third-party/action@v2

# SAFE: immutable SHA — attacker cannot change what this resolves to
- uses: some-third-party/action@1a4442cacd436585916779262731d1f68d8b3c56
```

Check also:
- Are build artifacts (Docker images, npm packages) signed?
- Is there separation of duties? (can a developer approve their own deployment?)
- Are pipeline secrets scoped with minimal permissions?

## Prevention Checklist

- [ ] No `pickle.loads()` / `Marshal.load()` / `unserialize()` on untrusted data
- [ ] Use `yaml.safe_load()` (Python) instead of `yaml.load()`
- [ ] Avoid Java `ObjectInputStream.readObject()` for untrusted data; use JSON/protobuf
- [ ] External CDN resources have SRI hashes (`integrity=` attribute)
- [ ] Auto-update mechanisms verify signatures/checksums before applying
- [ ] Cookies used for business logic are cryptographically HMAC-signed
- [ ] CI/CD pipeline: third-party actions pinned to commit SHA
- [ ] Build artifacts signed; promotion-based deployment (don't rebuild per environment)
- [ ] No untrusted infrastructure in authentication cookie scope chain
- [ ] Dynamic function construction never accepts user-supplied strings as function body
