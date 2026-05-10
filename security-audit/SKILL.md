---
name: security-audit
description: Performs comprehensive OWASP ASVS v5 security audits on any codebase (supersedes OWASP Top 10). ALWAYS invoke when the user asks to: review code for security issues, perform a security audit, find vulnerabilities or security weaknesses, check for security improvements, check for CVEs, do a pentest review, or uses words like "audit", "vulnerabilities", "security review", "security check", "secure code", "harden", or "penetration test". Also invoke for any general "code review" request — security is part of every good code review.
---

# Security Audit Skill — OWASP ASVS v5

Perform a comprehensive security audit aligned to **OWASP ASVS v5** (Application Security Verification Standard).

The full requirement set lives at: `references/asvs-v5-en.csv` (columns: chapter_id, chapter_name, section_id, section_name, req_id, req_description, L where L=1/2/3).

Produce a structured report at `$PROJECT_ROOT/audit/[YYYY-MM-DD]/security-audit-report.md`.

---

## Step 0: Capture Project Root

```bash
PROJECT_ROOT=$(pwd)
echo "Auditing project at: $PROJECT_ROOT"
```

All file paths use `$PROJECT_ROOT` as the base. Never use a relative path.

---

## Step 1: Project Setup

If source code exists (package.json, requirements.txt, go.mod, pom.xml, Cargo.toml, or any .js/.ts/.py/.php/.rb/.java/.go), proceed to Step 2.
If no code found, ask for a GitHub URL and clone it.

---

## Step 2: Reconnaissance + Stack Detection

Run all of these in parallel:

1. **Identify the stack** — check package.json, requirements.txt, go.mod, composer.json, Cargo.toml. Read package.json dependencies.
2. **Map the attack surface** — list API endpoints, auth flows, file upload handlers, DB interaction points, external integrations.
3. **Automated Semgrep scan** — run `mcp__plugin_semgrep_semgrep__semgrep_scan` on the project root with auto-detected rules. Capture all findings.
4. **Secrets scan**:
   ```bash
   grep -rn --include="*.{js,ts,py,php,rb,go,java,env,yml,yaml,toml}" \
     -E "(password|secret|api_key|apikey|token|private_key|client_secret)\s*[=:]\s*['\"][^'\"]{8,}" \
     "$PROJECT_ROOT" --exclude-dir={node_modules,.git,dist,build,.next}
   ```
5. **Determine audit level** — default is **L1+L2**. User requesting deep audit: use **L1+L2+L3**.

---

## Step 3: Stack-Aware ASVS Chapter Selection

Read `references/asvs-v5-en.csv`. Filter chapters by stack relevance:

| Chapter | Name | Skip when |
|---------|------|-----------|
| V1 | Encoding and Sanitization | Never skip |
| V2 | Validation and Business Logic | Never skip |
| V3 | Web Frontend Security | Pure API/CLI projects |
| V4 | API and Web Service | Pure frontend with no API |
| V5 | File Handling | No file upload features found |
| V6 | Authentication | Never skip |
| V7 | Session Management | Never skip |
| V8 | Authorization | Never skip |
| V9 | Self-contained Tokens | No JWT/SAML found |
| V10 | OAuth and OIDC | No OAuth flows found |
| V11 | Cryptography | Never skip |
| V12 | Secure Communication | TLS entirely delegated to platform (Vercel/AWS) |
| V13 | Configuration | Never skip |
| V14 | Data Protection | Never skip |
| V15 | Secure Coding and Architecture | Never skip |
| V16 | Security Logging and Error Handling | Never skip |
| V17 | WebRTC | Only if WebRTC/TURN code found |

Document which chapters were skipped and why in the report.

---

## Step 4: ASVS Chapter Audits

For each selected chapter:
1. Filter `references/asvs-v5-en.csv` to that chapter at the audit level (L≤2 by default).
2. Batch similar requirements into single code searches — do not check each of the 346 requirements individually.
3. Document findings with the ASVS requirement ID (e.g., `V1.2.4`), severity, and evidence.

---

### V1 — Encoding and Sanitization

**L1 batch — injection sinks.** Search for:
- Raw HTML output properties and methods that bypass the DOM (the React prop for raw HTML, innerHTML assignment, document.write)
- Dynamic code execution: the Function constructor called with string arguments, indirect eval calls
- Dynamic SQL built via template literals (SELECT/INSERT/UPDATE/DELETE keywords concatenated with `${}`)
- Process execution APIs used with user-controlled arguments (execSync, spawnSync, child_process module imports — flag every call site, verify args are NOT user-supplied)

```bash
grep -rn --include="*.{ts,tsx,js,jsx}" \
  -E "innerHTML\s*=|document\.write\(" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js,py,php,rb}" \
  -E "SELECT.*\$\{|INSERT.*\$\{|UPDATE.*\$\{|DELETE.*\$\{" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

**L2 batch — SSRF:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "new URL\(.*req\.|fetch\(.*req\." \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

Key ASVS items: V1.2.1 (output encoding), V1.2.4 (parameterized queries), V1.2.5 (OS command injection), V1.3.1 (HTML sanitization library), V1.3.2 (no dynamic code eval with user input), V1.3.6 (SSRF), V1.5.1 (XXE)

---

### V2 — Validation and Business Logic

**L1 — server-side validation:** For each exported server action / route handler, verify a Zod/yup/joi `.parse()` exists before any DB access.

```bash
grep -rn --include="*.{ts,js}" \
  -E "export\s+(async\s+)?function\s+(action|POST|PUT|PATCH|DELETE|GET)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js}" \
  -E "\.parse\(|\.safeParse\(|z\.object\(" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

**L2 — business logic:** Review transaction-critical flows (payment, booking) for step-skipping; check race conditions on limited-resource operations.

Key ASVS items: V2.2.1 (allowlist validation), V2.2.2 (server-side enforcement), V2.3.1 (sequential step order), V2.3.3 (atomic transactions), V2.4.1 (anti-automation)

---

### V3 — Web Frontend Security

**L1 — headers and cookies:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "Set-Cookie|cookies\(\)\.set\(" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js,mjs}" \
  -E "Strict-Transport-Security|Content-Security-Policy|X-Content-Type-Options|Referrer-Policy|frame-ancestors" \
  "$PROJECT_ROOT" --exclude-dir={node_modules,.next,.git}
```

**L2 — CSP and CORS:**
```bash
grep -rn --include="*.{ts,js,mjs}" \
  -E "Access-Control-Allow-Origin|cors\(|object-src|base-uri" \
  "$PROJECT_ROOT" --exclude-dir={node_modules,.next,.git}
```

Key ASVS items: V3.3.1 (Secure cookie attr), V3.3.2 (SameSite), V3.3.4 (HttpOnly), V3.4.1 (HSTS ≥1yr), V3.4.2 (CORS allowlist), V3.4.3 (CSP with object-src/base-uri none), V3.4.4 (X-Content-Type-Options: nosniff), V3.5.1 (CSRF), V3.5.3 (safe HTTP methods for mutations)

---

### V4 — API and Web Service

**L1:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "NextResponse\.json|Response\.json|res\.json\(" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js}" \
  -E "req\.method|request\.method" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

Key ASVS items: V4.1.1 (Content-Type with charset), V4.1.4 (only allowed HTTP methods), V4.2.1 (request smuggling), V4.4.1 (WebSocket over WSS/TLS only)

---

### V5 — File Handling *(skip if no uploads)*

**L1:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "formData\(\)|multipart|createWriteStream" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js}" \
  -E "path\.(join|resolve)\(.*req\." \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

Key ASVS items: V5.2.1 (max file size), V5.2.2 (type validation + magic bytes), V5.3.1 (no server execution of uploaded files), V5.3.2 (no path traversal), V5.4.1 (Content-Disposition on downloads)

---

### V6 — Authentication

**L1:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "signIn|login|authenticate|verifyPassword" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

# KDF for password storage (absence is a High finding)
grep -rn --include="*.{ts,js,py}" \
  -E "bcrypt|argon2|scrypt|pbkdf2" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules

# Weak hash for passwords
grep -rn --include="*.{ts,js,py}" \
  -E "createHash\('md5'\)|createHash\('sha1'\)" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules
```

**L2 — MFA:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "totp|mfa|two.?factor|otp|authenticator" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules
```

Key ASVS items: V6.2.1 (min 8 chars), V6.2.6 (type=password), V6.3.1 (rate limiting), V6.3.2 (no defaults), V6.3.3 (MFA for L2+), V6.4.1 (secure initial passwords), V6.4.2 (no secret questions)

---

### V7 — Session Management

**L1:**
```bash
# Non-CSPRNG for tokens
grep -rn --include="*.{ts,js}" \
  -E "Math\.random\(\).*token|Date\.now\(\).*session" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

# Session invalidation
grep -rn --include="*.{ts,js}" \
  -E "signOut|logout|destroySession|invalidateSession" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

Key ASVS items: V7.2.2 (dynamic tokens), V7.2.3 (≥128-bit entropy CSPRNG), V7.2.4 (new session on auth), V7.4.1 (invalidate on logout/expiry), V7.4.2 (terminate on account disable), V7.3.1 (inactivity timeout)

---

### V8 — Authorization

**L1 — IDOR/missing guards:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "params\.(id|userId|eventId|recordId)|searchParams\.get\('id'\)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
# For each: confirm ownership check precedes DB call

grep -rn -B2 -A15 --include="*.{ts,js}" \
  -E "'use server'" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
# Verify: getCurrentUser() + hasPermission() before any DB write
```

**L2:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "\.select\(\)" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules
```

Key ASVS items: V8.2.1 (function-level access control), V8.2.2 (IDOR/BOLA), V8.2.3 (field-level BOPLA), V8.3.1 (trusted-layer enforcement), V8.3.2 (immediate authorization changes)

---

### V9 — Self-contained Tokens *(skip if no JWT/SAML)*

```bash
grep -rn --include="*.{ts,js}" \
  -E "jwt\.sign|jwt\.verify|jsonwebtoken|jose\." \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules
# Check: algorithm allowlist, 'none' rejected, signature verified before payload is trusted
```

Key ASVS items: V9.1.1 (validate signature/MAC), V9.1.2 (algorithm allowlist, no 'none'), V9.1.3 (trusted key sources only), V9.2.1 (nbf/exp validity), V9.2.2 (token type check)

---

### V10 — OAuth and OIDC *(skip if no OAuth)*

```bash
grep -rn --include="*.{ts,js}" \
  -E "oauth|oidc|redirect_uri|code_verifier|PKCE" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules
# Check: PKCE present, state validated, redirect URIs exact-matched, no implicit grant
```

Key ASVS items: V10.2.1 (CSRF on code flow — PKCE or state), V10.4.1 (redirect URI exact allowlist), V10.4.2 (one-time codes), V10.4.3 (codes expire ≤10min), V10.4.4 (no implicit/ROPC), V10.4.6 (PKCE required, no plain method)

---

### V11 — Cryptography

**L1:**
```bash
# Weak hash algorithms
grep -rn --include="*.{ts,js,py}" \
  -E "createHash\('md5'\)|createHash\('sha1'\)" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules

# Weak cipher modes
grep -rn --include="*.{ts,js,py}" \
  -E "'ECB'|\"ECB\"|DES\b|RC4" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules

# Non-CSPRNG usage
grep -rn --include="*.{ts,js}" \
  -E "Math\.random\(\)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

**L2:**
```bash
# KDF presence for password storage
grep -rn --include="*.{ts,js,py}" \
  -E "bcrypt|argon2|scrypt|pbkdf2" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules
```

Key ASVS items: V11.3.1 (no ECB/weak padding), V11.3.2 (AES-GCM or equivalent), V11.4.1 (no MD5/SHA1 for security ops), V11.4.2 (password KDF with work factor), V11.5.1 (CSPRNG ≥128-bit entropy)

---

### V13 — Configuration

**L1:**
```bash
grep -rn --include="*.{ts,js,py,env,yml}" \
  -E "DEBUG\s*=\s*true|NODE_ENV.*development" \
  "$PROJECT_ROOT" --exclude-dir={node_modules,.git,.next}

grep -rn --include="*.{ts,js,tsx}" \
  -E "NEXT_PUBLIC_.*(KEY|SECRET|PASSWORD|TOKEN)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

ls -la "$PROJECT_ROOT/.git" 2>/dev/null && echo ".git present — verify not web-accessible"
```

**L2:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "SUPABASE_SERVICE_ROLE|DATABASE_URL|createServiceClient" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js}" \
  -E "fetch\(|axios\." \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
# Verify external fetch URLs come from allowlist, not user input
```

Key ASVS items: V13.3.1 (secrets in vault/env, not source), V13.4.1 (no .git web-exposure), V13.4.2 (no debug in prod), V13.2.1 (service auth, not shared creds), V13.2.2 (least privilege), V13.2.4 (outbound allowlist)

---

### V14 — Data Protection

**L1:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "searchParams\.(set|append)\(.*(?:token|key|password|secret)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

**L2:**
```bash
grep -rn --include="*.{ts,js}" \
  -E "Cache-Control|no-store" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,tsx,js,jsx}" \
  -E "localStorage\.(setItem|getItem)|sessionStorage\.(setItem|getItem)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
# Tokens/passwords must NOT be stored in browser storage
```

Key ASVS items: V14.2.1 (no secrets in URLs), V14.3.1 (clear auth data on session end), V14.3.2 (Cache-Control: no-store), V14.3.3 (no sensitive data in browser storage), V14.2.6 (data minimization)

---

### V15 — Secure Coding and Architecture

**L1:**
```bash
cd "$PROJECT_ROOT" && npm audit 2>&1 | grep -E "critical|high" | head -20
```

**L2:**
```bash
# Mass assignment / prototype pollution vectors
grep -rn --include="*.{ts,js}" \
  -E "Object\.assign\(.*req\.|\.\.\.req\.(body|query|params)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

grep -rn --include="*.{ts,js}" \
  -E "\.insert\(req\.body\)|\.update\(req\.body\)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

# Wildcard selects (over-exposure)
grep -rn --include="*.{ts,js}" \
  -E "\.select\(\)$" \
  "$PROJECT_ROOT/src" --exclude-dir=node_modules

# Loose equality
grep -rn --include="*.{ts,js}" \
  -E "[^=!]==[^=]" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next} | head -20
```

Key ASVS items: V15.2.1 (no outdated vulnerable deps), V15.3.1 (return only required fields), V15.3.3 (mass assignment protection), V15.3.5 (strict type checking), V15.3.6 (prototype pollution prevention)

---

### V16 — Security Logging and Error Handling

**L2:**
```bash
# Auth events — check they're logged
grep -rn --include="*.{ts,js}" \
  -E "signIn|signOut|login|logout|authError|authFailed" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

# Stack traces forwarded to client
grep -rn --include="*.{ts,js}" \
  -E "error\.stack|err\.stack" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}

# Sensitive values in log calls
grep -rn --include="*.{ts,js}" \
  -E "console\.(log|error|warn).*(?:password|secret|key|credit)" \
  "$PROJECT_ROOT/src" --exclude-dir={node_modules,.next}
```

Key ASVS items: V16.2.1 (log who/what/when/where), V16.3.1 (log all auth events), V16.3.2 (log failed authorization), V16.4.1 (prevent log injection), V16.5.1 (generic error messages to client), V16.5.3 (fail closed)

---

## Step 5: Generate the Report

```bash
mkdir -p "$PROJECT_ROOT/audit/$(date +%Y-%m-%d)"
```

Write to `$PROJECT_ROOT/audit/YYYY-MM-DD/security-audit-report.md`:

```markdown
# Security Audit Report

**Project:** [project name or repo URL]
**Date:** [YYYY-MM-DD]
**Auditor:** Claude Security Audit (OWASP ASVS v5)
**Audit Level:** L1+L2 (default) / L1+L2+L3 (comprehensive)
**Stack:** [detected tech stack]
**Chapters audited:** [list] | **Chapters skipped:** [list + reason]

---

## Executive Summary

[2–3 sentences: overall posture, critical findings, immediate priorities]

### Risk Overview

| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |
| Info     | N |

---

## Findings

### [SEVERITY] [Vx.y.z] — [Short descriptive title]

**Severity:** Critical / High / Medium / Low / Info
**ASVS:** [req_id] — [section_name]
**OWASP Top 10 (2025):** A0X (if applicable)
**Affected:** `path/to/file.ts:42`
**CWE:** CWE-XXX (if applicable)

**Description:** What the vulnerability is and why it matters in this context.

**Evidence:** [Code snippet or grep output]

**Suggested Fix:** Actionable recommendation with safe code example.

---

[Repeat, ordered Critical → High → Medium → Low → Info]

---

## Chapter Results

| Chapter | Requirements Checked | Findings | Status |
|---------|---------------------|----------|--------|
| V1 Encoding & Sanitization | L1+L2 (N reqs) | N | ✅ / ⚠️ |
| ... | | | |

---

## Passed Checks (notable)

List significant checks that passed.

---

## Recommended Next Steps

1. [Highest priority — link to finding]
2. [Second priority]
3. [Third priority]

---

## Semgrep Automated Findings

[Paste Semgrep results, cross-referenced with ASVS IDs]
```

---

## Severity Mapping

| Level | ASVS Level | Meaning |
|-------|-----------|---------|
| **Critical** | L1 violation | Exploitable now; data breach, RCE, or full account takeover likely |
| **High** | L1 violation | Significant risk; fix before next production deploy |
| **Medium** | L2 violation | Moderate risk; fix within current sprint |
| **Low** | L2/L3 gap | Minor risk; address in upcoming maintenance window |
| **Info** | L3 / best-practice | Not directly exploitable; recommended improvement |

---

## Stack-Specific Quick Checks

### Next.js / React / TypeScript
- Raw HTML prop without sanitization library → V1.3.1 (XSS)
- Public env prefix on secrets → V13.3.1 (exposure)
- Server actions missing Zod + auth check → V2.2.2 + V8.3.1
- Middleware not protecting authenticated routes → V8.2.1
- Missing HttpOnly + Secure + SameSite on session cookies → V3.3.1/V3.3.2/V3.3.4
- No CSP header in next.config.ts → V3.4.3
- Non-CSPRNG (Math.random) for security tokens → V11.5.1

### Supabase Projects
- Cookie-based client used for auth.users join → silently returns null; use service client after getCurrentUser()
- Service client without prior getCurrentUser() auth → V8.3.1
- Object reference from request used in DB query without ownership check → V8.2.2 (IDOR/BOLA)
- ILIKE with unescaped wildcards from user input → V1.2.4
- No schema validation before insert/update → V2.2.1
- Wildcard column select → V15.3.1 / V8.2.3
- Delete/update without FK scope to authorised entity → V8.2.2

### Node.js / Express
- String-concatenated SQL queries → V1.2.4 (SQLi)
- No rate limiting on login/password-reset → V6.3.1, V2.4.1
- Process execution with unsanitized user input → V1.2.5
- Missing security headers middleware → V3.4.1/V3.4.4/V3.4.5

### Python
- Formatted-string or percent-formatted SQL → V1.2.4
- Unsafe deserialization of untrusted binary data → V1.5.2
- Debug mode enabled in production → V13.4.2
- Missing CSRF protection → V3.5.1

### General
- Env files committed to version control → V13.3.1
- Outdated dependencies with known CVEs → V15.2.1
- No structured auth audit trail → V16.3.1
- Default credentials in any account → V6.3.2
- Full object select without field filtering → V15.3.1
