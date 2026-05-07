---
name: security-audit
description: Performs comprehensive OWASP Top 10 2025 security vulnerability audits on any codebase. ALWAYS invoke when the user asks to: review code for security issues, perform a security audit, find vulnerabilities or security weaknesses, check for security improvements, check for CVEs, do a pentest review, or uses words like "audit", "vulnerabilities", "security review", "security check", "secure code", "harden", or "penetration test". Also invoke for any general "code review" request — security is part of every good code review. Works on both existing local projects and GitHub repos.
---

# Security Audit Skill

Perform a comprehensive security audit based on the **OWASP Top 10 2025**. Produce a structured report stored in `$PROJECT_ROOT/audit/[YYYY-MM-DD]/security-audit-report.md` where `$PROJECT_ROOT` is the absolute path of the project being audited (captured via `pwd` at the start). Output always goes into the project directory, never the skill directory.

---

## Step 0: Capture Project Root

Before doing anything else, record the absolute path of the project being audited:

```bash
PROJECT_ROOT=$(pwd)
echo "Auditing project at: $PROJECT_ROOT"
```

All file paths in this skill — output directories, grep commands, report writes — use `$PROJECT_ROOT` as the base. Never use a relative path.

---

## Step 1: Project Setup

### Existing Project
If the current directory contains source code (package.json, requirements.txt, composer.json, go.mod, pom.xml, Cargo.toml, or any .js/.ts/.py/.php/.rb/.java/.go files), proceed to Step 2.

### No Code Found
If no source files are present, ask the user:

> "I don't see any source code here. Please provide a GitHub repository URL and I'll clone it for analysis, or navigate to your project directory."

Once you have a URL, clone it:
```bash
gh repo clone <URL> .
```

---

## Step 2: Reconnaissance

Before checking individual OWASP categories, build a picture of the project:

1. **Identify the stack** — check for package.json, requirements.txt, go.mod, composer.json, Gemfile, pom.xml, Cargo.toml, *.csproj
2. **Map the attack surface** — list:
   - API endpoints (routes, controllers, server actions)
   - Authentication flows (login, signup, password reset, OAuth)
   - File upload handlers
   - Database interaction points
   - External integrations (webhooks, payment providers, third-party APIs)
3. **Automated scan (if available)** — use the Semgrep MCP tool (`mcp__plugin_semgrep_semgrep__semgrep_scan`) on the project root with auto-detected rules. Capture findings for incorporation in the report.
4. **Secrets scan** — grep for hardcoded credentials before anything else:
   ```bash
   grep -rn --include="*.{js,ts,py,php,rb,go,java,env}" \
     -E "(password|secret|api_key|apikey|token|private_key)\s*=\s*['\"][^'\"]{8,}" \
     . --exclude-dir={node_modules,.git,dist,build}
   ```

---

## Step 3: OWASP Top 10 2025 Analysis

Work through all ten categories in order. For each one, **read the reference file first**, then check the codebase for the described patterns.

| # | Category | Reference File | What to Look For |
|---|----------|---------------|-----------------|
| A01 | Broken Access Control | `references/A01-broken-access-control.md` | Missing auth guards, IDOR, CORS misconfig |
| A02 | Security Misconfiguration | `references/A02-security-misconfiguration.md` | Default creds, exposed stack traces, open ports |
| A03 | Software Supply Chain Failures | `references/A03-software-supply-chain.md` | Outdated deps, unverified packages, CI/CD integrity |
| A04 | Cryptographic Failures | `references/A04-cryptographic-failures.md` | Weak hashing, plaintext secrets, no TLS enforcement |
| A05 | Injection | `references/A05-injection.md` | SQL concat, shell commands, unsanitized HTML rendering |
| A06 | Insecure Design | `references/A06-insecure-design.md` | Missing threat models, flawed business logic |
| A07 | Authentication Failures | `references/A07-authentication-failures.md` | No MFA, weak passwords, session management |
| A08 | Software/Data Integrity Failures | `references/A08-integrity-failures.md` | Unsigned updates, unsafe deserialization |
| A09 | Security Logging & Alerting | `references/A09-logging-alerting-failures.md` | Missing audit logs, no alerting, sensitive data in logs |
| A10 | Mishandling of Exceptional Conditions | `references/A10-exceptional-conditions.md` | Exposed stack traces, resource leaks, no rollback |

Document every finding as you go — file path, line number, severity, and evidence.

---

## Step 4: Generate the Report

Create the output directory inside the project (using the `$PROJECT_ROOT` captured in Step 0):
```bash
mkdir -p "$PROJECT_ROOT/audit/$(date +%Y-%m-%d)"
```

Write the full report to `$PROJECT_ROOT/audit/YYYY-MM-DD/security-audit-report.md` using the Write tool with the absolute path. Using this template:

```markdown
# Security Audit Report

**Project:** [project name or repo URL]
**Date:** [YYYY-MM-DD]
**Auditor:** Claude Security Audit (OWASP Top 10 2025)
**Stack:** [detected tech stack]

---

## Executive Summary

[2–3 sentences: overall posture, most critical findings, recommended immediate priorities]

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

### [SEVERITY] [A0X:2025] — [Short descriptive title]

**Severity:** Critical / High / Medium / Low / Info
**OWASP Category:** A0X:2025 — [Category Name]
**Affected:** `path/to/file.ts:42`
**CWE:** CWE-XXX (if applicable)

**Description:**
What the vulnerability is and why it matters in this specific context.

**Evidence:**
[Code snippet or grep output showing the issue]

**Suggested Fix:**
Specific, actionable recommendation. Include a code snippet showing the safe version if possible.

---

[Repeat for each finding, ordered Critical → High → Medium → Low → Info]

---

## Passed Checks

| Category | Status | Notes |
|----------|--------|-------|
| A01 — Broken Access Control | ✅ No issues | ... |

---

## Recommended Next Steps

1. [Highest priority action]
2. [Second priority action]
3. [Third priority action]
```

---

## Severity Definitions

| Level | Meaning |
|-------|---------|
| **Critical** | Exploitable now; data breach, RCE, or full account takeover likely |
| **High** | Significant risk; fix before next production deploy |
| **Medium** | Moderate risk; fix within current sprint |
| **Low** | Minor risk; address in upcoming maintenance window |
| **Info** | Best-practice improvement; not directly exploitable |

---

## Stack-Specific Quick Checks

### Next.js / React
- Raw HTML rendering prop used without sanitization library (DOMPurify) → XSS (A05)
- Secrets in `NEXT_PUBLIC_` env vars → exposure (A04)
- Server actions missing Zod validation or `getCurrentUser()` guard → A01, A05
- Middleware not protecting authenticated routes → A01

### Node.js / Express
- String-concatenated SQL queries → SQLi (A05)
- No rate limiting on `/login`, `/reset-password` → A07
- Shell command helpers invoked with unsanitized user input → A05
- Missing `helmet()` middleware → A02

### Python
- f-string or `%`-formatted SQL → SQLi (A05)
- `pickle.loads()` on untrusted data → A08
- `DEBUG = True` in production → A02
- Missing CSRF protection → A01

### PHP
- `$_GET`/`$_POST` directly in SQL → SQLi (A05)
- Output without `htmlspecialchars()` → XSS (A05)
- Shell functions invoked with user input → A05
- `display_errors = On` in production → A02

### General
- `.env` files committed to git → A04
- Outdated dependencies with known CVEs → A03
- No structured logging or audit trail → A09
- Default admin credentials → A02
