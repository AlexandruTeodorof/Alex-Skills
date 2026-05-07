# Alex Skills

A collection of Claude Code skills for security auditing and code review.

## Skills

### `security-audit`

Performs a comprehensive **OWASP Top 10 2025** security audit on any codebase — local projects or GitHub repos.

**Triggers automatically when you say:** "security audit", "find vulnerabilities", "security review", "harden my code", "check for CVEs", or do a general code review.

**What it does:**
- Maps your attack surface (API endpoints, auth flows, file uploads, DB access, external integrations)
- Runs an automated Semgrep scan
- Checks for hardcoded secrets
- Analyses all 10 OWASP Top 10 2025 categories with stack-specific checks (Next.js, Node.js, Python, PHP)
- Produces a structured report at `audit/YYYY-MM-DD/security-audit-report.md` with severity ratings, evidence, and suggested fixes

**Supported stacks:** Next.js · Node.js · Python · PHP · Ruby · Go · Java · Rust

---

## Installation

```bash
npx skills add AlexandruTeodorof/Alex-Skills
```

Then in any Claude Code session, just ask for a security audit and the skill activates automatically.
