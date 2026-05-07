# A05:2025 — Injection

**OWASP Position:** #5 (down from #3 in 2021)
**Incidence:** 100% of applications tested for some form; 37 CWEs; 62,000+ CVEs
**Subtypes:** SQL (14,000+ CVEs), XSS (30,000+ CVEs), NoSQL, OS command, ORM, LDAP, Expression Language

## What It Is

An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized before being sent to an interpreter. The interpreter executes it as a command or query, accessing data or functionality beyond what was intended.

## SQL Injection

```bash
# Find SQL string concatenation
grep -rn "query\s*[+]\s*\|query\s*=.*\+.*req\.\|execute(.*\+" \
  --include="*.{js,ts,py,php,rb,java}" .

# Template literals building SQL (Node.js) — backtick followed by SELECT/INSERT/etc
grep -rn 'SELECT.*\${' --include="*.{js,ts}" .
grep -rn "INSERT.*\${" --include="*.{js,ts}" .

# Python f-string SQL
grep -rn 'f"SELECT\|f"INSERT\|f"UPDATE\|f"DELETE\|f'"'"'SELECT' --include="*.py" .

# PHP: $_GET/$_POST directly in query
grep -rn '\$_GET\|\$_POST' --include="*.php" . | grep -i "query\|execute\|SELECT\|WHERE"
```

**Vulnerable pattern:** building a query by concatenating or interpolating user input directly into the SQL string — e.g., `"SELECT * FROM users WHERE id = '" + userId + "'"` — allows an attacker to inject arbitrary SQL.

**Safe pattern:** parameterized queries where the user value is a separate argument, never part of the query string:
```javascript
// SAFE: parameterized — user input goes in the values array, never the query string
const rows = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
```

```python
# SAFE: parameterized
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

## Cross-Site Scripting (XSS)

XSS occurs when untrusted user content is rendered as raw HTML in the browser.

```bash
# React: raw HTML rendering prop (renders unsanitized markup)
grep -rn "dangerously.SetInnerHTML\|dangerouslySetInner" --include="*.{jsx,tsx,js,ts}" .
# Each hit: verify the value is wrapped in DOMPurify.sanitize()

# Direct DOM modification with user content
grep -rn "innerHTML\s*=" --include="*.{js,ts,jsx,tsx}" .
grep -rn "outerHTML\s*=\|document\.write(" --include="*.{js,ts,jsx,tsx}" .

# Template engine raw/unescaped output markers
grep -rn "{!!.*!!\}\|\.raw\b\|markSafe\|unescape" --include="*.{html,blade.php,erb,ejs,hbs}" .
```

**Safe pattern:** use DOMPurify before passing content to any raw HTML rendering, or avoid raw HTML rendering entirely by using text-content APIs:
```javascript
// SAFE: sanitize user content before rendering as HTML
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userContent);
element.innerHTML = clean;

// SAFEST: use textContent instead — no HTML parsing at all
element.textContent = userContent;
```

## OS Command Injection

Occurs when user input reaches shell-execution functions (`exec`, `spawn`, `system`, `popen`, `subprocess.run(shell=True)`, etc.) and is interpolated into the command string.

```bash
# Find shell execution calls
grep -rn "child_process\|subprocess\|os\.system\|os\.popen\|shell=True" \
  --include="*.{js,ts,py,rb,php}" .
# For each hit: trace whether user-controlled data reaches the command string
```

**Vulnerable pattern:** interpolating user input into a shell command string — e.g., `` `convert ${filename} output.png` `` where `filename` comes from user input.

**Safe pattern:** use a native library for the operation, or if shell is unavoidable, pass user input as a separate argument array (not interpolated into the command string):
```javascript
// SAFE: use a library — no shell involved
const sharp = require('sharp');
const safeName = path.basename(filename).replace(/[^a-z0-9._-]/gi, '');
await sharp(path.join(uploadDir, safeName)).toFile('output.png');

// SAFE: execFile passes args array separately — no shell interpolation
const { execFile } = require('child_process');
execFile('convert', [safeName, 'output.png'], { cwd: uploadDir }, callback);
```

## NoSQL Injection

```bash
# MongoDB: user request object used directly as query (operator injection)
grep -rn "findOne(\|find(\|updateOne(" --include="*.{js,ts}" . | grep "req\."
# Attacker can send { "$gt": "" } to bypass equality checks
```

**Safe pattern:** cast inputs to expected types and use explicit operators:
```javascript
// SAFE: cast + explicit $eq prevents operator injection
User.findOne({ username: { $eq: String(req.body.username) } });
// Then verify password separately via bcrypt.compare()
```

## ILIKE / LIKE Wildcard Injection

User-supplied search strings used in `LIKE`/`ILIKE` queries without escaping `%` and `_` can return unexpected data volumes or cause performance DoS.

```bash
grep -rn "\.ilike(\|LIKE\s*'" --include="*.{js,ts,py}" .
```

```javascript
// SAFE: escape LIKE wildcards before use
const escaped = searchTerm.replace(/%/g, '\\%').replace(/_/g, '\\_');
.ilike('name', `%${escaped}%`)
```

## Template Injection (SSTI)

```bash
# Jinja2 / Twig with user-controlled template content
grep -rn "render_template_string\|Template(" --include="*.py" .
grep -rn "twig.*render\|smarty.*assign" --include="*.php" .
# User input like {{ 7*7 }} or {{ config }} can leak secrets or achieve RCE
```

## Prevention Checklist

- [ ] Parameterized queries / prepared statements for ALL database calls
- [ ] ORM used correctly — no raw query string interpolation
- [ ] Raw HTML rendering sanitized with DOMPurify (or replaced with text-content APIs)
- [ ] No `innerHTML`/`document.write()` with user content
- [ ] Shell commands: use native libraries; if shell required, args in separate array (not command string)
- [ ] NoSQL: validate input types; use `$eq`; never pass raw request objects as queries
- [ ] LIKE/ILIKE wildcards (`%`, `_`) escaped in user input
- [ ] Template engines: auto-escape enabled; never render user-controlled template strings
- [ ] Server-side input validation (positive allowlist where possible)
- [ ] Output encoding appropriate for context (HTML, JS, URL, CSS)
