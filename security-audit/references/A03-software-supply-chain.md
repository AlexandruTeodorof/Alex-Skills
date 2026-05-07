# A03:2025 — Software Supply Chain Failures

**OWASP Position:** #3 (expanded from "Vulnerable and Outdated Components" at #6 in 2021)
**Incidence:** Highest avg incidence rate at 5.72%; 215,248 occurrences; 11 documented CVEs
**Notable 2025 incidents:** SolarWinds, Bybit ($1.5B theft via conditional malware), Shai-Hulud npm worm (500+ packages)

## What It Is

Compromises stemming from vulnerabilities or malicious modifications in third-party code, tools, build pipelines, or dependencies — from direct imports to CI/CD infrastructure itself.

## What to Look For

### Outdated Dependencies with Known CVEs
```bash
# Node.js
npm audit
npx audit-ci --high  # fail on high severity

# Python
pip-audit  # or: safety check -r requirements.txt

# Ruby
bundle audit

# Java (Maven)
mvn org.owasp:dependency-check-maven:check

# Rust
cargo audit

# PHP
composer audit
```

Check the output for:
- Critical/High severity CVEs in direct or transitive dependencies
- Dependencies with no fix available (consider alternatives)
- Dependencies that are unmaintained (last release >2 years ago)

### Dependencies from Untrusted Sources
```bash
# Check for non-registry installs in package.json
grep -n "github:\|git+\|http:\|file:" package.json

# Check for .npmrc overrides pointing to custom registries
cat .npmrc 2>/dev/null

# Python: check for non-PyPI installs
grep -n "git+\|http\|@" requirements.txt 2>/dev/null
```

### Post-Install Scripts (Potential Malware Vector)
```bash
# npm packages with postinstall scripts can execute arbitrary code
cat node_modules/*/package.json 2>/dev/null | grep -l "postinstall\|preinstall\|install" | head -20
```

### Missing SBOM (Software Bill of Materials)
- Check if the project generates/maintains an SBOM (sbom.json, sbom.xml, cyclonedx.json)
- For high-security environments, SBOM generation should be part of the CI/CD pipeline

### CI/CD Pipeline Integrity
```bash
# Look for CI config files
find . -name "*.yml" -path "*/.github/workflows/*" -o \
       -name ".travis.yml" -o \
       -name "Jenkinsfile" -o \
       -name ".gitlab-ci.yml" | head -20
```

Check pipelines for:
- Pinned action versions (use SHA not tag: `actions/checkout@abc123` not `@v3`)
- Secrets in pipeline config files (not just env vars)
- Overly permissive `GITHUB_TOKEN` permissions
- Third-party actions from unverified sources

```yaml
# BAD: mutable tag, can be hijacked via tag overwrite
- uses: actions/setup-node@v3

# GOOD: immutable SHA
- uses: actions/setup-node@1a4442cacd436585916779262731d1f68d8b3c56
```

### Unsigned Packages
```bash
# Check if npm packages are verified (npm provenance)
npm install --audit

# Check if Docker images are signed
grep -rn "FROM " Dockerfile* --include="Dockerfile*" .
# Untagged or :latest images are a risk; check for digest pinning
```

## Common Vulnerable Patterns

```json
// BAD: wildcard versions, no lockfile audit
{
  "dependencies": {
    "lodash": "*",
    "express": "^4.0.0"
  }
}
```

```json
// BETTER: exact or tightly bounded versions + audit in CI
{
  "dependencies": {
    "lodash": "4.17.21",
    "express": "4.18.2"
  }
}
```

## Prevention Checklist

- [ ] Run `npm audit` / `pip-audit` / `bundle audit` in CI — fail on high/critical
- [ ] Pin dependency versions; use lockfiles (package-lock.json, poetry.lock, Pipfile.lock)
- [ ] Source packages exclusively from official registries
- [ ] Monitor CVE/NVD feeds for components in use
- [ ] GitHub Actions / CI: pin action versions to immutable SHAs
- [ ] Minimal `GITHUB_TOKEN` permissions (read-only where possible)
- [ ] No untrusted post-install scripts
- [ ] SBOM generated and stored as CI artifact
- [ ] Developer workstations: MFA enabled, regular patching
- [ ] Staged deployments to limit blast radius from compromised vendor
