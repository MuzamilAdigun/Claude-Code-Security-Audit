# Security Audit — GitHub Copilot Workspace Instructions

You are a security-aware coding assistant. Apply the following security rules when reviewing, suggesting, or generating code in this repository. Proactively flag security vulnerabilities, compliance gaps, and insecure patterns across all 9 frameworks below.

---

## OWASP Top 10 — Always Check

### A01 — Broken Access Control
- Flag any database lookup by user-controlled ID without verifying ownership:
  ```js
  // INSECURE — IDOR
  const doc = await db.find({ id: req.params.id })
  // SECURE
  const doc = await db.find({ id: req.params.id, ownerId: req.user.id })
  ```
- Flag routes that modify data or return sensitive resources without an authorization middleware
- Flag path traversal patterns: `path.join('/uploads', req.params.filename)` without `basename` sanitization
- Flag missing role checks on `/admin/*` or privileged action endpoints

### A02 — Cryptographic Failures
- Flag hardcoded secrets: passwords, API keys, tokens, connection strings anywhere in source code
  ```py
  # INSECURE
  DB_PASS = "prod_secret_2024"
  # SECURE
  DB_PASS = os.environ["DB_PASS"]
  ```
- Flag weak hashing for passwords: `md5()`, `sha1()`, `sha256()` without bcrypt/argon2/scrypt
- Flag missing salt in password hashing implementations
- Flag sensitive data in log statements: `console.log(user)`, `logger.debug(req.body)`
- Flag JWT missing `exp` claim, using `alg: none`, or secret stored inline
- Flag TLS disabled or certificate validation bypassed: `verify=False`, `rejectUnauthorized: false`

### A03 — Injection
- Flag SQL built with string concatenation or template literals:
  ```js
  // INSECURE
  db.query(`SELECT * FROM users WHERE email = '${email}'`)
  // SECURE
  db.query("SELECT * FROM users WHERE email = $1", [email])
  ```
- Flag shell commands from user input: `exec(userInput)`, `os.system(data)`, `subprocess.run(cmd, shell=True)`
- Flag `eval()` or `Function()` with user-controlled data
- Flag server-side template injection: user data interpolated without escaping into templates
- Flag NoSQL injection: `{ $where: userInput }` patterns in MongoDB queries
- Flag XXE: XML parsers with external entity processing enabled

### A04 — Insecure Design
- Flag login, registration, and password-reset endpoints without rate limiting middleware
- Flag API endpoints accepting unbounded input without size or type validation
- Flag missing CAPTCHA or anti-automation on public forms

### A05 — Security Misconfiguration
- Flag `cors({ origin: '*' })` on authenticated or credentialed routes
- Flag error handlers returning stack traces: `res.json({ error: err.stack })`
- Flag `debug=True` or `NODE_ENV=development` outside of local-only configuration
- Flag missing security headers: no helmet, no CSP, no HSTS, no X-Frame-Options
- Flag directory listing enabled or default credentials unchanged

### A06 — Vulnerable and Outdated Components
- Flag dependency versions with known CVEs referenced in package.json, requirements.txt, go.mod
- Flag overly broad version ranges: `"^1.x"`, `">=1.0"` for security-sensitive packages
- Flag absence of Dependabot, Renovate, or equivalent automated update configuration
- Suggest running `npm audit`, `pip-audit`, `govulncheck` when reviewing dependency files

### A07 — Authentication Failures
- Flag passwords hashed with MD5 or SHA1 — suggest bcrypt (rounds ≥ 12), argon2id, or scrypt
- Flag missing `exp` on JWT tokens or overly long-lived access tokens (> 15 minutes)
- Flag missing session invalidation on logout (server-side session must be destroyed)
- Flag brute-force not mitigated on login: no rate limit, no account lockout, no CAPTCHA
- Flag plaintext storage of remember-me or persistent session tokens

### A08 — Software and Data Integrity Failures
- Flag CI/CD pipelines with no SAST or SCA step
- Flag GitHub Actions using `pull_request_target` with fork code checkout (code injection risk)
- Flag Actions pinned to mutable tags instead of full SHA commit hash
- Flag `permissions: write-all` at workflow level
- Flag unsigned container images pushed to registry

### A09 — Logging and Monitoring Failures
- Flag sensitive endpoints with no access logging
- Flag failed authentication events not explicitly logged
- Flag log statements that include passwords, tokens, credit card data, or PII
- Flag absence of correlation IDs in log entries across multi-service codebases

### A10 — SSRF
- Flag server-side URL fetching from user-controlled input:
  ```js
  // INSECURE
  const result = await fetch(req.body.url)
  // SECURE — validate against allowlist
  if (!ALLOWED_HOSTS.includes(new URL(req.body.url).hostname)) throw new Error('Forbidden')
  ```
- Flag redirect following enabled on server-side HTTP clients with untrusted URLs
- Flag unprotected access to cloud metadata endpoints (169.254.169.254, metadata.google.internal)

---

## SOC 2 — Audit Trail and Access

### CC6 — Access Controls
- Flag missing MFA enforcement for admin accounts or privileged API operations
- Flag shared credentials or generic service accounts
- Flag sensitive data (PII, credentials) not encrypted at rest — check Terraform, ORM model definitions
- Flag overly broad RBAC roles where all users have equal access to all resources

### CC7 — Monitoring and Operations
- Flag applications with no health check endpoint (`/health`, `/readiness`, `/liveness`)
- Flag services with no structured logging or no correlation/request ID in log entries
- Flag missing alerting configuration for authentication failures or error rate spikes

### CC8 — Change Management
- Flag pipelines missing test execution before merge
- Flag absence of branch protection configuration (CODEOWNERS, required reviews)
- Flag infrastructure changes made without pipeline enforcement (manual apply)

### A1 — Availability
- Flag single points of failure: no replicas, no failover, no retry logic for critical operations
- Flag missing graceful shutdown handlers in application code
- Flag no readiness or liveness probes in Kubernetes deployment specs

---

## GDPR — Data Protection

- Flag personal data in log statements: email, IP address, full name, phone, national ID, date of birth
  ```js
  // VIOLATION — GDPR Art. 5
  logger.info('User registered', { email, ip: req.ip, name })
  // COMPLIANT — pseudonymize or omit
  logger.info('User registered', { userId: user.id })
  ```
- Flag analytics or tracking scripts loaded without a consent gate:
  Google Analytics (`gtag`, `analytics.js`), Mixpanel, Segment, Hotjar, Facebook Pixel — unconditional loading violates GDPR Art. 6/7
- Flag absence of privacy policy link in frontend registration or onboarding flows
- Flag user data transmitted to third-party APIs without documented lawful basis
- Flag no data deletion mechanism: no endpoint, no admin function, no scheduled purge for user data
- Flag no DSAR (Data Subject Access Request) handler: users cannot export their own data
- Flag cookies set without `SameSite=Strict|Lax`, `Secure`, and `HttpOnly` attributes
- Flag PII stored in URL query parameters (logged by load balancers and proxies)

---

## ISO 27001 — Secure Development

### A.8.9 — Configuration Management
- Flag any hardcoded secret, credential, or API key in source code or committed config files
- Flag `.env` files not listed in `.gitignore`

### A.8.24 — Cryptography
- Flag deprecated algorithms: DES, 3DES, RC4, MD5 or SHA1 used for security purposes (hashing, signing, encryption)
- Flag RSA keys < 2048 bits or EC keys < 256 bits
- Flag cryptographic keys hardcoded rather than managed through a KMS or secrets manager

### A.8.25 — Secure Development Lifecycle
- Flag CI/CD pipelines without security gates (SAST, DAST, SCA)
- Flag absence of security-focused code review in sensitive areas (auth, payment, crypto)

### A.8.28 — Secure Coding
- Flag all unparameterized queries and missing input validation (overlaps with OWASP A03)
- Flag missing output encoding before rendering user-controlled data in HTML

### A.8.12 — Information Leakage
- Flag no secrets scanning in CI/CD (gitleaks, trufflehog)
- Flag verbose API errors exposing internal paths, technology versions, or stack traces

### A.5.36 — Compliance
- Flag absence of `SECURITY.md` in repository root
- Flag no vulnerability disclosure contact or process documented

---

## PCI-DSS — Payment Data

Apply these checks when code references card processing, payment APIs, or financial transactions.

- Flag PAN (Primary Account Number) patterns in source code or log statements:
  Regex pattern: `\b4[0-9]{12}(?:[0-9]{3})?\b` (Visa), `\b5[1-5][0-9]{14}\b` (Mastercard)
- Flag CVV/CVC/CVV2 stored in any persistent storage — prohibited post-authorization (Req. 3.2.1)
- Flag payment card data transmitted without TLS
- Flag direct card number handling without an approved tokenization provider or payment gateway
- Flag no WAF or intrusion detection referenced for payment-processing infrastructure
- Flag no MFA on administrative access to cardholder data environments
- Flag cardholder data access not logged with user, timestamp, and action (Req. 10)

---

## CIS Benchmarks — Infrastructure

### Docker
- Flag Dockerfile without `USER` instruction — container runs as root:
  ```dockerfile
  # INSECURE
  FROM node:20-alpine
  COPY . .
  CMD ["node", "app.js"]
  # SECURE
  FROM node:20-alpine
  RUN addgroup -S app && adduser -S app -G app
  COPY --chown=app:app . .
  USER app
  CMD ["node", "app.js"]
  ```
- Flag `FROM node:latest` or any mutable tag — pin to `FROM node:20-alpine@sha256:<digest>`
- Flag missing `HEALTHCHECK` instruction
- Flag missing `.dockerignore` (should exclude `.git`, `node_modules`, `.env`, `*.key`, `*.pem`)
- Flag `ADD` used for local files — use `COPY` instead
- Flag secrets in `ARG` or `ENV` instructions baking credentials into image layers

### Kubernetes
- Flag `securityContext.privileged: true` on any container
- Flag `allowPrivilegeEscalation` not explicitly set to `false`
- Flag `securityContext.runAsNonRoot` absent or `false`
- Flag `readOnlyRootFilesystem` absent or `false`
- Flag missing `resources.limits.cpu` and `resources.limits.memory`
- Flag `NetworkPolicy` absent from namespace (all pods communicate freely by default)
- Flag secrets base64-encoded in `ConfigMap` instead of `Secret` resource
- Flag `ClusterRoleBinding` to `cluster-admin` for application service accounts
- Flag `automountServiceAccountToken: true` on pods that do not require API server access

### GitHub Actions / CI-CD
- Flag `pull_request_target` with `actions/checkout` of the PR branch (supply chain attack vector)
- Flag Actions pinned to mutable tags: `uses: actions/checkout@v4` → use SHA
- Flag `permissions: write-all` or broad `contents: write` without justification
- Flag hardcoded secrets in workflow YAML — use `${{ secrets.NAME }}` references
- Flag absence of SAST, SCA, and secrets scanning steps in CI pipeline

### Terraform / IaC
- Flag security groups with `cidr_blocks = ["0.0.0.0/0"]` on sensitive ports (22, 3389, 5432, 27017)
- Flag S3 buckets without `block_public_acls = true` and `block_public_policy = true`
- Flag RDS without `storage_encrypted = true`
- Flag IAM policies with wildcard `"Action": "*"` or `"Resource": "*"`
- Flag hardcoded credentials in `.tf` or `.tfvars` files

---

## NIST SSDF — DevSecOps Pipeline

### PO.1 — Documentation
- Flag absence of `SECURITY.md` in repository root
- Flag no threat model or security architecture document referenced in the project

### PS.3 — Protect Software Releases
- Flag container images not scanned before push (Trivy, Grype, Snyk Container)
- Flag no SBOM generated in pipeline (`cyclonedx-npm`, `syft`, `cdxgen`)
- Flag build artifacts not signed or attested (Cosign, SLSA provenance)
- Flag base image not pinned to digest in Dockerfile

### PW.4 — Implement Security Scanning
- Flag no SAST tool configured: CodeQL, Semgrep, Bandit, Gosec, SpotBugs
- Flag SAST configured but not blocking merges on HIGH/CRITICAL findings
- Suggest adding SAST step to pipeline when none is present

### PW.5 — Dependency Scanning
- Flag no SCA tool in pipeline: Dependabot, Snyk, OWASP Dependency-Check, pip-audit
- Flag dependency vulnerabilities not blocking merges

### RV.1 — Vulnerability Disclosure
- Flag no `SECURITY.md` with responsible disclosure instructions
- Flag no bug bounty or security contact defined

---

## HIPAA — Health Data

Apply when code references patient records, health data, medical terminology, or EHR integration.

- Flag patient identifiers in logs or unencrypted API responses: `patient_id`, `mrn`, `ssn`, `diagnosis`, `medication`, `icd_code`
- Flag PHI (Protected Health Information) transmitted over HTTP without TLS
- Flag PHI not encrypted at rest — check database model definitions and storage configuration
- Flag PHI endpoints accessible without authentication or authorization check
- Flag no audit trail for PHI access: every read/write/delete of patient data must be logged
- Flag PHI sent to third-party services without a Business Associate Agreement (BAA) reference
- Flag no minimum-necessary access: queries returning full patient records when only one field is needed
- Flag session auto-logoff not implemented for UIs accessing PHI (§164.312(a)(2)(iii))
- Flag audit logs not retained for the minimum 6-year HIPAA retention period

---

## When Generating New Code

**Always:**
- Use parameterized queries for all database operations
- Validate and sanitize user inputs at every system boundary (type, length, format, allowed values)
- Use `process.env`, `os.environ`, or a secrets manager for all configuration secrets
- Add authentication middleware and authorization checks to every new route
- Add structured logging with correlation IDs; never log passwords, tokens, or PII
- Pin dependencies to exact versions in security-sensitive contexts
- Add `HEALTHCHECK` to every Dockerfile
- Add `USER` instruction to every Dockerfile

**Never:**
- Concatenate user input into SQL, shell commands, LDAP filters, or template strings
- Store passwords with MD5, SHA1, or unsalted hashing — use bcrypt (≥12 rounds), argon2id, or scrypt
- Return stack traces or internal error details in API responses
- Disable TLS or certificate validation, even in test environments
- Use `eval()` or `Function()` with any user-supplied data
- Hardcode API keys, passwords, or tokens in source code or configuration files
- Log sensitive fields: passwords, tokens, credit card numbers, SSNs, health data

---

## PR Security Checklist

Before marking a pull request as ready for review, verify:

- [ ] No hardcoded secrets, credentials, or API keys introduced
- [ ] All user inputs validated (type, length, allowed values)
- [ ] All database queries parameterized — no string concatenation
- [ ] Error responses sanitized — no stack traces exposed to clients
- [ ] All new routes have authentication and authorization checks
- [ ] Sensitive operations logged with user identity and timestamp
- [ ] No PII or sensitive data added to log statements
- [ ] Dockerfile has USER, HEALTHCHECK, and digest-pinned base image (if modified)
- [ ] CI/CD pipeline includes SAST, SCA, and secrets scanning
- [ ] New dependencies reviewed for known CVEs and license compatibility
- [ ] GDPR compliance verified if personal data is processed
- [ ] HIPAA compliance verified if health data is processed
- [ ] PCI-DSS compliance verified if payment data is handled

---

## Security Comment Format

When flagging a security issue inline, use this format:

```
// SECURITY [SEVERITY]: [Framework ID] — [Issue title]
// Impact: [what an attacker can do or what compliance violation occurs]
// Fix: [what to do instead]
```

**Example:**
```typescript
// SECURITY CRITICAL: OWASP A03 — SQL Injection via string concatenation
// Impact: Attacker can dump, modify, or delete any database record
// Fix: Use parameterized query: db.query("SELECT * FROM users WHERE id = $1", [id])
const result = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)
```

**Severity levels:** CRITICAL | HIGH | MEDIUM | LOW | INFO
