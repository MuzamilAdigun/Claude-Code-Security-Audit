# Security Audit — Claude Code Commands

10 security audit slash commands for [Claude Code](https://claude.ai/code), covering 9 major compliance frameworks. Designed for vibe coders and developers who want to identify and fix security vulnerabilities in their projects.

## Frameworks covered

| Command | Framework | Focus |
|---|---|---|
| `/security-audit-full` | All 9 (parallel) | Master command — runs all audits simultaneously |
| `/security-audit-owasp-top10` | OWASP Top 10 (2021) | Application security vulnerabilities |
| `/security-audit-soc2` | SOC 2 Type II | Trust Service Criteria (AICPA) |
| `/security-audit-gdpr` | GDPR/RGPD | EU data protection regulation |
| `/security-audit-iso27001` | ISO 27001:2022 | Information security management |
| `/security-audit-pci-dss` | PCI-DSS v4.0 | Payment card data security |
| `/security-audit-nist` | NIST SP 800-53 Rev 5 | Security controls (Moderate profile) |
| `/security-audit-ssdf` | NIST SSDF SP 800-218 | Secure software development |
| `/security-audit-cis` | CIS Benchmarks | Infrastructure hardening |
| `/security-audit-hipaa` | HIPAA Security Rule | Health data protection |

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/security-audit-claude.git
cd security-audit-claude

# Install globally (available in all projects)
chmod +x install.sh && ./install.sh
```

Or manually copy the commands:

```bash
cp commands/security-audit-*.md ~/.claude/commands/
```

## Usage

Open Claude Code in your project directory and run:

```bash
# Full audit (all 9 frameworks in parallel)
/security-audit-full /path/to/your/project

# Single framework
/security-audit-owasp-top10 /path/to/your/project
/security-audit-gdpr /path/to/your/project
```

### Example output

Each audit produces a structured report with:
- **Compliance dashboard** with score per framework (🔴🟠🟡🟢)
- **Findings** classified by severity: CRITICAL / HIGH / MEDIUM / LOW
- **File:line references** for every finding
- **Concrete fixes** with code or configuration examples
- **Confidence score** (≥ 8/10 only — minimizes false positives)
- **Remediation roadmap** (0-7 days / 7-30 days / 30-90 days / 90+ days)

See [examples/example-audit-report.md](examples/example-audit-report.md) for a full sample report.

## What it checks

### Application security (OWASP Top 10)
- SQL / command / LDAP injection
- Authentication and session management
- Cryptographic failures (weak hashing, no TLS, secrets in code)
- Security misconfiguration (CORS, headers, debug mode)
- Vulnerable dependencies
- SSRF, insecure deserialization, logging failures

### CI/CD & DevSecOps (NIST SSDF, CIS)
All major CI/CD platforms are supported:
- GitHub Actions, GitLab CI
- Jenkins (Groovy Jenkinsfile)
- Azure DevOps (task-based syntax)
- CircleCI, Bitbucket Pipelines
- Drone CI, TeamCity, Travis CI

Checks include: SAST integration, SCA/Dependabot, secrets scanning, IaC scanning (Checkov, tfsec, terrascan), container signing (Cosign/Sigstore), Helm chart security, OPA/Kyverno policy enforcement, Falco runtime security.

### Infrastructure (CIS Benchmarks)
- Docker: non-root USER, no `--privileged`, read-only filesystem, healthchecks, no secrets in ENV, pinned digests, Cosign signing
- Kubernetes: NetworkPolicies, PSA Restricted, resource limits, no hostNetwork/hostPID, Helm chart security, OPA/Gatekeeper, Kyverno, Falco
- Terraform/IaC: no 0.0.0.0/0, CloudTrail, MFA root, S3 encryption, drift detection
- Cloud (AWS/GCP/Azure): security group rules, audit logging, encryption at rest

### Data protection (GDPR, HIPAA, PCI-DSS)
- Personal data mapping
- Legal basis for processing
- Data subject rights mechanisms
- Transfer outside EU/EEA
- PHI/ePHI detection and protection
- Payment card data scope assessment

## Requirements

- [Claude Code](https://claude.ai/code) CLI
- An Anthropic account

## Stack support

Works with any language or framework. Specific patterns for:
- **JavaScript / TypeScript** (Node.js, Express, Next.js, Vue, React)
- **Go** (chi, gin, echo)
- **Python** (FastAPI, Django, Flask)
- **Ruby** (Rails)
- **Java** (Spring Boot)
- **Prisma / SQL / PostgreSQL / MongoDB**

## Contributing

Pull requests welcome. If you find a false positive pattern or a missing check, please open an issue.

## License

MIT
