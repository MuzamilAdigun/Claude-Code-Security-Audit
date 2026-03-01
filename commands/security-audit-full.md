---
description: "Audit de conformite complet multi-frameworks. Lance en parallele les 9 audits (OWASP, SOC 2, GDPR, ISO 27001, PCI-DSS, NIST SP 800-53, NIST SSDF, CIS, HIPAA) et produit un tableau de bord consolide avec score par framework."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es le coordinateur d'audit de securite senior. Lance un audit de conformite multi-frameworks complet du projet situe a : **$ARGUMENTS**

Frameworks couverts :
- **OWASP Top 10 (2021)** — Vulnerabilites applicatives critiques
- **SOC 2 Type II** — Trust Service Criteria (AICPA)
- **RGPD/GDPR** — Reglement europeen sur la protection des donnees
- **ISO 27001:2022** — Systeme de management de la securite de l'information
- **PCI-DSS v4.0** — Securite des donnees de carte de paiement
- **NIST SP 800-53 Rev 5** — Controles de securite (profil Moderate)
- **NIST SSDF SP 800-218** — Secure Software Development Framework
- **CIS Benchmarks** — Durcissement infrastructure
- **HIPAA** — Protection des donnees de sante (si applicable)

---

## Instructions

1. Detecte les frameworks applicables au projet (Phase 1)
2. Lance tous les audits en parallele via Task (Phase 2)
3. Consolide les resultats en un rapport unifie (Phase 3)
4. Produit un tableau de bord de conformite global (Phase 4)

---

## Phase 1 — Detection du perimetre et des frameworks applicables

```bash
# Stack technologique
find $ARGUMENTS -maxdepth 4 \( \
  -name "package.json" -o -name "go.mod" -o -name "pyproject.toml" -o \
  -name "Gemfile" -o -name "pom.xml" -o -name "build.gradle" -o \
  -name "Dockerfile" -o -name "docker-compose*.yml" -o -name "*.tf" \
  -o -name "*.yaml" -o -name "*.yml" \
\) 2>/dev/null | grep -v node_modules | grep -v ".git"

# Indicateurs de donnees de paiement (-> PCI-DSS)
grep -rn "card.*number\|credit.*card\|debit.*card\|cvv\|cvc\|pan\|stripe\|braintree\|\
paypal\|card.*holder\|card.*exp" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" --include="*.prisma" 2>/dev/null | grep -v node_modules | head -10

# Indicateurs de donnees de sante (-> HIPAA)
grep -rn "patient\|medical\|diagnosis\|health\|prescription\|ehr\|emr\|fhir\|hl7\|\
ephi\|phi\|hipaa\|clinic\|hospital" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" --include="*.prisma" 2>/dev/null | grep -v node_modules | head -10

# Indicateurs de donnees personnelles (-> GDPR)
grep -rn "email\|phone\|address\|birthdate\|user_id\|ip.*addr\|cookie\|analytics" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" --include="*.prisma" 2>/dev/null | grep -v node_modules | head -10

# Infrastructure + CI/CD (-> CIS, SSDF)
find $ARGUMENTS \( \
  -name "Dockerfile" \
  -o -name "*.tf" \
  -o -path "*/.github/workflows/*.yml" \
  -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" \
  -o -name "Jenkinsfile" \
  -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" \
  -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" \
  -o -name "bitbucket-pipelines.yml" \
  -o -name ".travis.yml" \
  -o -name ".drone.yml" \
  -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules
```

---

## Phase 2 — Lancement des audits en parallele

Lance les audits suivants simultanement via des sous-agents :

### Tache 1 : Audit OWASP Top 10

```
Realise un audit OWASP Top 10 (2021) complet du projet $ARGUMENTS.
Analyse :
- A01 Broken Access Control (controles d'autorisation, IDOR, privilege escalation)
- A02 Cryptographic Failures (hashage mdp, chiffrement donnees sensibles, TLS)
- A03 Injection (SQL, commandes, LDAP, NoSQL — chercher les concatenations string dans les queries)
- A04 Insecure Design (logique metier, threat modeling)
- A05 Security Misconfiguration (headers, CORS, debug mode, default credentials)
- A06 Vulnerable Components (npm audit, pip-audit, govulncheck, etc.)
- A07 Auth Failures (session management, credential stuffing, MFA)
- A08 Software Integrity (CI/CD, supply chain, SRI)
- A09 Logging Failures (acces loggues, donnees sensibles dans les logs)
- A10 SSRF (fetches vers URLs controlees par l'utilisateur)
Pour chaque finding : fichier:ligne, severite (CRITIQUE/HAUTE/MOYENNE/BASSE), score confiance /10 (ne reporter que >= 8), fix propose.
```

### Tache 2 : Audit SOC 2

```
Realise un audit SOC 2 Type II (Trust Service Criteria AICPA 2017+2022) du projet $ARGUMENTS.
Couvre : CC6 (acces logique, chiffrement, reseau), CC7 (operations, monitoring, incidents), CC8 (change management), CC9 (fournisseurs), A1 (disponibilite), C1 (confidentialite), P1-P8 (privacy).
Pour chaque finding : critere TSC, fichier:ligne, severite, score confiance /10 (>= 8), fix.
Attribue un score de maturite /5 par critere TSC.
```

### Tache 3 : Audit GDPR/RGPD

```
Realise un audit RGPD (Reglement EU 2016/679) du projet $ARGUMENTS.
Cartographie d'abord toutes les donnees personnelles traitees (email, phone, adresse, IP, cookies, etc.).
Analyse : Art. 5 (principes), Art. 6-7 (bases legales, consentement), Art. 12-14 (transparence), Art. 15-22 (droits des personnes : acces, rectification, effacement, portabilite), Art. 25 (privacy by design), Art. 30 (registre), Art. 32 (securite), Art. 33-34 (violations), Art. 35 (DPIA), Art. 44-49 (transferts hors UE).
Pour chaque finding : article RGPD, fichier:ligne, severite (risque sanction CNIL jusqu'a 4% CA), score confiance /10 (>= 8), fix.
```

### Tache 4 : Audit ISO 27001

```
Realise un audit ISO/IEC 27001:2022 du projet $ARGUMENTS.
Couvre les 4 themes Annex A : Organisationnels (A.5), Personnes (A.6), Physiques (A.7), Technologiques (A.8).
Focus technique sur : A.8.2 (droits d'acces privilegies), A.8.7 (protection malware), A.8.9 (gestion config), A.8.12 (prevention fuite donnees), A.8.20 (securite reseau), A.8.24 (cryptographie), A.8.25 (dev securise), A.8.28 (secure coding).
Pour chaque finding : controle ISO 27001, fichier:ligne, severite, score confiance /10 (>= 8), fix.
```

### Tache 5 : Audit PCI-DSS

```
Realise un audit PCI-DSS v4.0 du projet $ARGUMENTS.
Verifie d'abord si des donnees de carte de paiement (PAN, CVV, expiry) sont traitees.
Couvre les 12 exigences : R1 (reseau securise), R2 (config secure), R3 (protection donnees stockees), R4 (chiffrement en transit), R5 (protection malware), R6 (dev securise), R7 (controle acces), R8 (auth : MFA, 12+ chars), R9 (acces physique), R10 (logs), R11 (tests), R12 (gouvernance).
Pour chaque finding : exigence PCI-DSS, fichier:ligne, severite, score confiance /10 (>= 8), fix.
Indique si l'audit PCI-DSS est applicable (Si pas de donnees CB detectees, le noter).
```

### Tache 6 : Audit NIST SP 800-53

```
Realise un audit NIST SP 800-53 Rev 5 (profil Moderate) du projet $ARGUMENTS.
Couvre les familles prioritaires : AC (access control), AU (audit), CM (configuration), IA (identification/auth), SC (systeme/communications), SI (integrite), SA (acquisition services), PT (PII si applicable), SR (supply chain).
Pour chaque finding : controle NIST, fichier:ligne, severite, score confiance /10 (>= 8), fix.
```

### Tache 7 : Audit CIS Benchmarks

```
Realise un audit CIS Benchmarks du projet $ARGUMENTS.
Detecte l'infrastructure presente (Docker, Kubernetes, Linux, AWS/GCP/Azure).
Pour Docker : verifie USER non-root, pas de --privileged, read-only filesystem, health checks, pas de secrets en ENV, image non-latest.
Pour K8s : NetworkPolicies, PSA Restricted, resource limits, pas de hostNetwork/hostPID.
Pour cloud (Terraform) : pas de 0.0.0.0/0, CloudTrail/CloudWatch, MFA root, chiffrement S3.
Pour chaque finding : controle CIS, fichier:ligne, severite, score confiance /10 (>= 8), fix.
Implementation Group cible : IG2.
```

### Tache 8 : Audit NIST SSDF

```
Realise un audit NIST SSDF SP 800-218 v1.1 (Secure Software Development Framework) du projet $ARGUMENTS.
Couvre les 4 groupes de pratiques :
- PO (Prepare the Organization) : politiques de dev securise, threat modeling, outils approuves
- PS (Protect the Software) : protection du code source, integrite des commits/artefacts, scan des secrets, SBOM
- PW (Produce Well-Secured Software) : SAST en CI/CD, SCA/Dependabot, code review avec checklist securite, tests unitaires securite, validation des inputs
- RV (Respond to Vulnerabilities) : SECURITY.md, delais de remediation par severite, CVE disclosure
Pour chaque finding : pratique SSDF (ex: PW.4.1), fichier:ligne, severite, score confiance /10 (>= 8), fix.
Attribue un score de maturite /10 par groupe (PO, PS, PW, RV).
```

### Tache 9 : Audit HIPAA (si applicable)

```
Verifie si le projet $ARGUMENTS traite des donnees de sante (ePHI) : patient, medical, diagnosis, health, prescription, ehr, emr, fhir, hl7.
Si ePHI detectees : realise un audit HIPAA Security Rule (45 CFR Part 164) complet.
Couvre : §164.308 (sauvegardes admin : gestion risques, contingence, acces, incidents), §164.310 (sauvegardes physiques), §164.312 (sauvegardes techniques : acces, audit, integrite, transmissions), §164.316 (documentation).
Si pas d'ePHI : indique "HIPAA non applicable — aucune donnee de sante detectee".
Pour chaque finding : section 45 CFR, fichier:ligne, severite, score confiance /10 (>= 8), fix.
```

---

## Phase 3 — Consolidation des resultats

Apres completion de toutes les taches paralleles, consolide les findings :

1. **Deduplication** : identifie les findings identiques ou similaires couverts par plusieurs frameworks
2. **Prioritisation** : classe les findings par severite globale (impactant plusieurs frameworks = priorite plus haute)
3. **Cross-referencing** : un meme finding peut violer plusieurs frameworks (ex: absence de MFA = OWASP A07 + SOC2 CC6.1 + ISO 27001 A.8.5 + NIST IA-2 + PCI-DSS R8 ; absence de SAST en CI/CD = SSDF PW.4.1 + OWASP A08 + SOC2 CC7.1 + ISO 27001 A.8.29)

---

## Phase 4 — Rapport consolide

Produis le rapport dans ce format exact :

```
# Rapport d'audit de conformite multi-frameworks — [Nom du projet]
Date : [date]
Auditeur : Claude Code (security-audit-full)
Frameworks evalues : OWASP Top 10 | SOC 2 | GDPR | ISO 27001 | PCI-DSS | NIST 800-53 | NIST SSDF | CIS | HIPAA

---

## Tableau de bord de conformite

| Framework | Score /10 | Statut | Findings Critiques | Findings Hauts |
|---|---|---|---|---|
| OWASP Top 10 (2021) | | 🔴/🟠/🟡/🟢 | | |
| SOC 2 Type II | | | | |
| GDPR/RGPD | | | | |
| ISO 27001:2022 | | | | |
| PCI-DSS v4.0 | N/A si non applicable | | | |
| NIST SP 800-53 | | | | |
| NIST SSDF SP 800-218 | | | | |
| CIS Benchmarks | | | | |
| HIPAA | N/A si non applicable | | | |
| **Score global** | **/10** | | | |

Legende : 🔴 Critique (<4) | 🟠 Insuffisant (4-6) | 🟡 Partiel (6-8) | 🟢 Conforme (>8)

---

## Resume executif
[3-5 phrases sur le niveau de conformite global, les risques majeurs, et les priorites immediates]

---

## Findings critiques consolidés (tous frameworks)

| # | Finding | Frameworks impactes | Fichier:ligne | Confiance | Fix |
|---|---|---|---|---|---|

---

## Findings hauts consolidés

| # | Finding | Frameworks impactes | Fichier:ligne | Confiance | Fix |
|---|---|---|---|---|---|

---

## Findings moyens consolidés

| # | Finding | Frameworks impactes | Fichier:ligne | Confiance | Fix |
|---|---|---|---|---|---|

---

## Cartographie des donnees sensibles

| Type | Donnees | Protection en place | Frameworks concernes |
|---|---|---|---|
| Donnees personnelles | | | GDPR, NIST PT |
| Donnees de paiement | | | PCI-DSS |
| Donnees de sante | | | HIPAA |
| Credentials/Secrets | | | OWASP A02, SOC2 CC6 |

---

## Analyse par framework

### OWASP Top 10
[Score + findings specifiques non deja listes dans la section consolidee]

### SOC 2 Type II
[Score maturite TSC + findings specifiques]

### GDPR/RGPD
[Score + findings specifiques + cartographie donnees personnelles]

### ISO 27001:2022
[Score + findings specifiques]

### PCI-DSS v4.0
[Score + findings specifiques OU "Non applicable — aucune donnee de carte detectee"]

### NIST SP 800-53 Rev 5
[Score par famille + findings specifiques]

### NIST SSDF SP 800-218
[Score par groupe (PO/PS/PW/RV) + findings specifiques pipeline/dev]

### CIS Benchmarks
[Score par benchmark (Docker/K8s/Linux/Cloud) + findings specifiques]

### HIPAA Security Rule
[Score + findings specifiques OU "Non applicable — aucune ePHI detectee"]

---

## Roadmap de remediation globale

### Immediat (0-30 jours) — Critiques
[Actions ordonnees, avec frameworks impactes et effort estime XS/S/M/L/XL]

### Court terme (30-90 jours) — Hauts
[Actions ordonnees]

### Moyen terme (90-180 jours) — Moyens
[Actions ordonnees]

### Long terme (180+ jours) — Gouvernance
[Politiques, formation, processus a mettre en place]

---

## Points positifs
[Controles de securite deja en place, bonnes pratiques observees]
```
