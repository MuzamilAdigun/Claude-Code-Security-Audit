---
description: "Audit de conformite NIST SSDF (Secure Software Development Framework) SP 800-218. Analyse les 4 groupes de pratiques : PO (preparation), PS (protection), PW (production securisee), RV (reponse aux vulnerabilites). Requis pour les fournisseurs federaux US (EO 14028)."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un auditeur NIST SSDF senior. Realise un audit de conformite du projet situe a : **$ARGUMENTS**

Reference : NIST SP 800-218 v1.1 (Secure Software Development Framework) — Février 2022.
Mappe chaque finding a la pratique SSDF applicable (PO.x, PS.x, PW.x, RV.x).

---

## Instructions

1. Detecte le stack, le pipeline CI/CD et les outils de securite en place
2. Analyse les 4 groupes de pratiques SSDF
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec code ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE

---

## Reference : NIST SSDF SP 800-218 — 4 groupes de pratiques

| Groupe | ID | Pratiques cles |
|--------|-----|----------------|
| Prepare the Organization | PO | Politiques, outils, environnements, fournisseurs |
| Protect the Software | PS | Intégrité du code, protection des branches, supply chain |
| Produce Well-Secured Software | PW | Threat modeling, secure coding, tests, review |
| Respond to Vulnerabilities | RV | Disclosure, analyse, patching, communication |

---

## Phase 1 — Detection du pipeline et des outils

```bash
# CI/CD — tous les systemes (GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket, Travis, Drone, TeamCity)
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" \
  -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" \
  -o -path "*/.gitlab-ci.yaml" \
  -o -name "Jenkinsfile" \
  -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" \
  -o -name "azure-pipelines.yaml" \
  -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" \
  -o -name "bitbucket-pipelines.yml" \
  -o -name ".travis.yml" \
  -o -name ".drone.yml" \
  -o -name ".drone.yaml" \
  -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules

# Outils de securite dans le pipeline (tous systemes CI/CD)
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name "bitbucket-pipelines.yml" \
  -o -name ".drone.yml" -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -l "codeql\|semgrep\|snyk\|sonar\|trivy\|gitleaks\|trufflehog\|\
bandit\|gosec\|npm.audit\|pip.audit\|govulncheck\|dependabot\|renovate\|\
SonarQubePrepare\|SnykSecurityScan\|MicrosoftSecurityDevOps\|WhiteSource" 2>/dev/null

# Hooks pre-commit
find $ARGUMENTS -name ".pre-commit-config.yaml" -o -name ".pre-commit-hooks.yaml" \
  2>/dev/null | grep -v node_modules

# Lock files (intégrité des dépendances)
find $ARGUMENTS -maxdepth 3 \( \
  -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o \
  -name "go.sum" -o -name "poetry.lock" -o -name "Gemfile.lock" -o \
  -name "Cargo.lock" -o -name "composer.lock" -o -name "pdm.lock" \
\) 2>/dev/null | grep -v node_modules

# Configuration des tests
find $ARGUMENTS -name "jest.config.*" -o -name "vitest.config.*" -o \
  -name "pytest.ini" -o -name "pyproject.toml" -o -name "*_test.go" \
  2>/dev/null | grep -v node_modules | head -10

# Gestion des secrets
find $ARGUMENTS \( -name ".env*" -o -name "*.env" \) 2>/dev/null | \
  grep -v node_modules | grep -v ".git"
grep -rn "vault\|secrets.*manager\|doppler\|1password\|aws.*secret\|gcp.*secret" \
  $ARGUMENTS --include="*.yml" --include="*.yaml" --include="*.json" \
  2>/dev/null | grep -v node_modules | head -10
```

---

## Phase 2 — Checklist NIST SSDF

### PO — Prepare the Organization

#### PO.1 — Politiques et processus de securite logicielle

- [ ] **PO.1.1** : Politique de developpement securise documentee et diffusee a toute l'equipe
- [ ] **PO.1.2** : Roles et responsabilites securite definis (qui est responsable du SAST, des reviews, du patching ?)
- [ ] **PO.1.3** : Standards de codage securise documentes (OWASP, CERT, langage-specifique)

```bash
# Chercher la documentation securite dev
find $ARGUMENTS \( -name "SECURITY*" -o -name "CONTRIBUTING*" -o -name "CODE_OF_CONDUCT*" \
  -o -name "coding*standard*" -o -name "secure*coding*" \) 2>/dev/null | grep -v node_modules
```

#### PO.2 — Roles et responsabilites

- [ ] **PO.2.1** : Champions securite identifies dans l'equipe de dev
- [ ] **PO.2.2** : Formation securite des developpeurs (OWASP, SANS, etc.)

#### PO.3 — Environnements de developpement securises

- [ ] **PO.3.1** : Environnements de dev/test/prod separes et isoles
- [ ] **PO.3.2** : Acces aux environnements de production restreint et audite
- [ ] **PO.3.3** : Outils de developpement verifies et approuves (pas d'outils non autorises)

#### PO.4 — Threat Modeling

- [ ] **PO.4.1** : Threat modeling realise pour les nouvelles fonctionnalites
- [ ] **PO.4.2** : Modele de menaces documente et maintenu a jour
- [ ] **PO.4.3** : Resultats du threat modeling integres dans les criteres d'acceptance

```bash
# Chercher la documentation threat model
find $ARGUMENTS \( -name "*threat*model*" -o -name "*threat*" -o \
  -name "STRIDE*" -o -name "*attack*tree*" \) 2>/dev/null | grep -v node_modules
```

#### PO.5 — Gestion des outils de securite

- [ ] **PO.5.1** : Inventaire des outils SAST/DAST/SCA utilises
- [ ] **PO.5.2** : Outils de securite integres dans le pipeline CI/CD
- [ ] **PO.5.3** : Resultats des outils de securite traites et trackes

---

### PS — Protect the Software

#### PS.1 — Protection du code source

- [ ] **PS.1.1** : Code source dans un SCM avec acces controle (GitHub, GitLab...)
- [ ] **PS.1.2** : Historique du code conserve et auditable
- [ ] **PS.1.3** : Acces en ecriture au depot restreint aux contributeurs autorises

```bash
# Verifier la protection des branches (GitHub, GitLab, Azure DevOps, Bitbucket)
# GitHub : rulesets / branch protection dans les workflows
find $ARGUMENTS \( \
  -path "*/.github/*.json" -o -path "*/.github/branch*" \
  -o -path "*/.github/rulesets*" \
\) 2>/dev/null | head -5
# GitLab : templates MR et regles de protection
find $ARGUMENTS -path "*/.gitlab/merge_request_templates/*" 2>/dev/null | head -5
# Azure DevOps : branch policies dans le pipeline
find $ARGUMENTS \( -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \) \
  2>/dev/null | xargs grep -n "trigger\|pr:\|branch\|protected" 2>/dev/null | head -10
# Regles de review dans tous les CI/CD
grep -rn "branch.*protection\|required.*review\|required.*status\|dismiss.*stale\|\
approvals\|min.*approvals\|requiresApproval\|pullRequestTemplate" \
  $ARGUMENTS --include="*.yml" --include="*.yaml" --include="*.json" \
  2>/dev/null | grep -v node_modules | head -10
```

#### PS.2 — Intégrité du code

- [ ] **PS.2.1** : Commits signes (GPG/SSH) si applicable
- [ ] **PS.2.2** : Tags de release signes
- [ ] **PS.2.3** : Verification de l'integrite des artefacts de build (checksums, signatures)
- [ ] **PS.2.4** : SBOM (Software Bill of Materials) genere a chaque build

```bash
# Verifier la signature des commits
git -C $ARGUMENTS log --show-signature -5 2>/dev/null | grep -E "Good signature|gpg:|commit" | head -20

# Chercher la generation de SBOM
grep -rn "sbom\|cyclonedx\|syft\|spdx\|bom.*gen" \
  $ARGUMENTS --include="*.yml" --include="*.yaml" \
  2>/dev/null | grep -v node_modules | head -10
```

#### PS.3 — Protection des artefacts de build

- [ ] **PS.3.1** : Registry d'images Docker prive et securise (pas de push sur Docker Hub public en prod)
- [ ] **PS.3.2** : Images scannees avant deploiement (Trivy, Grype, Snyk Container)
- [ ] **PS.3.3** : Artefacts de build stockes dans un depot securise (Nexus, Artifactory, GitHub Packages)
- [ ] **PS.3.4** : Pas de credentials dans les artefacts de build
- [ ] **PS.3.5** : Images de production signees avec Cosign/Sigstore (requis EO 14028) — `cosign sign`
- [ ] **PS.3.6** : Attestations SBOM attachees a l'image (`cosign attest --predicate sbom.json`)
- [ ] **PS.3.7** : Politique de verification des signatures en admission (Kyverno verifyImages, OPA)

```bash
# Verifier le scan des images dans tous les pipelines CI/CD
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name "bitbucket-pipelines.yml" \
  -o -name ".drone.yml" -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -ln "trivy\|grype\|snyk.*container\|docker.*scan\|image.*scan\|scan.*image" 2>/dev/null | head -10

# Verifier la signature Cosign dans CI/CD
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" \
  -o -name "azure-pipelines.yml" -o -name ".drone.yml" \
\) 2>/dev/null | xargs grep -ln "cosign\|sigstore\|notation\|docker.*trust" 2>/dev/null

# Verifier les push registry
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" \
  -o -name "azure-pipelines.yml" -o -name ".drone.yml" \
\) 2>/dev/null | xargs grep -ln "docker.*push\|registry\|ghcr\|ecr\|gcr\|artifactory" 2>/dev/null | head -10
```

#### PS.4 — Gestion des secrets dans le pipeline

- [ ] **PS.4.1** : Pas de secrets hardcodes dans le code source
- [ ] **PS.4.2** : Secrets injectes via variables d'environnement CI/CD ou gestionnaire de secrets
- [ ] **PS.4.3** : Scan des secrets en pre-commit et en CI/CD (Gitleaks, TruffleHog)
- [ ] **PS.4.4** : Rotation des secrets CI/CD documentee

```bash
# Chercher des secrets potentiellement hardcodes
grep -rn "password\s*=\s*['\"][^${\'" ]\|secret\s*=\s*['\"][^${\'" ]\|\
api[_-]key\s*=\s*['\"][^${\'" ]\|token\s*=\s*['\"][^${\'" ]" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | grep -v "_test\." | grep -v ".spec." | head -20

# Verifier Gitleaks ou TruffleHog dans CI
grep -rn "gitleaks\|trufflehog\|secret.*scan\|detect-secrets" \
  $ARGUMENTS --include="*.yml" --include="*.yaml" \
  2>/dev/null | grep -v node_modules | head -10

# Verifier les .env commites par erreur
find $ARGUMENTS -name ".env" -not -name ".env.example" -not -name ".env.sample" \
  2>/dev/null | grep -v node_modules
```

---

### PW — Produce Well-Secured Software

#### PW.1 — Design securise

- [ ] **PW.1.1** : Architecture de securite documentee (diagramme de flux de donnees, zones de confiance)
- [ ] **PW.1.2** : Principe du moindre privilege applique dans la conception
- [ ] **PW.1.3** : Separation des responsabilites (auth, metier, data access)
- [ ] **PW.1.4** : Fail-secure par defaut (deny-all si erreur)

#### PW.2 — Revues de code securite

- [ ] **PW.2.1** : Code review obligatoire avant merge (min. 1 approbateur)
- [ ] **PW.2.2** : Checklist securite dans le template de PR
- [ ] **PW.2.3** : Revues de code axees securite pour les composants sensibles (auth, paiement, donnees personnelles)

```bash
# Verifier le template de PR/MR (GitHub, GitLab, Azure DevOps, Bitbucket)
find $ARGUMENTS \( \
  -path "*/.github/PULL_REQUEST_TEMPLATE*" \
  -o -name "pull_request_template.md" \
  -o -path "*/.gitlab/merge_request_templates/*.md" \
  -o -path "*/.azure/pull_request_template.md" \
  -o -path "*/docs/pull_request_template.md" \
\) 2>/dev/null | head -10

# Verifier les codeowners (GitHub, GitLab, Gitea)
find $ARGUMENTS \( \
  -name "CODEOWNERS" \
  -o -path "*/.github/CODEOWNERS" \
  -o -path "*/.gitlab/CODEOWNERS" \
  -o -path "*/docs/CODEOWNERS" \
\) 2>/dev/null | head -5
```

#### PW.4 — Tests de securite (SAST)

- [ ] **PW.4.1** : SAST integre dans le pipeline CI/CD (CodeQL, Semgrep, SonarQube, Bandit, Gosec...)
- [ ] **PW.4.2** : Resultats SAST bloquants sur les findings HAUTE/CRITIQUE
- [ ] **PW.4.3** : Baseline de faux positifs geree et documentee
- [ ] **PW.4.4** : IaC Security Scanning integre en CI/CD pour Terraform, Helm, manifestes K8s (Checkov, tfsec, terrascan, Trivy config)

```bash
# Verifier la presence de SAST dans tous les pipelines CI/CD
# (find+xargs pour couvrir Jenkinsfile sans extension et .teamcity/*.kts)
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name "bitbucket-pipelines.yml" \
  -o -name ".drone.yml" -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -ln "codeql\|semgrep\|sonarqube\|sonar-scanner\|bandit\|gosec\|\
eslint.*security\|flawfinder\|spotbugs\|checkmarx\|veracode\|\
SonarQubePrepare@\|SnykSecurityScan@\|MicrosoftSecurityDevOps@\|\
sh.*semgrep\|sh.*sonar\|sh.*bandit\|sh.*gosec" 2>/dev/null

# Azure DevOps — taches SAST specifiques
find $ARGUMENTS \( -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \) \
  2>/dev/null | xargs grep -n "SonarQubePrepare@\|SonarQubeAnalyze@\|SonarQubePublish@\|\
SnykSecurityScan@\|MicrosoftSecurityDevOps@\|Checkmarx@\|Veracode@" 2>/dev/null | head -10

# Jenkins — invocations shell de SAST et gestion des credentials
find $ARGUMENTS \( -name "Jenkinsfile" -o -name "Jenkinsfile.*" \) 2>/dev/null | \
  xargs grep -n "sh.*semgrep\|sh.*sonar\|sh.*bandit\|sh.*gosec\|\
withCredentials\|credentials(\|@Library\|sast\|security.*scan" 2>/dev/null | head -10

# Publication des resultats SAST (SARIF → GitHub Security tab, artifacts → GitLab/Jenkins)
find $ARGUMENTS \( -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \) \
  2>/dev/null | xargs grep -n "sarif\|upload-sarif\|security-events\|codeql.*results" 2>/dev/null | head -5
find $ARGUMENTS -path "*/.gitlab-ci.yml" 2>/dev/null | \
  xargs grep -n "sast:\|dast:\|artifacts.*reports\|security-testing" 2>/dev/null | head -5

# Configurations SAST standalone
find $ARGUMENTS \( -name ".semgrep*" -o -name "semgrep*.yml" -o \
  -name "sonar-project.properties" -o -name "codeql-config.yml" -o \
  -name ".bandit" -o -name "gosec*" \) 2>/dev/null | grep -v node_modules

# IaC Security Scanning (PW.4.4) — Checkov, tfsec, terrascan, Trivy config
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name "bitbucket-pipelines.yml" \
  -o -name ".drone.yml" -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -ln "checkov\|tfsec\|terrascan\|trivy.*config\|trivy.*misconfig\|\
infracost\|snyk.*iac\|kics\|Snyk.*IaC@" 2>/dev/null

# Configurations IaC scanner standalone
find $ARGUMENTS \( -name ".checkov*" -o -name "checkov.yaml" -o \
  -name ".tfsec" -o -name "tfsec.yml" -o -name ".terrascan*" \) \
  2>/dev/null | grep -v node_modules
```

#### PW.5 — Analyse des dependances (SCA)

- [ ] **PW.5.1** : SCA (Software Composition Analysis) integre en CI/CD (Dependabot, Snyk, OWASP Dependency-Check)
- [ ] **PW.5.2** : Alertes automatiques sur les CVE dans les dependances
- [ ] **PW.5.3** : Politique de remediation des CVE documentee (delais par severite)
- [ ] **PW.5.4** : Licences des dependances verifiees (pas de GPL dans du code propriétaire)

```bash
# Verifier Dependabot (GitHub) / Renovate (tous SCM) / Mend / Snyk (Azure DevOps, GitLab, Jenkins)
find $ARGUMENTS \( \
  -path "*/.github/dependabot.yml" \
  -o -path "*/.github/dependabot.yaml" \
  -o -path "*/.github/renovate*" \
  -o -path "*/.gitlab/renovate*" \
  -o -name "renovate.json" \
  -o -name ".renovaterc" \
  -o -name ".renovaterc.json" \
\) 2>/dev/null | head -10

# Verifier les outils SCA dans tous les pipelines CI/CD
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name "bitbucket-pipelines.yml" \
  -o -name ".drone.yml" -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -ln "dependabot\|renovate\|snyk\|owasp.*dep\|dependency.*check\|\
npm.audit\|pip.audit\|govulncheck\|cargo.audit\|bundle.audit\|\
WhiteSource@\|Mend@\|sh.*snyk\|sh.*npm.*audit" 2>/dev/null | head -15
```

#### PW.6 — Tests de securite (DAST / Pentest)

- [ ] **PW.6.1** : DAST realise periodiquement (OWASP ZAP, Burp Suite)
- [ ] **PW.6.2** : Pentest annuel realise par une equipe independante
- [ ] **PW.6.3** : Resultats des tests de securite traques et resolus

#### PW.7 — Validation des entrees et encodage des sorties

- [ ] **PW.7.1** : Toutes les entrees utilisateur validees aux frontieres du systeme
- [ ] **PW.7.2** : Sorties encodees pour prevenir l'injection (XSS, SQL, commandes)
- [ ] **PW.7.3** : Principe de defense en profondeur sur la validation

```bash
# Verifier la validation et sanitisation des inputs
grep -rn "validate\|sanitize\|escape\|encode\|zod\|yup\|joi\|\
express-validator\|class-validator\|pydantic\|marshmallow" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20

# Verifier les requetes parametrees (anti-injection SQL)
grep -rn "query.*\$[0-9]\|prepare\|parameterized\|QueryRow\|db\.Query\|\
cursor\.execute.*%s\|cursor\.execute.*?" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -15
```

#### PW.8 — Tests automatises de securite

- [ ] **PW.8.1** : Tests unitaires couvrant les cas limites de securite (inputs malformes, auth, acces non autorise)
- [ ] **PW.8.2** : Tests d'integration verifiant les controles de securite
- [ ] **PW.8.3** : Fuzzing si applicable (API REST, parsers, protocols)
- [ ] **PW.8.4** : Couverture de tests >= seuil defini

```bash
# Verifier la couverture des tests
find $ARGUMENTS \( -name "*.test.ts" -o -name "*.test.js" -o -name "*.spec.ts" \
  -o -name "*_test.go" -o -name "test_*.py" \) 2>/dev/null | grep -v node_modules | wc -l

# Chercher les tests de securite specifiques
grep -rn "unauthorized\|forbidden\|403\|401\|injection\|xss\|csrf\|brute.*force\|\
invalid.*token\|expired.*token\|sql.*injection" \
  $ARGUMENTS --include="*.test.*" --include="*_test.*" --include="*.spec.*" \
  2>/dev/null | grep -v node_modules | head -15
```

---

### RV — Respond to Vulnerabilities

#### RV.1 — Identification des vulnerabilites

- [ ] **RV.1.1** : Processus de reception des rapports de vulnerabilites (SECURITY.md, email dedie, bug bounty)
- [ ] **RV.1.2** : Surveillance des CVE pour les composants utilises (feeds NVD, GitHub Advisories)
- [ ] **RV.1.3** : Processus de triage des vulnerabilites documentee

```bash
# Verifier SECURITY.md (responsible disclosure)
find $ARGUMENTS -name "SECURITY.md" -o -name "SECURITY.txt" 2>/dev/null | head -5

# Verifier les advisories GitHub
find $ARGUMENTS -path "*/.github/SECURITY*" 2>/dev/null | head -5
```

#### RV.2 — Analyse et resolution

- [ ] **RV.2.1** : Analyse de cause racine des vulnerabilites reportees
- [ ] **RV.2.2** : Delais de remediation par severite documentes et respectes :
  - Critique : <= 7 jours
  - Haute : <= 30 jours
  - Moyenne : <= 90 jours
- [ ] **RV.2.3** : Regression tests ajoutes apres correction d'une vulnerabilite
- [ ] **RV.2.4** : Analyse de la portee : la meme classe de vuln existe-t-elle ailleurs dans le code ?

#### RV.3 — Communication

- [ ] **RV.3.1** : Politique de disclosure responsable documentee (coordinated disclosure)
- [ ] **RV.3.2** : CVE attribue si applicable (CNA ou MITRE)
- [ ] **RV.3.3** : Release notes / changelog de securite publies
- [ ] **RV.3.4** : Utilisateurs notifies si donnees compromises

```bash
# Verifier le changelog
find $ARGUMENTS \( -name "CHANGELOG*" -o -name "CHANGES*" -o -name "HISTORY*" \
  -o -name "RELEASES*" \) 2>/dev/null | head -5
```

---

## Format du rapport

```
# Rapport d'audit NIST SSDF SP 800-218 — [Nom du projet]
Date : [date]
Reference : NIST SP 800-218 v1.1 (Secure Software Development Framework)
Auditeur : Claude Code (security-audit-ssdf)
Stack detecte : [liste]
Pipeline CI/CD : [GitHub Actions / GitLab CI / Jenkins / Azure DevOps / CircleCI / Bitbucket / Travis / Drone / TeamCity / aucun]

## Resume executif
[Etat de maturite SSDF, lacunes principales par groupe de pratiques]

## Findings

### CRITIQUE — Absence de controle fondamental
| # | Finding | SSDF | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — A corriger avant livraison
| # | Finding | SSDF | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — A planifier
| # | Finding | SSDF | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | SSDF | Recommandation |

## Score de maturite SSDF
| Groupe | Pratiques evaluees | Conformes | Partielles | Absentes | Score /10 |
|---|---|---|---|---|---|
| PO — Prepare the Organization | | | | | |
| PS — Protect the Software | | | | | |
| PW — Produce Well-Secured Software | | | | | |
| RV — Respond to Vulnerabilities | | | | | |
| **Global** | | | | | **/10** |

## Outils de securite identifies
| Outil | Type | Integre CI/CD | Bloquant |
|---|---|---|---|

## Plan de remediation SSDF
[Actions ordonnees par impact sur la posture de securite du developpement]
```
