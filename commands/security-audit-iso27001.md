---
description: "Audit de conformite ISO/IEC 27001:2022. Analyse les 93 controles Annex A : politiques, acces, cryptographie, operations, communications, SDLC, incidents, continuite."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un auditeur ISO 27001:2022 certifie. Realise un audit de conformite du projet situe a : **$ARGUMENTS**

Reference : ISO/IEC 27001:2022 (93 controles en 4 themes, Annex A).
Mappe chaque finding au controle Annex A applicable.

---

## Instructions

1. Detecte le stack et l'infrastructure du projet
2. Analyse les controles Annex A applicables (certains peuvent etre hors perimetre)
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec code ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE
7. Indique les controles "non applicables" avec justification

---

## Reference : Annex A ISO 27001:2022 (93 controles, 4 themes)

| Theme | Controles | Description |
|-------|-----------|-------------|
| A.5 Organisational | 5.1-5.37 | Politiques, roles, intelligence des menaces, fournisseurs |
| A.6 People | 6.1-6.8 | RH, teletravail, sensibilisation |
| A.7 Physical | 7.1-7.14 | Acces physique, equipements |
| A.8 Technological | 8.1-8.34 | Endpoints, acces, cryptographie, dev securise, logging |

---

## Phase 1 — Detection du perimetre

```bash
# Stack technologique
find $ARGUMENTS -maxdepth 4 \( \
  -name "package.json" -o -name "go.mod" -o -name "pyproject.toml" -o \
  -name "Dockerfile" -o -name "docker-compose*.yml" -o \
  -name "*.tf" -o -name ".github" \
\) 2>/dev/null | grep -v node_modules | grep -v ".git"

# CI/CD — GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket, Travis, Drone, TeamCity
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" \
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

# Politiques et documentation
find $ARGUMENTS -name "SECURITY*" -o -name "POLICY*" -o -name "policy*" -o \
  -name "security*" -o -name "CONTRIBUTING*" -o -name "*.md" 2>/dev/null | \
  grep -v node_modules | grep -v ".git" | head -20
```

---

## Phase 2 — Checklist ISO 27001:2022

### Theme A.5 — Controles Organisationnels

#### A.5.1 — Politiques de securite de l'information
- [ ] Politique de securite de l'information documentee et approuvee
- [ ] Politique revue periodiquement (min. annuellement)
- [ ] Politique communiquee a toutes les parties prenantes
- [ ] Politiques specifiques : acces, chiffrement, classification, BYOD, cloud

#### A.5.9 — Inventaire des actifs informationnels
- [ ] Inventaire des actifs (serveurs, bases de donnees, APIs, credentials)
- [ ] Proprietaire designe pour chaque actif critique
- [ ] Classification des actifs (public, interne, confidentiel, secret)

#### A.5.10 — Utilisation acceptable des actifs
- [ ] Politique d'utilisation acceptable documentee
- [ ] Restrictions sur l'usage des outils et systemes

#### A.5.14 — Transfert d'information
- [ ] Accords de confidentialite (NDA) avec les tiers
- [ ] Procedures de transfert securise des donnees sensibles

#### A.5.15 — Controle d'acces
- [ ] Politique de controle d'acces documentee
- [ ] Principe du moindre privilege applique
- [ ] Revue periodique des droits d'acces (trimestielle recommandee)
- [ ] Suppression immediate des acces a la depart d'un employe

#### A.5.16 — Gestion des identites
- [ ] Identifiant unique par utilisateur (pas de comptes partages)
- [ ] Processus de creation et suppression des comptes documente
- [ ] Comptes privilegies (admin) limites et controles

#### A.5.17 — Informations d'authentification
- [ ] Politique de mots de passe forte documentee
- [ ] MFA requis pour les acces privilegies et distants
- [ ] Secrets et mots de passe jamais transmis en clair

#### A.5.23 — Securite pour l'utilisation des services cloud
- [ ] Inventaire des services cloud utilises
- [ ] Responsabilites partagees clairement definies (shared responsibility model)
- [ ] Evaluation de securite des CSP (AWS, GCP, Azure, Vercel, Railway...)

#### A.5.30 — Preparation a la continuite ICT
- [ ] Plan de continuite d'activite (BCP) documente
- [ ] RTO et RPO definis pour les systemes critiques
- [ ] Tests de continuite realises periodiquement

#### A.5.37 — Procedures d'exploitation documentees
- [ ] Procedures operationnelles documentees (runbooks)
- [ ] Documentation des deploiements et rollbacks

### Theme A.8 — Controles Technologiques

#### A.8.2 — Acces privilegies
- [ ] Comptes admin/root utilises uniquement quand necessaire
- [ ] Sessions privilegiees loggees
- [ ] Separation des environnements (dev, staging, prod)
- [ ] Pas de mots de passe root partages

#### A.8.3 — Restriction d'acces a l'information
- [ ] Acces aux donnees base sur le role (RBAC)
- [ ] Acces aux donnees de production limite et log

#### A.8.4 — Acces au code source
- [ ] Acces au depot de code restreint aux developpeurs autorises
- [ ] Pas de credentials dans le code source ou l'historique git
- [ ] Code review obligatoire avant merge

```bash
# Verifier les secrets dans l'historique git
cd $ARGUMENTS && git log --all -p -- '*.env' '*.key' '*.pem' '*.secret' 2>/dev/null | head -50
git log --all --oneline 2>/dev/null | head -20
```

#### A.8.5 — Authentification securisee
- [ ] Protocoles d'auth securises (OAuth2, OIDC, SAML)
- [ ] Sessions expirees apres inactivite
- [ ] Lockout apres N tentatives echouees

#### A.8.7 — Protection contre les malwares
- [ ] Scanner de vulnerabilites integre en CI/CD
- [ ] Dependencies scannees regulierement (npm audit, pip-audit, trivy)
- [ ] Images Docker scannees (Trivy, Grype, Docker Scout)

```bash
# Verifier les scanners dans le CI/CD (GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket)
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" \
  -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" \
  -o -name "Jenkinsfile" \
  -o -name "azure-pipelines.yml" \
  -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" \
  -o -name "bitbucket-pipelines.yml" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -l "trivy\|snyk\|codeql\|semgrep\|sonar\|npm audit\|pip-audit\|gitleaks\|trufflehog" 2>/dev/null
```

#### A.8.8 — Gestion des vulnerabilites techniques
- [ ] Processus de veille sur les CVE (newsletters, advisories)
- [ ] Patch management : delais definis par criticite (critique <24h, haute <7j)
- [ ] Inventaire des versions des composants (SBOM)

#### A.8.9 — Gestion de la configuration
- [ ] Configuration as Code (Infrastructure as Code)
- [ ] Configurations de securite documentees et versionnees
- [ ] Pas de configuration par defaut non modifiee en production

#### A.8.10 — Suppression des informations
- [ ] Procedure de suppression securisee des donnees
- [ ] Sanitisation des medias avant reutilisation ou mise au rebut

#### A.8.11 — Masquage des donnees
- [ ] Donnees personnelles masquees dans les logs (PII masking)
- [ ] Donnees de test anonymisees (pas de donnees de prod en dev)

#### A.8.12 — Prevention de la fuite de donnees (DLP)
- [ ] Controles pour empecher l'exfiltration de donnees sensibles
- [ ] Surveillance des transferts de donnees anormaux

#### A.8.15 — Journalisation (Logging)
- [ ] Logs des evenements de securite actives
- [ ] Logs couvrent : auth, acces admin, modifications critiques, erreurs
- [ ] Logs proteges contre la modification (immuables)
- [ ] Retention des logs >= 12 mois (recommandation ISO)
- [ ] Synchronisation de l'horloge (NTP) pour coherence des timestamps

```bash
# Analyser la configuration de logging
grep -rn "logger\|winston\|pino\|slog\|logrus\|zap\|structlog" $ARGUMENTS \
  --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

#### A.8.16 — Surveillance des activites
- [ ] Monitoring des activites systeme (CPU, memoire, reseau, erreurs)
- [ ] Alertes sur les comportements anormaux
- [ ] SIEM ou equivalent si applicable

#### A.8.20 — Securite des reseaux
- [ ] Segmentation reseau (frontend/backend/DB separes)
- [ ] Regles de firewall documentees et restrictives
- [ ] Pas de services internes exposes sur internet

#### A.8.21 — Securite des services reseau
- [ ] TLS configure correctement (version, cipher suites)
- [ ] Certificats valides et renouvelables automatiquement

#### A.8.24 — Utilisation de la cryptographie
- [ ] Politique de cryptographie documentee
- [ ] Algorithmes approuves : AES-256, RSA-2048+, ECDSA P-256+, SHA-256+
- [ ] Algorithmes interdits : DES, 3DES, RC4, MD5, SHA-1
- [ ] Gestion du cycle de vie des cles (creation, rotation, revocation)

#### A.8.25 — Cycle de vie du developpement securise (SDLC)
- [ ] Security requirements integres des le debut du projet
- [ ] Threat modeling realise pour les nouvelles fonctionnalites
- [ ] Code review avec focus securite obligatoire
- [ ] Tests de securite (SAST, DAST) integres en CI/CD
- [ ] Environnements de dev/staging/prod separes

#### A.8.26 — Exigences de securite des applications
- [ ] Validation des inputs sur toutes les entrees utilisateur
- [ ] Protection contre les injections (SQL, XSS, CSRF...)
- [ ] Gestion des erreurs sans exposition d'informations internes

#### A.8.28 — Codage securise
- [ ] Standards de codage securise documentes et appliques
- [ ] Formation des developpeurs a la securite
- [ ] Pas de fonctions dangereuses (eval, exec, system avec input user)

#### A.8.32 — Gestion des changements
- [ ] Tout changement documente et approuve
- [ ] Tests avant deploiement en production
- [ ] Procedure de rollback definie

#### A.8.33 — Informations de test
- [ ] Pas de donnees de production en environnement de test
- [ ] Donnees de test anonymisees ou synthetiques

---

## Format du rapport

```
# Rapport d'audit ISO 27001:2022 — [Nom du projet]
Date : [date]
Reference : ISO/IEC 27001:2022
Auditeur : Claude Code (security-audit-iso27001)

## Resume executif
[Niveau de maturite, themes forts et faibles, readiness pour certification]

## Controles hors perimetre
| Controle | Justification d'exclusion |
|---|---|

## Findings

### CRITIQUE — Non-conformite majeure (blocage certification)
| # | Finding | Controle A. | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — Non-conformite significative
| # | Finding | Controle A. | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — Opportunite d'amelioration
| # | Finding | Controle A. | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Observation
| # | Observation | Controle | Recommandation |

## Score de conformite par theme
| Theme | Controles evalues | Conformes | Partiels | Non-conformes | Score |
|---|---|---|---|---|---|
| A.5 Organisational | | | | | /10 |
| A.6 People | | | | | /10 |
| A.7 Physical | | | | | /10 |
| A.8 Technological | | | | | /10 |
| **Global** | | | | | **/10** |

## Roadmap certification ISO 27001
[Actions prioritaires par theme avec effort estime (XS/S/M/L/XL)]
```
