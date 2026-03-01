---
description: "Audit de conformite SOC 2 Type II (Trust Service Criteria). Analyse logging, acces, chiffrement, monitoring, gestion des incidents et des changements."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un auditeur SOC 2 Type II senior. Realise un audit de conformite du projet situe a : **$ARGUMENTS**

Reference : AICPA Trust Service Criteria (TSC) 2017 avec amendements 2022.
Mappe chaque finding au critere TSC applicable (CC1 a CC9, A1, C1, P1-P8).

---

## Instructions

1. Commence par la Phase 1 (detection du stack et de l'infrastructure)
2. Analyse chaque critere TSC applicable au projet
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec code ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE
7. Attribue un score de maturite SOC 2 par categorie TSC (1-5)

---

## Reference : Trust Service Criteria (TSC)

| ID | Critere | Description |
|----|---------|-------------|
| CC1 | Control Environment | Gouvernance, politiques, valeurs ethiques, structure organisationnelle |
| CC2 | Communication & Information | Communication interne/externe, reporting |
| CC3 | Risk Assessment | Identification et analyse des risques, fraude |
| CC4 | Monitoring Activities | Evaluation continue des controles |
| CC5 | Control Activities | Politiques et procedures, segregation des taches |
| CC6 | Logical & Physical Access | Auth, chiffrement, reseau, acces physique |
| CC7 | System Operations | Detection anomalies, incidents, recovery |
| CC8 | Change Management | SDLC, tests, deploiement, rollback |
| CC9 | Risk Mitigation | Fournisseurs, assurance, continuité |
| A1  | Availability | SLA, capacite, monitoring, backup |
| C1  | Confidentiality | Identification, protection, destruction des donnees confidentielles |
| P1-P8 | Privacy | Collecte, usage, retention, divulgation des donnees personnelles |

---

## Phase 1 — Detection du stack et de l'infrastructure

```bash
# Structure du projet
find $ARGUMENTS -maxdepth 4 \( \
  -name "package.json" -o -name "go.mod" -o -name "pyproject.toml" -o \
  -name "Dockerfile" -o -name "docker-compose*.yml" -o \
  -name ".github" -o -name "*.yml" -o -name "*.yaml" \
\) 2>/dev/null | grep -v node_modules | grep -v ".git"

# CI/CD pipelines — GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket, Travis, Drone, TeamCity
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

# Infrastructure as Code
find $ARGUMENTS -name "*.tf" -o -name "*.tfvars" -o -name "helm" -type d 2>/dev/null | \
  grep -v node_modules | grep -v ".git"
```

---

## Phase 2 — Checklist SOC 2

### CC6 — Logical & Physical Access (priorite haute)

#### CC6.1 — Authentification et controle d'acces
- [ ] Authentification forte requise sur tous les endpoints sensibles (MFA si applicable)
- [ ] Principe du moindre privilege : chaque service/user a les droits minimaux
- [ ] Revocation immediate des acces a la deconnexion ou expiration de token
- [ ] Pas de credentials partages entre plusieurs services ou utilisateurs
- [ ] Comptes de service avec permissions minimales (pas de superuser pour l'app)
- [ ] Rotation des secrets et credentials documentee

#### CC6.2 — Chiffrement
- [ ] TLS 1.2+ sur toutes les communications (verifier config serveur/nginx/caddy)
- [ ] Donnees sensibles chiffrees au repos (DB chiffree si applicable)
- [ ] Algorithmes de chiffrement forts — pas DES, 3DES, RC4, MD5
- [ ] Cles de chiffrement stockees separement des donnees
- [ ] Certificats valides et non expires

#### CC6.3 — Segmentation reseau
- [ ] Base de donnees non exposee directement sur internet (bind 127.0.0.1)
- [ ] Services internes isoles des services publics
- [ ] Firewalls/groupes de securite configures et restrictifs
- [ ] Pas de ports non necessaires exposes

#### CC6.6 — Detection des menaces
- [ ] Logs d'acces actives et conserves (access logs HTTP)
- [ ] Tentatives d'auth echouees loggees avec IP et timestamp
- [ ] Alerting sur les patterns suspects (brute force, enumeration)
- [ ] Rate limiting sur les endpoints d'authentification

### CC7 — System Operations

#### CC7.1 — Detection des vulnerabilites
- [ ] Scanner de vulnerabilites integre en CI/CD (`npm audit`, `pip-audit`, `trivy`)
- [ ] Dependencies mises a jour regulierement
- [ ] Secrets scanning en pre-commit (gitleaks, trufflehog)
- [ ] SAST integre (CodeQL, Semgrep, Snyk)
- [ ] IaC scanning integre en CI/CD (Checkov, tfsec, terrascan) pour Terraform et manifestes K8s
- [ ] Runtime security monitoring en place si conteneurs/K8s (Falco — detection comportementale des anomalies)

```bash
# Verifier la presence de Falco (runtime security)
grep -rn "falco\|falcosecurity" $ARGUMENTS \
  --include="*.yml" --include="*.yaml" --include="*.tf" \
  2>/dev/null | grep -v node_modules | head -10

# Verifier IaC scanning dans le CI/CD
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" -o -name "Jenkinsfile.*" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name "bitbucket-pipelines.yml" \
  -o -name ".drone.yml" -o -path "*/.teamcity/settings.kts" \
\) 2>/dev/null | grep -v node_modules | \
  xargs grep -ln "checkov\|tfsec\|terrascan\|trivy.*config\|trivy.*misconfig" 2>/dev/null
```

#### CC7.2 — Monitoring et alerting
- [ ] Monitoring de disponibilite configure (uptime checks)
- [ ] Alerting sur les erreurs 5xx en production
- [ ] Metriques de performance collectees (latence, CPU, memoire)
- [ ] Logs centralises avec retention >= 12 mois (SOC 2 requirement)
- [ ] Dashboard de monitoring accessible a l'equipe

#### CC7.3 — Gestion des incidents
- [ ] Procedure de reponse aux incidents documentee
- [ ] Plan de communication en cas de breach
- [ ] Contacts d'urgence definis
- [ ] Post-mortems pour les incidents critiques

#### CC7.4 — Recovery
- [ ] Backups automatiques de la base de donnees
- [ ] Recovery procedure testee et documentee
- [ ] RTO (Recovery Time Objective) et RPO (Recovery Point Objective) definis

### CC8 — Change Management

#### CC8.1 — Gestion des changements
- [ ] Tout changement de code passe par une Pull Request avec review
- [ ] Branche principale protegee (branch protection rules)
- [ ] Tests automatises requis avant merge
- [ ] Deploiements en production tracables et reversibles
- [ ] Changelog ou release notes maintenu

```bash
# Verifier la configuration des branches protegees
git log --oneline -20
git branch -a
# Lister tous les fichiers de pipeline CI/CD trouves
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
\) 2>/dev/null | grep -v node_modules | xargs ls -la 2>/dev/null
```

### CC9 — Risk Mitigation

#### CC9.2 — Gestion des fournisseurs tiers
- [ ] Inventaire des services tiers (APIs, SaaS, cloud providers)
- [ ] Evaluation de securite des fournisseurs critiques
- [ ] SLA contractuels avec les fournisseurs critiques
- [ ] Pas de dependance sur un seul fournisseur critique sans plan de contingence

### A1 — Availability

- [ ] SLA de disponibilite defini et monitore
- [ ] Auto-scaling ou plan de capacite configure
- [ ] Health checks sur tous les services
- [ ] Load balancer avec failover si applicable
- [ ] Plan de disaster recovery documente

```bash
# Verifier les health checks
grep -rn "health\|healthcheck\|readiness\|liveness" $ARGUMENTS \
  --include="*.yml" --include="*.yaml" --include="*.json" 2>/dev/null | \
  grep -v node_modules
```

### C1 — Confidentiality

- [ ] Donnees confidentielles identifiees et classifiees
- [ ] Acces aux donnees confidentielles logge et auditable
- [ ] Donnees confidentielles exclues des logs d'application
- [ ] Politique de retention et destruction des donnees

### P1-P8 — Privacy (si donnees personnelles traitees)

- [ ] Inventaire des donnees personnelles collectees
- [ ] Base legale du traitement definie (consentement, contrat, interet legitime)
- [ ] Politique de confidentialite accessible et a jour
- [ ] Donnees personnelles minimisees (collecte du strict necessaire)
- [ ] Retention limitee avec purge automatique si applicable
- [ ] Donnees personnelles absentes des logs

### CC2 — Logging et audit trail

- [ ] Logs immutables (pas de modification ou suppression possible)
- [ ] Logs couvrent : auth, acces admin, modifications de donnees critiques, erreurs
- [ ] Timestamps en UTC avec timezone explicite
- [ ] Correlation ID par requete pour tracabilite
- [ ] Logs exportes vers systeme centralise (CloudWatch, Datadog, ELK)

```bash
# Rechercher la configuration de logging
grep -rn "winston\|pino\|log4j\|zap\|slog\|logrus\|structlog" $ARGUMENTS \
  --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

---

## Format du rapport

```
# Rapport d'audit SOC 2 Type II — [Nom du projet]
Date : [date]
Version TSC : 2017 + amendements 2022
Auditeur : Claude Code (security-audit-soc2)
Stack detecte : [liste]

## Resume executif
[2-3 phrases sur le niveau de maturite SOC 2 general]

## Findings

### CRITIQUE — Bloquant pour la certification
| # | Finding | TSC | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — A corriger avant audit externe
| # | Finding | TSC | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — A planifier
| # | Finding | TSC | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | TSC | Recommandation |

## Score de maturite par critere TSC
| Critere | Score /5 | Statut | Justification |
|---|---|---|---|
| CC6 Logical Access | | | |
| CC7 System Operations | | | |
| CC8 Change Management | | | |
| CC9 Risk Mitigation | | | |
| A1 Availability | | | |
| C1 Confidentiality | | | |
| **Maturite globale** | **/5** | | |

Niveaux : 1=Initial, 2=Managed, 3=Defined, 4=Quantitatively Managed, 5=Optimizing

## Points positifs
[Controles SOC 2 deja en place]

## Roadmap vers la certification
[Actions prioritaires avec effort estime (XS/S/M/L/XL)]
```
