---
description: "Audit de conformite NIST SP 800-53 Rev 5. Analyse les 20 familles de controles : AC, AU, CM, IA, IR, SC, SI, SA, CP, RA et autres. Oriente gouvernements et contractants US."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un auditeur NIST SP 800-53 Rev 5 senior. Realise un audit de conformite du projet situe a : **$ARGUMENTS**

Reference : NIST SP 800-53 Rev 5 (2020) + NIST SP 800-53B (profils de controles).
Mappe chaque finding a la famille de controles NIST applicable.
Utilise le profil **Moderate** (le plus courant pour les systemes federaux) sauf indication contraire.

---

## Instructions

1. Detecte le stack, l'infrastructure et le niveau d'impact (Low/Moderate/High)
2. Analyse les 20 familles de controles applicables
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec code ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE

---

## Reference : NIST SP 800-53 Rev 5 — 20 familles de controles

| ID | Famille | Priorite pour le code |
|----|---------|----------------------|
| AC | Access Control | Haute |
| AT | Awareness and Training | Moyenne |
| AU | Audit and Accountability | Haute |
| CA | Assessment, Authorization, Monitoring | Moyenne |
| CM | Configuration Management | Haute |
| CP | Contingency Planning | Moyenne |
| IA | Identification and Authentication | Haute |
| IR | Incident Response | Moyenne |
| MA | Maintenance | Basse |
| MP | Media Protection | Basse |
| PE | Physical and Environmental Protection | Basse |
| PL | Planning | Basse |
| PM | Program Management | Basse |
| PS | Personnel Security | Basse |
| PT | PII Processing and Transparency | Haute (si PII) |
| RA | Risk Assessment | Moyenne |
| SA | System and Services Acquisition | Haute |
| SC | System and Communications Protection | Haute |
| SI | System and Information Integrity | Haute |
| SR | Supply Chain Risk Management | Moyenne |

---

## Phase 1 — Detection du perimetre et niveau d'impact

```bash
# Stack technologique
find $ARGUMENTS -maxdepth 4 \( \
  -name "package.json" -o -name "go.mod" -o -name "pyproject.toml" -o \
  -name "Dockerfile" -o -name "docker-compose*.yml" -o -name "*.tf" \
\) 2>/dev/null | grep -v node_modules | grep -v ".git"

# Politiques et documentation existante
find $ARGUMENTS -name "SECURITY*" -o -name "*.policy*" -o -name "ssp*" \
  -o -name "system-security-plan*" 2>/dev/null | grep -v node_modules

# CI/CD — GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket, Travis, Drone, TeamCity
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
```

---

## Phase 2 — Checklist NIST SP 800-53 Rev 5

### AC — Access Control

#### AC-2 — Gestion des comptes
- [ ] Inventaire des comptes systeme (utilisateurs, services, admin)
- [ ] Processus de creation/modification/suppression des comptes documente
- [ ] Revue periodique des comptes (minimum annuelle)
- [ ] Comptes temporaires desactives apres usage
- [ ] Alertes sur les comptes inactifs (>= 90 jours sans connexion)

#### AC-3 — Application du controle d'acces
- [ ] Principe du moindre privilege (least privilege) applique
- [ ] Acces refuse par defaut (deny-all, then allow)
- [ ] RBAC ou ABAC implemente

#### AC-6 — Moindre privilege
- [ ] Comptes de service avec permissions minimales
- [ ] Pas de comptes avec droits superuser pour les applications

#### AC-7 — Tentatives de connexion infructueuses
- [ ] Verrouillage apres N echecs configures
- [ ] Delai croissant entre les tentatives

#### AC-11 — Verrouillage de session
- [ ] Session expiree apres inactivite (15 min pour systemes Moderate)
- [ ] Re-authentification requise apres expiration

#### AC-17 — Acces distant
- [ ] Acces distant via VPN ou tunnel chiffre
- [ ] MFA obligatoire pour l'acces distant

```bash
# Verifier la gestion des sessions et du verrouillage
grep -rn "session.*expire\|session.*timeout\|maxAge\|lockout\|brute.*force\|rate.*limit" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

### AU — Audit and Accountability

#### AU-2 — Evenements a auditer
- [ ] Evenements loggues : connexions (succes/echec), acces admin, modifications de donnees, erreurs, deploiements
- [ ] Contenu des logs : qui, quoi, quand, ou (source IP)

#### AU-3 — Contenu des enregistrements d'audit
- [ ] Chaque log contient : date/heure, type d'evenement, sujet, resultat
- [ ] Timestamps en UTC

#### AU-6 — Revue, analyse et reporting des audits
- [ ] Logs revus regulierement (minimum hebdomadaire pour Moderate)
- [ ] Processus d'escalade des anomalies

#### AU-9 — Protection des informations d'audit
- [ ] Logs proteges contre modification et suppression non autorisees
- [ ] Acces en ecriture aux logs restreint aux systemes de logging

#### AU-11 — Retention des audits
- [ ] Logs conserves >= 3 ans (NIST recommendation pour systemes federaux)
- [ ] Logs en ligne >= 1 an

```bash
# Analyser la configuration des logs
grep -rn "retention\|log.*level\|audit.*log\|syslog\|cloudwatch\|elasticsearch\|splunk\|datadog" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.yml" 2>/dev/null | grep -v node_modules | head -20
```

### CM — Configuration Management

#### CM-2 — Configuration de base
- [ ] Configuration de base documentee pour chaque composant
- [ ] Configuration as Code (IaC) — Terraform, Ansible, Helm
- [ ] Configurations versionnees dans le SCM

#### CM-6 — Parametres de configuration
- [ ] Configurations de securite activees (headers, TLS, CORS)
- [ ] Parametres par defaut non securises modifies
- [ ] Revue periodique des configurations

#### CM-7 — Fonctionnalite minimale
- [ ] Seuls les services, ports et protocoles necessaires actives
- [ ] Fonctionnalites non utilisees desactivees

#### CM-8 — Inventaire des composants systeme
- [ ] Inventaire a jour de tous les composants (SBOM)
- [ ] Versions de toutes les dependances documentees

```bash
# Generer SBOM depuis package.json / go.mod
cat $ARGUMENTS/package.json 2>/dev/null | python3 -m json.tool | grep -E '"version"|"name"' | head -30
cat $ARGUMENTS/go.mod 2>/dev/null | grep "require" -A 100 | head -30
```

### IA — Identification and Authentication

#### IA-2 — Identification et authentification (organisationnelle)
- [ ] Identifiant unique par utilisateur
- [ ] MFA pour tous les comptes privilegies (IA-2(1))
- [ ] MFA pour acces reseau (IA-2(2))

#### IA-5 — Gestion des authentifiants
- [ ] Complexite des mots de passe : min. 12 caracteres, diversite
- [ ] Pas de mots de passe par defaut
- [ ] Rotation periodique des credentials de service
- [ ] Secrets stockes dans un gestionnaire de secrets (Vault, AWS Secrets Manager...)

#### IA-8 — Identification et authentification (non-organisationnelle)
- [ ] Authentification des utilisateurs externes via protocoles approuves (OAuth2/OIDC)

```bash
# Verifier la gestion des secrets
grep -rn "vault\|secrets.*manager\|aws.*secret\|doppler\|1password" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.yml" 2>/dev/null | grep -v node_modules | head -10
```

### IR — Incident Response

#### IR-4 — Gestion des incidents
- [ ] Procedure de reponse aux incidents documentee (detection, confinement, eradication, recovery)
- [ ] Contacts d'urgence definis
- [ ] Exercices de reponse aux incidents realises periodiquement

#### IR-6 — Reporting des incidents
- [ ] Processus de reporting aux autorites competentes
- [ ] Timeframe de notification defini

### SC — System and Communications Protection

#### SC-5 — Protection contre les deni de service
- [ ] Rate limiting configure
- [ ] Protection DDoS (CDN, WAF)

#### SC-7 — Protection des frontieres
- [ ] Segmentation reseau entre zones de confiance differentes
- [ ] Pas de connexion directe internet-DB

#### SC-8 — Confidentialite et integrite des transmissions
- [ ] TLS 1.2+ sur toutes les communications
- [ ] Integrity checking (HMAC, signatures) sur les donnees critiques

#### SC-12 — Etablissement et gestion des cles cryptographiques
- [ ] Politique de gestion des cles documentee
- [ ] Rotation des cles planifiee
- [ ] Sauvegarde securisee des cles

#### SC-13 — Protection cryptographique
- [ ] Seuls les algorithmes FIPS 140-2/3 valides si systeme federal
- [ ] AES-256, RSA-2048+, SHA-256+

#### SC-23 — Authenticite des sessions
- [ ] Sessions invalidees apres deconnexion
- [ ] Tokens de session opaques et aleatoires

### SI — System and Information Integrity

#### SI-2 — Remediations de defauts
- [ ] Correctifs de securite appliques dans les delais :
  - Critique : <= 30 jours
  - Haute : <= 90 jours
- [ ] Scanner de vulnerabilites automatise

#### SI-3 — Protection contre le code malveillant
- [ ] Scanner de malware integre en CI/CD
- [ ] Images Docker scannees

#### SI-4 — Surveillance du systeme
- [ ] Monitoring des performances et de la disponibilite
- [ ] Alertes sur les comportements anormaux
- [ ] SIEM si applicable

#### SI-7 — Integrite des logiciels, firmwares et informations
- [ ] Verification de l'integrite des artefacts de deploiement (checksums, signatures)
- [ ] SRI sur les scripts CDN externes

#### SI-10 — Validation des entrees d'information
- [ ] Validation de tous les inputs utilisateur aux frontieres du systeme
- [ ] Rejection des inputs malformes

```bash
# Verifier la validation des inputs
grep -rn "validate\|sanitize\|escape\|validator\|zod\|yup\|joi\|express-validator" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

### SA — System and Services Acquisition

#### SA-11 — Tests de securite pour les developpeurs
- [ ] SAST (CodeQL, Semgrep, SonarQube) integre en CI/CD
- [ ] DAST (OWASP ZAP, Burp Suite) periodique
- [ ] Penetration testing annuel

#### SA-15 — Processus de developpement et standards
- [ ] Standards de codage securise documentes
- [ ] Threat modeling realise

### PT — PII Processing and Transparency (si donnees personnelles)

#### PT-1 — Politique PII
- [ ] Politique de traitement des PII documentee

#### PT-3 — Finalite du traitement des PII
- [ ] Finalite de chaque traitement documentee et limitee

#### PT-5 — Minimisation des PII
- [ ] Seules les PII necessaires collectees

### SR — Supply Chain Risk Management

#### SR-3 — Plans et controles SCRM
- [ ] Inventaire des composants tiers
- [ ] Evaluation de securite des fournisseurs critiques

#### SR-11 — Authenticite des composants
- [ ] Verification de l'integrite des packages (checksums, lock files)
- [ ] Pas de packages non verifies

---

## Format du rapport

```
# Rapport d'audit NIST SP 800-53 Rev 5 — [Nom du projet]
Date : [date]
Reference : NIST SP 800-53 Rev 5 — Profil Moderate
Auditeur : Claude Code (security-audit-nist)
Niveau d'impact FIPS 199 : [Low / Moderate / High]

## Resume executif
[Etat de conformite, lacunes principales par famille de controles]

## Findings

### CRITIQUE — Non-conformite majeure
| # | Finding | Controle NIST | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE
| # | Finding | Controle NIST | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE
| # | Finding | Controle NIST | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | Controle | Recommandation |

## Score de conformite par famille
| Famille | Controles evalues | Conformes | Non-conformes | Score /10 |
|---|---|---|---|---|
| AC | | | | |
| AU | | | | |
| CM | | | | |
| IA | | | | |
| IR | | | | |
| SC | | | | |
| SI | | | | |
| SA | | | | |
| **Global** | | | | **/10** |

## Plan de remediation NIST
[Actions ordonnees par priorite avec effort estime]
```
