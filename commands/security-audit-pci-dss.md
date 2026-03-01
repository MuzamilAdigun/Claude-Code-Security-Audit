---
description: "Audit de conformite PCI-DSS v4.0. Analyse la protection des donnees de paiement, segmentation reseau, cryptographie, controle d'acces, logging et tests de securite."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un QSA (Qualified Security Assessor) PCI-DSS. Realise un audit de conformite PCI-DSS v4.0 du projet situe a : **$ARGUMENTS**

Reference : PCI DSS v4.0 (mars 2022) — 12 exigences.
Mappe chaque finding a l'exigence PCI-DSS applicable.
ATTENTION : si aucune donnee de paiement (PAN, CVV, piste magnetique) n'est traitee directement, indique-le et evalue le perimetre indirect (integration Stripe, PayPal, etc.).

---

## Instructions

1. Commence par determiner le perimetre : le projet traite-t-il directement des donnees de carte ?
2. Si integration via iframe/hosted fields (Stripe Elements, Braintree) : perimetre reduit (SAQ A)
3. Si traitement direct des PAN : perimetre complet
4. Analyse chaque exigence applicable
5. Note chaque finding avec fichier:ligne exact
6. Attribue un score de confiance 1-10 — ne rapporte que >= 8

---

## Reference : PCI-DSS v4.0 — 12 Exigences

| Req | Domaine |
|-----|---------|
| 1 | Installer et maintenir des controles de securite reseau |
| 2 | Appliquer des configurations securisees |
| 3 | Proteger les donnees de compte stockees |
| 4 | Proteger les donnees en transit avec une cryptographie forte |
| 5 | Proteger tous les systemes contre les malwares |
| 6 | Developper et maintenir des systemes et logiciels securises |
| 7 | Restreindre l'acces aux composants systeme et donnees |
| 8 | Identifier les utilisateurs et authentifier l'acces |
| 9 | Restreindre l'acces physique aux donnees de compte |
| 10 | Journaliser et surveiller tous les acces |
| 11 | Tester la securite des systemes et reseaux regulierement |
| 12 | Soutenir la securite de l'information avec des politiques |

---

## Phase 1 — Determination du perimetre

```bash
# Detecter les integrations de paiement
grep -rn "stripe\|paypal\|braintree\|adyen\|square\|mollie\|checkout\|payment\|paiement\|card\|carte" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.env*" 2>/dev/null | grep -v node_modules | grep -v ".git" | head -30

# Detecter le stockage potentiel de donnees de carte
grep -rn "pan\|card_number\|numero.*carte\|cvv\|cvc\|expiry\|expiration\|track.*data\|magnetic" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" 2>/dev/null | grep -v node_modules | head -20

# Schemas de base de donnees
find $ARGUMENTS -name "*.sql" -o -name "*.prisma" -o -name "schema.rb" 2>/dev/null | \
  grep -v node_modules | xargs grep -l "card\|payment\|paiement" 2>/dev/null
```

---

## Phase 2 — Checklist PCI-DSS v4.0

### Req. 1 — Controles de securite reseau

- [ ] Firewall/NSC (Network Security Control) configure entre internet et CDE (Cardholder Data Environment)
- [ ] Regles de firewall documentees, revues tous les 6 mois
- [ ] Pas de connexion directe entre internet et la base de donnees
- [ ] Reseau cartes isole des autres reseaux (segmentation)
- [ ] NAT/PAT pour masquer les IPs internes
- [ ] Pas de protocoles non securises (Telnet, FTP) en CDE

```bash
# Verifier docker-compose pour la segmentation reseau
grep -rn "network\|subnet\|ports:" $ARGUMENTS --include="docker-compose*.yml" 2>/dev/null
```

### Req. 2 — Configurations securisees

- [ ] Identifiants et mots de passe par defaut changes
- [ ] Fonctionnalites inutiles desactivees (ports, services, protocoles)
- [ ] Composants systeme documentes avec justification pour chaque service actif
- [ ] Configuration durcie (hardened) pour tous les composants
- [ ] Pas de comptes et mots de passe par defaut des fournisseurs

```bash
# Verifier les configurations par defaut
grep -rn "admin.*password\|default.*password\|root.*123\|password.*1234" \
  $ARGUMENTS 2>/dev/null | grep -v node_modules | grep -v ".git"
```

### Req. 3 — Protection des donnees stockees

- [ ] **PAN (Primary Account Number) JAMAIS stocke en clair** — si stocke : tronque, hache ou chiffre
- [ ] CVV/CVC/CAV JAMAIS stocke apres autorisation (meme chiffre)
- [ ] Donnees de piste magnetique JAMAIS stockees
- [ ] PIN JAMAIS stocke
- [ ] Politique de retention des donnees de carte documentee
- [ ] Purge automatique des donnees au-dela de la duree de retention

```bash
# Recherche critique : PAN ou CVV dans le code ou les logs
grep -rn "4[0-9]{12}(?:[0-9]{3})?\|5[1-5][0-9]{14}\|cvv\|cvc\|card_number\|pan" \
  $ARGUMENTS 2>/dev/null | grep -v node_modules | grep -v ".git" | grep -v test | head -20
```

### Req. 4 — Cryptographie en transit

- [ ] TLS 1.2 minimum (TLS 1.3 recommande) pour toutes les transmissions de donnees de carte
- [ ] Pas de protocoles faibles (SSL, TLS 1.0, TLS 1.1)
- [ ] Certificats valides et non auto-signes en production
- [ ] Cipher suites fortes uniquement
- [ ] Pas de donnees de carte transmises via email, chat, SMS (non chiffres end-to-end)

```bash
# Verifier la config TLS
grep -rn "tls\|ssl\|https\|cipher\|protocol" $ARGUMENTS \
  --include="*.conf" --include="*.yml" --include="*.yaml" --include="*.json" \
  2>/dev/null | grep -v node_modules | head -20
```

### Req. 5 — Protection contre les malwares

- [ ] Solution anti-malware deployee sur tous les composants
- [ ] Scanner de vulnerabilites en CI/CD (npm audit, trivy, Snyk)
- [ ] Images Docker scannees avant deploiement
- [ ] Analyse des logs pour detecter les comportements malveillants

### Req. 6 — Developpement securise

#### 6.2 — Gestion des vulnerabilites
- [ ] Processus de correction des vulnerabilites par criticite :
  - Critique : <= 1 mois
  - Haute : <= 3 mois
- [ ] Verification de vulnerabilites avant deploiement en production

#### 6.3 — Securite des applications web
- [ ] Protection contre OWASP Top 10
- [ ] WAF (Web Application Firewall) devant les applications exposant les donnees de carte
- [ ] Pas de XSS, SQLi, CSRF, injection dans le code

#### 6.4 — Inventaire des composants logiciels (SBOM)
- [ ] Liste des composants tiers avec versions
- [ ] Processus de mise a jour des composants vulnerables

#### 6.5 — Securite du code
- [ ] Revue de code avec focus securite avant mise en production
- [ ] SAST integre (CodeQL, Semgrep, SonarQube)
- [ ] Formation securite pour les developpeurs (min. annuelle)

### Req. 7 — Restriction d'acces

- [ ] Acces aux donnees de carte base sur le besoin metier (need-to-know)
- [ ] RBAC (Role-Based Access Control) configure
- [ ] Acces refuse par defaut si non explicitement autorise
- [ ] Revue des droits d'acces tous les 6 mois

### Req. 8 — Identification et authentification

- [ ] Identifiant unique par utilisateur (pas de comptes partages)
- [ ] MFA obligatoire pour :
  - Tous les acces distants au CDE
  - Tous les acces d'administration
  - Acces des utilisateurs non-consommateurs aux interfaces web
- [ ] Mots de passe : minimum 12 caracteres (PCI DSS v4.0), complexite requise
- [ ] Verrouillage apres 10 tentatives echouees maximum
- [ ] Expiration des sessions inactive apres 15 minutes max
- [ ] Rotation des mots de passe tous les 90 jours

```bash
# Verifier la politique de mots de passe
grep -rn "password.*length\|minLength\|passwordPolicy\|session.*timeout\|lockout\|maxAttempts" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -15
```

### Req. 10 — Journalisation et surveillance

- [ ] Logs actives pour tous les acces aux donnees de carte
- [ ] Logs couvrent : auth (succes et echec), acces admin, acces aux donnees, modifications
- [ ] Timestamps synchronises via NTP
- [ ] Logs conserves >= 12 mois (3 mois minimum en ligne)
- [ ] Logs proteges contre la modification et suppression
- [ ] Revue quotidienne des logs de securite

```bash
# Verifier la configuration des logs
grep -rn "accesslog\|audit.*log\|log.*access\|morgan\|winston\|pino" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" \
  2>/dev/null | grep -v node_modules | head -15
```

### Req. 11 — Tests de securite

- [ ] Scanner de vulnerabilites interne trimestriel
- [ ] Penetration test annuel (externe) + apres changements majeurs
- [ ] Detection des points d'acces sans fil non autorises
- [ ] Surveillance de l'integrite des fichiers (FIM) sur les fichiers critiques
- [ ] Tests d'intrusion sur les segmentations reseau

### Req. 12 — Politiques de securite

- [ ] Politique de securite de l'information documentee et revue annuellement
- [ ] Programme de sensibilisation a la securite pour tout le personnel
- [ ] Procedures de reponse aux incidents documentees
- [ ] Inventaire des fournisseurs de services (TPSPs) avec leur etendue PCI
- [ ] Accords de responsabilite PCI avec les fournisseurs de services

---

## Format du rapport

```
# Rapport d'audit PCI-DSS v4.0 — [Nom du projet]
Date : [date]
Reference : PCI DSS v4.0
Auditeur : Claude Code (security-audit-pci-dss)

## Determination du perimetre
Niveau de marchand : [1/2/3/4]
Type SAQ applicable : [A / A-EP / B / B-IP / C / D]
Perimetre CDE : [description des composants en perimetre]

## Resume executif
[Etat de conformite, risques critiques, recommandations principales]

## Findings

### CRITIQUE — Non-conformite critique (risque de violation de donnees de carte)
| # | Finding | Req. PCI | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — Non-conformite significative
| # | Finding | Req. PCI | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — A corriger dans le plan de remediation
| # | Finding | Req. PCI | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | Req. PCI | Recommandation |

## Score de conformite par exigence
| Req. | Domaine | Statut | Score /10 |
|---|---|---|---|
| 1 | Securite reseau | | |
| 2 | Configurations | | |
| 3 | Donnees stockees | | |
| 4 | Cryptographie transit | | |
| 5 | Anti-malware | | |
| 6 | Dev securise | | |
| 7 | Controle d'acces | | |
| 8 | Authentification | | |
| 10 | Logging | | |
| 11 | Tests securite | | |
| 12 | Politiques | | |
| **Global** | | | **/10** |

## Plan de remediation PCI
[Actions ordonnees par criticite avec responsable et delai]
```
