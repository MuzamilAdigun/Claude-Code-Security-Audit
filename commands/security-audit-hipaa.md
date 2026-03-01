---
description: "Audit de conformite HIPAA (Health Insurance Portability and Accountability Act). Analyse les sauvegardes administratives, physiques et techniques pour la protection des ePHI (donnees de sante electroniques)."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un auditeur HIPAA senior et expert en securite des donnees de sante. Realise un audit de conformite HIPAA du projet situe a : **$ARGUMENTS**

Reference : HIPAA Security Rule (45 CFR Part 164) + NIST SP 800-66 Rev 2 (Implementation Guide for HIPAA).
Mappe chaque finding a la section 45 CFR applicable.

---

## Instructions

1. Detecte si le projet traite des ePHI (Protected Health Information electroniques)
2. Analyse les trois types de sauvegardes HIPAA : Administrative, Physique, Technique
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec code ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE
7. Identifie les risques ePHI non proteges (acces non autorise, alteration, destruction)

---

## Reference : HIPAA Security Rule — 45 CFR Part 164

| Section | Type | Description |
|---------|------|-------------|
| §164.308 | Administrative | Sauvegardes administratives |
| §164.310 | Physique | Sauvegardes physiques |
| §164.312 | Technique | Sauvegardes techniques |
| §164.314 | Organisationnelle | Contrats Business Associate |
| §164.316 | Policies | Documentation et revision |

---

## Phase 1 — Identification des ePHI

Recherche dans le code toutes les donnees de sante (PHI/ePHI) :

```bash
# Donnees de sante directement identifiantes (les 18 identifiants HIPAA)
grep -rn "patient\|medical\|diagnosis\|health\|prescription\|medication\|treatment\|\
ssn\|social.*security\|date_of_birth\|dob\|birthdate\|insurance\|policy.*number\|\
provider\|physician\|doctor\|hospital\|clinic\|drug\|icd.*code\|cpt.*code\|snomed\|\
fhir\|hl7\|dicom\|lab.*result\|vital.*sign\|allergy\|immuniz" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" --include="*.prisma" 2>/dev/null | grep -v node_modules | grep -v ".git" | head -40

# Schemas de base de donnees
find $ARGUMENTS \( -name "*.sql" -o -name "*.prisma" -o -name "schema.rb" \
  -o -name "models.py" -o -name "*.migration.*" \) 2>/dev/null | grep -v node_modules

# APIs et endpoints sante
grep -rn "fhir\|hl7\|dicom\|cda\|ccda\|x12\|hipaa\|phi\|ephi\|ehr\|emr\|phr" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

---

## Phase 2 — Checklist HIPAA Security Rule

### §164.308 — Sauvegardes Administratives

#### §164.308(a)(1) — Gestion des risques de securite (REQUIS)

- [ ] **Analyse de risques documentee** : identification des menaces sur les ePHI
- [ ] **Gestion des risques** : mesures pour reduire les risques a un niveau raisonnable
- [ ] **Sanction policy** : politique de sanctions pour les violations HIPAA documentee
- [ ] **Revue des activites du systeme** : revue periodique des logs et activites

```bash
# Chercher la documentation securite
find $ARGUMENTS \( -name "SECURITY*" -o -name "risk*assess*" -o -name "hipaa*" \
  -o -name "*sanction*" -o -name "*privacy*policy*" \) 2>/dev/null | grep -v node_modules
```

#### §164.308(a)(2) — Plan de contingence (REQUIS)

- [ ] **Plan de backup des donnees** : sauvegarde des ePHI (§164.308(a)(7)(ii)(A))
- [ ] **Plan de reprise d'activite** : procedure de restauration
- [ ] **Plan de mode degrade** : operations critiques pendant une panne
- [ ] **Tests et revisions** : tests periodiques du plan de contingence
- [ ] **Analyse critique des applications** : classification des apps critiques pour les ePHI

#### §164.308(a)(3) — Gestion des acces (REQUIS)

- [ ] **Autorisation et/ou supervision** : politique d'acces aux ePHI documentee
- [ ] **Etablissement et modification** : procedure de creation/modification/suppression de comptes
- [ ] **Terminaison** : revocation immediate des acces lors du depart

```bash
# Verifier la gestion des comptes et permissions
grep -rn "role\|permission\|access.*control\|rbac\|acl\|authorize\|authenticate" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

#### §164.308(a)(4) — Revue et controle de l'acces aux informations (REQUIS)

- [ ] **Politique d'isolement** : isolation des ePHI des autres donnees si applicable
- [ ] **Procedure d'acces** : moindre privilege applique
- [ ] **Revue d'acces** : revue periodique des droits d'acces

#### §164.308(a)(5) — Formations securite (REQUIS)

- [ ] **Formation de securite** : formation de tous les employes sur HIPAA
- [ ] **Protection contre les malwares** : procedures de gestion des logiciels malveillants
- [ ] **Surveillance des connexions** : alerte sur les connexions suspectes
- [ ] **Gestion des mots de passe** : procedures de creation/changement de mots de passe

#### §164.308(a)(6) — Procedure de reporting des incidents (REQUIS)

- [ ] **Identification et reponse** : procedure de detection et reponse aux incidents
- [ ] **Documentation** : incidents documentes (date, type, impact, mesures prises)

#### §164.308(b)(1) — Business Associate Agreements (REQUIS)

- [ ] **BAA signe** avec tous les prestataires accedant aux ePHI
- [ ] **Clauses HIPAA** dans les contrats des sous-traitants

---

### §164.310 — Sauvegardes Physiques

#### §164.310(a)(1) — Controles d'acces physiques (REQUIS)

- [ ] **Acces aux installations** : acces physique aux serveurs restreint
- [ ] **Procedures d'acces** : badges, serrures, cameras
- [ ] **Plan de securite physique** : plan d'urgence pour incidents physiques

#### §164.310(b) — Controles des postes de travail (REQUIS)

- [ ] **Usage des postes** : politique d'usage des postes de travail traitant des ePHI
- [ ] **Protection des postes** : ecrans de verrouillage, BIOS securise

#### §164.310(d)(1) — Controles des supports (REQUIS)

- [ ] **Suppression securisee** : procedure de destruction securisee des supports
- [ ] **Reutilisation des supports** : effacement des ePHI avant reutilisation
- [ ] **Sauvegarde** : backup avant decommissionnement
- [ ] **Tracabilite** : inventaire des supports contenant des ePHI

---

### §164.312 — Sauvegardes Techniques

#### §164.312(a)(1) — Controles d'acces (REQUIS)

- [ ] **Identifiants utilisateur uniques** : chaque utilisateur a un identifiant unique (§164.312(a)(2)(i))
- [ ] **Authentification d'urgence** : procedure d'acces d'urgence aux ePHI (§164.312(a)(2)(ii))
- [ ] **Deconnexion automatique** : session expiree apres inactivite (§164.312(a)(2)(iii))
- [ ] **Chiffrement et dechiffrement** : ePHI chiffrees si applicable (§164.312(a)(2)(iv))

```bash
# Verifier la gestion des sessions et timeouts
grep -rn "session.*timeout\|session.*expire\|maxAge\|inactivity\|auto.*logout\|auto.*logoff" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -15

# Verifier le chiffrement
grep -rn "encrypt\|aes\|rsa\|bcrypt\|argon2\|crypto\|cipher" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -15
```

#### §164.312(b) — Controles d'audit (REQUIS)

- [ ] **Logs d'audit** : enregistrement de toutes les activites sur les ePHI
- [ ] **Logs de connexion** : succes et echecs d'authentification
- [ ] **Logs d'acces aux donnees** : qui accede a quelles ePHI et quand
- [ ] **Logs de modification** : creation, modification, suppression d'ePHI
- [ ] **Conservation des logs** : retention adequathe (minimum 6 ans selon HIPAA)
- [ ] **Protection des logs** : logs non modifiables

```bash
# Analyser la configuration de logging
grep -rn "audit.*log\|access.*log\|activity.*log\|event.*log\|trail\|log.*patient\|\
log.*medical\|log.*health" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.yml" 2>/dev/null | grep -v node_modules | head -20
```

#### §164.312(c)(1) — Controles d'integrite (REQUIS)

- [ ] **Verification d'integrite** : mecanisme de verification que les ePHI ne sont pas alterees
- [ ] **HMAC ou signatures** sur les enregistrements sensibles
- [ ] **Checksums** sur les fichiers ePHI en transit ou au repos

```bash
# Chercher les mecanismes d'integrite
grep -rn "hmac\|signature\|checksum\|hash\|digest\|integrity\|tamper" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -10
```

#### §164.312(d) — Authentification de personne ou d'entite (REQUIS)

- [ ] **Verification d'identite** : authentification de chaque utilisateur accedant aux ePHI
- [ ] **MFA** : recommande pour l'acces aux systemes contenant des ePHI
- [ ] **Pas de comptes partages** : identifiants uniques par utilisateur
- [ ] **Comptes de service** : authentication des systemes acces aux ePHI

```bash
# Verifier l'authentification
grep -rn "mfa\|2fa\|multi.*factor\|totp\|otp\|passkey\|fido" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -10
```

#### §164.312(e)(1) — Securite des transmissions (REQUIS)

- [ ] **TLS 1.2+** : toutes les transmissions d'ePHI chiffrees
- [ ] **Pas de HTTP** : redirect vers HTTPS pour toutes les pages avec ePHI
- [ ] **Chiffrement des emails** : si ePHI transmises par email
- [ ] **VPN** : pour les acces distants aux ePHI

```bash
# Verifier la securite des transmissions
grep -rn "ssl\|tls\|https\|http:\|force.*ssl\|redirect.*https\|hsts" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.conf" --include="*.yml" 2>/dev/null | grep -v node_modules | head -20
```

---

### §164.316 — Documentation (REQUIS)

- [ ] **Politiques ecrites** : toutes les politiques HIPAA documentees par ecrit
- [ ] **Revisions periodiques** : politiques revues periodiquement (minimum annuelle)
- [ ] **Conservation** : documentation conservee 6 ans minimum
- [ ] **Accessibilite** : documentation accessible aux employes concernes

---

## Controles supplementaires recommandes (NIST 800-66)

### Gestion des ePHI dans le code

```bash
# Verifier que les ePHI ne sont pas exposees dans les logs
grep -rn "console\.log\|log\.info\|log\.debug\|logger\." $ARGUMENTS \
  --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | \
  grep -iE "patient|medical|health|diagnosis|ssn|dob|insurance|provider|prescription" | head -20

# Verifier l'absence d'ePHI dans les tests/fixtures
find $ARGUMENTS \( -path "*/test*" -o -path "*/spec*" -o -path "*/fixture*" \
  -o -path "*/seed*" -o -path "*/mock*" \) \
  \( -name "*.json" -o -name "*.sql" -o -name "*.ts" -o -name "*.js" \) \
  2>/dev/null | grep -v node_modules | head -20

# Verifier le chiffrement au repos
grep -rn "encrypt.*column\|encrypted.*attribute\|pgcrypto\|attr_encrypted\|vault.*encrypt\|\
field.*encrypt" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" --include="*.prisma" 2>/dev/null | grep -v node_modules | head -10
```

### Controles API/Web pour les ePHI

- [ ] Pas d'ePHI dans les URLs (GET parameters) — utiliser POST avec body chiffre
- [ ] Headers HTTPS stricts (HSTS, X-Content-Type-Options, X-Frame-Options)
- [ ] Tokens d'acces aux ePHI a duree de vie courte (< 1h)
- [ ] Pagination/limitation des exports d'ePHI (eviter les exports massifs non autorises)
- [ ] Watermarking ou journalisation des acces en masse aux ePHI
- [ ] CORS restrictif sur les endpoints ePHI

```bash
# Verifier la configuration CORS et des headers de securite
grep -rn "cors\|x-frame\|x-content\|hsts\|content-security\|helmet\|security.*header" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.conf" 2>/dev/null | grep -v node_modules | head -15

# Verifier les endpoints exposant des ePHI via GET avec params
grep -rn "req\.query\|request\.GET\|r\.URL\.Query\|request\.args" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -15
```

---

## Format du rapport

```
# Rapport d'audit HIPAA Security Rule — [Nom du projet]
Date : [date]
Reference : HIPAA Security Rule 45 CFR Part 164 + NIST SP 800-66 Rev 2
Auditeur : Claude Code (security-audit-hipaa)

## Cartographie des ePHI
| Type de donnee | Localisation dans le code | Chiffree | Loggee |
|---|---|---|---|

## Resume executif
[Niveau de conformite HIPAA, risques ePHI identifies, mesures en place]

## Findings

### CRITIQUE — Risque d'exposition d'ePHI / Non-conformite majeure
| # | Finding | §45 CFR | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — Corriger avant traitement d'ePHI en production
| # | Finding | §45 CFR | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — A planifier dans les 90 jours
| # | Finding | §45 CFR | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | §45 CFR | Recommandation |

## Score de conformite HIPAA
| Domaine | Score /10 | Statut |
|---|---|---|
| Sauvegardes administratives (§164.308) | | |
| Sauvegardes physiques (§164.310) | | |
| Sauvegardes techniques — Acces (§164.312(a)) | | |
| Sauvegardes techniques — Audit (§164.312(b)) | | |
| Sauvegardes techniques — Integrite (§164.312(c)) | | |
| Sauvegardes techniques — Transmissions (§164.312(e)) | | |
| Documentation (§164.316) | | |
| **Conformite globale** | **/10** | |

## Risques non traites
[ePHI potentiellement non proteges, avec niveau de risque et priorite]

## Actions prioritaires
[Ordonnees par risque d'exposition des ePHI, avec effort estime]
```
