---
description: "Audit de conformite RGPD/GDPR. Analyse collecte de donnees personnelles, base legale, droits des personnes, securite, breaches et transferts hors UE."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un DPO (Data Protection Officer) et auditeur RGPD senior. Realise un audit de conformite RGPD du projet situe a : **$ARGUMENTS**

Reference : Reglement (UE) 2016/679 (RGPD) + lignes directrices EDPB.
Mappe chaque finding a l'article RGPD applicable.

---

## Instructions

1. Commence par la Phase 1 : identifier les donnees personnelles traitees
2. Analyse chaque article RGPD applicable
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec code ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE
7. Identifie les donnees a risque eleve (categories speciales, donnees de mineurs)

---

## Reference : Articles RGPD cles

| Article | Sujet |
|---------|-------|
| Art. 5 | Principes du traitement (licite, loyal, transparent, minimisation, exactitude, limitation) |
| Art. 6 | Base legale du traitement |
| Art. 7 | Conditions du consentement |
| Art. 9 | Categories speciales (sante, origine raciale, opinions politiques...) |
| Art. 12-14 | Transparence et information des personnes |
| Art. 15-22 | Droits des personnes (acces, rectification, effacement, portabilite, opposition) |
| Art. 25 | Privacy by design et by default |
| Art. 30 | Registre des activites de traitement |
| Art. 32 | Securite du traitement |
| Art. 33-34 | Notification de violation (72h CNIL, communication aux personnes) |
| Art. 35 | Analyse d'impact (DPIA) |
| Art. 37-39 | Designe d'un DPO |
| Art. 44-49 | Transferts hors UE |

---

## Phase 1 — Cartographie des donnees personnelles

Recherche dans le code toutes les donnees personnelles traitees :

```bash
# Donnees directement identifiantes
grep -rn "email\|phone\|nom\|name\|prenom\|firstname\|lastname\|address\|adresse\|ip.*addr\|user_id\|birthdate\|birth_date\|date_nais" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.sql" --include="*.prisma" 2>/dev/null | grep -v node_modules | grep -v ".git" | head -40

# Categories speciales (art. 9)
grep -rn "health\|sante\|medical\|religion\|political\|syndic\|biometric\|sexual\|racial\|ethnic" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20

# Schemas de base de donnees
find $ARGUMENTS -name "*.sql" -o -name "*.prisma" -o -name "schema.rb" -o \
  -name "models.py" 2>/dev/null | grep -v node_modules

# Cookies et tracking
grep -rn "cookie\|localStorage\|sessionStorage\|analytics\|gtag\|_ga\|mixpanel\|amplitude\|segment" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.vue" --include="*.jsx" \
  --include="*.tsx" --include="*.html" 2>/dev/null | grep -v node_modules | head -30
```

---

## Phase 2 — Checklist RGPD

### Art. 5 — Principes fondamentaux

- [ ] **Licéite** : base legale identifiee pour chaque traitement (Art. 6)
- [ ] **Transparence** : politique de confidentialite accessible et comprehensible
- [ ] **Limitation des finalites** : donnees utilisees uniquement pour les finalites declarees
- [ ] **Minimisation** : seules les donnees necessaires sont collectees
- [ ] **Exactitude** : mecanisme de mise a jour des donnees
- [ ] **Limitation de conservation** : duree de retention definie et appliquee
- [ ] **Integrite et confidentialite** : mesures de securite appropriees (Art. 32)

### Art. 6 — Base legale du traitement

- [ ] Base legale identifiee pour chaque traitement :
  - Consentement (6.1.a) — verifier qu'il est libre, specifique, eclaire, univoque
  - Contrat (6.1.b) — execution d'un contrat avec la personne
  - Obligation legale (6.1.c)
  - Interet vital (6.1.d)
  - Mission d'interet public (6.1.e)
  - Interet legitime (6.1.f) — verifier le test de mise en balance

```bash
# Rechercher la gestion du consentement
grep -rn "consent\|consentement\|gdpr\|rgpd\|accept.*terms\|cookie.*banner\|opt.in\|opt.out" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.vue" 2>/dev/null | \
  grep -v node_modules | head -20
```

### Art. 7 — Consentement

- [ ] Consentement positif explicite (pas de cases pre-cochees)
- [ ] Possibilite de retirer le consentement aussi facilement qu'il a ete donne
- [ ] Preuve du consentement conservee (date, version, moyen)
- [ ] Consentement separe par finalite (pas de tout-en-un)

### Art. 13-14 — Information des personnes

- [ ] Politique de confidentialite presente sur le site
- [ ] Identite et coordonnees du responsable de traitement mentionnees
- [ ] Finalites et base legale de chaque traitement expliquees
- [ ] Durees de conservation mentionnees
- [ ] Droits des personnes mentionnes avec modalites d'exercice
- [ ] Transferts hors UE mentionnes si applicable

### Art. 15-22 — Droits des personnes

- [ ] **Droit d'acces (Art. 15)** : endpoint ou procedure pour exporter les donnees d'un utilisateur
- [ ] **Droit de rectification (Art. 16)** : possibilite de modifier ses donnees
- [ ] **Droit a l'effacement (Art. 17)** : procedure de suppression du compte et des donnees
- [ ] **Droit a la portabilite (Art. 20)** : export des donnees dans un format lisible (JSON, CSV)
- [ ] **Droit d'opposition (Art. 21)** : opt-out du marketing et du profilage
- [ ] Delai de reponse <= 1 mois implemente

```bash
# Verifier les fonctions de suppression et export
grep -rn "delete.*user\|deleteUser\|account.*delete\|export.*data\|data.*export\|right.*erasure\|droit.*effacement" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | head -20
```

### Art. 25 — Privacy by Design et by Default

- [ ] Minimisation des donnees : seuls les champs necessaires dans les formulaires
- [ ] Parametres de confidentialite les plus stricts par defaut
- [ ] Donnees personnelles absentes des logs d'application (pas d'email, IP, nom dans les logs)
- [ ] Pseudonymisation ou anonymisation quand possible

```bash
# Verifier si des donnees personnelles sont loggees
grep -rn "console\.log\|log\.info\|log\.debug\|logger\." $ARGUMENTS \
  --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  2>/dev/null | grep -v node_modules | grep -iE "email|phone|name|ip|user" | head -20
```

### Art. 30 — Registre des activites de traitement

- [ ] Registre des traitements existe (fichier ou outil ddie)
- [ ] Chaque traitement documente : finalite, categories de donnees, destinataires, retention
- [ ] Registre mis a jour lors de chaque nouveau traitement

### Art. 32 — Securite du traitement

- [ ] Chiffrement des donnees personnelles en transit (TLS 1.2+)
- [ ] Chiffrement des donnees au repos si donnees sensibles
- [ ] Hachage des mots de passe (bcrypt/argon2 — pas MD5/SHA1)
- [ ] Acces aux donnees personnelles restreint au strict necessaire
- [ ] Tests de securite reguliers (penetration tests, audits)
- [ ] Procedure de gestion des incidents documentee

### Art. 33-34 — Notification de violation de donnees

- [ ] Procedure de detection des violations de donnees definie
- [ ] Processus de notification a l'autorite (CNIL) dans les 72h documente
- [ ] Processus de notification aux personnes concernees documente
- [ ] Registre des violations tenu

### Art. 35 — Analyse d'impact (DPIA)

- [ ] DPIA realisee si traitement a risque eleve (surveillance, profilage, donnees sensibles)
- [ ] DPIA documentee et a jour
- [ ] Consultation de l'autorite de controle si risque residuel eleve

### Art. 44-49 — Transferts hors UE

- [ ] Identification des transferts de donnees hors EEE (AWS us-east-1, Google Analytics, etc.)
- [ ] Mecanisme de transfert valide : adequation, CCT, BCR, derogation
- [ ] Post-Schrems II : TIA (Transfer Impact Assessment) si transfert vers USA

```bash
# Identifier les services tiers potentiellement hors UE
grep -rn "googleapis\|amazonaws\|azure\|cloudflare\|stripe\|twilio\|sendgrid\|mailgun\|intercom\|hubspot\|salesforce" \
  $ARGUMENTS --include="*.js" --include="*.ts" --include="*.go" --include="*.py" \
  --include="*.env*" 2>/dev/null | grep -v node_modules | head -20
```

### Cookies et traceurs (ePrivacy)

- [ ] Bandeau cookies conforme (pas de consentement pre-donne)
- [ ] Cookies analytiques/marketing necessitent consentement explicite
- [ ] Cookies strictement necessaires seuls autorises sans consentement
- [ ] Liste des cookies documentee (nom, finalite, duree, emetteur)

---

## Format du rapport

```
# Rapport d'audit RGPD — [Nom du projet]
Date : [date]
Reference : RGPD (UE) 2016/679
Auditeur : Claude Code (security-audit-gdpr)

## Cartographie des donnees personnelles
| Categorie | Donnees | Base legale | Retention | Destinataires | Transferts UE |
|---|---|---|---|---|---|

## Resume executif
[Niveau de conformite general, risques principaux, categories de donnees traitees]

## Findings

### CRITIQUE — Risque de sanction CNIL (jusqu a 4% CA ou 20M EUR)
| # | Finding | Article RGPD | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — Corriger avant traitement de donnees en production
| # | Finding | Article RGPD | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — A planifier
| # | Finding | Article RGPD | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | Article | Recommandation |

## Score de conformite RGPD
| Domaine | Score /10 | Statut |
|---|---|---|
| Bases legales (Art. 6-7) | | |
| Droits des personnes (Art. 15-22) | | |
| Securite (Art. 32) | | |
| Privacy by Design (Art. 25) | | |
| Transferts hors UE (Art. 44-49) | | |
| Notification breaches (Art. 33-34) | | |
| **Conformite globale** | **/10** | |

## Actions prioritaires
[Ordonnees par risque de sanction, avec effort estime]
```
