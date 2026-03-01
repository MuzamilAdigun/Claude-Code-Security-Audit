# Rapport d'audit de conformité multi-frameworks — SampleApp
Date : 2026-03-01
Auditeur : Claude Code (security-audit-full)
Frameworks évalués : OWASP Top 10 | SOC 2 | GDPR | ISO 27001 | PCI-DSS | NIST | CIS | HIPAA
Périmètre : `/path/to/your-project`

---

## Tableau de bord de conformité

| Framework | Score /10 | Statut | Findings Critiques | Findings Hauts |
|---|---|---|---|---|
| OWASP Top 10 (2021) | 6.5 | 🟠 Insuffisant | 2 | 4 |
| SOC 2 Type II | 5.4 | 🟠 Insuffisant | 1 | 5 |
| GDPR/RGPD | 3.5 | 🔴 Critique | 2 | 4 |
| ISO 27001:2022 | 6.4 | 🟠 Insuffisant | 1 | 4 |
| PCI-DSS v4.0 | N/A | — | N/A | N/A |
| NIST SP 800-53 Rev 5 | 4.5 | 🔴 Critique | 1 | 5 |
| CIS Benchmarks | 5.8 | 🟠 Insuffisant | 1 | 4 |
| HIPAA | N/A | — | N/A | N/A |
| **Score global** | **5.4/10** | 🟠 **Insuffisant** | **5** | **15** |

Légende : 🔴 Critique (<4) | 🟠 Insuffisant (4-6) | 🟡 Partiel (6-8) | 🟢 Conforme (>8)

---

## Résumé exécutif

Le projet présente un niveau de conformité **insuffisant (5.4/10)** avec des lacunes critiques principalement sur la protection des données personnelles (GDPR 3.5/10) et la gestion des secrets. Deux frameworks ne sont pas applicables : PCI-DSS (aucune donnée de carte détectée) et HIPAA (aucune donnée de santé traitée). Les risques immédiats incluent des credentials en clair dans le repository, un container Docker tournant en root, et l'utilisation d'un outil d'analytics sans base légale RGPD. La remise en conformité requiert une action urgente sur 5 findings critiques dans les 7 prochains jours, suivie d'un plan de remédiation sur 90 jours couvrant la sécurité infrastructure, la gouvernance RGPD, et la mise en place d'une chaîne CI/CD sécurisée.

---

## Informations sur le projet

- **Stack technique** :
  - Backend : Go 1.24 (chi router, pgx/v5, httprate)
  - Serveur legacy : Node.js/Express (helmet, express-rate-limit, express-validator)
  - Frontend : Vue 3 + Vite (PWA, analytics tiers, Pinia)
  - Base de données : PostgreSQL 17 (Docker)
  - Infrastructure : Docker multi-stage Alpine, docker-compose, cloud PaaS
- **Outils sécurité présents** : `.gitleaks.toml`, `.trufflehog.toml`

---

## Findings critiques consolidés (tous frameworks)

| # | Finding | Frameworks impactés | Fichier:ligne | Confiance | Fix |
|---|---|---|---|---|---|
| C-01 | Credentials en clair dans `.env` world-readable (chmod 644) | OWASP A02, SOC2 CC6.1, GDPR Art.32, NIST IA-5, ISO A.8.9, CIS Control 3 | `backend/.env` | 10/10 | `chmod 600 backend/.env` ; ajouter `backend/.env` au `.gitignore` ; migrer vers un secret manager |
| C-02 | Credential hardcode fallback `'default_password'` en clair dans le code | OWASP A02/A05, NIST IA-5, ISO A.8.9, CIS Control 3 | `server/scripts/seed.js:16` | 10/10 | Supprimer le fallback ; lever une erreur si `DB_PASSWORD` non définie |
| C-03 | Binaire compilé (16 MB) commité dans git — secrets potentiels embarqués | OWASP A08, SOC2 CC8, ISO A.8.25, NIST SA-12 | `backend/app-backend` | 9/10 | `git rm --cached backend/app-backend` ; ajouter au `.gitignore` ; purger l'historique avec `git filter-repo` |
| C-04 | Analytics tiers envoient des données comportementales hors UE sans base légale RGPD ni consentement | GDPR Art.6/7/44-49, NIST PT-1 | `frontend/src/App.vue:9-10,18-19` | 10/10 | Conditionner le chargement au consentement explicite ; implémenter une bannière cookies conforme ePrivacy ; documenter la base légale |
| C-05 | Container Docker tourne en root (aucune directive `USER`) — privilege escalation triviale | OWASP A05, CIS Docker 4.1, NIST CM-6, ISO A.8.9 | `backend/Dockerfile` | 10/10 | Ajouter `RUN addgroup -S appgroup && adduser -S appuser -G appgroup` + `USER appuser` avant CMD |

---

## Findings hauts consolidés

| # | Finding | Frameworks impactés | Fichier:ligne | Confiance | Fix |
|---|---|---|---|---|---|
| H-01 | Erreurs brutes base de données exposées au client en production | OWASP A05, SOC2 CC7.2, ISO A.8.28 | `server/src/routes/regions.js:11`, `sectors.js:16,26` | 10/10 | Remplacer `res.status(500).json({ error: err.message })` par `next(err)` pour utiliser le handler centralisé |
| H-02 | Aucun logging d'accès HTTP (pas de middleware access log) | OWASP A09, SOC2 CC7.2, NIST AU-2/AU-12, ISO A.8.15 | `server/src/index.js`, `backend/main.go` | 9/10 | Ajouter middleware de logging dans Go et Express — logs vers stdout |
| H-03 | Pas de CI/CD — aucun pipeline de test ou de sécurité automatisé | OWASP A08, SOC2 CC8, ISO A.8.25/A.8.8, NIST SA-11 | Absent du repo | 9/10 | Créer `.github/workflows/ci.yml` avec : tests unitaires, `npm audit`, SAST, scan image, secrets scanning |
| H-04 | Aucune sauvegarde de la base de données documentée ou automatisée | SOC2 A1.2, ISO A.8.13, NIST CP-9 | `docker-compose.yml` | 9/10 | Configurer `pg_dump` quotidien ; stocker les backups chiffrés dans un bucket S3 ; tester la restauration mensuellement |
| H-05 | Aucun monitoring/alerting applicatif (pas de healthcheck API, pas d'alertes d'erreurs) | SOC2 CC7.1, NIST SI-4, ISO A.8.16 | Absent | 9/10 | Intégrer Sentry ou Prometheus+Alertmanager ; configurer des alertes sur taux d'erreur > 1% |
| H-06 | Pas de SSL/TLS entre le backend et PostgreSQL (`sslmode` absent du DSN) | OWASP A02, NIST SC-8, ISO A.8.24 | `backend/internal/db/db.go` | 9/10 | Ajouter `sslmode=require&sslrootcert=...` au DSN PostgreSQL |
| H-07 | Packages npm vulnérables (CVE détectées via npm audit) | OWASP A06, NIST SA-10, ISO A.8.8 | `frontend/package.json`, `server/package.json` | 9/10 | `npm audit fix --force` ; activer Dependabot ou Renovate |
| H-08 | Aucune notice de confidentialité / politique de données accessible aux utilisateurs | GDPR Art.12-14, NIST PT-5 | `frontend/` | 10/10 | Rédiger et publier une politique de confidentialité couvrant : données collectées, finalités, bases légales, durée de conservation, droits des personnes, transferts hors UE |
| H-09 | Aucun mécanisme de droits RGPD (accès, rectification, effacement, portabilité) | GDPR Art.15-22 | Absent | 9/10 | Créer un formulaire de contact DPO ; implémenter les endpoints API correspondants |
| H-10 | Aucun HEALTHCHECK dans le Dockerfile backend | CIS Docker 4.6, SOC2 A1.1, NIST SI-6 | `backend/Dockerfile` | 9/10 | Ajouter `HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:8080/health \|\| exit 1` |
| H-11 | Images Docker avec tags mutables — pas de digest SHA256 | CIS Docker 4.5, OWASP A08, NIST SA-12 | `backend/Dockerfile` | 8/10 | Pincer avec `FROM golang:1.24-alpine@sha256:...` ; automatiser via Renovate |
| H-12 | `setFilter()` dans le store sans allowlist — risque de pollution de prototype | OWASP A03/A04, ISO A.8.28 | `frontend/src/stores/app.js:149-151` | 8/10 | Valider `key` contre une liste blanche de champs autorisés |
| H-13 | CDN externe chargé sans attribut `integrity` (SRI absent) | OWASP A08, ISO A.8.25 | `frontend/index.html:7-9` | 8/10 | Ajouter `integrity="sha384-..."` ou auto-héberger les ressources |
| H-14 | Cache PWA pour toutes les routes `/api/*` sans `Cache-Control: no-store` | OWASP A02, GDPR Art.32 | `frontend/vite.config.js:46-67` | 8/10 | Ajouter l'en-tête `Cache-Control: no-store` sur les réponses API sensibles ; exclure les endpoints privés du cache |
| H-15 | Middleware de recovery absent dans le router — panics non gérées exposent la stack | OWASP A09, SOC2 CC7.2, ISO A.8.28 | `backend/main.go` | 9/10 | Ajouter `Recoverer` et `Logger` middleware dans le setup du router |

---

## Findings moyens consolidés

| # | Finding | Frameworks impactés | Fichier:ligne | Confiance | Fix |
|---|---|---|---|---|---|
| M-01 | `restartPolicyMaxRetries: 3` trop bas pour un service stateless | SOC2 A1.1, NIST CP-10 | `railway.json` | 8/10 | Passer à `ON_FAILURE` avec `maxRetries: 10` ou `ALWAYS` |
| M-02 | Filesystem container non en lecture seule | CIS Docker 5.12, NIST CM-7 | `docker-compose.yml` | 8/10 | Ajouter `read_only: true` + volumes temporaires pour `/tmp` |
| M-03 | Pas de limite PIDs dans le container | CIS Docker 5.28, NIST SC-6 | `docker-compose.yml` | 8/10 | Ajouter `pids_limit: 100` dans docker-compose |
| M-04 | Réseau Docker par défaut (bridge global) — pas d'isolation réseau interne | CIS Docker 5.29, NIST SC-7 | `docker-compose.yml` | 8/10 | Définir un réseau `internal: true` pour la communication backend-postgres |
| M-05 | Pas de `.dockerignore` — contexte de build potentiellement large avec fichiers sensibles | CIS Docker 4.3, OWASP A05 | `backend/Dockerfile` | 8/10 | Créer `backend/.dockerignore` excluant `.env`, `*.md`, `tests/`, `.git/` |
| M-06 | SSL conditionnellement désactivé en développement | NIST SC-8, ISO A.8.24 | `server/src/db.js` | 8/10 | Activer SSL en dev via un certificat local self-signed |
| M-07 | Données de tiers utilisées sans base légale documentée | GDPR Art.6, NIST PT-2 | `scripts/parse_data.py` | 8/10 | Documenter la base légale dans le registre Art.30 ; vérifier la licence de réutilisation |
| M-08 | Aucune durée de conservation des données définie | GDPR Art.5(1)(e), NIST PT-3 | Config/code absent | 8/10 | Définir une politique de rétention ; implémenter des scripts de purge automatique |
| M-09 | Pas de registre des activités de traitement (ROPA Art.30) | GDPR Art.30 | Documentation absente | 8/10 | Créer et maintenir un registre ROPA |
| M-10 | DPIA non réalisée pour le traitement de données à grande échelle | GDPR Art.35 | Documentation absente | 8/10 | Réaliser une Analyse d'Impact relative à la Protection des Données avant mise en production |
| M-11 | Dépendance externe critique sans circuit-breaker | OWASP A04, SOC2 CC9.2, NIST SA-9 | `backend/internal/routes/external.go` | 8/10 | Implémenter un circuit-breaker ; ajouter un timeout strict ; mettre en cache les résultats |
| M-12 | Dépendance CDN externe sans vérification d'intégrité | OWASP A08, ISO A.8.25 | `backend/internal/routes/external.go` | 8/10 | Ajouter vérification de hash sur les réponses JSON ; ou auto-héberger les données |
| M-13 | Pattern SQL dynamique avec concaténation de chaînes — risque d'injection si évolution du code | OWASP A03, ISO A.8.28 | `backend/internal/routes/list.go` | 8/10 | Remplacer par un query builder type-safe ; ajouter des tests unitaires sur les inputs malicieux |

---

## Cartographie des données sensibles

| Type | Données | Protection en place | Frameworks concernés |
|---|---|---|---|
| Données personnelles | Adresses IP (analytics tiers), comportements de navigation | Aucune (pas de consentement, pas de base légale documentée) | GDPR, NIST PT |
| Données métier agrégées | Données statistiques anonymisées | Agrégation/anonymisation partielle | GDPR Art.6, NIST PT-2 |
| Données de paiement | Aucune détectée | N/A | PCI-DSS non applicable |
| Données de santé (ePHI) | Aucune détectée | N/A | HIPAA non applicable |
| Credentials/Secrets | DB_PASSWORD, API keys cloud | Outils de scan présents ; `.env` world-readable 644 ; fallback hardcodé | OWASP A02, SOC2 CC6, ISO A.8.9, NIST IA-5 |
| Binaire compilé | Binaire Go (16 MB) | Aucune — commité dans git | OWASP A08, NIST SA-12 |

---

## Analyse par framework

### OWASP Top 10 (2021) — Score : 6.5/10 🟠

| Catégorie | Statut | Findings |
|---|---|---|
| A01 Broken Access Control | 🟡 Partiel | Pas de tests d'autorisation documentés ; no panic recovery (H-15) |
| A02 Cryptographic Failures | 🟠 Insuffisant | C-01 (env 644), C-02 (hardcode), H-06 (no DB SSL) |
| A03 Injection | 🟡 Partiel | Queries paramétrées OK ; ORDER BY whitelist OK ; M-13 (pattern fragile) |
| A04 Insecure Design | 🟠 Insuffisant | H-12 (setFilter sans allowlist) ; M-11 (no circuit-breaker) |
| A05 Security Misconfiguration | 🔴 Critique | C-05 (root container) ; H-01 (erreurs brutes) ; M-05 (no .dockerignore) |
| A06 Vulnerable Components | 🟠 Insuffisant | H-07 (packages npm vulnérables) ; H-11 (mutable tags) |
| A07 Auth Failures | 🟡 Partiel | Pas d'auth utilisateur (plateforme publique) |
| A08 Software Integrity | 🔴 Critique | C-03 (binaire git) ; H-03 (no CI/CD) ; H-13 (no SRI) |
| A09 Logging Failures | 🟠 Insuffisant | H-02 (no access logs) ; H-15 (no recovery middleware) |
| A10 SSRF | 🟢 Conforme | URL non user-controlled, LimitReader, Content-Type check OK |

**Points positifs** : headers de sécurité complets (HSTS, CSP, X-Frame-Options, Referrer-Policy) ; rate-limiting backend + legacy ; helmet.js.

---

### SOC 2 Type II — Score : 5.4/10 🟠

| Critère TSC | Maturité /5 | Findings |
|---|---|---|
| CC6 (Accès logique) | 2/5 | C-01, C-02 (credentials) ; H-06 (no DB SSL) |
| CC7 (Opérations/Monitoring) | 2/5 | H-02 (no logs) ; H-05 (no monitoring) ; H-15 (no Recoverer) |
| CC8 (Change Management) | 1/5 | H-03 (no CI/CD) ; C-03 (binaire git) |
| CC9 (Fournisseurs) | 2/5 | M-11 (API externe sans SLA) ; M-12 (CDN externe) |
| A1 (Disponibilité) | 3/5 | H-04 (no backup) ; H-10 (no HEALTHCHECK) ; M-01 (restart retries) |
| C1 (Confidentialité) | 3/5 | Données agrégées, accès public intentionnel |
| P1-P8 (Privacy) | 2/5 | C-04 (analytics sans consentement) ; H-08/H-09 (pas de politique/droits RGPD) |

---

### GDPR/RGPD — Score : 3.5/10 🔴

**Données personnelles identifiées** : adresses IP (analytics tiers), comportements de navigation.

| Article | Statut | Finding |
|---|---|---|
| Art.5 (Principes) | 🟠 | Finalités non documentées ; durée conservation absente |
| Art.6-7 (Base légale) | 🔴 | C-04 (analytics sans base légale) ; M-07 (données tiers sans base légale documentée) |
| Art.12-14 (Transparence) | 🔴 | H-08 (aucune politique de confidentialité) |
| Art.15-22 (Droits) | 🔴 | H-09 (aucun mécanisme de droits) |
| Art.25 (Privacy by Design) | 🟠 | Données agrégées OK ; mais analytics injecté sans consentement |
| Art.30 (Registre ROPA) | 🔴 | M-09 (absent) |
| Art.32 (Sécurité) | 🟠 | C-01 (env 644) ; H-06 (no DB SSL) |
| Art.33-34 (Violations) | 🟠 | Pas de procédure de notification breach documentée |
| Art.35 (DPIA) | 🔴 | M-10 (absente) |
| Art.44-49 (Transferts) | 🔴 | C-04 (transfert hors UE sans SCC/adequacy decision) |

**Risque CNIL** : Sanction potentielle jusqu'à 4% du CA mondial ou 20 M EUR pour les violations Art.6 et Art.44.

---

### ISO 27001:2022 — Score : 6.4/10 🟠

| Thème | Statut | Findings principaux |
|---|---|---|
| A.5 Organisationnels | 🟠 | Pas de politique sécurité formelle ; pas de ROPA |
| A.6 Personnes | 🟡 | Pas de formation sécurité documentée |
| A.7 Physiques | 🟢 | Cloud managed — hors périmètre direct |
| A.8.2 (Accès privilégiés) | 🟠 | C-05 (root Docker) ; C-01 (credentials) |
| A.8.7 (Protection malware) | 🟡 | Scanner absent du pipeline (pas de CI/CD) |
| A.8.9 (Gestion config) | 🔴 | C-01, C-02 (secrets) ; C-03 (binaire git) |
| A.8.12 (Prévention fuite) | 🟠 | Outils présents mais pas exécutés en CI |
| A.8.20 (Sécurité réseau) | 🟠 | H-06 (no DB SSL) ; M-04 (réseau Docker default) |
| A.8.24 (Cryptographie) | 🟠 | H-06 ; M-06 (SSL dev désactivé) |
| A.8.25 (Dev sécurisé) | 🟠 | H-03 (no CI/CD) ; H-07 (packages vulnérables) |
| A.8.28 (Secure coding) | 🟡 | H-01 (erreurs brutes) ; H-12 (setFilter) ; M-13 (SQL dynamique) |

---

### PCI-DSS v4.0 — Non applicable

Aucune donnée de carte de paiement (PAN, CVV, date d'expiration) détectée dans le codebase.

---

### NIST SP 800-53 Rev 5 (Profil Moderate) — Score : 4.5/10 🔴

| Famille | Score | Findings principaux |
|---|---|---|
| AC (Access Control) | 5/10 | C-05 (root) ; no RBAC admin |
| AU (Audit) | 3/10 | H-02 (no access logs) ; H-15 (no Recoverer) |
| CM (Configuration) | 4/10 | C-01/C-02/C-03 (secrets/binaire) ; H-11 (mutable tags) |
| IA (Identification/Auth) | 5/10 | C-01 (credentials exposées) ; H-06 (no DB SSL) |
| SC (Système/Communications) | 5/10 | H-06 ; M-03 (no PIDs) ; M-04 (réseau default) |
| SI (Intégrité) | 4/10 | H-03 (no CI/CD) ; H-07 (packages vulnérables) |
| SA (Acquisition) | 3/10 | H-03 (no pipeline) ; C-03 (binaire git) |
| PT (PII) | 3/10 | C-04 (analytics sans consentement) ; M-07/M-08/M-09 |
| SR (Supply Chain) | 4/10 | H-11 (tags mutables) ; M-11/M-12 (deps externes) |
| CP (Continuité) | 3/10 | H-04 (no backup) ; M-01 (restart retries bas) |

---

### CIS Benchmarks v8 / Docker v1.6 — Score : 5.8/10 🟠

| Contrôle CIS Docker | Statut | Finding |
|---|---|---|
| 4.1 — USER non-root | 🔴 FAIL | C-05 — aucune directive USER |
| 4.3 — .dockerignore | 🟠 FAIL | M-05 — absent |
| 4.5 — Digest pinning | 🟠 FAIL | H-11 — tags mutables |
| 4.6 — HEALTHCHECK | 🟠 FAIL | H-10 — absent |
| 5.12 — Filesystem read-only | 🟠 FAIL | M-02 — non configuré |
| 5.28 — PIDs limit | 🟠 FAIL | M-03 — absent |
| 5.29 — Réseau interne | 🟠 FAIL | M-04 — bridge global |
| 4.9 — No secrets in ENV | 🟢 PASS | `env_file` utilisé (OK) |
| Resource limits | 🟢 PASS | Limites RAM/CPU configurées dans docker-compose (OK) |
| Healthcheck DB | 🟢 PASS | PostgreSQL healthcheck configuré (OK) |
| Port binding localhost | 🟢 PASS | Base de données non exposée publiquement (OK) |

---

### HIPAA Security Rule — Non applicable

Aucune donnée de santé électronique protégée (ePHI) détectée.

---

## Roadmap de remédiation globale

### Immédiat (0-7 jours) — Critiques

| Priorité | Action | Frameworks | Effort |
|---|---|---|---|
| 1 | `chmod 600 backend/.env` ; vérifier `.gitignore` inclut `*.env` | OWASP, GDPR, ISO, NIST | XS |
| 2 | Supprimer le fallback password hardcodé dans `seed.js:16` | OWASP, NIST, ISO | XS |
| 3 | `git rm --cached backend/app-backend` + ajouter au `.gitignore` + purger historique avec `git filter-repo` | OWASP, SOC2, NIST | S |
| 4 | Ajouter `USER appuser` + création utilisateur dans `backend/Dockerfile` | CIS, OWASP, NIST | XS |
| 5 | Conditionner l'analytics tiers au consentement dans `App.vue` | GDPR | S |

### Court terme (7-30 jours) — Hauts

| Priorité | Action | Frameworks | Effort |
|---|---|---|---|
| 1 | Remplacer les erreurs brutes par un handler centralisé dans `regions.js` et `sectors.js` | OWASP, SOC2, ISO | XS |
| 2 | Ajouter Recovery + Logger middleware dans `main.go` | OWASP, SOC2, NIST | XS |
| 3 | Ajouter middleware de logging dans Express `index.js` | OWASP, SOC2, NIST | XS |
| 4 | Ajouter `HEALTHCHECK` dans `backend/Dockerfile` | CIS, SOC2 | XS |
| 5 | Créer `.github/workflows/ci.yml` avec tests, npm audit, SAST, trivy, gitleaks | SOC2, ISO, NIST | M |
| 6 | `npm audit fix --force` + activer Dependabot | OWASP A06, NIST | S |
| 7 | Publier une politique de confidentialité | GDPR | M |
| 8 | Ajouter `sslmode=require` au DSN PostgreSQL | OWASP, NIST, ISO | XS |
| 9 | Valider `key` par allowlist dans `setFilter()` | OWASP A03 | XS |
| 10 | Créer `backend/.dockerignore` | CIS, OWASP | XS |

### Moyen terme (30-90 jours) — Moyens

| Priorité | Action | Frameworks | Effort |
|---|---|---|---|
| 1 | Configurer `pg_dump` automatisé + stockage chiffré backups | SOC2, NIST, ISO | M |
| 2 | Pinner les images Docker avec digest SHA256 | CIS, OWASP, NIST | S |
| 3 | Ajouter `read_only: true` + `pids_limit: 100` + réseau interne dans docker-compose | CIS, NIST | S |
| 4 | Intégrer Sentry ou Prometheus pour le monitoring | SOC2, NIST | M |
| 5 | Rédiger ROPA (registre Art.30) | GDPR | M |
| 6 | Réaliser la DPIA | GDPR | L |
| 7 | Implémenter circuit-breaker sur les APIs externes | SOC2, NIST | S |
| 8 | Ajouter SRI sur les ressources CDN externes | OWASP A08 | XS |
| 9 | Configurer `Cache-Control: no-store` sur les endpoints API sensibles | OWASP, GDPR | XS |

### Long terme (90-180 jours) — Gouvernance

| Action | Frameworks | Effort |
|---|---|---|
| Rédiger une politique de sécurité formelle (SMSI ISO 27001) | ISO 27001, SOC2 | L |
| Mettre en place un programme de gestion des vulnérabilités (scan trimestriel) | NIST, ISO, SOC2 | L |
| Former l'équipe dev aux bonnes pratiques sécurité (OWASP, RGPD) | Tous | M |
| Évaluer un secret manager dédié pour la gestion des credentials | NIST IA-5, ISO A.8.9 | M |
| Établir un plan de continuité / PRI (RTO < 4h, RPO < 24h) | SOC2 A1, NIST CP | L |

---

## Points positifs

Les éléments suivants démontrent une attention initiale à la sécurité :

1. **Headers de sécurité complets** : HSTS, CSP `default-src 'none'`, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
2. **Rate limiting** en place sur le backend et le serveur legacy
3. **Outils de détection de secrets** : `.gitleaks.toml` et `.trufflehog.toml` présents dans le repository
4. **Input validation** via librairie dédiée ; helmet.js configuré
5. **Base de données non exposée** publiquement (bind localhost)
6. **Resource limits** Docker configurés dans docker-compose
7. **Healthcheck PostgreSQL** correctement configuré
8. **Protection SSRF** : LimitReader, vérification Content-Type, URL non user-controlled
9. **Guard sur les variables d'environnement** : erreur levée si variable absente
10. **Queries SQL paramétrées** — pas d'injection SQL directe
11. **Architecture multi-stage Docker** minimisant la surface d'attaque
12. **Whitelist ORDER BY** pour prévenir l'injection via tri

---

*Rapport généré par Claude Code (`/security-audit-full`)*
*Classification : CONFIDENTIEL — Usage interne uniquement*
