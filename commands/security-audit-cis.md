---
description: "Audit de conformite CIS Benchmarks. Analyse le durcissement Docker, Kubernetes, Linux OS, et cloud providers (AWS/GCP/Azure). Reference : CIS Controls v8 + CIS Benchmarks sectoriels."
argument-hint: "<chemin du projet>"
allowed-tools: "Bash, Read, Grep, Glob, Task, WebFetch, WebSearch"
---

## Mission

Tu es un expert CIS Benchmarks senior. Realise un audit de conformite du projet situe a : **$ARGUMENTS**

Reference : CIS Controls v8 (2021) + CIS Benchmarks Docker, Kubernetes, Linux (Ubuntu/RHEL/Debian), AWS, GCP, Azure.
Mappe chaque finding au controle CIS applicable (CIS Control + Safeguard ID).

---

## Instructions

1. Detecte le stack d'infrastructure (Docker, K8s, cloud, OS)
2. Analyse les benchmarks applicables au projet
3. Note chaque finding avec fichier:ligne exact
4. Propose un fix concret avec commande ou configuration
5. Attribue un score de confiance 1-10 — ne rapporte que >= 8
6. Classe par severite : CRITIQUE > HAUTE > MOYENNE > BASSE
7. Attribue un niveau d'implementation CIS (IG1 / IG2 / IG3)

---

## Reference : CIS Controls v8 — Implementation Groups

| IG | Description | Cible |
|----|-------------|-------|
| IG1 | Cyber hygiene essentielle | Toutes organisations |
| IG2 | Securite intermediaire | Organisations avec ressources IT |
| IG3 | Securite avancee | Organisations sensibles / regulees |

---

## Phase 1 — Detection de l'infrastructure

```bash
# Docker
find $ARGUMENTS -name "Dockerfile" -o -name "docker-compose*.yml" \
  2>/dev/null | grep -v node_modules | grep -v ".git"

# Kubernetes
find $ARGUMENTS -name "*.yaml" -o -name "*.yml" 2>/dev/null | \
  xargs grep -l "kind: Deployment\|kind: Pod\|kind: Service\|kind: Ingress" 2>/dev/null | \
  grep -v node_modules | head -20

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

# Infrastructure as Code
find $ARGUMENTS -name "*.tf" -o -name "*.tfvars" 2>/dev/null | grep -v node_modules

# OS (Linux)
find $ARGUMENTS -name "sshd_config" -o -name "*.conf" -path "*/nginx/*" \
  -o -name "*.conf" -path "*/apache2/*" 2>/dev/null | grep -v node_modules
```

---

## Phase 2 — Checklist CIS Benchmarks

### CIS Docker Benchmark (v1.6+)

#### 1 — Configuration de l'hote Docker

- [ ] **CIS 1.1** : Utilisateur dedie non-root pour le daemon Docker
- [ ] **CIS 1.2** : Auditd configure pour monitorer les fichiers Docker (`/etc/docker`, `/var/lib/docker`)
- [ ] **CIS 1.6** : Seuls les packages necessaires installes sur l'hote Docker

```bash
# Verifier si Docker tourne en rootless mode ou daemon config
find $ARGUMENTS -name "daemon.json" 2>/dev/null | xargs cat 2>/dev/null
```

#### 2 — Configuration du daemon Docker

- [ ] **CIS 2.1** : Reseau inter-conteneurs restreint (`--icc=false`)
- [ ] **CIS 2.2** : Logs du daemon configures (syslog ou json-file avec limite)
- [ ] **CIS 2.3** : Autorisation du daemon activee si applicable
- [ ] **CIS 2.4** : TLS active pour le daemon Docker (port 2376)
- [ ] **CIS 2.5** : Ulimits par defaut configures
- [ ] **CIS 2.6** : Healthcheck par defaut active
- [ ] **CIS 2.7** : Userns-remap active (isolation des utilisateurs)
- [ ] **CIS 2.8** : Pas de port experimental en production

```bash
# Analyser daemon.json
grep -rn "icc\|tls\|userns-remap\|log-driver\|log-opts\|live-restore\|userland-proxy" \
  $ARGUMENTS --include="daemon.json" 2>/dev/null

# Verifier les Dockerfiles
find $ARGUMENTS -name "Dockerfile" | xargs grep -n "USER\|EXPOSE\|HEALTHCHECK\|RUN.*apt\|RUN.*yum" 2>/dev/null
```

#### 4 — Images Docker

- [ ] **CIS 4.1** : Image de base officielle et minimale (pas de :latest en prod)
- [ ] **CIS 4.2** : Utilisateur non-root dans le Dockerfile (`USER <non-root>`)
- [ ] **CIS 4.3** : Acces superflus supprimes (SUID/SGID binaries)
- [ ] **CIS 4.4** : Packages inutiles non installes
- [ ] **CIS 4.5** : Dockerfile source de confiance uniquement
- [ ] **CIS 4.6** : HEALTHCHECK instruction presente dans le Dockerfile
- [ ] **CIS 4.7** : Instruction USER definie pour ne pas tourner en root
- [ ] **CIS 4.8** : Secrets non inclus dans les layers d'image (ARG/ENV)
- [ ] **CIS 4.9** : Instructions ADD remplacees par COPY si possible
- [ ] **CIS 4.10** : Secrets non passes en variables d'environnement dans le Dockerfile

```bash
# Chercher les mauvaises pratiques dans les Dockerfiles
find $ARGUMENTS -name "Dockerfile" | while read f; do
  echo "=== $f ==="
  grep -n "FROM.*:latest\|^USER root\|^ENV.*SECRET\|^ENV.*PASSWORD\|^ARG.*SECRET\|ADD http\|sudo" "$f" 2>/dev/null
done
```

#### 6 — Signature des images (Supply Chain Security — Cosign/Sigstore)

- [ ] **CIS 6.1** : Images de production signees avec Cosign (CNCF Sigstore) — requis par EO 14028
- [ ] **CIS 6.2** : Attestations SBOM attachees a l'image via Cosign
- [ ] **CIS 6.3** : Politique d'admission verifiant les signatures (Kyverno, OPA/Gatekeeper, Connaisseur)
- [ ] **CIS 6.4** : Registry prive avec content trust active (Docker Notary ou Cosign)

```bash
# Verifier Cosign dans les pipelines CI/CD
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" \
  -o -name "azure-pipelines.yml" -o -path "*/.circleci/config.yml" \
  -o -name ".drone.yml" \
\) 2>/dev/null | xargs grep -ln "cosign\|sigstore\|notation\|docker.*trust\|content.*trust" 2>/dev/null

# Verifier les politiques de verification de signature (Kyverno/OPA)
find $ARGUMENTS \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | \
  xargs grep -ln "kind: ClusterPolicy\|kind: Policy\|imageVerif\|verifyImages\|cosign.*key" 2>/dev/null | head -10
```

#### 5 — Containers en execution

- [ ] **CIS 5.1** : AppArmor profile applique aux containers (`--security-opt apparmor`)
- [ ] **CIS 5.2** : SELinux active si applicable
- [ ] **CIS 5.3** : Pas de mode privileged (`--privileged` absent)
- [ ] **CIS 5.4** : Capabilities Linux non necessaires droppees (`--cap-drop ALL`)
- [ ] **CIS 5.5** : Volumes SSH non montes dans les containers
- [ ] **CIS 5.6** : Namespace PID de l'hote non partage (`--pid=host` absent)
- [ ] **CIS 5.7** : Namespace net de l'hote non partage (`--net=host` absent si possible)
- [ ] **CIS 5.8** : Namespace IPC de l'hote non partage
- [ ] **CIS 5.9** : Informations de l'hote non exposees
- [ ] **CIS 5.10** : Systeme de fichiers racine en lecture seule (`--read-only`)
- [ ] **CIS 5.11** : Volumes avec propagation slave/rprivate
- [ ] **CIS 5.12** : Pas de sockets Docker montes dans les containers
- [ ] **CIS 5.13** : Memoire limitee (`--memory`)
- [ ] **CIS 5.14** : CPU limitee (`--cpu-shares`)
- [ ] **CIS 5.15** : Liveness et readiness probes configurees
- [ ] **CIS 5.28** : PIDs limites (`--pids-limit`)

```bash
# Analyser docker-compose pour les mauvaises configurations
find $ARGUMENTS -name "docker-compose*.yml" | xargs grep -n \
  "privileged\|pid: host\|network_mode: host\|/var/run/docker.sock\|read_only\|cap_add\|security_opt" \
  2>/dev/null
```

---

### CIS Kubernetes Benchmark (v1.8+)

#### 1 — Composants Control Plane

- [ ] **CIS 1.1** : Permissions des fichiers de config du control plane (600 ou 644)
- [ ] **CIS 1.2.1** : Authentification anonyme desactivee (`--anonymous-auth=false`)
- [ ] **CIS 1.2.2** : `--token-auth-file` non utilise
- [ ] **CIS 1.2.6** : Profils AppArmor actives
- [ ] **CIS 1.2.7** : Admission controllers configures
- [ ] **CIS 1.2.16** : Audit logging active sur le API server
- [ ] **CIS 1.3.1** : Arguments du controller manager securises
- [ ] **CIS 1.4.1** : Arguments du scheduler securises

#### 2 — Etcd

- [ ] **CIS 2.1** : TLS active pour etcd
- [ ] **CIS 2.2** : Client certificate auth active
- [ ] **CIS 2.3** : Acces etcd restreint (pas ouvert sur internet)

#### 3 — Configuration de l'hote worker

- [ ] **CIS 3.1** : Configuration kubelet securisee
- [ ] **CIS 3.2** : Logs du kubelet configures

#### 4 — Politiques

- [ ] **CIS 4.1** : ClusterRoles/RoleBindings restreints au minimum
- [ ] **CIS 4.2** : PSA (Pod Security Admission) configure en mode Restricted si possible
- [ ] **CIS 4.3** : NetworkPolicies configurees pour isoler les namespaces
- [ ] **CIS 4.4** : Secrets Kubernetes non exposes dans les env vars en clair
- [ ] **CIS 4.5** : PodDisruptionBudget configure pour les services critiques
- [ ] **CIS 4.6** : Resources limits et requests definies sur tous les pods

```bash
# Analyser les manifestes K8s
find $ARGUMENTS \( -name "*.yaml" -o -name "*.yml" \) | \
  xargs grep -ln "kind: Deployment\|kind: Pod\|kind: DaemonSet" 2>/dev/null | \
  while read f; do
    echo "=== $f ==="
    grep -n "privileged\|hostNetwork\|hostPID\|hostIPC\|runAsRoot\|allowPrivilegeEscalation\|readOnlyRootFilesystem\|resources:" "$f" 2>/dev/null
  done

# Chercher les NetworkPolicy
find $ARGUMENTS \( -name "*.yaml" -o -name "*.yml" \) | \
  xargs grep -l "kind: NetworkPolicy" 2>/dev/null
```

#### 5 — Helm Charts Security

- [ ] **Helm 1** : Charts Helm scannes avec Checkov (`checkov -d . --framework helm`)
- [ ] **Helm 2** : Charts scannes avec Trivy (`trivy config .`) ou kube-score
- [ ] **Helm 3** : `values.yaml` ne contient pas de secrets en clair — utiliser External Secrets / Sealed Secrets
- [ ] **Helm 4** : Charts provenant de registries verifies (artifacthub.io avec badge securite)
- [ ] **Helm 5** : `helm lint` passe sans erreurs dans le pipeline

```bash
# Verifier la presence de charts Helm
find $ARGUMENTS \( -name "Chart.yaml" -o -name "Chart.yml" \) 2>/dev/null | head -10

# Verifier Checkov/Trivy/kube-score dans CI/CD pour Helm
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.gitlab-ci.yml" \
  -o -name "Jenkinsfile" -o -name "azure-pipelines.yml" \
  -o -path "*/.circleci/config.yml" -o -name ".drone.yml" \
\) 2>/dev/null | xargs grep -ln "helm.*lint\|checkov.*helm\|trivy.*config\|kube-score\|kubesec" 2>/dev/null

# Verifier les valeurs sensibles dans values.yaml
find $ARGUMENTS -name "values*.yaml" -o -name "values*.yml" 2>/dev/null | \
  xargs grep -n "password\|secret\|token\|key\|credential" 2>/dev/null | head -10
```

#### 6 — Policy Enforcement (OPA/Gatekeeper, Kyverno)

- [ ] **OPA 1** : Policy engine installe dans le cluster (OPA/Gatekeeper ou Kyverno)
- [ ] **OPA 2** : Policies definies en code et versionnees dans le SCM
- [ ] **OPA 3** : Politique bloquant les containers privilegies (MustRunAsNonRoot, no privileged)
- [ ] **OPA 4** : Politique imposant des resource limits sur tous les pods
- [ ] **OPA 5** : Politique imposant des labels obligatoires (app, version, team)
- [ ] **OPA 6** : Politique verifiant les signatures d'images (Cosign)

```bash
# Verifier la presence de Kyverno
find $ARGUMENTS \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | \
  xargs grep -l "kind: ClusterPolicy\|kind: Policy" 2>/dev/null | \
  grep -v node_modules | head -10

# Verifier la presence de OPA/Gatekeeper
find $ARGUMENTS \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | \
  xargs grep -l "kind: ConstraintTemplate\|kind: Constraint\|gatekeeper" 2>/dev/null | \
  grep -v node_modules | head -10
```

#### 7 — Runtime Security (Falco)

- [ ] **Falco 1** : Falco installe dans le cluster pour la detection comportementale runtime
- [ ] **Falco 2** : Regles Falco configurees pour les processus suspects (shell dans un container, lecture /etc/shadow...)
- [ ] **Falco 3** : Alertes Falco integrees au SIEM ou au monitoring (Prometheus, Datadog, Splunk)
- [ ] **Falco 4** : Regles personnalisees pour les workloads metier sensibles

```bash
# Verifier la presence de Falco dans le cluster (DaemonSet)
find $ARGUMENTS \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | \
  xargs grep -l "falco\|falcosecurity" 2>/dev/null | grep -v node_modules | head -5

# Verifier les regles Falco
find $ARGUMENTS -name "falco*.yaml" -o -name "falco*.yml" -o -name "falco_rules*" \
  2>/dev/null | grep -v node_modules | head -5
```

---

### IaC Security (Terraform, Helm, CloudFormation, Bicep)

- [ ] **IaC 1** : Checkov integre en CI/CD — scanne Terraform, Helm, K8s, CloudFormation (`checkov -d .`)
- [ ] **IaC 2** : tfsec ou terrascan utilise pour les fichiers Terraform (`tfsec .` / `terrascan scan`)
- [ ] **IaC 3** : Trivy mode misconfig (`trivy config .`) sur les manifestes K8s et Helm
- [ ] **IaC 4** : Findings IaC bloquants sur HAUTE/CRITIQUE avant merge (quality gate)
- [ ] **IaC 5** : Drift detection — etat Terraform vs infrastructure reelle (Atlantis, Spacelift, Env0)
- [ ] **IaC 6** : `terraform plan` revue en PR avant `apply`
- [ ] **IaC 7** : Remote state Terraform chiffre (S3+SSE, GCS, Azure Blob) et versionne

```bash
# Verifier la presence de scanners IaC dans CI/CD
find $ARGUMENTS \( \
  -path "*/.github/workflows/*.yml" -o -path "*/.github/workflows/*.yaml" \
  -o -path "*/.gitlab-ci.yml" -o -name "Jenkinsfile" \
  -o -name "azure-pipelines.yml" -o -path "*/.azure/pipelines/*.yml" \
  -o -path "*/.circleci/config.yml" -o -name ".drone.yml" \
\) 2>/dev/null | xargs grep -ln \
  "checkov\|tfsec\|terrascan\|trivy.*config\|trivy.*misconfig\|infracost\|atlantis" 2>/dev/null

# Verifier les fichiers de config des scanners IaC
find $ARGUMENTS \( \
  -name ".checkov.yaml" -o -name ".checkov.yml" -o -name "checkov*config*" \
  -o -name ".tfsec*" -o -name "tfsec*config*" \
  -o -name ".terrascan*" -o -name "atlantis.yaml" \
\) 2>/dev/null | grep -v node_modules | head -10

# Verifier la configuration du remote state Terraform
find $ARGUMENTS -name "*.tf" 2>/dev/null | xargs grep -l "backend\|remote.*state" 2>/dev/null | head -5
find $ARGUMENTS -name "*.tf" 2>/dev/null | xargs grep -n "encrypt\|sse_algorithm\|kms_key" 2>/dev/null | head -10
```

---

### CIS Linux Benchmark (Ubuntu/Debian/RHEL)

#### 1 — Configuration initiale

- [ ] **CIS 1.1** : Partitions separees pour `/tmp`, `/var`, `/var/log`, `/home`
- [ ] **CIS 1.3** : AIDE ou autre outil de surveillance d'integrite de fichiers
- [ ] **CIS 1.4** : Securite au demarrage (GRUB password)
- [ ] **CIS 1.5** : Profil AppArmor ou SELinux actif

#### 2 — Services

- [ ] **CIS 2.1** : Services inutiles desactives (telnet, rsh, ypserv, etc.)
- [ ] **CIS 2.2** : Client telnet non installe
- [ ] **CIS 2.3** : Services de partage de fichiers NFS restreints

#### 3 — Configuration reseau

- [ ] **CIS 3.1** : IP forwarding desactive si pas de routeur
- [ ] **CIS 3.2** : Redirections ICMP ignorees
- [ ] **CIS 3.3** : IP source routing desactive
- [ ] **CIS 3.4** : Logs des paquets suspects actives
- [ ] **CIS 3.5** : IPv6 desactive si non utilise

#### 4 — Acces et authentification

- [ ] **CIS 4.1** : Cron restreint aux utilisateurs autorises
- [ ] **CIS 4.2** : SSH durci (`PermitRootLogin no`, `PasswordAuthentication no`, `Protocol 2`)
- [ ] **CIS 4.3** : PAM configure (complexite mdp, lockout)
- [ ] **CIS 4.4** : Permissions sur `/etc/passwd`, `/etc/shadow` correctes (644 / 640)

```bash
# Verifier la config SSH si accessible
find $ARGUMENTS -name "sshd_config" | xargs grep -n \
  "PermitRootLogin\|PasswordAuthentication\|Protocol\|AllowUsers\|MaxAuthTries\|ClientAliveInterval" \
  2>/dev/null

# Verifier les fichiers de configuration Nginx/Apache
find $ARGUMENTS \( -path "*/nginx/*.conf" -o -path "*/apache2/*.conf" \) | \
  xargs grep -n "ssl_protocols\|ssl_ciphers\|server_tokens\|add_header\|autoindex" 2>/dev/null
```

#### 5 — Logs et audit

- [ ] **CIS 5.1** : Rsyslog ou systemd-journald configure
- [ ] **CIS 5.2** : Auditd installe et active
- [ ] **CIS 5.3** : Regles d'audit pour les fichiers sensibles (`/etc/passwd`, `/etc/sudoers`, `/var/log`)
- [ ] **CIS 5.4** : Retention des logs >= 90 jours

---

### CIS Benchmarks Cloud

#### AWS (CIS AWS Foundations v1.5)

- [ ] **AWS 1.1** : Root account sans cles d'acces actives
- [ ] **AWS 1.2** : MFA sur le compte root
- [ ] **AWS 1.4** : Cles d'acces root non utilisees (>= 90 jours)
- [ ] **AWS 1.8** : Politique de mdp IAM : min 14 chars, expiration 90j
- [ ] **AWS 1.14** : Acces hardware MFA sur root
- [ ] **AWS 2.1** : CloudTrail active dans toutes les regions
- [ ] **AWS 2.2** : Validation des logs CloudTrail active
- [ ] **AWS 2.3** : Logs CloudTrail chiffres avec SSE-KMS
- [ ] **AWS 3.1-3.14** : Alertes CloudWatch sur les changements critiques
- [ ] **AWS 4.1** : Pas de groupe de securite avec 0.0.0.0/0 sur SSH (port 22)
- [ ] **AWS 4.2** : Pas de groupe de securite avec 0.0.0.0/0 sur RDP (port 3389)

```bash
# Chercher les configurations AWS dans le code (Terraform, CDK, CloudFormation)
find $ARGUMENTS -name "*.tf" | xargs grep -n \
  "0.0.0.0/0\|ingress\|enable_logging\|multi_region\|mfa_delete\|versioning" 2>/dev/null | head -30
```

#### GCP (CIS GCP v1.3)

- [ ] **GCP 1.1** : Cles de comptes de service non creees
- [ ] **GCP 1.4** : Comptes de service sans roles Owner/Editor sur le projet
- [ ] **GCP 1.9** : KMS rotation automatique des cles
- [ ] **GCP 2.1** : Cloud Audit Logs active sur tous les services
- [ ] **GCP 3.1** : Pas de regles de pare-feu 0.0.0.0/0 sur SSH/RDP
- [ ] **GCP 6.1** : Postgres require_ssl active

#### Azure (CIS Azure v2.0)

- [ ] **Azure 1.1** : MFA pour tous les utilisateurs avec droits Owner
- [ ] **Azure 2.1** : Microsoft Defender for Cloud active
- [ ] **Azure 3.1** : Chiffrement des comptes de stockage
- [ ] **Azure 4.1** : Audit SQL Server active
- [ ] **Azure 5.1** : Logs de diagnostic actives sur les Key Vaults

---

## CIS Controls v8 — Top Safeguards

### IG1 (Essentiel — toutes organisations)

- [ ] **CIS 1.1** : Inventaire des assets enterprise (SBOM + liste services)
- [ ] **CIS 2.1** : Inventaire des logiciels autorises
- [ ] **CIS 3.3** : Chiffrement des donnees sur les devices portables
- [ ] **CIS 4.1** : Etablir et maintenir une configuration securisee
- [ ] **CIS 5.2** : Utiliser des credentials uniques par compte de service
- [ ] **CIS 6.1** : Etablir un processus de gestion des acces
- [ ] **CIS 7.2** : Etablir et maintenir un processus de gestion des vulnerabilites
- [ ] **CIS 8.2** : Collecter les logs d'audit
- [ ] **CIS 11.2** : Backups automatiques et test de restauration
- [ ] **CIS 14.1** : Etablir et maintenir un processus de classification des donnees

### IG2 (Intermediaire)

- [ ] **CIS 1.2** : Adressage de toutes les assets (inventaire complet)
- [ ] **CIS 4.2** : Configuration securisee des systemes d'exploitation
- [ ] **CIS 5.4** : Restriction des droits d'administration
- [ ] **CIS 8.9** : Centralisation des logs
- [ ] **CIS 9.2** : Utiliser des DNS filtrants
- [ ] **CIS 12.2** : Etablir et maintenir une architecture reseau securisee
- [ ] **CIS 16.1** : Code reviews de securite
- [ ] **CIS 18.1** : Etablir un programme de penetration testing

---

## Format du rapport

```
# Rapport d'audit CIS Benchmarks — [Nom du projet]
Date : [date]
Reference : CIS Controls v8 + CIS Benchmarks Docker/K8s/Linux/Cloud
Auditeur : Claude Code (security-audit-cis)
Infrastructure detectee : [Docker / K8s / Linux / AWS / GCP / Azure]
Implementation Group cible : [IG1 / IG2 / IG3]

## Resume executif
[Niveau de conformite CIS, lacunes principales par benchmark]

## Findings

### CRITIQUE — Non-conformite bloquante
| # | Finding | CIS Control | Fichier:ligne | Confiance | Impact | Fix |
|---|---|---|---|---|---|---|

### HAUTE — A corriger dans les 30 jours
| # | Finding | CIS Control | Fichier:ligne | Confiance | Impact | Fix |

### MOYENNE — A planifier (90 jours)
| # | Finding | CIS Control | Fichier:ligne | Confiance | Impact | Fix |

### BASSE / Recommandation
| # | Observation | CIS Control | Recommandation |

## Score de conformite CIS
| Benchmark | Controles evalues | Conformes | Non-conformes | Score /10 |
|---|---|---|---|---|
| CIS Docker | | | | |
| CIS Kubernetes | | | | |
| CIS Linux | | | | |
| CIS Cloud | | | | |
| CIS Controls v8 | | | | |
| **Global** | | | | **/10** |

## Plan de remediation
[Actions ordonnees par priorite IG1 → IG2 → IG3, avec effort estime]
```
