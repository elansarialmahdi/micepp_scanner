# MICEPP Scanner

Plateforme intranet d’analyse forensique et de détection de logiciels malveillants, réalisée à partir de `Descriptif du projet.docx` et `Draft sur le projet.docx`. Le système ingère des fichiers ou images forensiques, conserve l’original, vérifie son intégrité, orchestre de vrais moteurs d’analyse, soumet les résultats à un expert et produit un rapport PDF traçable.

Il n’existe aucun verdict simulé : un moteur indisponible est déclaré indisponible dans les constats et la couverture du résultat. L’analyse dynamique n’est activée que lorsqu’une vraie sandbox CAPE/Cuckoo est configurée.

## Démarrage rapide

Prérequis : Docker Desktop sous Windows ou Docker Engine avec le plugin Compose sous Linux, au moins 4 Go de mémoire disponibles et suffisamment d’espace pour les preuves.

Windows PowerShell :

```powershell
.\scripts\bootstrap.ps1
```

Linux :

```sh
sh scripts/bootstrap.sh
```

Le script crée un `.env` avec des secrets cryptographiques, construit les images, applique les migrations, attend tous les contrôles de santé et affiche le mot de passe administrateur initial une seule fois. L’application est ensuite disponible sur [http://127.0.0.1:8787](http://127.0.0.1:8787).

Commandes quotidiennes :

```powershell
docker compose ps
docker compose logs -f api worker clamav
docker compose stop
docker compose up -d
.\scripts\backup.ps1
```

Ne lancez pas `docker compose down -v` en production : l’option `-v` supprime les volumes persistants.

## Fonctions livrées

- authentification JWT, mots de passe Argon2 et rôles `admin`, `analyst`, `reviewer` ;
- dossiers, scellage, ingestion en flux jusqu’à la limite configurée et empreintes SHA-256/SHA-1/MD5 ;
- original stocké séparément en lecture seule, ré-hachage avant toute analyse et blocage en cas d’altération ;
- extraction sûre des archives ZIP/TAR et des images RAW/E01 avec Sleuth Kit (`tsk_recover`) ;
- analyse statique YARA, ClamAV, type MIME, entropie, chaînes, PE, macros Office et marqueurs PDF actifs ;
- sandbox CAPE/Cuckoo réelle par API, avec soumission, attente, récupération et corrélation du rapport ;
- modèle RandomForest versionné, entraîné uniquement sur des artefacts qualifiés par un expert ;
- file Celery/Redis, statuts temps réel, revue humaine, rapport PDF et journal HMAC chaîné ;
- interface React responsive pour les dossiers, preuves, analyses, constats, modèles et audits.

## Parcours opérationnel

1. L’administrateur crée les comptes nominatifs via `POST /api/v1/users` ou un client API interne.
2. L’analyste crée un dossier puis charge une preuve avec son contexte d’acquisition.
3. L’original est haché et rendu non modifiable ; une copie de travail est extraite.
4. Les agents d’intégrité, d’extraction, statiques, IA et éventuellement sandbox produisent des constats normalisés.
5. Le maître consolide le risque et place le résultat en `awaiting_review`.
6. Un reviewer approuve, rejette ou demande une analyse complémentaire et peut qualifier chaque artefact comme bénin ou malveillant.
7. Lorsque les deux classes contiennent assez d’exemples réels, un reviewer lance une nouvelle version du modèle depuis l’écran **Modèles IA**.
8. Le rapport PDF et la chaîne d’audit sont téléchargeables/vérifiables.

## Sandbox dynamique réelle

La sandbox doit être installée sur une machine ou un segment de virtualisation séparé, avec des machines invitées jetables et sans route vers le réseau de production. Configurez ensuite :

```dotenv
CAPE_BASE_URL=https://cape.intranet
CAPE_API_TOKEN=un_jeton_restreint
CAPE_VERIFY_TLS=true
CAPE_TIMEOUT_SECONDS=900
```

Puis redémarrez l’API et le worker :

```powershell
docker compose up -d --force-recreate api worker
```

L’intégration utilise les endpoints CAPE v2 de création, suivi et récupération de rapport. Si CAPE n’est pas configuré, aucun comportement fictif n’est généré et l’interface l’indique. Référence officielle : [soumission CAPE](https://capev2.readthedocs.io/en/latest/usage/submit.html) et [API CAPE](https://capev2.readthedocs.io/en/latest/usage/api.html).

## ClamAV connecté ou hors ligne

Seul le conteneur ClamAV possède un réseau sortant dédié pour récupérer les signatures officielles ; PostgreSQL, Redis et le réseau des preuves restent internes. Le comportement de l’image suit la [documentation Docker officielle de ClamAV](https://docs.clamav.net/manual/Installing/Docker.html).

Sur un intranet totalement déconnecté, préchargez `daily.cvd`, `main.cvd` et `bytecode.cvd` validés dans le volume `micepp-scanner_clamav-db` depuis un relais de mise à jour contrôlé, puis démarrez la pile. Ne désactivez pas la vérification de signatures pour contourner l’absence réseau.

## RAW, E01 et règles YARA

Les images RAW et E01 sont extraites dans une copie de travail par Sleuth Kit ; la preuve source n’est jamais montée dans une sandbox. La commande utilisée est conforme à la documentation de [`tsk_recover`](https://www.sleuthkit.org/sleuthkit/man/tsk_recover.html). Les règles locales se trouvent dans `backend/rules/` et sont chargées via l’API Python officielle de [YARA](https://yara.readthedocs.io/en/stable/yarapython.html).

## Configuration importante

Les valeurs sont documentées dans `.env.example`. En particulier :

- `BIND_ADDRESS=127.0.0.1` n’expose rien au LAN ; pour un serveur intranet, placez un reverse proxy TLS d’entreprise devant l’application avant de choisir `0.0.0.0` ;
- `MAX_UPLOAD_BYTES`, `MAX_EXTRACTED_FILES` et `MAX_EXTRACTED_BYTES` limitent les bombes d’archives ;
- `MODEL_MIN_SAMPLES_PER_CLASS` empêche l’entraînement sur un jeu insuffisant ;
- `APP_SECRET_KEY`, `AUDIT_HMAC_KEY`, les mots de passe et le jeton CAPE doivent résider dans un coffre de secrets en production.

## Tests et vérifications

Backend :

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q
..\.venv\Scripts\python.exe -m ruff check app tests migrations
```

Frontend :

```powershell
cd frontend
pnpm install --frozen-lockfile
pnpm typecheck
pnpm build
```

Déploiement :

```powershell
docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 1800
Invoke-RestMethod http://127.0.0.1:8787/health/ready
```

La recette effectuée pendant la livraison a analysé le DOCX source réel, vérifié son SHA-256, exécuté le worker, créé un verdict expertisable, vérifié la chaîne d’audit et produit un PDF valide.

## Documentation technique

- [Architecture](docs/ARCHITECTURE.md)
- [Sécurité et mise en production](SECURITY.md)
- API FastAPI : préfixe `/api/v1` ; la documentation interactive n’est volontairement exposée qu’en environnement non-production.

