# Sécurité et mise en production

## Modèle de menace retenu

Le système traite des fichiers potentiellement hostiles. Le serveur applicatif ne doit donc jamais exécuter un artefact. L’exécution dynamique appartient exclusivement à une sandbox dédiée, sur un réseau sans route vers le SI, avec invités jetables, filtrage de sortie, collecte centralisée et procédure de réinitialisation vérifiée.

## Mesures présentes

- originaux séparés, rendus en lecture seule et vérifiés avant analyse ;
- conteneurs applicatifs non-root, `no-new-privileges` et capacités Linux supprimées ;
- aucune publication directe de PostgreSQL, Redis, ClamAV ou de l’API ;
- mots de passe Argon2, comparaison temporelle égalisée, JWT d’une heure, rôles et validation stricte des entrées ;
- limitation nginx des tentatives d’authentification par adresse source ;
- protections contre Zip Slip/Tar Slip, limites de taille/nombre et délais YARA/CAPE ;
- rapport dynamique absent plutôt que substitué ;
- journal HMAC chaîné et verrouillage des écritures concurrentes ;
- en-têtes CSP, anti-framing, nosniff, politique de permissions et referrer minimal ;
- migrations versionnées et sauvegardes signées par SHA-256.

## Avant ouverture au réseau intranet

1. Placez nginx derrière le reverse proxy TLS de l’organisation et gardez `BIND_ADDRESS=127.0.0.1` si le proxy est local.
2. Stockez les secrets dans un coffre et injectez-les au démarrage ; ne versionnez jamais `.env`.
3. Remplacez le compte bootstrap par des comptes nominatifs et faites tourner son mot de passe.
4. Chiffrez les disques/volumes, restreignez les sauvegardes et testez une restauration sur une machine séparée.
5. Configurez NTP, la rétention, la supervision des conteneurs et des alertes sur `evidence.integrity_failed`, `analysis.failed` et chaîne d’audit invalide.
6. Validez les règles YARA en préproduction, organisez la mise à jour hors ligne de ClamAV si nécessaire et épinglez les images Docker par digest dans un environnement réglementé.
7. Effectuez une revue de sécurité et un test d’intrusion adaptés à l’infrastructure réelle.

## Sauvegarde et restauration

`scripts/backup.ps1` et `scripts/backup.sh` exportent PostgreSQL ainsi que les volumes preuves, rapports et modèles, puis créent `SHA256SUMS`. Copiez le répertoire obtenu vers un support chiffré et immuable.

Une restauration est volontairement manuelle car elle écrase des données : arrêtez les services, vérifiez `SHA256SUMS`, restaurez les volumes dans une pile vide, importez `database.dump` avec `pg_restore`, puis exécutez `/api/v1/audit/verify` avant toute remise en service. Faites valider cette opération par deux personnes dans les contextes judiciaires.

## Signalement

Ne joignez jamais de preuve ou d’échantillon de malware à un ticket non sécurisé. Un signalement doit contenir la version, les journaux expurgés, l’identifiant d’analyse et les étapes reproductibles, sans secret, jeton, donnée personnelle ni contenu de preuve.
