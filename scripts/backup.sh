#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"
[ -f .env ] || { echo "Le fichier .env est requis." >&2; exit 1; }

DESTINATION=${1:-"$PROJECT_ROOT/backups"}
STAMP=$(date -u +%Y%m%d-%H%M%S)
BACKUP_PATH="$DESTINATION/$STAMP"
mkdir -p "$BACKUP_PATH"

DATABASE_ID=$(docker compose ps -q database)
API_ID=$(docker compose ps -q api)
[ -n "$DATABASE_ID" ] && [ -n "$API_ID" ] || { echo "Les services database et api doivent être démarrés." >&2; exit 1; }

docker compose exec -T database sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc -f /tmp/micepp.dump'
docker cp "$DATABASE_ID:/tmp/micepp.dump" "$BACKUP_PATH/database.dump"
docker compose exec -T database rm -f /tmp/micepp.dump
docker run --rm --volumes-from "$API_ID" --mount "type=bind,source=$BACKUP_PATH,target=/backup" alpine:3.21 sh -c 'tar -czf /backup/evidence.tar.gz -C /evidence . && tar -czf /backup/reports.tar.gz -C /reports . && tar -czf /backup/models.tar.gz -C /models .'
(cd "$BACKUP_PATH" && sha256sum database.dump evidence.tar.gz reports.tar.gz models.tar.gz > SHA256SUMS)
echo "Sauvegarde complète créée: $BACKUP_PATH"

