#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$PROJECT_ROOT"

command -v docker >/dev/null 2>&1 || { echo "Docker est requis." >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL est requis pour générer les secrets." >&2; exit 1; }

CREATED_ENV=0
ADMIN_PASSWORD=""
if [ ! -f .env ]; then
  umask 077
  DB_PASSWORD=$(openssl rand -hex 24)
  APP_SECRET=$(openssl rand -hex 48)
  AUDIT_SECRET=$(openssl rand -hex 48)
  ADMIN_PASSWORD=$(openssl rand -hex 16)
  sed \
    -e "s/CHANGE_ME_RANDOM_DATABASE_PASSWORD/$DB_PASSWORD/" \
    -e "s/CHANGE_ME_RANDOM_64_CHAR_SECRET/$APP_SECRET/" \
    -e "s/CHANGE_ME_DIFFERENT_RANDOM_64_CHAR_SECRET/$AUDIT_SECRET/" \
    -e "s/CHANGE_ME_RANDOM_ADMIN_PASSWORD/$ADMIN_PASSWORD/" \
    .env.example > .env
  CREATED_ENV=1
  echo "Fichier .env sécurisé créé."
fi

docker compose config --quiet
docker compose up -d --build --wait --wait-timeout 1800

PORT=$(sed -n 's/^HTTP_PORT=//p' .env | head -n 1)
PORT=${PORT:-8787}
echo
echo "MICEPP Scanner est opérationnel: http://127.0.0.1:$PORT"
echo "Utilisateur initial: admin"
if [ "$CREATED_ENV" -eq 1 ]; then
  echo "Mot de passe initial: $ADMIN_PASSWORD"
  echo "Conservez-le dans un coffre puis créez les comptes nominatifs."
else
  echo "Le fichier .env existant a été conservé."
fi

