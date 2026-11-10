#!/usr/bin/env bash
# Move the accounts out of Photos into ZOOMRIYA ID, once (run as root, with
# zoomriya-id stopped), on a box upgraded from when sign-in was in Photos:
#
#   sudo deploy/import-from-photos.sh
#
# Same ids, password hashes and app switches, the profile photos and the
# signing key, so nobody is signed out (backend/app/import_from_photos.py).
# Reads Photos' database with the DATABASE_URL in /opt/zoomriya/.env.
# Afterwards, once signing in works: sudo rm -r /data/zoomriya/keys (Photos'
# old copy of the key, which its container could see).
set -euo pipefail

APP=/opt/zoomriya/id
[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
if systemctl is-active --quiet zoomriya-id; then
    echo "Stop ZOOMRIYA ID first: sudo systemctl stop zoomriya-id" >&2
    exit 1
fi

photos_url="$(sed -n 's/^DATABASE_URL=//p' /opt/zoomriya/.env | tail -n 1)"
[ -n "$photos_url" ] || { echo "No DATABASE_URL in /opt/zoomriya/.env" >&2; exit 1; }

set -a
# shellcheck disable=SC1091
. /etc/zoomriya/id.env
set +a
cd "$APP/backend"
"$APP/venv/bin/alembic" upgrade head
PHOTOS_DATABASE_URL="$photos_url" "$APP/venv/bin/python" -m app.import_from_photos
chown -R zoomriya-id:zoomriya-id "${ZOOMRIYA_ID_DATA_DIR:-/data/zoomriya-id}"
