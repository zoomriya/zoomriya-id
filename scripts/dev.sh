#!/usr/bin/env bash
# Run ZOOMRIYA ID for development on :8050 (the sign-in every app shares).
# Open the apps through the gateway (zoomriya-apps' platform/gateway/dev.sh),
# which gives it
# /id/, so the login cookies reach every app.
#
# Needs its own database once:
#   sudo -u postgres createdb -O zoomriya zoomriya_id
# and, on a machine whose Photos already has accounts, moves them over once:
#   cd backend && \
#     PHOTOS_DATABASE_URL=postgresql+psycopg://zoomriya:root@localhost:5432/zoomriya \
#     PHOTOS_LIBRARY_ROOT=<Photos' library> PHOTOS_SIGNING_KEY=<Photos' key> \
#     .zrvenv/bin/python -m app.import_from_photos
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$HERE/backend"
VENV="$BACKEND/.zrvenv"
PORT="${ZOOMRIYA_ID_PORT:-8050}"

if [ ! -x "$VENV/bin/python" ]; then
    echo "Creating ZOOMRIYA ID's virtualenv..."
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install -q -r "$BACKEND/requirements.txt"
    "$VENV/bin/pip" install -q -e "$HERE/identity-py" \
        --config-settings editable_mode=compat
fi

# Where the family lives (shown as "Same as the family" on a member's own
# place), as the box service's dev server keeps it in a zoomriya-apps
# checkout beside this one, unless the box's is here.
if [ ! -d /var/lib/zoomriya-box ]; then
    export ZOOMRIYA_PLACE_FILE="${ZOOMRIYA_PLACE_FILE:-$HERE/../zoomriya-apps/platform/zoomriya-box/data/place.json}"
fi

cd "$BACKEND"
"$VENV/bin/python" -m alembic upgrade head
# Development only: an empty development database gets admin / admin123, as
# before. An installed ZOOMRIYA ID has no default account or password.
printf '%s' admin123 | "$VENV/bin/python" -m app.first_admin admin 2>/dev/null || true
echo "ZOOMRIYA ID on 127.0.0.1:${PORT}/id/"
exec "$VENV/bin/python" -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT" --reload
