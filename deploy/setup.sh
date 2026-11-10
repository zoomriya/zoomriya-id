#!/usr/bin/env bash
# Set ZOOMRIYA ID up on this machine if it isn't yet (run as root, after the
# code is installed). Safe to run again, and from more than one place at once:
# ZOOMRIYA OS runs it at first boot (zoomriya-id-setup.service); where the apps
# run without the box, the apps' installer runs it after deploy/install.sh.
#
#   sudo deploy/setup.sh
#
# Makes only what's missing: its PostgreSQL role and database (zoomriya_id)
# with a password of its own, /etc/zoomriya/id.env holding it, and
# /data/zoomriya-id. The service brings the schema up to date and makes the
# signing key when it starts. It makes no account: whoever set it up makes the
# first admin with app.first_admin (README, "On the box").
#
# Done is /var/lib/zoomriya-id/set-up, written last: a run cut short (power,
# a crash) leaves no mark, and the next run finishes the job.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE=/etc/zoomriya/id.env
DONE=/var/lib/zoomriya-id/set-up
ROLE=zoomriya_id
DATABASE=zoomriya_id

[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

# One at a time: the box and an app's installer may both get here.
install -d -m 0755 /var/lib/zoomriya-id
exec 9>/var/lib/zoomriya-id/setup.lock
flock 9

if [ -f "$DONE" ]; then
    echo "ZOOMRIYA ID is already set up."
    exit 0
fi

systemd-sysusers zoomriya-id.conf
install -d -m 0700 -o zoomriya-id -g zoomriya-id /data/zoomriya-id
install -d -m 0755 /etc/zoomriya
[ -f "$ENV_FILE" ] || install -m 0600 "$HERE/deploy/id.env.example" "$ENV_FILE"

psql_admin() { runuser -u postgres -- psql -v ON_ERROR_STOP=1 -qtA "$@"; }

# PostgreSQL may still be starting (a box's first start).
for _ in $(seq 60); do
    runuser -u postgres -- pg_isready -q && break
    sleep 1
done

# The URL in id.env, if it already reaches the database, is kept; otherwise
# the role gets a new password and id.env the URL with it.
url=$(sed -n 's/^DATABASE_URL=//p' "$ENV_FILE" | tail -1)
if ! PGCONNECT_TIMEOUT=5 psql "${url/+psycopg/}" -qtAc 'SELECT 1' >/dev/null 2>&1; then
    password=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
    if [ "$(psql_admin -c "SELECT 1 FROM pg_roles WHERE rolname = '$ROLE'")" = 1 ]; then
        psql_admin -c "ALTER ROLE $ROLE LOGIN PASSWORD '$password'"
    else
        psql_admin -c "CREATE ROLE $ROLE LOGIN PASSWORD '$password'"
    fi
    url="postgresql+psycopg://$ROLE:$password@127.0.0.1:5432/$DATABASE"
    tmp=$(mktemp "$ENV_FILE.XXXXXX")
    grep -v '^DATABASE_URL=' "$ENV_FILE" > "$tmp" || true
    echo "DATABASE_URL=$url" >> "$tmp"
    chmod 0600 "$tmp"
    mv "$tmp" "$ENV_FILE"
fi
if [ "$(psql_admin -c "SELECT 1 FROM pg_database WHERE datname = '$DATABASE'")" != 1 ]; then
    psql_admin -c "CREATE DATABASE $DATABASE OWNER $ROLE"
fi

sync
touch "$DONE"
sync
echo "ZOOMRIYA ID is set up. Start it (systemctl enable --now zoomriya-id), then make the first admin."
