#!/usr/bin/env bash
# Install or update ZOOMRIYA ID on the box from this checkout (run as root):
#
#   sudo deploy/install.sh
#
# Code into /opt/zoomriya/id, its own venv, its account (zoomriya-id), its
# folder (/data/zoomriya-id) and its unit. It doesn't start anything; then:
#
#   sudo deploy/setup.sh                       # only what's missing; safe again
#   sudo deploy/import-from-photos.sh          # a box with accounts in Photos
#   sudo systemctl enable --now zoomriya-id
#   printf '%s' "$PASSWORD" | ...app.first_admin <username>   # README
#
# An update: run this again, then `sudo systemctl restart zoomriya-id`.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/zoomriya/id

[ "$(id -u)" = 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

install -D -m 0644 "$HERE/systemd/zoomriya-id.sysusers.conf" /usr/lib/sysusers.d/zoomriya-id.conf
systemd-sysusers zoomriya-id.conf

install -d -m 0755 "$APP"
rm -rf "$APP/backend.new"
install -d -m 0755 "$APP/backend.new"
cp -a "$HERE/backend/app" "$HERE/backend/migrations" "$HERE/backend/alembic.ini" \
    "$HERE/backend/requirements.txt" "$APP/backend.new/"
find "$APP/backend.new" -name __pycache__ -prune -exec rm -rf {} +
rm -rf "$APP/backend.old"
[ -d "$APP/backend" ] && mv "$APP/backend" "$APP/backend.old"
mv "$APP/backend.new" "$APP/backend"
rm -rf "$APP/backend.old"

[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q -r "$APP/backend/requirements.txt"
"$APP/venv/bin/pip" install -q "$HERE/identity-py"

install -d -m 0700 -o zoomriya-id -g zoomriya-id /data/zoomriya-id
install -d -m 0755 /etc/zoomriya
[ -f /etc/zoomriya/id.env ] || install -m 0600 "$HERE/deploy/id.env.example" /etc/zoomriya/id.env

install -m 0644 "$HERE/systemd/zoomriya-id.service" /etc/systemd/system/
# What the box's backup holds of ZOOMRIYA ID (zoomriya-apps' platform/backup).
install -D -m 0644 "$HERE/deploy/backup.conf" /etc/zoomriya/backup.d/10-id.conf
systemctl daemon-reload
echo "ZOOMRIYA ID installed in $APP. Settings: /etc/zoomriya/id.env"
