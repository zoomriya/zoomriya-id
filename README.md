# ZOOMRIYA ID

The one sign-in every ZOOMRIYA app shares: a small service of its own, so no
app's restart, update or crash stops anyone signing in.

One ZOOMRIYA ID per machine, shared by everything on it. On a ZOOMRIYA Box,
ZOOMRIYA OS sets it up; where the apps run without the box, the first app
installed sets it up. Either way it is set up only if it isn't there yet.

| Folder | What |
| --- | --- |
| `backend/` | The service (FastAPI, PostgreSQL, Redis) |
| `identity-py/` | `zoomriya_identity`, the formats ZOOMRIYA ID and every app share: the token claims, the public key, the identity events, a member's level, quiet hours and the family's place |
| `deploy/`, `systemd/` | Installing it on a machine, and its unit |
| `scripts/dev.sh` | Running it for development |

- **Holds** the accounts (passwords, roles, profile photos, theme and
  language), the sessions, the Ed25519 signing key, the family directory and
  which apps each member may open.
- **Serves** everything at `/id/api/v1/…` behind the gateway (port 8050).
  Its screens are Family Hub's: the sign-in page, Account settings and Manage
  Family (`@zoomriya/web` calls it).
- **Announces** every change to a member on the Redis channel
  `zoomriya:identity` (`user:created`, `user:updated`, `user:deactivated`,
  `user:revoked`).
- **Doesn't** run AI or media code. Apps never read its database: they check
  tokens with its public key (`zoomriya_identity.identity`) and keep their
  own copy of the members.

| Address (under `/id/api/v1`) | What |
| --- | --- |
| `POST /auth/login`, `/auth/refresh`, `/auth/logout` | Sign in, renew the 15-minute token from the 30-day session cookie, sign out everywhere |
| `GET /auth/jwks.json` | The public key every app checks tokens with |
| `GET/PATCH /auth/me`, `PATCH /auth/me/preferences`, `POST /auth/me/password`, `POST/DELETE /auth/me/avatar` | Your own account |
| `GET /users/directory` | Every active member, for any signed-in member and every app's member list |
| `GET/POST /users`, `PATCH /users/{id}`, `GET/PUT /users/{id}/apps` | Manage Family (admins): child or adult, birth year, a child's one or two guardians |
| `GET /users/children`, `GET/PATCH /users/children/{id}`, `PUT /users/children/{id}/apps`, `POST /users/children/{id}/seen`, `POST /users/children/{id}/changes` | A guardian's children: Family Hub's child pages (the level move, quiet hours, apps, the log of changes and what each guardian has seen). Not found for anyone else, admins included |
| `GET /users/{id}/avatar?v=…` | A member's profile photo |
| `GET /health` | For the service manager |

Its data: the database `zoomriya_id` (accounts, app switches) and the folder
`/data/zoomriya-id` (`keys/`, `avatars/`), readable only by its own account
`zoomriya-id`. Both are in every backup, as `deploy/backup.conf` declares.

Sign-in and password changes are limited per address
(`RATE_LIMIT_AUTH_REQUESTS` per `RATE_LIMIT_WINDOW_SECONDS`, 10 a minute).

## Development

```bash
sudo -u postgres createdb -O zoomriya zoomriya_id         # once
sudo -u postgres createdb -O zoomriya zoomriya_id_test    # once, for the tests
scripts/dev.sh                                            # :8050, migrates first
```

With zoomriya-apps checked out beside this repository, its `./dev-all.sh`
starts this with every other dev server; open the apps through the gateway
(<http://localhost:8088/>), which gives it `/id/`.
Settings go in `backend/.env` (see `backend/app/config.py`), for example
`INSTALLED_APPS=photos,vault`. In development, `scripts/dev.sh` gives an
empty database one account, `admin` / `admin123`; an existing one keeps its
accounts.

To bring a development machine's existing Photos accounts over (once, with
the service stopped):

```bash
cd backend
PHOTOS_DATABASE_URL=postgresql+psycopg://zoomriya:root@localhost:5432/zoomriya \
    .zrvenv/bin/python -m app.import_from_photos
```

It finds Photos' library where Photos keeps it and the key at
`/data/zoomriya/keys/zoomriya-id-ed25519.pem`; on a machine without `/data`,
add `PHOTOS_SIGNING_KEY=` the `data/keys/zoomriya-id-ed25519.pem` in Photos' checkout
and `PHOTOS_LIBRARY_ROOT=` Photos' `STORAGE_ROOT`.

Tests: `cd backend && .zrvenv/bin/python -m pytest -q` (in `zoomriya_id_test`),
and `cd identity-py && ../backend/.zrvenv/bin/python -m pytest -q`.

## On the box

```bash
sudo deploy/install.sh                 # code, venv, account, folder, unit
sudo deploy/setup.sh                   # database, role, settings: only what's missing
sudoedit /etc/zoomriya/id.env          # INSTALLED_APPS
sudo systemctl enable --now zoomriya-id
```

On a ZOOMRIYA Box, ZOOMRIYA OS installs the code and runs `deploy/setup.sh`
at first boot, so the apps find ZOOMRIYA ID already there. Elsewhere, the
first app's installer runs both scripts. `setup.sh` makes only what's
missing, holds a lock while it works and writes `/var/lib/zoomriya-id/set-up`
last, so a second caller, or a run after a power cut, is safe.

**There is no default account and no default password.** The first admin is
made by whoever sets ZOOMRIYA ID up, with a password the person chose: the
first-boot setup page on a ZOOMRIYA Box, the apps' installer elsewhere. It
works only while there are no accounts, so any of them may run it:

```bash
# 0: made; 3: accounts exist, nothing changed
printf '%s' "$PASSWORD" | sudo systemd-run --quiet --pipe --wait -p User=zoomriya-id \
    -p EnvironmentFile=/etc/zoomriya/id.env -p WorkingDirectory=/opt/zoomriya/id/backend \
    /opt/zoomriya/id/venv/bin/python -m app.first_admin <username>
```

**Upgrading a box where sign-in was inside Photos**, in this order, on the
release that brought ZOOMRIYA ID (Photos' migration `0009`, a release later,
drops the columns the import reads; after it, import from a backup of
Photos' database taken before). Members
sign in again once afterwards: tokens from before ZOOMRIYA ID are not
accepted (anyone with Photos' old shared secret could have signed one).

1. Install this service as above (don't start it yet).
2. Remove `JWT_SECRET_KEY` from `/etc/zoomriya/id.env` if an earlier version
   of these steps put it there; ZOOMRIYA ID no longer reads it.
3. `sudo deploy/import-from-photos.sh`: the accounts,
   app switches, profile photos and signing key, with the same ids.
4. `sudo systemctl enable --now zoomriya-id`, then install the gateway's new
   Caddyfile (`/id/`, and the old `/api/v1/auth/…` and `/api/v1/users/…`
   addresses passed to ZOOMRIYA ID for one release) and reload it.
5. Release Photos as usual: its migration `0007` turns `users` into its copy
   of the members.
6. Once signing in works: `sudo rm -r /data/zoomriya/keys` (Photos' old copy
   of the private key, which its container could see).

## Licence

[MPL-2.0](LICENSE). Changes to these files stay open; you may combine them
with your own code under its own terms. The ZOOMRIYA name and logo are not
covered by the licence: see [TRADEMARKS.md](TRADEMARKS.md).

## Related

The box is [ZOOMRIYA OS](https://github.com/zoomriya/zoomriya-os); the apps
and Family Hub are in zoomriya-apps (private).
