# ZOOMRIYA ID

ZOOMRIYA ID is the shared sign-in service for ZOOMRIYA apps. It runs
separately from the apps, so restarting or updating one app does not interrupt
sign-in for the others.

Each machine has one ZOOMRIYA ID service, shared by the apps installed there.
On a ZOOMRIYA Box, ZOOMRIYA OS sets it up. On other installations, the first
app's installer can set it up. The setup scripts leave an existing
installation in place rather than creating a second one.

## How it fits together

ZOOMRIYA ID owns member accounts, sessions and the signing key used for
identity tokens. Apps verify those tokens with its public key and keep their
own copy of the member information they need; they do not read ZOOMRIYA ID's
database directly.

The service also keeps profile photos, preferences and the family directory,
and controls which apps each member can open. It does not run AI or media
processing. Its sign-in, account and family-management screens are part of
Family Hub. On a ZOOMRIYA Box, admins can also manage the family's
accounts from Box Desktop on the box's own screen.

## Repository map

| Folder | What |
| --- | --- |
| `backend/` | The service (FastAPI, PostgreSQL, Valkey) |
| `identity-py/` | Shared Python types and formats used by the service and apps, including token fields, public keys, identity events and family/member data |
| `deploy/`, `systemd/` | Installing it on a machine, and its unit |
| `scripts/dev.sh` | Running it for development |

ZOOMRIYA ID serves its API under `/id/api/v1/` through the gateway (on port
8050). When a member changes, it publishes an event to the Valkey channel
`zoomriya:identity`. Events include `user:created`, `user:updated`,
`user:deactivated` and `user:revoked`.

## API reference

The endpoints below are relative to `/id/api/v1`:

| Endpoint | What it does |
| --- | --- |
| `POST /auth/login`, `/auth/refresh`, `/auth/logout` | Sign in, refresh a 15-minute token using the 30-day session cookie, and sign out everywhere |
| `POST /auth/login/new-password` | The first sign-in after an admin set someone's password from afar: that temporary password, and their own, which replaces it. `/auth/login` refuses a temporary password with a 403 and `"code": "new_password_needed"`. A password the person typed themselves at the box (`"temporary": false`) isn't temporary |
| `POST /auth/login/second-step`, `/auth/login/second-step/resend` | Sign-in codes by email: when a member has them on, `/auth/login` emails a six-digit code and answers 403 with `"code": "second_step_needed"`, a `ticket` and `sent_to` (the address, partly hidden); this takes the ticket and the code. A wrong or old code is a 400 (ask again); a ticket that ran out is a 401 (start again); a mail server that fails is a 503. With `remember` (on unless sent false) the device is trusted for 30 days: a cookie, and `trusted_device` in the answer for a client that keeps its own (it sends it back as `trusted_device` with `/auth/login`). Resend waits 30 seconds |
| `POST /auth/second-step/setup`, `/auth/second-step/setup/finish` | Signed in, with the password and an address: a code goes there, and the code turns it on (or moves it). Refused until the family's email account is set up |
| `POST /auth/me/second-step/off` | Turn it off with the password; anyone, admins too |
| `POST /auth/me/confirm-password` | "Your password again" for something that matters (Box Desktop), without signing in again or asking for a code |
| `POST /users/{id}/second-step/reset` | An admin turns off someone else's sign-in codes (their email is gone); their own they turn off from their account |
| `GET/PUT/DELETE /mail`, `POST /mail/test` | Admins: the family's own email account that sends the codes (server, port, `ssl` or `starttls`, username, password, from address). `PUT` signs in to it first and keeps it only when that works; without `password` the kept one stays. `DELETE` turns everyone's codes by email off. Box Desktop shows and sets it |
| `GET /auth/jwks.json` | Return the public key apps use to verify tokens |
| `GET/PATCH /auth/me`, `PATCH /auth/me/preferences`, `POST /auth/me/password`, `POST/DELETE /auth/me/avatar` | View or update your account, preferences, password or profile photo |
| `GET /users/directory` | List active members for signed-in users and app member lists |
| `GET/POST /users`, `PATCH /users/{id}`, `GET/PUT /users/{id}/apps` | Admins manage family members, their roles and the apps they can use. Family Hub and the box's own Box Desktop both use these. An admin can't remove their own admin role or turn off their own account, a child can't be an admin, and the box always keeps one active admin |
| `GET /users/children`, `GET/PATCH /users/children/{id}`, `PUT /users/children/{id}/apps`, `POST /users/children/{id}/seen`, `POST /users/children/{id}/changes` | Guardians view and manage their children, including level, quiet hours, apps, change history and which updates each guardian has seen. These routes are unavailable to everyone else, including admins. |
| `GET/POST /auth/me/ai-keys`, `DELETE /auth/me/ai-keys/{id}` | A member's keys for their own AI apps, when an admin turned AI apps (`mcp`) on for them: listed, made (the key is shown once; only its hash is kept) and removed. Never for a child |
| `POST /auth/ai-keys/token` | The box's MCP service trades a member's key, with its own secret (`MCP_SERVICE_KEY_FILE`), for a 15-minute token as that member. Without the secret a key gets nothing, so no one can skip the service |
| `GET /users/{id}/avatar?v=…` | Return a member's profile photo |
| `GET /health` | Report service health to the service manager |

## Data and security

ZOOMRIYA ID stores account and app-access information in the `zoomriya_id`
database. Its signing keys and profile photos live in
`/data/zoomriya-id/keys/` and `/data/zoomriya-id/avatars/`. The directory is
readable only by the `zoomriya-id` service account. Both the database and
directory are in every backup: on ZOOMRIYA OS, the box's own backup seals
them onto the backup drive with the backup key; elsewhere,
`deploy/backup.conf` declares them.

`mcp` (a member's own AI apps) is the one app that is off until an admin
turns it on for a member, and it is never on for a child's account.

**The second sign-in step** (`app/second_step.py`, `app/mail.py`) is a
six-digit code sent by email, and a choice for everyone, admins too. It goes
out through the family's own email account, which an admin sets in Box
Desktop: nothing goes through ZOOMRIYA's servers, and there are no text
messages. A code works once, for ten minutes; only a
keyed hash of it is kept, and the email account's password is kept encrypted
(AES-GCM), both with `keys/second-step.key` beside the signing key
(`app/sealing.py`). A device that passed the code skips it for 30 days, until
the member signs out or changes their password or the address.
An admin who can't sign in at all is let back in at the box: ZOOMRIYA OS's
agent checks the box's setup code, then runs `app.recover_admin` (a new
password, sign-in codes by email turned off, signed out everywhere). The setup code is
planned to become the box phrase (*Recovery keys* in zoomriya-docs,
`/developers/recovery/`); `app.recover_admin` doesn't change.

When a backup is brought back on ZOOMRIYA OS, every account comes back as it
was: passwords, sign-in codes by email, the family's email account and signed-in devices. An admin who forgot their
old password can name their account and a new one at the same time; the
backup key stands in for the setup code, and the agent runs
`app.recover_admin`. It then runs `app.restored`, which writes "This box was
restored from the backup of … by …" in the family's activity.

Sign-in (including `/auth/login/new-password`, the second step and
`/auth/me/confirm-password`) and password changes are rate-limited by address. The limit is
controlled by `RATE_LIMIT_AUTH_REQUESTS` within
`RATE_LIMIT_WINDOW_SECONDS` (currently 10 requests per minute).
Five wrong passwords in a row for one person lock their sign-in for 15
minutes, wherever they come from, even with the right password
(`app/sign_in_lock.py`; `SIGN_IN_LOCK_TRIES`, `SIGN_IN_LOCK_MINUTES`). A wrong
password older than that is forgotten, the right one clears the count, and an
admin setting a new password or `app.recover_admin` lifts the lock. Each lock
is written in the family's activity. Planned with remote access
(zoomriya-connect, Direct+): connectd can label each connection with the
paired device it came from (PROXY protocol), so the limit by address applies
per device away from home too.

## Run it for development

```bash
sudo -u postgres createdb -O zoomriya zoomriya_id         # once
sudo -u postgres createdb -O zoomriya zoomriya_id_test    # once, for the tests
scripts/dev.sh                                            # :8050, migrates first
```

If you also have `zoomriya-apps` checked out beside this repository, its
`./dev-all.sh` script starts ZOOMRIYA ID along with the other development
servers. Open the apps through the gateway at <http://localhost:8088/>; the
gateway makes the API available under `/id/`.

Put local settings in `backend/.env` (see `backend/app/config.py`). For
example, `INSTALLED_APPS=photos,vault` enables those apps. When
`scripts/dev.sh` starts with an empty database, it creates a development
account named `admin` with password `admin123`. It leaves existing accounts
unchanged. Use this account only in a local development environment.

To import existing Photos accounts on a development machine, stop the
service first and run:

```bash
cd backend
PHOTOS_DATABASE_URL=postgresql+psycopg://zoomriya:root@localhost:5432/zoomriya \
    .zrvenv/bin/python -m app.import_from_photos
```

The script looks for the Photos library in its usual location and for the
signing key at `/data/zoomriya/keys/zoomriya-id-ed25519.pem`. If your
development machine does not have `/data`, set `PHOTOS_SIGNING_KEY` to the
key at `data/keys/zoomriya-id-ed25519.pem` in the Photos checkout, and set
`PHOTOS_LIBRARY_ROOT` to Photos' `STORAGE_ROOT`.

Run each test suite from the repository root:

```bash
(cd backend && .zrvenv/bin/python -m pytest -q)
(cd identity-py && ../backend/.zrvenv/bin/python -m pytest -q)
```

The backend tests use the `zoomriya_id_test` database.

## Install on a machine

```bash
sudo deploy/install.sh                 # install code, virtual environment, service account and unit
sudo deploy/setup.sh                   # create the database, role and settings if missing
sudoedit /etc/zoomriya/id.env          # configure INSTALLED_APPS
sudo systemctl enable --now zoomriya-id
```

On a ZOOMRIYA Box, ZOOMRIYA OS installs the service and runs
`deploy/setup.sh` during first boot. On another machine, the first app's
installer runs both scripts. The setup script creates only what is missing,
uses a lock to avoid running twice at once and writes
`/var/lib/zoomriya-id/set-up` only after it finishes. This makes it safe to
run again after an interrupted setup.

**There is no default account or password.** During setup, the person
installing the service creates the first admin and chooses the password. On a
ZOOMRIYA Box, this happens in the first-boot setup. Elsewhere, it is handled
by the app installer. The command below is provided for administrators
setting up a machine manually; it succeeds only if no accounts exist yet:

```bash
# 0: made; 3: accounts exist, nothing changed
printf '%s' "$PASSWORD" | sudo systemd-run --quiet --pipe --wait -p User=zoomriya-id \
    -p EnvironmentFile=/etc/zoomriya/id.env -p WorkingDirectory=/opt/zoomriya/id/backend \
    /opt/zoomriya/id/venv/bin/python -m app.first_admin <username>
```

## Migrate sign-in from Photos

Use these steps when upgrading a box whose sign-in service was previously
part of Photos. Run them with the ZOOMRIYA ID release that introduces the
migration, before a later Photos release removes the columns the import
needs. If that later release is already installed, import from a backup of
the Photos database made before the migration.

After migration, members must sign in again. Tokens from before ZOOMRIYA ID
are not accepted because someone with Photos' old shared secret could have
created one.

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

[AGPL-3.0-only](LICENSE-AGPL-3.0). The ZOOMRIYA name and logo are not
covered by the licence: see [TRADEMARKS.md](TRADEMARKS.md).

## Related projects

The box is [ZOOMRIYA OS](https://github.com/zoomriya/zoomriya-os); the apps
and Family Hub are in zoomriya-apps (private).
