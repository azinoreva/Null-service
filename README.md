# Null Service

Backend API for the Null app: accounts, contacts, DH key exchange and a
federated server registry.

FastAPI + async SQLAlchemy. Durable data lives in SQL (SQLite by default,
PostgreSQL for production); short-lived data stays in Redis.

## Stack

- **FastAPI** (Starlette) with custom logging, rate-limit, JSON-enforcement and
  body-size middleware.
- **SQLAlchemy 2.0 async** via `aiosqlite` (default) or `asyncpg` (Postgres).
- **Redis** for OTPs, refresh-token sessions, rate limits/backoff and shareable
  contact links.
- **Pydantic v2** request/response models.
- Auth: HS256 access tokens (JWT) + JWE-encrypted recovery blobs; Ed25519
  passport signing.

## Quick start

```powershell
# 1. Environment
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Configuration (see table below). Create a .env with at least
#    REDIS_URL and a stable SALT.

# 3. Run
uvicorn app.main:app --reload
```

- API docs: `http://127.0.0.1:8000/docs`
- Health/root: `GET /`

Tables are created automatically on startup (`init_db()` in the startup event).
There is no migration framework wired in yet (Alembic is installed but unused) —
schema changes to existing tables need manual handling or a migration.

## Configuration

All configuration is read from the environment (`.env` is loaded automatically).

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite+aiosqlite:///./app.db` | SQL connection. Plain `sqlite://` and `postgresql://`/`postgres://` URLs are normalised onto the async driver automatically. |
| `REDIS_URL` | `redis://localhost:6379` | Ephemeral store. |
| `REDIS_MAX_CONNECTIONS` | `20` | Redis pool size. |
| `SERVER_PRIVATE_KEY` / `SERVER_PUBLIC_KEY` | PEM files in repo root | Base64-encoded Ed25519 PEM. Falls back to `server_private_key.pem` / `server_public_key.pem`. |
| `JWE_SECRET` | none | Secret for signing access tokens. **Required.** |
| `JWE_EXP_MINUTES` | `1440` | Access-token lifetime. |
| `INVITATION_JWS_KEY` | none | Invitation signing key. |
| `SALT` | `""` | Server-side HMAC salt for hashing phone/email on server registration. **Must be stable** — changing it invalidates existing `phone_hash`/`email_hash` values. |
| `SERVER_ID` | `local` | This node's id. |

### Using PostgreSQL

Set `DATABASE_URL` to a normal URL:

```
DATABASE_URL=postgresql://user:password@localhost:5432/nulldb
```

The driver suffix is added for you (`postgresql+asyncpg://...`). Foreign keys
and `ON DELETE CASCADE` are enforced natively by Postgres; for SQLite the engine
enables `PRAGMA foreign_keys=ON` on every connection so behaviour matches.

## Storage model

Durable records (SQL):

| Table | Model | Contents |
| --- | --- | --- |
| `users` | `UserORM` | Account: phone, salt, scrypt password hash, recovery type, push tokens, blobs. `phone_number` is unique. |
| `servers` | `ServerORM` | **Public** server record only: url/name/type, media, colour, about, categories, flags, location. Contains **no owner data**. |
| `server_owners` | `ServerOwnerORM` | Owner identity for a server, joined by `server_id` (FK, `ON DELETE CASCADE`). `phone_hash` is unique (registration dedup); `email_hash` authorises ownership. Plaintext `phone`/`email` are stored only when the server is not `ephemeral`. |
| `user_servers` | `UserServerORM` | Per-account server membership list (`user_id`, `server_id`). |
| `contact_drops` | `ContactDropORM` | Contacts dropped into a recipient's inbox. Unique on `(recipient_id, sender_id)`; rows carry `expires_at`. |
| `dh_drops` | `DhDropORM` | DH keys dropped into a recipient's inbox. Same shape/expiry rules. |

Ephemeral records (Redis):

- OTPs and attempt counters (signup, login, server registration, media-url).
- Refresh-token sessions and the blocked-`jti` list.
- Rate-limit counters and brute-force backoff lockouts.
- Shareable contact links (`/send_contact`, `/get_contact`,
  `/send_contact_rebound`) — these are inherently short-lived link tokens.

### Persistence design notes

- **Owner privacy:** a `server_id` on its own can never yield owner data. Owner
  rows are only read (a) by `phone_hash` during registration dedup, or (b) via
  `get_owned_server(server_id, email_hash)` which requires the owner's email and
  compares the hash in constant time. The public `servers` table has no owner
  columns at all.
- **Drops are cleaned up:** reads filter on `expires_at`, `save_*_drop` purges a
  recipient's expired rows on write, and a background task
  (`_drop_cleanup_loop`, every 5 min) globally purges expired drops so unfetched
  inboxes don't grow without bound.
- **Register transaction:** `servers` and `server_owners` are inserted together;
  a duplicate phone returns `409`, an id collision regenerates the id and retries.

## API reference

All routes are mounted under `/api`. Most require a Bearer access token
(`Authorization: Bearer <token>`).

### Accounts & auth

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/create-new-user-preprocess` | Send signup OTP. |
| POST | `/api/create-new-user-postprocess` | Verify OTP and create the account. |
| POST | `/api/sign-in` | Password sign-in; returns access + refresh tokens. |
| POST | `/api/refresh` | Rotate a refresh token. |
| POST | `/api/get-details` | Rebuild the caller's account document. |
| POST | `/api/forgot_password` | Start password recovery. |
| POST | `/api/new-passport` | Issue a new signed passport. |
| POST | `/api/change-password` | Change password. |
| POST | `/api/push-notification-token` | Register/replace a device push token. |
| POST | `/api/send_push_notification` | Send a push. |
| POST | `/api/edit-phone` | Change the account phone number. |

### Connections (contacts & DH keys)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/api/send_contact` | Create a shareable contact link (Redis). |
| POST | `/api/get_contact` | Fetch a shareable contact (Redis). |
| POST | `/api/send_contact_rebound` | Reply with your own contact (Redis). |
| POST | `/api/drop_contact` | Drop a contact into a recipient's inbox (SQL). |
| POST | `/api/check_contact` | Fetch + clear your inbox (SQL). |
| POST | `/api/dh-drop` | Drop a DH key into a recipient's inbox (SQL). |
| POST | `/api/check_dh_drops` | Fetch + clear your DH inbox (SQL). |
| POST | `/api/clear_dh_inbox` | Wipe your DH inbox (SQL). |

### Servers

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/api/servers` | List public server records. |
| POST | `/api/register-server-pre` | Send a registration OTP. |
| POST | `/api/register-server-post` | Verify OTP and register (creates server + owner). |
| POST | `/api/servers/{server_id}/media-url/otp` | Send an OTP to the owner's email. |
| POST | `/api/servers/{server_id}/media-url` | Update media URL / server URL / owner email. |
| POST | `/api/add-servers` | Add server ids to the caller's membership list. |
| POST | `/api/exchange-servers` | Read another user's membership list. |

## Project layout

```
app/
  main.py                 # app factory, middleware, startup/shutdown
  routers.py              # /api router assembly
  rules.py                # rate-limit rules per path
  models/
    user_model.py         # UserORM + helpers
    server.py             # server pydantic models, ServerORM/ServerOwnerORM/UserServerORM + helpers
    connections.py        # ContactDropORM/DhDropORM + helpers, purge_expired_drops
    updates.py            # Categories and content-annotation models
    safe_base_model.py    # structural payload-size guards
  routes/
    signup.py login.py account.py connections.py servers.py
  utils/
    db.py                 # async engine/session, get_db, init_db, FK pragma
    _redis.py config.py auth.py limiter.py logger.py backoff.py
    lua_script.py mails_n_sms.py firebase.py
```
