# Enterprise Auth System

Multi-tenant authentication service: FastAPI + PostgreSQL + Redis on the
backend, React + TypeScript + Vite on the frontend, with Docker Compose and
Kubernetes deployment manifests.

Feature set:

- **Argon2id** password hashing (not bcrypt, not PBKDF2).
- **RS256 access tokens** (JWT, 15 min) signed with a private key this service
  never shares, published as a **JWKS** so other systems can verify them without
  being able to forge one.
- **Rotating refresh tokens** (7 days). Only SHA-256 hashes of refresh tokens
  are stored, so a database leak does not hand out live sessions.
- **Roles in the token** (`roles` claim) for downstream authorization, with an
  admin API for assigning them.
- **Replay detection** — reusing an already-rotated refresh token is treated as
  a compromise and revokes every session for that user.
- **Per-account lockout** after repeated failures, and **per-IP rate limiting**
  on register/login/refresh.
- **CAPTCHA** on registration and login, single-use and consumed even when the
  answer is wrong.
- **Email verification** with single-use, expiring links.
- **Tenant isolation** at the data layer: every table carries `tenant_id` and
  repositories are always constructed with a tenant.

## Architecture

```
browser ──► nginx :8080 ──┬── /            SPA (static files)
                          └── /api/*   ──► FastAPI :8000 ──┬── PostgreSQL  :5432
                                                           └── Redis       :6379
```

The browser only ever talks to **one origin**. In development Vite proxies
`/api` to the backend; in production and on Kubernetes nginx does. That keeps
CORS empty in production, keeps the access token from crossing origins, and
lets the CSP stay at `default-src 'self'`.

Redis holds only ephemeral security state: the access-token blacklist, captcha
answers and per-IP rate-limit counters. Losing it forces users to sign in again
but does not corrupt accounts — which is why it runs with persistence off.
Lockout state, by contrast, lives on the `users` row in Postgres, because a
cache flush must not hand an attacker a fresh set of password attempts.

### Repository layout

```
backend/
  app/
    api/            route handlers (auth, user, admin)
    core/           settings, role vocabulary, JWT signing keys (JWKS)
    middleware/     Redis-backed rate limiting
    models/         SQLAlchemy models (Tenant, User, RefreshToken, EmailVerificationToken)
    repositories/   data access, always tenant-scoped
    schemas/        pydantic request/response contracts
    services/       auth, captcha, email
    dependencies.py FastAPI dependency wiring, role guards
    main.py         application factory, middleware, lifespan
  alembic/          migrations
  test/             pytest suite (needs real Postgres + Redis)
scripts/
  generate-jwt-key.sh   writes secrets/jwt-private.pem (git-ignored)
frontend/
  src/
    api/client.ts        HTTP client, single-flight token refresh
    auth/                AuthProvider, route guards
    components/          CaptchaField
    pages/               Login, Register, VerifyEmail, Account
  tests/            Vitest + Testing Library
k8s/                manifests, applied in filename order
```

## Quick start (Docker Compose)

```bash
docker compose up --build
```

No `.env` is needed: `docker-compose.yml` supplies local defaults and points
email at MailHog. To override a value, copy `.env.example` to `.env` and edit
it — but that file is written for production (real SMTP relay, real
`FRONTEND_URL`), so use it as a reference rather than as-is.

| Service  | URL                              |
| -------- | -------------------------------- |
| UI       | http://localhost:5173            |
| API docs | http://localhost:8000/api/docs   |
| MailHog  | http://localhost:8025            |

Registration emails are captured by MailHog — open it to get the verification
link. Migrations run automatically when the backend container starts.

The development defaults are deliberately unsafe (known database password, no
signing key). Production refuses them: `docker-compose.prod.yml` uses
`${VAR:?}` for the sensitive values, and outside `DEBUG=true` the backend
refuses to start without a signing key. Locally, `DEBUG=true` makes it mint an
ephemeral RSA key pair at start-up — fine for a throwaway stack, but tokens die
with the process, so a `--reload` restart signs everyone out.

## Running without Docker

Backend (Python 3.11):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # point DATABASE_URL at a real Postgres
../scripts/generate-jwt-key.sh  # or set DEBUG=true for an ephemeral key
# then set JWT_PRIVATE_KEY_PATH in backend/.env
alembic upgrade head
uvicorn app.main:app --reload   # http://localhost:8000
```

Frontend (Node 20):

```bash
cd frontend
npm install
npm run dev                     # http://localhost:5173, proxies /api
```

Both dependencies are connected lazily: the app starts even if Postgres or
Redis is down, and the failure only shows up on the first request that needs
them. Compose starts the backend after both pass their healthchecks, and the
Kubernetes Deployment uses an init container that polls the two ports; running
`uvicorn` by hand leaves that ordering to you.

## Configuration

Settings come from the environment via `pydantic-settings`
(`backend/app/core/config.py`); `backend/.env.example` lists every key.

| Variable | Default | Notes |
| --- | --- | --- |
| `DATABASE_URL` | `postgresql+asyncpg://auth:auth@localhost:5432/authdb` | asyncpg driver, not psycopg |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_DB` | `localhost` / `6379` / `0` | `REDIS_URL` overrides all three |
| `REDIS_MAX_CONNECTIONS` | `50` | pool size |
| `JWT_PRIVATE_KEY` / `JWT_PRIVATE_KEY_PATH` | `""` | **required** when `DEBUG=false`; PEM inline or a file. Newlines in an inline value may be written as `\n` |
| `JWT_PUBLIC_KEY` / `JWT_PUBLIC_KEY_PATH` | `""` | optional; derived from the private key when unset. Set it only for a verify-only process |
| `JWT_KEY_ID` | `auth-1` | goes into the token's `kid` header; change it when you rotate |
| `JWT_PREVIOUS_PUBLIC_KEYS` | `""` | JSON `kid -> PEM` of retired keys; keeps their tokens verifiable |
| `JWT_ALGORITHM` | `RS256` | pinned; `HS256` is refused (a shared secret lets verifiers mint tokens) |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `enterprise-auth-system` / `enterprise-auth-api` | verified on every decode |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | also the maximum staleness of the `roles` claim |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | sliding: rotation issues a full-lifetime token |
| `MAX_LOGIN_ATTEMPTS` | `5` | failures before lockout |
| `LOCKOUT_DURATION_MINUTES` | `15` | |
| `CAPTCHA_LENGTH` / `CAPTCHA_EXPIRE_SECONDS` | `6` / `300` | answer case-insensitive |
| `EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS` | `24` | |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USE_TLS` | `localhost` / `1025` / `false` | dev defaults target MailHog |
| `SMTP_FROM_EMAIL` | `noreply@example.com` | |
| `FRONTEND_URL` | `http://localhost:5173` | base of the verification link |
| `ALLOWED_ORIGINS` | `["http://localhost:5173"]` | JSON list; `[]` behind a same-origin proxy |
| `DEFAULT_TENANT_ID` | `550e8400-e29b-41d4-a716-446655440000` | public endpoints always resolve here |
| `BOOTSTRAP_ADMIN_EMAILS` | `[]` | JSON list; these addresses register with the `admin` role |
| `SECURITY_CSP`, `SECURITY_HSTS_ENABLED`, `SECURITY_HSTS_MAX_AGE_SECONDS` | see config | security headers |

## API

All routes are under `/api`. Every error is JSON `{"detail": "..."}`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/auth/captcha` | — | `{token, image}`; image is a `data:image/png;base64,` URL |
| `GET` | `/auth/jwks` | — | Public signing keys (JWKS) for verifying access tokens elsewhere |
| `POST` | `/auth/register` | — | Create account, send verification email. `201` |
| `POST` | `/auth/login` | — | Returns access + refresh token and a user summary |
| `POST` | `/auth/refresh` | — | Rotate refresh token; the old one stops working |
| `POST` | `/auth/verify-email?token=&user_id=` | — | Consume a verification link |
| `POST` | `/auth/logout` | Bearer | Blacklist the access token, revoke all refresh tokens. `204` |
| `GET` | `/users/me` | Bearer | Current profile, including `roles` |
| `GET` | `/admin/roles` | Bearer + `admin` | Role vocabulary and its meaning |
| `GET` | `/admin/users?limit=&offset=` | Bearer + `admin` | Accounts in the caller's tenant, oldest first |
| `POST` | `/admin/users/{id}/roles` | Bearer + `admin` | Replace an account's roles with `{"roles": [...]}` |
| `GET` | `/health` | — | `{"status": "ok"}`, used by probes |

Status codes worth knowing:

| Code | Meaning |
| --- | --- |
| `400` | Wrong/expired captcha, duplicate email, invalid verification token, unknown role |
| `401` | Bad credentials, invalid/blacklisted token, bad refresh token — the caller is not identified |
| `403` | The caller is identified but lacks the required role. Do not prompt for a new login |
| `404` | No such account in the caller's tenant |
| `409` | Refused to remove the last administrator |
| `422` | Validation failure (e.g. password policy) |
| `423` | Account locked |
| `429` | Rate limited; `Retry-After` is the window length (60s), not the time left in it |

Password policy: at least 12 characters, upper + lower + digit + symbol, not a
known common password, and no three identical consecutive characters.

Rate limits (per IP, fixed window in Redis): register 5/min, login 10/min,
refresh 20/min.

## Tokens and JWKS

Access tokens are **RS256** (asymmetric): this service signs with a private key
that never leaves it, and publishes the matching public key at
`GET /api/auth/jwks` so any other system can *verify* tokens without being able
to mint them. With an HMAC secret (`HS256`) every verifier would also be a
signer, which is the wrong contract for an integration point.

The token is meant to be consumed by other services:

```json
{
  "sub": "…user id…", "tenant_id": "…", "jti": "…",
  "type": "access", "roles": ["admin", "user"],
  "iat": 1730000000, "exp": 1730000900,
  "iss": "enterprise-auth-system", "aud": "enterprise-auth-api"
}
```

Consumers should check, in this order: signature against the JWKS key named by
the token's `kid`, `iss`, `aud`, `exp`, and `type == "access"` (the JOSE header
also carries `typ: "at"`, per RFC 9068). The JWKS response is cached for 5
minutes, so fetch it lazily and keep the keys warm.

**Key rotation does not sign anyone out.** Tokens name their key in the `kid`
header. To rotate:

1. `./scripts/generate-jwt-key.sh` with a new `JWT_KEY_ID` (it will not
   overwrite the existing file — move it aside first).
2. Add the *old* public key to `JWT_PREVIOUS_PUBLIC_KEYS` (JSON `kid -> PEM`)
   and restart. The JWKS now lists the new key first and the old one after it.
3. Keep the old entry for at least `ACCESS_TOKEN_EXPIRE_MINUTES` (15 minutes;
   30 is comfortable), then remove it.

Without step 2 tokens issued before the switch stop verifying at once, and
every user has to log in again.

## Roles

A role here *is* a permission: `roles` in the token is the list of strings a
consumer should recognise. The vocabulary (`backend/app/core/roles.py`) is
`admin`, `support`, `user`; `admin` is a superuser role that satisfies every
gate, so adding a check never needs the admin list updated. Role assignment is
`POST /api/admin/users/{id}/roles` with `{"roles": ["user", "support"]}`; the
list replaces the old one.

Roles are copied into the access token at issue time, so **a downstream system
authorizes from a snapshot** — at most `ACCESS_TOKEN_EXPIRE_MINUTES` (15 min)
stale. This service's own gates re-read `users.roles` on each request (the row
is loaded anyway), so a demotion takes effect here immediately even while the
old token still claims the old role. Revoking a role is therefore not enough to
kick someone out of an external system: also end their session, or let the
token expire.

The API refuses to remove the last administrator (`409`), because that would
leave nobody able to assign roles, with no way back short of editing the
database.

### Bootstrapping the first administrator

Nobody can grant the first admin through the API, so registration is the only
path. Put the address in `BOOTSTRAP_ADMIN_EMAILS` (a JSON list) *before* it
registers; that account is created with `admin`. The list is configuration, not
client input, so it cannot be used to self-promote. Afterwards, an existing
admin can promote anyone else — leave the variable set only if that address
should stay admin if it ever re-registers in a fresh database.

## Security notes

- **Access tokens live in memory only** in the frontend. Nothing is written to
  `localStorage`, so an XSS payload cannot read a token from storage; a reload
  signs the user out (the refresh token is not persisted either). If you need
  reload persistence, the safe place for it is an `HttpOnly` cookie, not
  storage.
- **Refresh token rotation is strict.** The client funnels every refresh
  through a single in-flight promise, because two parallel refreshes would race,
  and the loser looks exactly like a stolen token — which triggers a full
  session revocation.
- **Tenant identity is server-side.** `get_public_tenant_id()` returns the
  configured tenant; a client-supplied tenant header is never trusted. Real
  multi-tenant deployments should resolve the tenant from the authenticated
  hostname or a trusted gateway — see the docstring in
  `backend/app/dependencies.py`.
- **The health endpoint is unauthenticated and deliberately shallow.** It
  reports liveness, not readiness of Postgres or Redis; a backend whose
  database is down still answers `200`. That is intentional — a restart would
  not fix the database.
- **TLS is terminated at nginx / the Ingress.** HSTS is emitted by the backend
  when `DEBUG=false` and by nginx; both are only meaningful over HTTPS, so do
  not serve production over plain HTTP.
- **The signing key is the whole trust anchor.** Anyone holding it can mint a
  token for any user and any role, in this system and in every system that
  verifies against the JWKS. Keep it out of the image, out of git, out of
  environment variables where you can (a mounted file or a secret store), and
  rotate it if it may have leaked — at which point old tokens must be allowed
  to expire, not carried over in `JWT_PREVIOUS_PUBLIC_KEYS`.
- **`roles` in a token is a snapshot, not a live permission check.** It is
  correct for authorization in downstream systems and stale by up to 15 minutes.
  This service ignores it for its own gates and reads `users.roles` instead.
- **The K8s Secret is a template.** `k8s/02-secret.yaml.example` contains
  `CHANGE_ME_*` placeholders and must be created from real values
  (`kubectl create secret generic ...`). Committing a filled-in Secret defeats
  the point.

## Tests

```bash
cd backend && pytest                    # needs Postgres + Redis
cd frontend && npm test                 # Vitest + jsdom
```

The backend suite runs against real Postgres and Redis rather than fakes,
because the behaviour that matters (unique indexes, `FOR UPDATE` rotation,
Redis Lua scripts, the blacklist) is exactly what fakes get wrong. It
**truncates tables between tests**, so `conftest.py` refuses to run unless the
database name contains `test` — override deliberately with
`ALLOW_NON_TEST_DATABASE=1` at your own risk. Point it elsewhere with
`TEST_DATABASE_URL`.

`REDIS_DB=15` is used by default so the test cache cannot collide with a
development one.

## Production deployment

Docker Compose:

```bash
cp .env.example .env                     # every REQUIRED value must be real
./scripts/generate-jwt-key.sh            # writes secrets/jwt-private.pem
docker compose -f docker-compose.prod.yml up -d --build
```

Only the frontend publishes a port; nginx proxies `/api` to the backend over
the compose network. Migrations run as a one-shot `migrate` service that must
complete before the API starts. The signing key is bind-mounted read-only from
`./secrets`, not passed as an environment variable, so it stays out of
`docker inspect` and crash dumps.

Kubernetes — apply in filename order:

```bash
./scripts/generate-jwt-key.sh
kubectl apply -f k8s/00-namespace.yaml
kubectl create secret generic app-secrets -n enterprise-auth \
  --from-literal=POSTGRES_USER=auth \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -base64 24)" \
  --from-file=JWT_PRIVATE_KEY=secrets/jwt-private.pem \
  --from-literal=JWT_KEY_ID=auth-1 \
  --from-literal=SMTP_HOST=smtp.example.com \
  --from-literal=SMTP_USER=... \
  --from-literal=SMTP_PASSWORD=... \
  --from-literal=SMTP_FROM_EMAIL=noreply@example.com \
  --from-literal=FRONTEND_URL=https://auth.example.com
kubectl apply -f k8s/01-configmap.yaml
# 02-secret.yaml.example is a template only — never `kubectl apply` it as-is.
kubectl apply -f k8s/03-databases.yaml
kubectl apply -f k8s/04-migrate-job.yaml
kubectl apply -f k8s/05-backend.yaml
kubectl apply -f k8s/06-frontend.yaml
kubectl apply -f k8s/07-ingress.yaml
kubectl apply -f k8s/08-hpa.yaml
kubectl apply -f k8s/09-networkpolicy.yaml
```

Things the manifests assume:

- the images are built and pushed as `enterprise-auth/backend` and
  `enterprise-auth/frontend` — the `images` CI job builds `:ci` tags;
- an nginx ingress controller and, optionally, cert-manager
  (`letsencrypt-prod` ClusterIssuer) exist;
- `metrics-server` is installed, otherwise the HPAs report `<unknown>`;
- the cluster enforces NetworkPolicy (many CNIs silently ignore it).

The `migrate` Job is immutable: re-applying it after an image change fails
until it is deleted — `kubectl delete job migrate -n enterprise-auth
--ignore-not-found` first.

`DATABASE_URL` is assembled **inside the container spec** from `POSTGRES_*`
entries declared above it, because Kubernetes only expands `$(VAR)` within a
container's own `env` list. It cannot be built in the ConfigMap.

## CI

`.github/workflows/ci.yml` runs three jobs on push to `main` and on pull
requests:

1. **backend** — Postgres 16 and Redis 7 service containers, `ruff` on the
   fatal-error rule set, `alembic upgrade head` (verifying the migrations
   actually apply), then `pytest`.
2. **frontend** — `npm install`, `tsc --noEmit`, `vitest run`, `vite build`.
3. **images** — builds both images after the first two pass.

The frontend job uses `npm install`, not `npm ci`, because no
`package-lock.json` is committed yet. Commit one and switch to `npm ci` for
reproducible installs.
