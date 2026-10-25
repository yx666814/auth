# Enterprise Auth System

Multi-tenant authentication service: FastAPI + PostgreSQL + Redis on the
backend, React + TypeScript + Vite on the frontend, with Docker Compose and
Kubernetes deployment manifests.

Feature set:

- **Argon2id** password hashing (not bcrypt, not PBKDF2).
- **Short-lived access tokens** (JWT, 15 min) plus **rotating refresh tokens**
  (7 days). Only SHA-256 hashes of refresh tokens are stored, so a database
  leak does not hand out live sessions.
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
    api/            route handlers (auth, user)
    core/           settings and cryptography (JWT, blacklist)
    middleware/     Redis-backed rate limiting
    models/         SQLAlchemy models (Tenant, User, RefreshToken, EmailVerificationToken)
    repositories/   data access, always tenant-scoped
    schemas/        pydantic request/response contracts
    services/       auth, captcha, email
    dependencies.py FastAPI dependency wiring
    main.py         application factory, middleware, lifespan
  alembic/          migrations
  test/             pytest suite (needs real Postgres + Redis)
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

The development defaults are deliberately unsafe (known JWT secret, `auth`
database password). They are refused in production because
`docker-compose.prod.yml` uses `${VAR:?}` for the sensitive values and the
backend rejects a short `JWT_SECRET_KEY` whenever `DEBUG=false`.

## Running without Docker

Backend (Python 3.11):

```bash
cd backend
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # point DATABASE_URL at a real Postgres
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
| `JWT_SECRET_KEY` | `""` | **required**; must be ≥ 32 chars when `DEBUG=false` |
| `JWT_ISSUER` / `JWT_AUDIENCE` | `enterprise-auth-system` / `enterprise-auth-api` | verified on every decode |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | |
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
| `SECURITY_CSP`, `SECURITY_HSTS_ENABLED`, `SECURITY_HSTS_MAX_AGE_SECONDS` | see config | security headers |

## API

All routes are under `/api`. Every error is JSON `{"detail": "..."}`.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/auth/captcha` | — | `{token, image}`; image is a `data:image/png;base64,` URL |
| `POST` | `/auth/register` | — | Create account, send verification email. `201` |
| `POST` | `/auth/login` | — | Returns access + refresh token and a user summary |
| `POST` | `/auth/refresh` | — | Rotate refresh token; the old one stops working |
| `POST` | `/auth/verify-email?token=&user_id=` | — | Consume a verification link |
| `POST` | `/auth/logout` | Bearer | Blacklist the access token, revoke all refresh tokens. `204` |
| `GET` | `/users/me` | Bearer | Current profile |
| `GET` | `/health` | — | `{"status": "ok"}`, used by probes |

Status codes worth knowing:

| Code | Meaning |
| --- | --- |
| `400` | Wrong/expired captcha, duplicate email, invalid verification token |
| `401` | Bad credentials, invalid/blacklisted token, bad refresh token |
| `422` | Validation failure (e.g. password policy) |
| `423` | Account locked |
| `429` | Rate limited; `Retry-After` is the window length (60s), not the time left in it |

Password policy: at least 12 characters, upper + lower + digit + symbol, not a
known common password, and no three identical consecutive characters.

Rate limits (per IP, fixed window in Redis): register 5/min, login 10/min,
refresh 20/min.

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
docker compose -f docker-compose.prod.yml up -d --build
```

Only the frontend publishes a port; nginx proxies `/api` to the backend over
the compose network. Migrations run as a one-shot `migrate` service that must
complete before the API starts.

Kubernetes — apply in filename order:

```bash
kubectl apply -f k8s/00-namespace.yaml
kubectl create secret generic app-secrets -n enterprise-auth \
  --from-literal=POSTGRES_USER=auth \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -base64 24)" \
  --from-literal=JWT_SECRET_KEY="$(openssl rand -base64 48)" \
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
