# MICEPP Scanner — Technical Documentation

This document is derived exclusively from the repository source, configuration, tests, and Docker definitions. It describes the implementation as present in the repository.

## 1. Project purpose

MICEPP Scanner is an intranet forensic evidence-analysis platform. It accepts files, archives, RAW images, and EWF/E01 images associated with a case; preserves and re-hashes originals; extracts working copies; performs static, signature, optional dynamic sandbox, and optional supervised ML analysis; collects findings; requires human review; produces PDF reports; and records sensitive actions in a verifiable HMAC audit chain.

It is not implemented as a network vulnerability scanner. The code contains no Nmap, WhatWeb, CPE, CVE, NVD, OSV, host discovery, port scanning, or software-inventory workflow.

## 2. Overall architecture

The browser receives a React single-page application from Nginx. Nginx proxies `/api/` and `/health/` to a FastAPI API. The API stores metadata in PostgreSQL, enqueues analysis in Redis-backed Celery, and uses shared Docker volumes for originals, working copies, reports, and trained models. A separate Celery worker executes the pipeline. ClamAV is accessed over its network socket. CAPE/Cuckoo is optional and external to this Compose stack.

```text
Browser ──HTTP──> Nginx + static React
                       │ /api, /health
                       v
                    FastAPI ─────── PostgreSQL (metadata/audit)
                       │                 ^
                       │                 │
                       ├── Redis/Celery ─┘
                       │        │
                       │        v
                       │     Celery worker ──> ClamAV
                       │        │             YARA / local analyzers
                       │        ├────────────> shared evidence/work/report/model volumes
                       │        └────────────> optional CAPE/Cuckoo API
                       v
                   PDF response
```

Docker networks separate the private `backend` network, the Nginx/API `frontend` network, and the ClamAV-only `updates` network. PostgreSQL, Redis, ClamAV, API, and worker publish no host ports; Nginx publishes the configured HTTP port.

## 3. Complete request flow from browser to database

1. Vite-built React loads in the browser. `main.tsx` creates React Query and React Router providers.
2. The login view posts URL-encoded credentials to `POST /api/v1/auth/token`. Nginx rate-limits this exact route to 5 requests/minute per source IP (burst 5).
3. FastAPI authenticates the database user and returns an HS256 JWT. The frontend places it in `localStorage` under `micepp_access_token`.
4. `request()` adds `Authorization: Bearer <token>` to subsequent API calls. FastAPI decodes the token, looks up the user by `sub`, and rejects inactive or missing users.
5. Endpoint dependencies obtain a SQLAlchemy `Session` from `get_db()`. ORM operations are committed explicitly by state-changing API handlers.
6. Case creation inserts `cases`; ingestion streams an uploaded multipart file into `EVIDENCE_ROOT/<UUID>/`, calculates MD5/SHA-1/SHA-256 in the same stream, then inserts `evidence` metadata. Audit events are inserted in the same session before commit.
7. Starting analysis creates an `analysis_jobs` row, commits it, then calls Celery `.delay(job_id)`. Celery uses Redis as broker and result backend.
8. The worker opens its own database session, writes job/evidence status and findings, and commits progress in batches of 25 artifacts and again at completion/failure.
9. React Query polls recent jobs every 10 seconds and an active job every 3 seconds; it reads persisted API state rather than receiving a push event.

## 4. Folder structure

```text
.
├── backend/                 Python service, migrations, analyzers, tests and YARA rules
│   ├── app/                 FastAPI application and pipeline code
│   │   └── analyzers/       Static, extraction, feature, ML and CAPE integrations
│   ├── migrations/          Alembic environment and initial migration
│   ├── rules/               Local YARA rule files
│   └── tests/               Pytest integration/unit coverage
├── frontend/                React/Vite application and Nginx production proxy
│   └── src/                 UI, route layout, API client, TS types and CSS
├── docs/                    Repository documentation
├── scripts/                 Windows/Linux bootstrap and backup scripts
├── docker-compose.yml       Entire local/production Compose topology
├── .env.example             Configurable deployment environment variables
├── README.md                Operator-facing quick start and capabilities
├── SECURITY.md              Security/deployment guidance
└── Descriptif du projet.docx, Draft sur le projet.docx
                            Source project documents; ignored by Git
```

`backend/app`: `api.py` declares all HTTP routes; `main.py` creates FastAPI and readiness endpoints; `config.py` defines settings; `database.py` creates the SQLAlchemy engine/session; `models.py` declares tables/enums; `schemas.py` declares Pydantic request/response contracts; `security.py` implements JWT/password/RBAC; `storage.py` implements safe ingestion/hash utilities; `audit.py` implements audit-chain creation/verification; `pipeline.py` executes analysis; `worker.py` defines Celery configuration/task; `reports.py` creates PDF reports.

## 5. Technologies, libraries, and frameworks

| Area | Technology | Repository use |
|---|---|---|
| Backend web | FastAPI 0.139.2, Uvicorn 0.41.0 | HTTP API, dependency injection, OpenAPI outside production, ASGI serving. |
| Validation/config | Pydantic Settings 2.14.2 | Settings from environment/`.env`; Pydantic request/response models. |
| Database | PostgreSQL 17 Alpine; SQLAlchemy 2.0.51; psycopg 3.3.3; Alembic 1.18.4 | Persistent relational data, ORM, PostgreSQL driver, schema migration. SQLite supports tests/default development URL. |
| Authentication | PyJWT 2.11.0; pwdlib[argon2] 0.3.0 | HS256 bearer tokens and recommended Argon2 password hashing. |
| Async work | Celery 5.6.3; Redis 7.4 | Analysis task broker/result backend; late acknowledgements and worker-loss handling. |
| HTTP client | httpx 0.28.1 | CAPE/Cuckoo upload, polling and report retrieval. |
| Signature/static analysis | clamd 1.0.2, yara-python 4.5.4, python-magic 0.4.27, pefile 2024.8.26, oletools 0.60.2, pypdf 6.6.2 | ClamAV, YARA, MIME, PE, VBA macro and PDF inspection. |
| ML | scikit-learn 1.9.0, joblib 1.5.3 | RandomForest training, metrics, persistence, prediction. |
| Reporting | ReportLab 4.4.10 | Per-job PDF evidence/report document. |
| Forensic OS tools | Sleuth Kit `tsk_recover`, libewf/ewf-tools | Extract files from RAW and EWF images. Installed in backend container. |
| Frontend | React 19.2.7, React DOM, React Router DOM 7.18.1 | Single-page UI, rendering, browser routes. |
| Frontend data | TanStack React Query 5.101.4 | Server-state cache, mutations and polling. |
| UI | lucide-react 1.25.0, CSS | Icons and all custom styling. |
| Build | Vite 8.1.5, TypeScript 7.0.2, pnpm 11.9.0 | Development server/proxy, typed build, locked dependency install. |
| Edge/proxy | Nginx 1.29 Alpine | Serves build, reverse-proxies API, headers/body/rate limits. |
| Testing/quality | pytest 9.0.2, pytest-cov 7.0.0, Ruff 0.15.7 | Backend tests, optional coverage, linting. No frontend test runner is configured. |
| Containers | Docker, Docker Compose, tini | Service orchestration and PID-1 signal handling. |

## 6. Docker services and roles

| Service | Role |
|---|---|
| `database` | PostgreSQL metadata store, persisted in `postgres-data`; health checked with `pg_isready`. |
| `redis` | Celery broker/result backend, persisted with AOF in `redis-data`; `noeviction` memory policy. |
| `clamav` | Clamd malware scanner and Freshclam signature updater, persisted in `clamav-db`; only service connected to `updates`. |
| `migrate` | One-shot Alembic `upgrade head` job, after PostgreSQL is healthy. |
| `api` | Backend Uvicorn/FastAPI server. Depends on DB, Redis and completed migration. |
| `worker` | Celery worker (`--concurrency=2`) executing evidence analysis. Depends additionally on healthy ClamAV; 2-minute grace period. |
| `web` | Nginx production frontend and proxy; the only published service (`BIND_ADDRESS:HTTP_PORT` to container 8080). |

`api`, `worker`, and `web` drop all Linux capabilities and use `no-new-privileges`. Backend image runs as UID/GID 10001; Nginx runs as `nginx`.

## 7. Environment variables

Settings resolve environment variables case-insensitively and also read `.env`; Compose supplies the starred backend environment block.

| Variable | Purpose/default |
|---|---|
| `ENVIRONMENT` | `development`, `test`, or `production`; Compose default `production`. Controls secret validation and docs exposure. |
| `BIND_ADDRESS` | Nginx host bind address; default `127.0.0.1`. |
| `HTTP_PORT` | Published Nginx host port; default `8787`. |
| `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` | PostgreSQL initialization and Compose database URL credentials. Password is required in Compose. |
| `DATABASE_URL` | SQLAlchemy URL; Compose generates PostgreSQL URL; code default is `sqlite:///./data/micepp.db`. |
| `REDIS_URL` | Celery/readiness Redis URL; default `redis://localhost:6379/0`, Compose uses `redis://redis:6379/0`. |
| `APP_SECRET_KEY` | JWT signing secret; must be random/at least 32 characters in production. |
| `AUDIT_HMAC_KEY` | HMAC audit-chain secret; same production checks, independent from JWT key. |
| `ACCESS_TOKEN_MINUTES` | JWT lifetime, default 60. |
| `EVIDENCE_ROOT`, `WORK_ROOT`, `REPORT_ROOT`, `MODEL_ROOT` | Original evidence, analysis copy, PDF, and Joblib roots; Compose `/evidence`, `/work`, `/reports`, `/models`. |
| `YARA_RULES_ROOT` | Rules directory; Compose `/app/rules`, code default `./rules`. |
| `BOOTSTRAP_ADMIN_USERNAME`, `BOOTSTRAP_ADMIN_PASSWORD`, `BOOTSTRAP_ADMIN_FULL_NAME` | Optional first-admin bootstrap; username default `admin`, full name default given, password required by Compose. |
| `CLAMAV_HOST`, `CLAMAV_PORT`, `CLAMAV_TIMEOUT_SECONDS` | Clamd connection target/time limit; Compose host `clamav`, port `3310`; timeout defaults 120 seconds. |
| `CAPE_BASE_URL`, `CAPE_API_TOKEN` | Optional external CAPE endpoint and `Token` authorization credential. Empty URL disables dynamic analysis. |
| `CAPE_VERIFY_TLS` | HTTPX TLS verification; default true. |
| `CAPE_POLL_SECONDS`, `CAPE_TIMEOUT_SECONDS` | CAPE task polling cadence/default 10 seconds and overall deadline/default 900 seconds. |
| `MAX_UPLOAD_BYTES` | Maximum streamed upload, default 50 GiB. |
| `MAX_EXTRACTED_FILES`, `MAX_EXTRACTED_BYTES` | Archive/image-extraction limits, defaults 100,000 files and 100 GiB. |
| `YARA_TIMEOUT_SECONDS` | YARA match timeout, default 30 seconds. |
| `SANDBOX_RISK_THRESHOLD` | Static score that qualifies an artifact for CAPE, default 55. |
| `MODEL_MIN_SAMPLES_PER_CLASS` | Minimum expert-labeled benign and malicious samples before training, default 20. |
| `ALLOWED_ORIGINS` | Comma-separated FastAPI CORS origins; code default `http://localhost:8787`. It is defined in settings but not exposed by `.env.example` or Compose’s backend environment block. |
| `CLAMD_STARTUP_TIMEOUT`, `FRESHCLAM_CHECKS` | ClamAV image settings: startup limit 1800 and 12 update checks/day. |

## 8. Database schema

All IDs except `audit_events.sequence` are UUID strings. ORM schema is created by initial Alembic migration calling `Base.metadata.create_all`.

| Table | Important fields and constraints | Relationships |
|---|---|---|
| `users` | unique/indexed `username`, `password_hash`, role enum, `is_active`, timestamps | Creates cases/evidence/jobs; reviews and validates labels. |
| `cases` | unique/indexed `reference`, title, description, classification, status enum, `created_by_id` | One case has many evidence rows; ORM cascade delete-orphan applies to relationship. |
| `evidence` | case FK `RESTRICT`, label/file name/kind/status, unique `storage_path`, size and SHA-256/SHA-1/MD5, acquisition/source metadata, verifier time | Belongs to case/creator; has jobs and artifacts. |
| `artifacts` | evidence FK `CASCADE`, unique `(evidence_id, relative_path)`, working `storage_path`, hashes, MIME, JSON metadata | Has many findings and exactly zero/one ground-truth label. |
| `analysis_jobs` | evidence FK `RESTRICT`, requester, indexed status, pipeline version, score/verdict, JSON summary/error/times | Has many findings; exactly zero/one review. |
| `findings` | job FK `CASCADE`, nullable artifact FK, agent/category/severity/confidence, JSON details; `(job_id,severity)` index | Belongs to one job and optionally one artifact. |
| `reviews` | unique `job_id`, reviewer, decision and comments | One review per job. |
| `ground_truth` | unique/indexed `artifact_id`, label, validator and notes | One expert label per artifact. |
| `model_versions` | unique version, Joblib path, feature names/metrics JSON, manifest SHA-256, indexed active flag, trainer | Active model is selected by `is_active`. |
| `audit_events` | autoincrement sequence, actor/action/target, JSON payload, UTC time, previous/event hashes; event hash unique | Linked logically by hashes, not FKs. |

Enums: user roles `admin|analyst|reviewer`; cases `open|sealed|closed`; evidence `ingested|verified|compromised|analyzing|analyzed`; kinds `file|raw_image|ewf_image|archive`; jobs `queued|running|awaiting_review|approved|rejected|failed`; verdicts `benign|suspicious|malicious|inconclusive`; reviews `approve|reject|needs_more_analysis`; labels `benign|malicious`.

## 9. Authentication flow

1. An administrator is bootstrapped at FastAPI lifespan start only if both bootstrap username and password are set and no matching user exists.
2. `POST /auth/token` uses `OAuth2PasswordRequestForm`; usernames are lowercased for lookup. Unknown-user checks verify a dummy Argon2 hash to equalize timing.
3. Valid active users receive a JWT signed with `APP_SECRET_KEY`, algorithm `HS256`, containing `sub`, `usr`, `role`, `iat`, and `exp`.
4. Browser stores the token in `localStorage`; the API client attaches it as a bearer token. A 401 removes it, and the root app returns to the login view.
5. `get_current_user` verifies signature/expiry, requires `sub`, then queries the database and requires `is_active`.

There is no refresh token, server-side session, logout endpoint/token revocation list, MFA, password-reset workflow, or UI for user administration in this repository.

## 10. Authorization and permissions

All non-health routes require a valid bearer token. API permission enforcement is role based:

| Operation | Permission |
|---|---|
| Read dashboard, cases, evidence, jobs, artifacts, models; create case; upload/verify evidence; queue analysis; download eligible report | Any active user, including analyst. |
| List/create users | `admin`. |
| Seal a case | `admin` or `reviewer`. |
| Review analysis; set artifact ground truth; train model; list/verify audit chain | `admin` or `reviewer`. |

There is no per-case ownership/access-control rule: any active authenticated user can read any case/evidence/job and can queue analysis for it. The frontend hides audit navigation from analysts and redirects the audit route, but backend dependencies enforce the actual rule. The role claim in the JWT is not trusted for authorization; `require_roles` uses the current database user role.

## 11. Security mechanisms

- Passwords use Argon2 through `PasswordHash.recommended`; inputs require at least 14 characters when creating users.
- Production startup rejects weak/short `APP_SECRET_KEY`, `AUDIT_HMAC_KEY`, and bootstrap passwords.
- JWT expiry and verified bearer-token authentication protect APIs; disabled users are rejected even with a still-valid token.
- Nginx rate limits login, enforces 50 GiB request body maximum, disables proxy request buffering for uploads, and has one-hour proxy read/send timeouts.
- Nginx adds `nosniff`, frame denial, no-referrer, restrictive permissions policy, and a CSP restricting resources to same origin (inline CSS is allowed).
- Upload filenames are basename-normalized to `[A-Za-z0-9._-]`, paths are resolved and verified under the intended root, files stream in 1 MiB chunks, and overflow raises HTTP 413.
- Originals are written as `.uploading`, flushed/fsynced, atomically renamed, then chmod 0440 where supported. The analysis pipeline re-hashes size and three hashes before extraction; mismatch blocks the analysis and records critical evidence/job events.
- ZIP/TAR extraction prevents traversal, writes newly created targets only, removes symlinks after image extraction, and applies declared/observed file/count/byte limits. RAW/EWF extraction is capped at six hours.
- YARA and CAPE have configurable deadlines; CAPE uses TLS verification by default. An unavailable engine creates availability findings rather than fabricated results.
- Docker uses internal networks, non-root application users, dropped capabilities, `no-new-privileges`, persistent volumes, and no direct public database/Redis/API ports.
- Audit events are canonical JSON HMAC-SHA-256 chained and serialized with a PostgreSQL transaction advisory lock.

## 12. API endpoints grouped by module

API prefix is `/api/v1`.

| Module | Method and route | Behavior |
|---|---|---|
| Health | `GET /health/live` | Static liveness result. |
| Health | `GET /health/ready` | Tests SQL `SELECT 1` and Redis `PING`; returns 503/degraded on either failure. |
| Auth | `POST /auth/token` | Login and audit event; returns bearer token. |
| Auth | `GET /auth/me` | Current user. |
| Users | `GET /users` | Admin user list. |
| Users | `POST /users` | Admin creates a user; username conflict is 409. |
| Dashboard | `GET /dashboard` | Case/job counts, CAPE/model configured state. |
| Cases | `GET /cases?limit=1..500` | Recent cases. |
| Cases | `POST /cases` | Creates case; unique reference is enforced. |
| Cases | `GET /cases/{case_id}` | Reads one case. |
| Cases | `POST /cases/{case_id}/seal` | Reviewer/admin sets status sealed. |
| Evidence | `GET /cases/{case_id}/evidence` | Case evidence list. |
| Evidence | `POST /evidence` | Multipart proof ingest: file, case ID, label, kind, notes, source identifier. |
| Evidence | `GET /evidence/{evidence_id}` | Reads evidence metadata. |
| Evidence | `POST /evidence/{evidence_id}/verify` | Rehashes and records verified/compromised state. |
| Evidence | `POST /evidence/{evidence_id}/analyze` | Creates/enqueues job (202); blocks compromised or concurrent job. |
| Evidence | `GET /evidence/{evidence_id}/artifacts?limit=1..5000` | Extracted artifact inventory/labels. |
| Jobs | `GET /jobs?status=&limit=1..500` | Jobs, optionally status filtered. |
| Jobs | `GET /jobs/{job_id}` | Job with findings/review. |
| Jobs | `POST /jobs/{job_id}/review` | Reviewer/admin creates/updates review and job state. |
| Jobs | `GET /jobs/{job_id}/report` | Generates and downloads an eligible PDF. |
| Artifacts | `PUT /artifacts/{artifact_id}/ground-truth` | Reviewer/admin assigns benign/malicious label. |
| Models | `GET /models` | Version list. |
| Models | `POST /models/train` | Reviewer/admin trains/activates RandomForest. |
| Audit | `GET /audit?limit=1..2000` | Reviewer/admin event list, newest first. |
| Audit | `GET /audit/verify` | Reviewer/admin full chain verification. |

## 13. Background workers and scheduled jobs

`worker.py` defines one Celery task, `micepp.analyze_evidence(job_id)`, which calls `run_analysis`. Redis is both broker and result backend. Messages/results are JSON, timezone UTC; tasks are late-acked, prefetch is one, worker loss rejects tasks, and visibility timeout is 21,600 seconds. Compose starts two concurrent workers.

There is no Celery Beat service, `beat_schedule`, cron definition, application scheduler, or recurring application job. Freshclam checks are configured by the external ClamAV image at 12 checks/day. UI polling is client-side query refetching, not a scheduled backend job.

## 14. Scan workflow: creation to notification

In implemented terms this is an **evidence-analysis** workflow:

```text
open case → upload evidence → hashes/original persisted → queue job
→ worker validates original → working extraction → per-artifact analyses
→ scores/consolidation → awaiting_review → expert review → PDF on request
```

Evidence starts `ingested`. A manual verification marks it `verified` or `compromised`; the worker repeats verification, then marks it `analyzing`. Successful completion marks evidence `analyzed` and job `awaiting_review`; an integrity failure marks evidence `compromised` and job `failed`; other exceptions return non-compromised evidence to `ingested` and mark the job failed. Reviews set job to `approved`, `rejected`, or remain `awaiting_review` for more analysis. Re-review is permitted from awaiting-review, approved, and rejected states.

There is no notification system: no email, webhook, SMS, websocket/SSE, push notification, notification table, or alert dispatcher. The UI makes state visible through 10-second job/dashboard polls and 3-second active-job polling.

## 15. Vulnerability workflow

No Nmap, WhatWeb, CPE, CVE, NVD, OSV, or equivalent dependency/vulnerability API appears in source, requirements, Docker configuration, or tests. Consequently there is no asset/port/service discovery, CPE generation, CVE matching, NVD/OSV lookup, vulnerability persistence, severity correlation, or vulnerability notification implementation.

Implemented malware/forensic workflow:

1. Extract one or more artifacts from file/archive/image evidence.
2. Derive base features from up to 4 MiB: entropy, printable ratio, ASCII strings, URLs, IPs, sensitive terms, type flags and later engine results.
3. Determine MIME with libmagic; inspect PE structure/imports/section entropy, Office VBA macros, and PDF active tokens.
4. Send artifacts to ClamAV; an exact `FOUND` result yields severity 100. Run all `*.yar`/`*.yara` rules; local rules detect PowerShell downloader patterns, PE process-injection primitives, Office auto-execution strings, and risky system-tool combinations.
5. Use the active RandomForest, if any, to predict malicious probability and create an ML finding at >=0.5.
6. If static score reaches threshold, or artifact is executable/script/has macros, submit it to CAPE; at most 20 artifacts/job. CAPE creates a file task, polls task state, gets report, records score/signatures/network summary/process count, and maps signatures to findings.
7. Consolidate maximum static/ML/CAPE score: >=80 malicious, 45–79 suspicious, otherwise benign; if sandbox was requested but none completed and score 45–79, verdict is inconclusive.

## 16. Logging system

The application defines no Python `logging.getLogger`, structured application log sink, log formatter, log-retention policy, centralized log transport, or dedicated logging configuration. Operational logs are therefore process/container output: Uvicorn/FastAPI and Celery are invoked at their standard levels (`worker --loglevel=INFO`), and Docker exposes them through `docker compose logs`. Alembic’s `alembic.ini` configures console logging at WARN for root/SQLAlchemy and INFO for Alembic.

The persistent audit system is separate from logging and is described next.

## 17. Audit system

Every sensitive implemented action uses `append_event` within the caller’s database session: bootstrap admin creation, login, user/case/evidence creation, integrity outcomes, analysis queue/start/completion/failure, reviews, artifact labels, model training, and PDF generation.

The event includes actor, action, target type/ID, JSON payload, UTC timestamp, previous hash, and event HMAC. The canonical input is sorted compact UTF-8 JSON. The first `previous_hash` is 64 zeros. On PostgreSQL, an advisory transaction lock plus `with_for_update()` serializes writers so two events cannot take the same predecessor. `verify_chain()` recomputes HMACs in sequence order and reports count and first invalid event hash. The audit endpoint and PDF report invoke verification. The report includes events whose target ID is the case, evidence, or job ID.

## 18. Notification system

No notification subsystem is implemented. There are no notification models/endpoints/services, email/SMS/push/webhook packages, destination settings, scheduler/worker notification task, or notification templates. The only related behavior is React Query polling and user-visible error/status panels.

## 19. Frontend architecture

The frontend is a compact single-file UI architecture: `src/App.tsx` contains pages and reusable components, `api.ts` contains HTTP/auth/download helpers, `types.ts` mirrors API data, `main.tsx` wires providers, and `styles.css` contains styling. It does not use Redux, component folders, code splitting, or route-specific modules.

Routes: `/` dashboard; `/cases`; `/cases/:caseId`; `/jobs`; `/jobs/:jobId`; `/models`; `/audit`; wildcard redirects home. The audit route is client-hidden/redirected for analyst users. Pages provide login, navigation/layout, dashboard, case creation/evidence upload, job list/detail, finding display, artifact labeling, review, PDF download, model training/listing, and audit list/verification. Lucide icons and custom CSS form the UI.

Vite development proxies `/api` and `/health` to `http://localhost:8000`; production Nginx serves `dist`, proxies those paths to Docker service `api`, and falls back to `index.html` for browser routes.

## 20. State management

Server state is TanStack React Query. `QueryClient` uses 10-second stale time, one retry, and no refetch on window focus. Queries are keyed by resource; mutations call the API then invalidate affected keys. Recent jobs and jobs list poll every 10 seconds; a job detail polls every three seconds only while queued/running. Local component `useState` holds form inputs, login form, mobile menu state, filters, review decision/comments, and UI error/busy flags. The only durable client state is the JWT in `localStorage`; no other persisted store exists.

## 21. Error handling

FastAPI supplies status-specific errors: 401 for invalid credentials/session, 403 for insufficient role, 404 for missing entities, 409 for conflicts/state/integrity/training constraints, 413 for oversized uploads, and 503 when queuing fails. Pydantic/FastAPI handle malformed inputs and field bounds. Unique constraint failures on username/case reference are converted to 409 after rollback.

The upload routine cleans partial file/directory on failure. Extraction cleans its whole work directory on an exception. Static engine exceptions become metadata errors/low-severity availability findings, not fabricated detections. CAPE unavailability is accumulated into an availability finding. Unexpected pipeline exceptions roll back current changes, then persist job failure with a truncated traceback in audit payload. Nginx provides 429 on login-rate excess. The frontend’s `request()` parses API JSON detail where possible, clears JWT on 401, throws `ApiError`, and page components render error boxes.

## 22. Testing architecture

Backend tests use pytest with FastAPI `TestClient`, an in-memory/static-pool SQLite URL, temporary evidence/work/report/model directories, and bootstrap test admin credentials. The autouse fixture drops/recreates schema and bootstraps an admin for each test.

- `test_api.py`: case creation, multipart evidence upload, hash verification, audit verification, duplicate-case conflict.
- `test_audit.py`: valid chain and tampering detection.
- `test_storage.py`: filename/path guards, deterministic hashes/features, and individual-file work-copy extraction.

`requirements-dev.txt` additionally declares `pytest-cov` and Ruff. The configured commands are `pytest -q` and `ruff check app tests migrations`. No frontend unit/integration/e2e test files, test scripts, browser automation, Docker Compose test profile, or CI workflow exists in the repository.

## 23. Build process

Backend image: `python:3.13-slim-bookworm` installs runtime OS dependencies, installs pinned `requirements.txt`, copies application/migrations/rules, creates writable roots, changes ownership to UID 10001, and starts via `tini` and Uvicorn.

Frontend image has two stages: Node 24 Alpine enables Corepack, runs `pnpm install --frozen-lockfile`, copies sources, runs `pnpm build` (`tsc -b && vite build`), then Nginx Alpine receives `/app/dist` and config. TypeScript is strict/no-emit in source configs. `pnpm typecheck` is also `tsc -b --pretty false`. Compose builds each context during `up --build`.

## 24. Startup sequence

1. Bootstrap scripts create `.env` only when absent, using OS cryptographic random generation; they preserve an existing `.env`.
2. Script validates Compose config and starts with `up -d --build --wait --wait-timeout 1800` (PowerShell accepts `-NoBuild`).
3. Database and Redis health checks succeed; migration runs `alembic upgrade head`.
4. API/worker start after migration. API lifespan validates production secrets, ensures roots exist, creates mapped tables (idempotently), and creates the bootstrap admin if eligible.
5. Worker waits for ClamAV health; web waits for API liveness. The script calls `/health/ready` and requires status `ok`.

## 25. Production deployment

Compose is the provided production deployment definition. Set production secrets rather than example placeholders; retain `BIND_ADDRESS=127.0.0.1` unless an organizational TLS reverse proxy controls public/intranet exposure. Only Nginx is host-exposed. CAPE must be deployed separately on an isolated sandbox network and configured by URL/token. ClamAV has the dedicated `updates` network for signature updates.

Persistent named volumes are PostgreSQL data, Redis data/AOF, ClamAV database, evidence originals, work area, reports, and models. Backup scripts require running `database` and `api`, create a PostgreSQL custom-format dump plus tarballs for evidence/reports/models, and write SHA-256 manifests. No restore automation, TLS termination/certificates, external secret manager integration, monitoring stack, image digest pinning, orchestration manifests, or CI/CD configuration is present.

## 26. Configuration files

| File | Function |
|---|---|
| `docker-compose.yml` | Services, networks, volumes, backend environment, health checks, startup dependencies, security options, port mapping. |
| `.env.example` | Template deployment values and operational limits. `.env` is local/ignored and is not documented here for its secret values. |
| `backend/Dockerfile` | Backend runtime build/user/entrypoint. |
| `frontend/Dockerfile` | Vite build and hardened non-root Nginx image. |
| `frontend/nginx.conf` | SPA serving, API proxy, auth rate limit, security headers, proxy/body limits. |
| `backend/alembic.ini` | Alembic location/default URL and console log configuration. |
| `backend/migrations/env.py` | Reads application DB URL and target metadata for online/offline migration. |
| `backend/migrations/versions/0001_initial.py` | Initial schema create/drop from SQLAlchemy metadata. |
| `frontend/vite.config.ts` | React plugin and local API/health proxy. |
| `frontend/tsconfig*.json` | Root/project-reference, application strict compilation and Vite config typing. |
| `frontend/package.json` / lockfile/workspace | Pinned frontend dependencies, package manager and commands. |
| `backend/requirements*.txt` | Pinned runtime/development Python dependencies. |
| `backend/rules/micepp_core.yar` | Four local detection rules. |
| `.gitignore` / `.dockerignore` files | Exclude secrets, environments, generated assets/data, tests/logs as applicable. |
| `scripts/bootstrap.*` | Cross-platform secret generation/start/ready check. |
| `scripts/backup.*` | Cross-platform dump/volume backup/hash manifest. |
| `README.md`, `SECURITY.md`, `docs/ARCHITECTURE.md` | Existing operational, security, and architecture documentation. |

## 27. External APIs and services

| External interface | Use |
|---|---|
| CAPE/Cuckoo v2-compatible API | Optional `POST /apiv2/tasks/create/file/`, polling `GET /apiv2/tasks/view/{id}/`, report `GET /apiv2/tasks/get/report/{id}/`, then fallback `GET /tasks/report/{id}`. Uses `Authorization: Token <CAPE_API_TOKEN>` when configured. |
| ClamAV clamd TCP protocol | `ClamdNetworkSocket` scans each artifact at configured host/port. |
| PostgreSQL | SQLAlchemy/psycopg persistence. |
| Redis | Celery broker/result backend; FastAPI readiness ping. |

There are no NVD, OSV, CVE, CPE, Nmap, WhatWeb, mail, chat, webhook, cloud-storage, identity-provider, or third-party analytics API integrations.

## 28. Important design patterns

- **Layered service boundaries:** frontend API client; FastAPI routers/dependencies; persistence/analyzers/pipeline/report services.
- **Dependency injection:** FastAPI injects database sessions and current/role-authorized users.
- **Repository/ORM model:** SQLAlchemy mapped entities and relationship navigation.
- **Pipeline/orchestrator:** `run_analysis` coordinates integrity, extraction, static, ML, sandbox, and consolidation stages.
- **Strategy-like analyzers:** separate extraction/static/ML/CAPE modules return normalized findings/metadata.
- **Append-only tamper-evident ledger:** event chaining with HMAC and serialized appends.
- **Command/message queue:** API persists a job, then asks Celery to execute it asynchronously.
- **Configuration object:** cached Pydantic `Settings` centralizes environment settings.
- **Human-in-the-loop ML:** only reviewer/admin labels feed training; activation flips existing active versions off before enabling new version.
- **Defensive file handling:** containment check, filename normalization, atomic upload rename, multiple hashes, extraction quotas.

## 29. ASCII sequence diagrams

### Authentication

```text
Browser             Nginx              FastAPI              PostgreSQL
  | POST token        |                    |                      |
  |------------------>| proxy/rate limit   |                      |
  |                   |------------------->| lookup + Argon2      |
  |                   |                    |--------------------->|
  |                   |                    |<---------------------|
  |                   |                    | audit login + JWT     |
  |<------------------|<-------------------|                      |
  | localStorage JWT  |                    |                      |
```

### Evidence submission and analysis

```text
Browser → Nginx → API → evidence volume
                    | stream upload; hashes; chmod; metadata/audit
                    v
                 PostgreSQL ← API commits evidence/job
                    ^
                    |                         API → Redis → Celery worker
                    |                                           |
                    |                      rehash original / extract work copy
                    |                                           |
                    |              ClamAV, YARA, PE/Office/PDF, ML, optional CAPE
                    |                                           |
                    └──── artifacts/findings/status/audit ←─────┘
Browser ← polls API ← job awaiting_review / reviewer decision
```

### Audit append and verification

```text
Mutating operation → append_event → PostgreSQL advisory transaction lock
                                      → lock/read last event
                                      → canonical JSON + HMAC(previous hash)
                                      → insert event → commit

Verifier → ordered events → compare previous hash and recomputed HMAC → valid / first invalid hash
```

### CAPE analysis

```text
Worker → CAPE: create/file upload
Worker ← CAPE: task ID
loop until deadline:
  Worker → CAPE: task view
  Worker ← CAPE: pending/reported/failed
Worker → CAPE: report (v2, then legacy fallback on 404)
Worker ← CAPE: score, signatures, network, behavior
Worker → PostgreSQL: artifact metadata and behavior findings
```

## 30. TODO, FIXME, and incomplete features

Exact-text search over repository source/configuration (excluding lockfiles and DOCX) found **no `TODO`, `FIXME`, or `XXX` markers**. The `pass` occurrences are empty class bodies for `Base`, `ExtractionError`, and `CapeUnavailable`, plus deliberate `OSError` handling; they are not TODOs.

Repository-observable unimplemented/absent capabilities relevant to the requested categories:

- No network-vulnerability scanning or Nmap/WhatWeb/CPE/CVE/NVD/OSV workflow.
- No notification delivery mechanism; polling only.
- No scheduled application jobs/Celery Beat.
- No frontend automated tests or CI pipeline.
- No user-management UI, despite admin user API endpoints.
- No case closing API/UI even though `closed` exists in `CaseStatus`.
- No evidence/original download endpoint or deletion endpoints.
- No explicit progress database field, although `pipeline.py` assigns `job.progress = 100` in the integrity-failure branch; `AnalysisJob` has no mapped `progress` column and the API schema exposes none.
- No explicit artifact cleanup lifecycle after analysis; work files persist in `WORK_ROOT` until extraction of the same job removes/recreates its work directory.
- No automated restore implementation; security documentation describes manual restoration.
- No TLS certificates or reverse-proxy configuration beyond Nginx HTTP binding; production TLS is delegated to an external organizational proxy.
- No token refresh/revocation/logout server endpoint, MFA, password reset, account deactivation endpoint, or authorization scoped by case ownership/classification.
- No migration diff history beyond an initial metadata-create migration.

