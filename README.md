# google-security-audit (`gsa`)

A local security harness you point at **any repo you're allowed to test**. It reads the code, finds every
endpoint, hits a running instance with realistic requests, fuzzes the inputs, maps the database schema,
inventories third-party software, works out where the app and its database are hosted — and **auto-uploads
the results** to the team dashboard when it finishes.

> Only scan systems you own or have explicit permission to test. Point `--target` at a local or staging
> instance, not production, unless you've cleared it.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Algebras/google-security-audit/main/install.sh | bash
```

Or manually: `pip install "google-security-audit[browser] @ git+https://github.com/Algebras/google-security-audit.git" && playwright install chromium`.
Python 3.9+.

## Run

```bash
# static + live (recommended): start the app locally first
gsa scan ~/code/my-app --target http://localhost:3000

# a remote repo, static only
gsa scan https://github.com/org/repo.git

# already have a session? skip the browser
gsa scan . --target https://staging.example.com --cookie "sessionid=…" -H "Authorization: Bearer …"
```

Results upload automatically — no token or sign-up — and open at **https://local-scan-audit-results.vercel.app**
(team PIN required to view). Each scan is labelled with your laptop username, the date/time and the repo name. A copy is saved locally
as `gsa-report-<time>.json`. If the upload fails, the report is queued in `~/.gsa/pending/` — retry with `gsa upload <file>`.

## What it does

| Area | How |
|---|---|
| **Endpoint discovery** | Express/Koa/Fastify/Hono, Next.js (pages + app router), Flask, FastAPI, Django + DRF routers, Rails, Spring, Go (net/http, gin, echo, chi), Laravel, OpenAPI/Swagger files, front-end `fetch`/`axios` calls, and live `/openapi.json`-style specs. |
| **Parameter filling** | Reads handler bodies (`req.body.x`, `request.json.get("x")`, pydantic models, `params.permit`, …) and fills keys with type/name-aware values (emails, UUIDs, dates, amounts…). Sends each endpoint its real method (POST/PUT/PATCH with JSON bodies). |
| **Login** | If endpoints return 401/403 (or code shows auth guards), a browser opens (your Chrome if installed). Log in, press Enter, and gsa reads the session the same way you'd read DevTools → **Application → Cookies / Local Storage / Session Storage**: cookies, bearer/JWT tokens, CSRF tokens. `--login manual` walks you through pasting them instead. |
| **Fuzzing** | SQLi (error, boolean, time-based), NoSQLi, XSS reflection, SSTI, command injection, path traversal, SSRF, type confusion, overflow/unicode/control chars. `--fuzz-level 3` adds SecLists if found at `~/SecLists`. |
| **Access control** | Replays authenticated requests without credentials to spot endpoints that leak data. |
| **Input fields & rate limits** | Finds `<input>`/`<textarea>` constraints in the front-end, tests server-side length limits and special characters live, bursts auth endpoints to see if a 429 / `RateLimit-*` header ever appears, and checks for rate-limit middleware in code. |
| **Database schema** | `.sql` files, Prisma, Django, SQLAlchemy/SQLModel, Rails `schema.rb`, Drizzle, TypeORM, Mongoose, plus tables inferred from JSON responses. Rendered as an ER diagram. |
| **Third-party software** | Every manifest (npm, pip/poetry/pipenv, Go, Ruby, Cargo, Composer, Maven/Gradle) with the folder it lives in **and the folders that import each package**; SaaS integrations (Stripe, Sentry, Supabase, Auth0, OpenAI…); known CVEs via [OSV.dev](https://osv.dev). |
| **Hosting & DB provider** | Response headers, DNS/ASN (ipinfo.io), deploy configs (vercel.json, fly.toml, Procfile, wrangler.toml…) and connection strings (Neon, Supabase, RDS, PlanetScale, Atlas, Upstash…). |
| **Extras** | Security headers, CORS, cookie flags, exposed `.env`/`.git`/actuator paths, hardcoded secrets (masked). |

## Privacy & safety

- The report includes **who ran it** (OS username, full name, hostname) so the team knows whose scan it is.
- Captured cookies/tokens are used **only in memory** for the scan. Before saving/uploading, every captured
  value and anything that looks like a JWT, bearer token, session cookie, API key or DB password is replaced with `[REDACTED]`.
  Secrets found in the repo are stored masked (`sk_liv…3xQ`).
- `DELETE` requests are skipped unless you pass `--allow-destructive`. Requests are paced (`--rps`, default 10) and capped (`--max-requests`).
- Non-local targets require a typed confirmation (or `--yes`).
- `--no-upload` keeps everything local; `--no-external` skips OSV.dev and ipinfo.io lookups.

## Options

```
gsa scan REPO [--target URL] [--login-url URL] [--login auto|browser|manual|never]
              [--cookie STR] [-H "Name: value"]... [--fuzz-level 0-3] [--rps N]
              [--max-requests N] [--burst N] [--allow-destructive] [--insecure]
              [--no-osv] [--no-external] [--no-upload] [--out FILE] [--note TEXT] [-y]
gsa configure --endpoint URL     # only if you run your own dashboard; stored in ~/.gsa/config.json
gsa upload FILE
```

Env overrides: `GSA_ENDPOINT`, `SECLISTS`.

## Develop

```bash
pip install -e . pytest && pytest
python tests/fixture_app/app.py   # deliberately vulnerable demo on :5055
gsa scan tests/fixture_app --target http://127.0.0.1:5055 --login-url http://127.0.0.1:5055/login --no-upload
```

MIT licensed.
