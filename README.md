# google-security-audit (`gsa`)

A local security harness you point at **a project you're allowed to test**. It reads the code, finds every
endpoint, sends realistic requests to the app while it runs on your machine, fuzzes the inputs, maps the database
schema, lists the third-party software each folder uses, and works out where the app and its database are hosted.

```
gsa scan <project folder> <address of the running app>
gsa scan ~/Desktop/myapp http://localhost:3000
```

> Only scan projects you own or have permission to test. Run the app locally (or on staging), not against production.

---

## 1. Install (one time)

You need **Python 3.9+**, **Git** and **Google Chrome**.

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/Algebras/google-security-audit/main/install.sh | bash
```

Check it worked with `gsa --version`. If you see `command not found`, open a new terminal, or use
`python3 -m gsa` wherever this guide says `gsa`.

### Windows (PowerShell)

```powershell
py -m pip install --user "google-security-audit[browser] @ git+https://github.com/Algebras/google-security-audit.git"
py -m playwright install chromium
```

Check it worked with `py -m gsa --version`. On Windows, use `py -m gsa` wherever this guide says `gsa`.

---

## 2. Run a scan

### Step 1: Clone the project you want to test

```bash
git clone https://github.com/your-org/your-app.git
cd your-app
```

### Step 2: Copy the project's folder location

| OS | How |
|---|---|
| macOS | In Terminal inside the folder run `pwd`, or right-click the folder in Finder, hold **Option**, and choose **Copy "your-app" as Pathname** |
| Linux | In the terminal inside the folder run `pwd` |
| Windows | In PowerShell inside the folder run `(Get-Location).Path`, or **Shift + right-click** the folder in Explorer and choose **Copy as path** |

Example results:
- macOS: `/Users/alex/Desktop/your-app`
- Linux: `/home/alex/projects/your-app`
- Windows: `C:\Users\alex\Desktop\your-app`

### Step 3: Start the app's local server

Open a **second** terminal window, go to the same folder, and start the app the way you normally would. For example:

| Stack | Typical command |
|---|---|
| Node / Next.js / Vite / Express | `npm install` then `npm run dev` (or `npm start`) |
| Django | `python manage.py runserver` |
| Flask | `flask run` |
| FastAPI | `uvicorn main:app --reload` |
| Rails | `bin/rails server` |
| Go | `go run .` |

Leave this window running while you scan.

### Step 4: Copy the address the server prints

The server prints the address it's running on, for example:

```
  ➜  Local:   http://localhost:3000/
```

Copy that address (`http://localhost:3000`). You can check it by opening it in your browser.

### Step 5: Run the scan

Go back to your **first** terminal and run `gsa scan`, then the folder location from Step 2, then the address from Step 4.

**macOS**
```bash
gsa scan /Users/alex/Desktop/your-app http://localhost:3000
```

**Linux**
```bash
gsa scan /home/alex/projects/your-app http://localhost:3000
```

**Windows (PowerShell)**
```powershell
py -m gsa scan "C:\Users\alex\Desktop\your-app" http://localhost:3000
```

Shortcuts that also work:

```bash
gsa scan ~/Desktop/your-app localhost:3000      # "http://" is added for you
gsa scan Desktop/your-app http://localhost:3000 # paths relative to your home folder
gsa scan . http://localhost:8000                # when you're already inside the project folder
gsa scan ~/Desktop/your-app                     # code-only scan, no running server needed
```

> Put the folder in quotes if it contains spaces: `gsa scan "/Users/alex/My Projects/your-app" http://localhost:3000`

### Step 6: Log in when asked (only if the app needs it)

If parts of the app need you to be logged in, gsa asks:

```
Some endpoints need auth. Open a browser to log in? [Y/n]
```

Press **Enter**. A Chrome window opens on the app. Log in as you normally would (including MFA), then come
back to the terminal and press **Enter** again. gsa reads the session the same way you would in Chrome DevTools →
**Application → Cookies / Local Storage**, uses it only while it scans, and removes it from the report.

If your login page isn't the home page, give its address too:

```bash
gsa scan ~/Desktop/your-app http://localhost:3000 --login-url http://localhost:3000/login
```

When the scan finishes, the terminal shows a summary of what was found.

---

## What it checks

| Area | How |
|---|---|
| **Endpoint discovery** | Express/Koa/Fastify/Hono, Next.js (pages + app router), Flask, FastAPI, Django + DRF routers, Rails, Spring, Go (net/http, gin, echo, chi), Laravel, OpenAPI/Swagger files, front-end `fetch`/`axios` calls, and live `/openapi.json`-style specs. |
| **Realistic requests** | Reads each handler (`req.body.x`, `request.json.get("x")`, pydantic models, `params.permit`, …) and fills the fields with sensible values (emails, UUIDs, dates, amounts…), using each endpoint's real method (POST/PUT/PATCH with JSON bodies). |
| **Fuzzing** | SQL injection (error, boolean, time-based), NoSQL injection, XSS, template injection, command injection, path traversal, SSRF, wrong types, very long / unicode / control-character input. `--fuzz-level 3` adds SecLists if it's in `~/SecLists`. |
| **Access control** | Repeats logged-in requests without the session to find endpoints that leak data. |
| **Input fields & rate limits** | Finds `<input>`/`<textarea>` limits in the front-end, tests server-side length limits and special characters, sends quick bursts to login/signup endpoints to see if they're ever throttled, and looks for rate-limit middleware in the code. |
| **Database schema** | `.sql` files, Prisma, Django, SQLAlchemy/SQLModel, Rails `schema.rb`, Drizzle, TypeORM, Mongoose, plus tables inferred from API responses. |
| **Third-party software** | Every manifest (npm, pip/poetry/pipenv, Go, Ruby, Cargo, Composer, Maven/Gradle), which folder it's in, **which folders import each package**, SaaS integrations (Stripe, Sentry, Supabase, Auth0, OpenAI…), and known vulnerabilities via [OSV.dev](https://osv.dev). |
| **Hosting & database provider** | Response headers, DNS/ASN, deploy configs (vercel.json, fly.toml, Procfile, wrangler.toml…) and connection strings (Neon, Supabase, RDS, PlanetScale, Atlas, Upstash…). |
| **Extras** | Security headers, CORS, cookie flags, exposed `.env`/`.git`/actuator paths, hardcoded secrets (masked). |

## Inspired by

google-security-audit borrows ideas from these projects:

| Project | What we took from it |
|---|---|
| [Arachni](https://github.com/Arachni/arachni) | Crawling an app's endpoints and fuzzing every input of a running instance (DAST). |
| [Cloudflare Security Audit Skill](https://github.com/cloudflare/security-audit-skill) | A multi-phase, adversarial security review of a codebase. |
| [CodeQL](https://github.com/github/codeql) | Reading source code to trace where user input flows (routes, handlers, models) rather than only probing from outside. |
| [GitHub audit logs](https://github.com/github/docs/blob/main/content/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization.md) | Recording who did what and when: every scan is attributed to a person, a time and a repo. |

## Privacy & safety

- Each scan is labelled with **the username of the laptop that ran it**, the date and time, and the project folder's name.
- Cookies and tokens captured at login are used only while the scan runs. Before anything leaves your machine, every captured value — and anything that looks like a JWT, bearer token, session cookie, API key or database password — is replaced with `[REDACTED]`. Secrets found in the code are masked (`sk_liv…3xQ`).
- `DELETE` requests are skipped unless you add `--allow-destructive`. Requests are paced (`--rps`, default 10) and capped (`--max-requests`).
- Addresses that aren't on your own machine ask you to confirm you're allowed to test them.

## Options

```
gsa scan FOLDER [URL]
    --login-url URL          page to open for logging in (default: URL)
    --login auto|browser|manual|never
    --cookie "name=value"    use an existing session instead of logging in
    -H "Name: value"         extra header (repeatable)
    --fuzz-level 0-3         0 = no fuzzing, 3 = adds SecLists (default 2)
    --rps N                  max requests per second (default 10)
    --max-requests N         total request cap (default 6000)
    --allow-destructive      also send DELETE requests
    --insecure               skip TLS certificate checks
    --no-external            skip OSV.dev and ipinfo.io lookups
    --no-upload              keep the results on this machine only
    --note "text"            attach a note to the scan
    -y                       skip the "are you authorized" prompt
```

## Develop

```bash
pip install -e . pytest && pytest
python tests/fixture_app/app.py                       # deliberately vulnerable demo on :5055
gsa scan tests/fixture_app http://127.0.0.1:5055 --login-url http://127.0.0.1:5055/login --no-upload
```

MIT licensed.
