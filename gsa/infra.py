"""Identify hosting provider (live fingerprint + repo config) and database provider."""
from __future__ import annotations

import re
import socket
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

from .util import iter_files, read_text, rel, log

HOST_HEADERS = [
    ("x-vercel-id", None, "Vercel"), ("server", r"^Vercel", "Vercel"),
    ("x-nf-request-id", None, "Netlify"), ("server", r"Netlify", "Netlify"),
    ("cf-ray", None, "Cloudflare (proxy/CDN)"), ("server", r"cloudflare", "Cloudflare (proxy/CDN)"),
    ("fly-request-id", None, "Fly.io"), ("server", r"Fly/", "Fly.io"),
    ("x-render-origin-server", None, "Render"), ("rndr-id", None, "Render"),
    ("x-railway-request-id", None, "Railway"), ("server", r"railway", "Railway"),
    ("via", r"vegur", "Heroku"), ("server", r"heroku", "Heroku"),
    ("x-amz-cf-id", None, "AWS CloudFront"), ("x-amzn-requestid", None, "AWS (API Gateway/Lambda)"),
    ("x-amz-apigw-id", None, "AWS API Gateway"), ("server", r"AmazonS3", "AWS S3"), ("server", r"awselb", "AWS ELB"),
    ("x-cloud-trace-context", None, "Google Cloud"), ("server", r"Google Frontend", "Google Cloud (App Engine/Cloud Run)"),
    ("x-goog-generation", None, "Google Cloud Storage"),
    ("x-azure-ref", None, "Azure Front Door"), ("x-ms-request-id", None, "Microsoft Azure"),
    ("x-github-request-id", None, "GitHub Pages"), ("x-served-by", r"cache-", "Fastly CDN"),
    ("x-firebase-hosting", None, "Firebase Hosting"), ("server", r"DigitalOcean|do-app", "DigitalOcean App Platform"),
    ("x-powered-by", r"Next\.js", "Next.js (framework)"), ("x-supabase-api-version", None, "Supabase"),
    ("x-deno-ray", None, "Deno Deploy"), ("server", r"openresty", "OpenResty/Nginx"), ("server", r"nginx", "Nginx"),
]

HOST_FILES = {
    "vercel.json": "Vercel", ".vercel": "Vercel", "netlify.toml": "Netlify", "fly.toml": "Fly.io", "render.yaml": "Render",
    "railway.json": "Railway", "railway.toml": "Railway", "Procfile": "Heroku (or Procfile-compatible)", "app.json": "Heroku",
    "app.yaml": "Google App Engine", "cloudbuild.yaml": "Google Cloud Build", "firebase.json": "Firebase",
    "wrangler.toml": "Cloudflare Workers/Pages", "serverless.yml": "AWS Lambda (Serverless Framework)",
    "amplify.yml": "AWS Amplify", "apprunner.yaml": "AWS App Runner", "Dockerfile": "Container (Docker)",
    "docker-compose.yml": "Docker Compose", "docker-compose.yaml": "Docker Compose", "azure-pipelines.yml": "Azure",
    ".do/app.yaml": "DigitalOcean App Platform", "zeabur.json": "Zeabur", "now.json": "Vercel (legacy)",
}

DB_PATTERNS = [
    (r"[\w\-\.]+\.neon\.tech", "Neon (Postgres)"),
    (r"[\w\-\.]+\.supabase\.(co|com)|supabase", "Supabase (Postgres)"),
    (r"psdb\.cloud|planetscale", "PlanetScale (MySQL)"),
    (r"[\w\-\.]+\.rds\.amazonaws\.com", "AWS RDS"),
    (r"dynamodb|DynamoDB", "AWS DynamoDB"),
    (r"[\w\-\.]+\.mongodb\.net|mongodb\+srv://", "MongoDB Atlas"),
    (r"mongodb://", "MongoDB (self-hosted)"),
    (r"firestore|firebaseio\.com", "Firebase Firestore/RTDB"),
    (r"[\w\-\.]+\.upstash\.io", "Upstash (Redis/Kafka)"),
    (r"redis(s)?://[^\s'\"]*redislabs|redis-cloud|\.redns\.redis-cloud\.com", "Redis Cloud"),
    (r"cockroachlabs\.cloud", "CockroachDB Cloud"),
    (r"turso\.io|libsql://", "Turso (libSQL)"),
    (r"database\.windows\.net|cosmos\.azure\.com", "Azure SQL/Cosmos DB"),
    (r"cloudsql|/cloudsql/|sqladmin\.googleapis", "Google Cloud SQL"),
    (r"railway\.app|rlwy\.net", "Railway (managed DB)"),
    (r"dpg-[\w\-]+\.\w+-postgres\.render\.com|render\.com", "Render Postgres"),
    (r"aivencloud\.com", "Aiven"),
    (r"xata\.sh", "Xata"),
    (r"fauna\.com|faunadb", "Fauna"),
    (r"elephantsql", "ElephantSQL"),
    (r"herokupostgres|compute-1\.amazonaws\.com:5432", "Heroku Postgres"),
    (r"POSTGRES_URL|@vercel/postgres", "Vercel Postgres (Neon)"),
    (r"@vercel/kv|KV_REST_API_URL", "Vercel KV (Upstash)"),
    (r"d1_databases|\bD1Database\b", "Cloudflare D1"),
    (r"convex\.cloud|convex/", "Convex"),
    (r"pocketbase", "PocketBase"),
    (r"localhost:5432|127\.0\.0\.1:5432|@db:5432|@postgres:5432", "Postgres (local/container)"),
    (r"localhost:3306|@mysql:3306|@db:3306", "MySQL (local/container)"),
    (r"sqlite3?:|\.sqlite3?\b|db\.sqlite3", "SQLite (file)"),
]

DB_ENGINES = [
    (r"postgres|psycopg|\bpg\b|django\.db\.backends\.postgresql|provider\s*=\s*\"postgresql\"", "PostgreSQL"),
    (r"mysql|mariadb|provider\s*=\s*\"mysql\"", "MySQL/MariaDB"),
    (r"sqlite", "SQLite"),
    (r"mongo", "MongoDB"),
    (r"redis", "Redis"),
    (r"sqlserver|mssql", "SQL Server"),
    (r"dynamodb", "DynamoDB"),
    (r"firestore", "Firestore"),
]


def hosting(target_url: Optional[str], root: Path, use_external: bool = True) -> dict:
    out: Dict = {"providers": [], "evidence": [], "ip": None, "asn": None, "repo_config": []}
    votes = defaultdict(int)
    for f in iter_files(root, names=set(k.split("/")[-1] for k in HOST_FILES)):
        r = rel(root, f).replace("\\", "/")
        prov = HOST_FILES.get(r) or HOST_FILES.get(f.name)
        if prov:
            out["repo_config"].append({"file": r, "provider": prov})
            votes[prov] += 1
    for f in iter_files(root, {".yml", ".yaml"}):
        if ".github/workflows" in str(f).replace("\\", "/"):
            t = read_text(f)
            for rx, prov in [(r"amondnet/vercel-action|vercel deploy|vercel --prod", "Vercel"), (r"netlify", "Netlify"),
                             (r"flyctl|superfly", "Fly.io"), (r"aws-actions|aws s3|aws ecs", "AWS"), (r"google-github-actions|gcloud", "Google Cloud"),
                             (r"azure/", "Azure"), (r"heroku", "Heroku"), (r"railway", "Railway"), (r"cloudflare/wrangler", "Cloudflare")]:
                if re.search(rx, t, re.I):
                    out["repo_config"].append({"file": rel(root, f), "provider": prov})
                    votes[prov] += 1
    if target_url:
        host = urlparse(target_url).hostname
        try:
            r = requests.get(target_url, timeout=10, allow_redirects=True)
            h = {k.lower(): v for k, v in r.headers.items()}
            for hk, rx, prov in HOST_HEADERS:
                if hk in h and (rx is None or re.search(rx, h[hk], re.I)):
                    out["evidence"].append(f"{hk}: {h[hk][:80]}")
                    votes[prov] += 3
        except Exception as e:
            out["evidence"].append(f"fetch failed: {type(e).__name__}")
        try:
            out["ip"] = socket.gethostbyname(host)
        except Exception:
            pass
        if host and re.search(r"\.vercel\.app$", host): votes["Vercel"] += 3
        if host and re.search(r"\.netlify\.app$", host): votes["Netlify"] += 3
        if host and re.search(r"\.herokuapp\.com$", host): votes["Heroku"] += 3
        if host and re.search(r"\.fly\.dev$", host): votes["Fly.io"] += 3
        if host and re.search(r"\.onrender\.com$", host): votes["Render"] += 3
        if host and re.search(r"\.up\.railway\.app$", host): votes["Railway"] += 3
        if host and re.search(r"\.pages\.dev$|\.workers\.dev$", host): votes["Cloudflare Workers/Pages"] += 3
        if host and re.search(r"\.web\.app$|\.firebaseapp\.com$", host): votes["Firebase"] += 3
        if host and re.search(r"\.run\.app$|\.appspot\.com$", host): votes["Google Cloud (App Engine/Cloud Run)"] += 3
        if host and re.search(r"\.azurewebsites\.net$", host): votes["Microsoft Azure"] += 3
        if out["ip"] and use_external and not out["ip"].startswith(("127.", "10.", "192.168.", "172.")):
            try:
                j = requests.get(f"https://ipinfo.io/{out['ip']}/json", timeout=8).json()
                out["asn"] = j.get("org")
                out["geo"] = ", ".join(x for x in (j.get("city"), j.get("country")) if x)
                org = (j.get("org") or "").lower()
                for kw, prov in [("amazon", "AWS"), ("google", "Google Cloud"), ("microsoft", "Microsoft Azure"), ("cloudflare", "Cloudflare (proxy/CDN)"),
                                 ("digitalocean", "DigitalOcean"), ("hetzner", "Hetzner"), ("ovh", "OVH"), ("linode", "Akamai/Linode"),
                                 ("fastly", "Fastly CDN"), ("vercel", "Vercel"), ("fly.io", "Fly.io")]:
                    if kw in org:
                        votes[prov] += 2
            except Exception:
                pass
        elif out["ip"] and out["ip"].startswith("127."):
            votes["Local (localhost)"] += 5
    out["providers"] = [{"name": k, "confidence": min(100, v * 20)} for k, v in sorted(votes.items(), key=lambda x: -x[1])]
    out["primary"] = out["providers"][0]["name"] if out["providers"] else "Unknown"
    return out


def database(root: Path) -> dict:
    providers = defaultdict(set)
    engines = defaultdict(set)
    exts = {".py", ".js", ".ts", ".mjs", ".json", ".toml", ".yaml", ".yml", ".prisma", ".rb", ".go", ".java", ".properties", ".env", ".example", ".tf", ".php", ".cs", ".ini", ".cfg", ".xml"}
    env_names = {".env", ".env.example", ".env.local", ".env.sample", ".env.template", ".env.production", ".env.development", "settings.py", "database.yml"}
    for f in list(iter_files(root, exts)) + list(iter_files(root, names=env_names)):
        if f.name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            continue
        text = read_text(f)
        if not text:
            continue
        r = rel(root, f)
        for rx, prov in DB_PATTERNS:
            if re.search(rx, text, re.I):
                providers[prov].add(r)
        if re.search(r"DATABASE|DB_|datasource|ENGINE|createClient|connect\(|create_engine|mongoose|knex|sequelize|typeorm|drizzle", text, re.I):
            for rx, eng in DB_ENGINES:
                if re.search(rx, text, re.I):
                    engines[eng].add(r)
    prov_list = [{"name": k, "files": sorted(v)[:15]} for k, v in sorted(providers.items(), key=lambda x: -len(x[1]))]
    # prefer managed providers over local/file
    managed = [p for p in prov_list if "local" not in p["name"] and "file" not in p["name"]]
    return {
        "providers": prov_list,
        "engines": [{"name": k, "files": sorted(v)[:15]} for k, v in sorted(engines.items(), key=lambda x: -len(x[1]))],
        "primary": (managed or prov_list or [{"name": "Unknown"}])[0]["name"],
    }
