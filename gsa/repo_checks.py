"""Static repo checks: hardcoded secrets, front-end input field constraints,
server-side validators and rate-limit middleware."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List

from .util import SOURCE_EXT, Context, iter_files, line_of, read_text, rel

SECRET_RULES = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key", "critical"),
    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS secret key", "critical"),
    (r"gh[pousr]_[A-Za-z0-9]{36,}", "GitHub token", "critical"),
    (r"github_pat_[A-Za-z0-9_]{60,}", "GitHub fine-grained token", "critical"),
    (r"sk_live_[0-9a-zA-Z]{20,}", "Stripe live secret key", "critical"),
    (r"rk_live_[0-9a-zA-Z]{20,}", "Stripe restricted key", "high"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key", "medium"),
    (r"xox[baprs]-[0-9A-Za-z\-]{10,}", "Slack token", "high"),
    (r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "Slack webhook", "medium"),
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "Private key", "critical"),
    (r"sk-(proj-)?[A-Za-z0-9_\-]{32,}", "OpenAI API key", "high"),
    (r"sk-ant-[A-Za-z0-9_\-]{32,}", "Anthropic API key", "high"),
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "SendGrid API key", "high"),
    (r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^\s:'\"]+:[^\s@'\"]{3,}@[^\s'\"]+", "Database URL with credentials", "critical"),
    (r"eyJhbGciOi[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "Hardcoded JWT", "medium"),
    (r"(?i)(secret_key|api[_-]?key|client_secret|auth[_-]?token|password|passwd)\s*[=:]\s*['\"][^'\"\s$%{}<>]{8,}['\"]", "Hardcoded credential", "medium"),
]

PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxx|dummy|test|sample|<|\*\*\*|\.\.\.|replace|insecure|fake|redacted")

RATE_LIMIT_LIBS = r"express-rate-limit|rate-limiter-flexible|@upstash/ratelimit|slowapi|flask[_-]limiter|django[_-]ratelimit|" \
                  r"DEFAULT_THROTTLE_RATES|throttle_classes|rack-attack|Rack::Attack|bucket4j|resilience4j\.ratelimiter|" \
                  r"golang\.org/x/time/rate|ulule/limiter|ThrottleRequests|throttle:|@nestjs/throttler|koa-ratelimit|fastify-rate-limit|@fastify/rate-limit"

VALIDATORS = r"pydantic|marshmallow|serializers\.|zod|yup|joi|express-validator|class-validator|@Valid|validates\s|Validator::make|ajv"


def mask(s: str) -> str:
    s = s.strip()
    if len(s) <= 10:
        return s[:2] + "…"
    return s[:6] + "…" + s[-3:]


def tracked_files(root: Path) -> set:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files"], capture_output=True, text=True, timeout=20)
        return set(out.stdout.splitlines()) if out.returncode == 0 else set()
    except Exception:
        return set()


def secrets(root: Path, ctx: Context) -> List[dict]:
    tracked = tracked_files(root)
    rows = []
    exts = SOURCE_EXT | {".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg", ".properties", ".xml", ".tf", ".sh", ".txt", ".md", ".pem", ".key"}
    files = list(iter_files(root, exts)) + list(iter_files(root, names={".env", ".env.local", ".env.production", ".npmrc", ".pypirc", "id_rsa"}))
    seen = set()
    for f in files:
        if f in seen or f.name.endswith((".lock", "-lock.json")) or f.name in ("package-lock.json",):
            continue
        seen.add(f)
        text = read_text(f)
        r = rel(root, f)
        is_tracked = (r in tracked) if tracked else None
        if f.name.startswith(".env") and not f.name.endswith((".example", ".sample", ".template")) and is_tracked:
            ctx.add("high", "secrets", f"Environment file committed to git: {r}", file=r,
                    recommendation="Remove from git history (git rm --cached, rewrite history) and rotate the values.")
        for rx, label, sev in SECRET_RULES:
            for m in re.finditer(rx, text):
                val = m.group(0)
                if PLACEHOLDER.search(val) or "os.environ" in val or "process.env" in val:
                    continue
                ln = line_of(text, m.start())
                row = {"file": r, "line": ln, "type": label, "match": mask(val), "tracked": is_tracked}
                rows.append(row)
                ctx.add(sev if is_tracked is not False else "low", "secrets", f"{label} in source", file=r, line=ln, evidence=mask(val),
                        recommendation="Move to environment variables/secret manager and rotate the credential.")
                if len(rows) > 300:
                    return rows
    return rows


INPUT_TAG = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.I | re.S)


def _attr(attrs: str, name: str):
    m = re.search(rf"\b{name}\s*=\s*(?:\{{\s*['\"]?([^'\"}}]+)['\"]?\s*\}}|['\"]([^'\"]*)['\"])", attrs, re.I)
    return (m.group(1) or m.group(2)) if m else None


def input_fields(root: Path, ctx: Context) -> dict:
    fields = []
    for f in iter_files(root, {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".erb", ".ejs", ".hbs", ".php", ".astro", ".js", ".ts"}):
        text = read_text(f)
        if "<input" not in text and "<textarea" not in text:
            continue
        for m in INPUT_TAG.finditer(text):
            tag, attrs = m.group(1).lower(), m.group(2)
            typ = (_attr(attrs, "type") or ("textarea" if tag == "textarea" else "text")).lower()
            if typ in ("hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset", "color", "range"):
                continue
            row = {
                "file": rel(root, f), "line": line_of(text, m.start()), "tag": tag, "type": typ,
                "name": _attr(attrs, "name") or _attr(attrs, "id") or _attr(attrs, r"\{\.\.\.register") or "",
                "maxlength": _attr(attrs, "maxLength") or _attr(attrs, "maxlength"),
                "pattern": _attr(attrs, "pattern"),
                "required": bool(re.search(r"\brequired\b", attrs)),
                "min": _attr(attrs, "min"), "max": _attr(attrs, "max"),
                "autocomplete": _attr(attrs, "autoComplete") or _attr(attrs, "autocomplete"),
            }
            fields.append(row)
            if typ == "password" and (row["autocomplete"] or "").lower() not in ("current-password", "new-password", "off"):
                pass
    unconstrained = [x for x in fields if x["type"] in ("text", "textarea", "search", "email", "url", "tel", "password") and not x["maxlength"] and not x["pattern"]]
    if unconstrained:
        ctx.add("info", "input-validation", f"{len(unconstrained)} text input(s) without maxlength/pattern",
                "Client-side limits are UX only, but their absence often mirrors missing server-side limits.",
                file=unconstrained[0]["file"], line=unconstrained[0]["line"])
    # server-side validators / rate limit libs
    rate_hits, validator_hits = set(), set()
    for f in iter_files(root, SOURCE_EXT | {".json", ".toml", ".txt", ".rb"}):
        t = read_text(f)
        if re.search(RATE_LIMIT_LIBS, t):
            rate_hits.add(rel(root, f))
        if re.search(VALIDATORS, t):
            validator_hits.add(rel(root, f))
    if not rate_hits:
        ctx.add("medium", "rate-limiting", "No rate-limiting library or config found in the repo",
                recommendation="Add throttling for auth and write endpoints (app middleware or platform WAF).")
    return {"fields": fields[:500], "total": len(fields), "unconstrained": len(unconstrained),
            "rate_limit_config_files": sorted(rate_hits)[:30], "validator_files": sorted(validator_hits)[:30]}
