"""Third-party software inventory: manifests per folder, where each package is
imported, known SaaS integrations, and known vulnerabilities via OSV.dev."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

import requests

from .util import SOURCE_EXT, Context, iter_files, read_text, rel, log

try:
    import tomllib  # py311+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

MANIFESTS = {"package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "go.mod",
             "Gemfile", "Cargo.toml", "composer.json", "pom.xml", "build.gradle", "build.gradle.kts", "setup.py"}

SERVICES = {
    # name: (category, regex over code/config)
    "Stripe": ("payments", r"\bstripe\b|sk_(live|test)_|api\.stripe\.com"),
    "PayPal": ("payments", r"paypal"),
    "Twilio": ("messaging", r"\btwilio\b"),
    "SendGrid": ("email", r"sendgrid"),
    "Mailgun": ("email", r"mailgun"),
    "Resend": ("email", r"\bresend\b"),
    "Postmark": ("email", r"postmark"),
    "AWS": ("cloud", r"aws-sdk|@aws-sdk/|boto3|amazonaws\.com"),
    "Google Cloud": ("cloud", r"@google-cloud/|google\.cloud|googleapis\.com"),
    "Firebase": ("backend", r"firebase"),
    "Supabase": ("backend", r"supabase"),
    "Auth0": ("auth", r"auth0"),
    "Clerk": ("auth", r"@clerk/|clerk\.com"),
    "NextAuth/Auth.js": ("auth", r"next-auth|@auth/"),
    "Okta": ("auth", r"okta"),
    "Sentry": ("monitoring", r"@sentry/|sentry_sdk|sentry\.io"),
    "Datadog": ("monitoring", r"datadog|dd-trace"),
    "PostHog": ("analytics", r"posthog"),
    "Segment": ("analytics", r"analytics-node|@segment/|segment\.io"),
    "Mixpanel": ("analytics", r"mixpanel"),
    "Google Analytics": ("analytics", r"gtag\(|googletagmanager|react-ga"),
    "OpenAI": ("ai", r"\bopenai\b"),
    "Anthropic": ("ai", r"anthropic"),
    "Algolia": ("search", r"algolia"),
    "Cloudinary": ("media", r"cloudinary"),
    "Pusher": ("realtime", r"pusher"),
    "Redis": ("cache", r"\bioredis\b|\bredis\b"),
    "Upstash": ("cache", r"upstash"),
    "Prisma": ("orm", r"@prisma/client|prisma"),
    "Vercel": ("platform", r"@vercel/"),
    "Cloudflare": ("platform", r"cloudflare|wrangler"),
    "Slack": ("messaging", r"@slack/|slack_sdk|hooks\.slack\.com"),
    "GitHub API": ("devtools", r"@octokit|PyGithub|api\.github\.com"),
    "Mapbox": ("maps", r"mapbox"),
    "Google Maps": ("maps", r"maps\.googleapis\.com|@react-google-maps"),
    "Intercom": ("support", r"intercom"),
    "LaunchDarkly": ("feature-flags", r"launchdarkly"),
}

ECOSYSTEM = {"package.json": "npm", "requirements.txt": "PyPI", "requirements-dev.txt": "PyPI", "pyproject.toml": "PyPI",
             "Pipfile": "PyPI", "setup.py": "PyPI", "go.mod": "Go", "Gemfile": "RubyGems", "Cargo.toml": "crates.io",
             "composer.json": "Packagist", "pom.xml": "Maven", "build.gradle": "Maven", "build.gradle.kts": "Maven"}


def _clean_ver(v: str) -> str:
    v = (v or "").strip()
    m = re.search(r"\d+(\.\d+){0,3}([\w\.\-+]*)?", v)
    return m.group(0) if m else ""


def parse_manifest(f: Path) -> List[dict]:
    text = read_text(f)
    name = f.name
    pkgs = []
    try:
        if name == "package.json":
            j = json.loads(text)
            lock = {}
            lf = f.parent / "package-lock.json"
            if lf.exists():
                try:
                    lj = json.loads(read_text(lf))
                    for k, v in (lj.get("packages") or {}).items():
                        if k.startswith("node_modules/") and k.count("node_modules/") == 1:
                            lock[k[len("node_modules/"):]] = v.get("version")
                except Exception:
                    pass
            for sect, dev in (("dependencies", False), ("devDependencies", True), ("peerDependencies", False)):
                for n, v in (j.get(sect) or {}).items():
                    pkgs.append({"name": n, "spec": v, "version": lock.get(n) or _clean_ver(v), "exact": n in lock, "dev": dev})
        elif name.startswith("requirements"):
            for line in text.splitlines():
                line = line.split("#")[0].strip()
                if not line or line.startswith(("-", "git+", "http")):
                    continue
                m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(==|>=|~=|<=|>|<)?\s*([^;\s]*)", line)
                if m:
                    pkgs.append({"name": re.sub(r"\[.*\]", "", m.group(1)), "spec": (m.group(2) or "") + (m.group(3) or ""),
                                 "version": _clean_ver(m.group(3)), "exact": m.group(2) == "==", "dev": "dev" in name})
        elif name == "pyproject.toml" and tomllib:
            j = tomllib.loads(text)
            deps = list((j.get("project") or {}).get("dependencies") or [])
            poetry = ((j.get("tool") or {}).get("poetry") or {})
            for n, v in (poetry.get("dependencies") or {}).items():
                if n != "python":
                    deps.append(f"{n}{v if isinstance(v, str) else ''}")
            for d in deps:
                m = re.match(r"([A-Za-z0-9_.\-\[\]]+)\s*(.*)", d)
                if m:
                    pkgs.append({"name": re.sub(r"\[.*\]", "", m.group(1)), "spec": m.group(2), "version": _clean_ver(m.group(2)),
                                 "exact": "==" in m.group(2), "dev": False})
        elif name == "Pipfile" and tomllib:
            j = tomllib.loads(text)
            for sect, dev in (("packages", False), ("dev-packages", True)):
                for n, v in (j.get(sect) or {}).items():
                    v = v if isinstance(v, str) else ""
                    pkgs.append({"name": n, "spec": v, "version": _clean_ver(v), "exact": v.startswith("=="), "dev": dev})
        elif name == "go.mod":
            for m in re.finditer(r"^\s*(?:require\s+)?([\w\.\-/]+\.[\w\-/\.]+)\s+(v[\w\.\-+]+)", text, re.M):
                pkgs.append({"name": m.group(1), "spec": m.group(2), "version": m.group(2).lstrip("v"), "exact": True, "dev": False})
        elif name == "Gemfile":
            for m in re.finditer(r"^\s*gem\s+['\"]([\w\-]+)['\"](?:\s*,\s*['\"]([^'\"]+)['\"])?", text, re.M):
                pkgs.append({"name": m.group(1), "spec": m.group(2) or "", "version": _clean_ver(m.group(2) or ""), "exact": False, "dev": False})
        elif name == "Cargo.toml" and tomllib:
            j = tomllib.loads(text)
            for sect, dev in (("dependencies", False), ("dev-dependencies", True)):
                for n, v in (j.get(sect) or {}).items():
                    v = v if isinstance(v, str) else (v.get("version", "") if isinstance(v, dict) else "")
                    pkgs.append({"name": n, "spec": v, "version": _clean_ver(v), "exact": False, "dev": dev})
        elif name == "composer.json":
            j = json.loads(text)
            for sect, dev in (("require", False), ("require-dev", True)):
                for n, v in (j.get(sect) or {}).items():
                    if "/" in n:
                        pkgs.append({"name": n, "spec": v, "version": _clean_ver(v), "exact": False, "dev": dev})
        elif name == "pom.xml":
            for m in re.finditer(r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?", text):
                pkgs.append({"name": f"{m.group(1)}:{m.group(2)}", "spec": m.group(3) or "", "version": _clean_ver(m.group(3) or ""), "exact": True, "dev": False})
        elif name.startswith("build.gradle"):
            for m in re.finditer(r"(?:implementation|api|compile|testImplementation)\s*\(?\s*['\"]([\w\.\-]+):([\w\.\-]+):([\w\.\-]+)['\"]", text):
                pkgs.append({"name": f"{m.group(1)}:{m.group(2)}", "spec": m.group(3), "version": m.group(3), "exact": True, "dev": False})
        elif name == "setup.py":
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", text, re.S)
            for d in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1) if m else ""):
                mm = re.match(r"([A-Za-z0-9_.\-]+)\s*(.*)", d)
                if mm:
                    pkgs.append({"name": mm.group(1), "spec": mm.group(2), "version": _clean_ver(mm.group(2)), "exact": "==" in mm.group(2), "dev": False})
    except Exception as e:
        log(f"Could not parse {f}: {e}", "warn")
    return pkgs


def import_usage(root: Path, names: List[str]) -> Dict[str, set]:
    """Which folders import each package."""
    usage: Dict[str, set] = defaultdict(set)
    if not names:
        return usage
    # map python dist names to module names roughly
    norm = {}
    for n in names:
        base = n.split(":")[-1].split("/")[-1] if not n.startswith("@") else n
        norm[n] = {n, base, base.replace("-", "_"), base.lower().replace("-", "_")}
    py_alias = {"beautifulsoup4": "bs4", "pyyaml": "yaml", "pillow": "PIL", "scikit-learn": "sklearn", "python-dotenv": "dotenv",
                "djangorestframework": "rest_framework", "psycopg2-binary": "psycopg2", "psycopg": "psycopg", "python-jose": "jose",
                "pyjwt": "jwt", "opencv-python": "cv2", "google-cloud-storage": "google.cloud"}
    for k, v in py_alias.items():
        for n in names:
            if n.lower() == k:
                norm[n].add(v)
    imp_re = re.compile(r"(?:from\s+([\w\.]+)\s+import|^\s*import\s+([\w\.]+)|require\(\s*['\"]([^'\"]+)['\"]\)|from\s+['\"]([^'\"]+)['\"]|import\s+['\"]([^'\"]+)['\"]|^\s*\"([\w\.\-/]+)\"$)", re.M)
    lookup = {}
    for n, alts in norm.items():
        for a in alts:
            lookup[a] = n
    for f in iter_files(root, SOURCE_EXT):
        text = read_text(f)
        folder = rel(root, f.parent) or "."
        for m in imp_re.finditer(text):
            mod = next((g for g in m.groups() if g), "")
            if not mod or mod.startswith("."):
                continue
            cands = [mod]
            if mod.startswith("@"):
                cands.append("/".join(mod.split("/")[:2]))
            else:
                cands.append(mod.split("/")[0])
                cands.append(mod.split(".")[0])
            for c in cands:
                if c in lookup:
                    usage[lookup[c]].add(folder)
                    break
    return usage


def osv_check(packages: List[dict], ctx: Context) -> List[dict]:
    queries, idx = [], []
    for i, p in enumerate(packages):
        if not p.get("version") or not p.get("ecosystem"):
            continue
        name = p["name"]
        queries.append({"package": {"name": name, "ecosystem": p["ecosystem"]}, "version": p["version"]})
        idx.append(i)
    vulns = []
    for start in range(0, len(queries), 500):
        chunk = queries[start: start + 500]
        try:
            r = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": chunk}, timeout=30)
            r.raise_for_status()
            results = r.json().get("results", [])
        except Exception as e:
            log(f"OSV lookup failed: {e}", "warn")
            return vulns
        for j, res in enumerate(results):
            ids = [v["id"] for v in (res.get("vulns") or [])]
            if not ids:
                continue
            p = packages[idx[start + j]]
            p["vulns"] = ids
            vulns.append({"package": p["name"], "version": p["version"], "ecosystem": p["ecosystem"], "manifest": p["manifest"], "ids": ids})
            ctx.add("high" if len(ids) >= 3 else "medium", "dependencies", f"{p['name']}@{p['version']} has {len(ids)} known vulnerabilit{'y' if len(ids)==1 else 'ies'}",
                    ", ".join(ids[:8]) + (" (version inferred from range)" if not p.get("exact") else ""), file=p["manifest"],
                    recommendation="Upgrade to a patched version (see https://osv.dev).")
    return vulns


def scan_deps(root: Path, ctx: Context, use_osv: bool = True) -> dict:
    packages = []
    folders = defaultdict(list)
    for f in iter_files(root, names=MANIFESTS):
        mrel = rel(root, f)
        for p in parse_manifest(f):
            p["manifest"] = mrel
            p["ecosystem"] = ECOSYSTEM.get(f.name)
            packages.append(p)
            folders[rel(root, f.parent) or "."].append(p["name"])
    usage = import_usage(root, sorted({p["name"] for p in packages}))
    for p in packages:
        p["used_in"] = sorted(usage.get(p["name"], []))[:50]
    # SaaS / service detection
    services = defaultdict(set)
    scan_ext = SOURCE_EXT | {".json", ".toml", ".yaml", ".yml", ".env", ".example", ".tf"}
    compiled = {k: re.compile(v[1], re.I) for k, v in SERVICES.items()}
    for f in iter_files(root, scan_ext):
        if f.name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"):
            continue
        text = read_text(f)
        folder = rel(root, f.parent) or "."
        for k, rx in compiled.items():
            if rx.search(text):
                services[k].add(folder)
    vulns = osv_check(packages, ctx) if use_osv else []
    return {
        "packages": packages,
        "by_folder": {k: sorted(set(v)) for k, v in sorted(folders.items())},
        "services": [{"name": k, "category": SERVICES[k][0], "folders": sorted(v)[:50]} for k, v in sorted(services.items())],
        "vulnerabilities": vulns,
        "totals": {"packages": len(packages), "manifests": len({p["manifest"] for p in packages}), "vulnerable": len(vulns)},
    }
