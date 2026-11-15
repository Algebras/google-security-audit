"""gsa — google-security-audit command line."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from . import auth as authmod
from . import deps, dynamic, endpoints, infra, repo_checks, schema
from .client import Client
from .identity import device_user, repo_info
from .redact import scrub
from .upload import load_config, save_config, upload, upload_file
from .util import SEVERITIES, Context, log

LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "host.docker.internal"}


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="gsa", description="Local security harness with auto-upload to the team dashboard.")
    ap.add_argument("--version", action="version", version=f"gsa {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Scan a project folder and (optionally) its running local server.",
                       usage="gsa scan FOLDER [URL] [options]   e.g.  gsa scan ~/Desktop/myapp http://localhost:3000")
    s.add_argument("repo", metavar="FOLDER", help="Path to the project folder (or a git URL to clone)")
    s.add_argument("url", metavar="URL", nargs="?", help="Address of the running app, e.g. http://localhost:3000 (omit for a code-only scan)")
    s.add_argument("--target", "-t", help=argparse.SUPPRESS)  # legacy flag, same as URL
    s.add_argument("--login-url", help="URL to open for interactive login (default: target)")
    s.add_argument("--login", choices=["auto", "browser", "manual", "never"], default="auto",
                   help="auto: open a browser if endpoints return 401/403 (default)")
    s.add_argument("--cookie", help="Cookie header to use instead of logging in")
    s.add_argument("--header", "-H", action="append", default=[], help="Extra header 'Name: value' (repeatable)")
    s.add_argument("--fuzz-level", type=int, choices=[0, 1, 2, 3], default=2, help="0 disables fuzzing; 3 adds SecLists")
    s.add_argument("--rps", type=float, default=10, help="Max requests/second (default 10)")
    s.add_argument("--max-requests", type=int, default=6000)
    s.add_argument("--burst", type=int, default=30, help="Requests per rate-limit probe")
    s.add_argument("--allow-destructive", action="store_true", help="Also send DELETE requests")
    s.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    s.add_argument("--no-osv", action="store_true", help="Skip OSV.dev vulnerability lookup")
    s.add_argument("--no-external", action="store_true", help="No third-party lookups (OSV, ipinfo)")
    s.add_argument("--no-upload", action="store_true", help="Do not upload results")
    s.add_argument("--out", help="Where to write the JSON report (default ./gsa-report-<time>.json)")
    s.add_argument("--yes", "-y", action="store_true", help="Skip the authorization confirmation for non-local targets")
    s.add_argument("--note", help="Free-text note shown on the dashboard")

    c = sub.add_parser("configure", help="Point uploads at a different dashboard (default: the team dashboard)")
    c.add_argument("--endpoint", required=True)

    u = sub.add_parser("upload", help="Upload a saved report JSON")
    u.add_argument("file")
    return ap.parse_args(argv)


LOCAL_RX = re.compile(r"(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(:\d+)?(/\S*)?", re.I)


def _bad_url(raw):
    log(f"'{raw}' doesn't look like an address. Use the URL your app prints, e.g. http://localhost:3000", "err")
    sys.exit(2)


def normalize_url(raw: str) -> str:
    """Accept 'http://localhost:3000', 'localhost:3000', '127.0.0.1:8000/', and fix common typos
    such as 'http//localhost:3000' or 'httpl/localhost:3000'."""
    t = raw.strip().strip('"\'')
    if not re.match(r"^https?://", t, re.I):
        first = re.split(r"[/:]", t, 1)[0]
        looks_like_host = first.lower() in ("localhost", "127.0.0.1", "0.0.0.0") or "." in first or first.startswith("[")
        if "://" in t or not looks_like_host:
            m = LOCAL_RX.search(t)
            if not m:
                _bad_url(raw)
            t = m.group(0)
            log(f"Interpreting '{raw}' as http://{t}", "warn")
        t = "http://" + t
    if not urlparse(t).hostname:
        _bad_url(raw)
    return t.rstrip("/")


def resolve_repo(spec: str):
    spec = spec.strip().strip('"\'')
    p = Path(spec).expanduser()
    if not p.exists() and not p.is_absolute() and (Path.home() / spec).exists():
        p = Path.home() / spec  # allow "Desktop/myapp" from any directory
    if p.exists():
        if not p.is_dir():
            log(f"{p} is a file. Pass the project folder instead.", "err")
            sys.exit(2)
        return p.resolve(), None
    if spec.startswith(("http://", "https://", "git@")):
        tmp = Path(tempfile.mkdtemp(prefix="gsa-"))
        log(f"Cloning {spec} …")
        r = subprocess.run(["git", "clone", "--depth", "1", spec, str(tmp / "repo")], capture_output=True, text=True)
        if r.returncode != 0:
            log(r.stderr.strip(), "err")
            sys.exit(2)
        return tmp / "repo", tmp
    log(f"Folder not found: {spec}  (tip: drag the folder into the terminal to paste its full path)", "err")
    sys.exit(2)


def confirm_target(target: str, yes: bool):
    host = urlparse(target).hostname or ""
    if host in LOCAL_HOSTS or host.endswith(".local") or yes:
        return
    print(f"\nYou are about to send active test traffic (fuzzing, bursts) to: {target}")
    try:
        ans = input("Confirm you own this system or are authorized to test it [y/N]: ").strip().lower()
    except EOFError:
        ans = ""
    if ans not in ("y", "yes"):
        log("Aborted.", "err")
        sys.exit(1)


def scan(a) -> int:
    started = time.time()
    if a.url and a.target and normalize_url(a.url) != normalize_url(a.target):
        log("Give the app address once (as the second argument).", "err")
        return 2
    a.target = normalize_url(a.url or a.target) if (a.url or a.target) else None
    root, tmp = resolve_repo(a.repo)
    ctx = Context(repo=root)
    who = device_user()
    repo = repo_info(root)
    if a.repo.startswith(("http", "git@")):
        repo["remote"] = a.repo
        repo["name"] = a.repo.rstrip("/").split("/")[-1].removesuffix(".git")
    log(f"gsa {__version__} — scanning {repo['name']} as {who['full_name']} ({who['username']}@{who['hostname']})", "head")
    log("The report records your device user name and is uploaded to the team dashboard (use --no-upload to opt out).")
    if a.target:
        confirm_target(a.target, a.yes)

    # ---------- static
    log("Discovering endpoints …")
    eps = endpoints.discover(root)
    log(f"  {len(eps)} endpoints found in source")
    log("Inventorying third-party software …")
    dep_report = deps.scan_deps(root, ctx, use_osv=not (a.no_osv or a.no_external))
    log(f"  {dep_report['totals']['packages']} packages, {len(dep_report['services'])} external services")
    log("Mapping database schema …")
    tables = schema.static_schema(root)
    log("Checking secrets and input fields …")
    secret_rows = repo_checks.secrets(root, ctx)
    inputs = repo_checks.input_fields(root, ctx)
    db = infra.database(root)

    # ---------- dynamic
    live = {}
    auth_state = authmod.from_cli(a.cookie, a.header)
    client = None
    if a.target:
        client = Client(a.target, rps=a.rps, max_requests=a.max_requests, verify_tls=not a.insecure)
        log(f"Probing {a.target} …")
        live_eps = dynamic.live_discover(client, ctx)
        eps = endpoints.dedupe(eps + live_eps)
        if auth_state:
            client.auth_headers = auth_state.build_headers()
        baseline = dynamic.probe(client, eps, ctx, a.allow_destructive)
        needs_auth = dynamic.detect_auth_required(baseline) or any(e.auth_hint for e in eps)
        if not auth_state and a.login != "never" and (needs_auth or a.login in ("browser", "manual")):
            login_url = a.login_url or a.target
            if a.login == "manual":
                auth_state = authmod.manual_login(login_url)
            else:
                ans = "y" if a.login == "browser" else input("\nSome endpoints need auth. Open a browser to log in? [Y/n]: ").strip().lower()
                if ans in ("", "y", "yes"):
                    auth_state = authmod.browser_login(login_url, a.target) or authmod.manual_login(login_url)
            if auth_state and (auth_state.cookies or auth_state.headers or auth_state.storage):
                client.auth_headers = auth_state.build_headers()
                log("Re-probing with captured session …")
                baseline = dynamic.probe(client, eps, Context(repo=root), a.allow_destructive)
        authz = dynamic.access_control(client, eps, baseline, ctx) if auth_state else {}
        log("Checking headers, CORS and cookies …")
        headers = dynamic.check_headers(client, ctx)
        fuzz_stats = {}
        if a.fuzz_level > 0:
            log(f"Fuzzing (level {a.fuzz_level}) …")
            fuzz_stats = dynamic.fuzz(client, eps, baseline, ctx, a.fuzz_level, a.allow_destructive)
        log("Testing input limits and rate limits …")
        limits = dynamic.input_limits(client, eps, baseline, ctx)
        rl = dynamic.rate_limits(client, eps, baseline, ctx, a.burst)
        schema.infer_from_responses(baseline, tables)
        live = {"baseline": baseline, "headers": headers, "fuzz": fuzz_stats, "input_limits": limits,
                "rate_limits": rl, "unauthenticated_replay": authz, "requests_sent": client.sent}
    host = infra.hosting(a.target, root, use_external=not a.no_external)

    findings = sorted((f.to_dict() for f in ctx.findings), key=lambda f: SEVERITIES.index(f["severity"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    report = {
        "schema_version": 1,
        "id": str(uuid.uuid4()),
        "tool": {"name": "google-security-audit", "version": __version__},
        "started_at": dt.datetime.fromtimestamp(started, dt.timezone.utc).isoformat(),
        "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "duration_s": round(time.time() - started, 1),
        "scanner": who,
        "repo": repo,
        "target": a.target,
        "note": a.note,
        "options": {"fuzz_level": a.fuzz_level, "rps": a.rps, "allow_destructive": a.allow_destructive},
        "summary": {"counts": counts, "endpoints": len(eps), "tables": len(tables), "packages": dep_report["totals"]["packages"],
                    "hosting": host["primary"], "database": db["primary"], "auth": auth_state.summary() if auth_state else {"method": "none"}},
        "findings": findings,
        "endpoints": [e.to_dict() for e in eps],
        "schema": {"tables": list(tables.values()), "mermaid": schema.to_mermaid(tables) if tables else ""},
        "dependencies": dep_report,
        "inputs": inputs,
        "secrets": secret_rows,
        "infrastructure": {"hosting": host, "database": db},
        "live": live,
    }
    report = scrub(report, auth_state.secrets() if auth_state else [])

    out = Path(a.out) if a.out else Path.cwd() / f"gsa-report-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    print()
    log(f"Done in {report['duration_s']}s — " + ", ".join(f"{counts[s]} {s}" for s in SEVERITIES), "head")
    log(f"Hosting: {host['primary']}  |  Database: {db['primary']}  |  Endpoints: {len(eps)}  |  Tables: {len(tables)}")
    log(f"Report written to {out}", "ok")
    if not a.no_upload:
        upload(report)
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


def main(argv=None) -> int:
    a = parse_args(argv)
    if a.cmd == "configure":
        save_config(a.endpoint)
        log(f"Uploads will go to: {load_config()['endpoint']}")
        return 0
    if a.cmd == "upload":
        return 0 if upload_file(Path(a.file)) else 1
    if a.cmd == "scan":
        try:
            return scan(a)
        except KeyboardInterrupt:
            log("Interrupted.", "err")
            return 130
    return 1
