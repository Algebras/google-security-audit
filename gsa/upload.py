"""Config + auto-upload of finished reports to the shared results dashboard."""
from __future__ import annotations

import gzip
import json
import os
import time
from pathlib import Path
from typing import Optional

import requests

from .util import log

# Shared team dashboard. Override with GSA_ENDPOINT or `gsa configure --endpoint`.
DEFAULT_ENDPOINT = "https://local-scan-audit-results.vercel.app"

CONFIG_DIR = Path(os.environ.get("GSA_HOME", Path.home() / ".gsa"))
CONFIG_FILE = CONFIG_DIR / "config.json"
PENDING_DIR = CONFIG_DIR / "pending"


def load_config() -> dict:
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    cfg["endpoint"] = os.environ.get("GSA_ENDPOINT") or cfg.get("endpoint") or DEFAULT_ENDPOINT
    cfg["upload_token"] = os.environ.get("GSA_UPLOAD_TOKEN") or cfg.get("upload_token")
    return cfg


def save_config(endpoint: Optional[str], token: Optional[str]):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = {}
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    if endpoint:
        cfg["endpoint"] = endpoint.rstrip("/")
    if token:
        cfg["upload_token"] = token
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    try:
        CONFIG_FILE.chmod(0o600)
    except Exception:
        pass
    log(f"Saved config to {CONFIG_FILE}", "ok")


def upload(report: dict, cfg: Optional[dict] = None) -> Optional[str]:
    cfg = cfg or load_config()
    token = cfg.get("upload_token")
    if not token:
        log("No upload token configured. Run: gsa configure --token <team upload token>", "warn")
        _save_pending(report)
        return None
    url = cfg["endpoint"].rstrip("/") + "/api/ingest/"
    body = gzip.compress(json.dumps(report, default=str).encode())
    if len(body) > 4_000_000:
        log("Report is large; trimming probe details to fit upload limit.", "warn")
        report = dict(report)
        report.pop("probe", None)
        report.pop("inputs", None)
        body = gzip.compress(json.dumps(report, default=str).encode())
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Content-Encoding": "gzip"}
    for attempt in range(3):
        try:
            r = requests.post(url, data=body, headers=headers, timeout=60)
            if r.status_code in (200, 201):
                j = r.json()
                link = cfg["endpoint"].rstrip("/") + f"/scans/{j.get('id')}"
                log(f"Uploaded. View results: {link}", "ok")
                return link
            log(f"Upload failed: HTTP {r.status_code} {r.text[:200]}", "err")
            if r.status_code in (400, 401, 403, 413):
                break
        except requests.RequestException as e:
            log(f"Upload error: {e}", "err")
        time.sleep(2 * (attempt + 1))
    _save_pending(report)
    return None


def _save_pending(report: dict):
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    p = PENDING_DIR / f"report-{int(time.time())}.json"
    p.write_text(json.dumps(report, default=str))
    log(f"Saved report for later upload: {p}  (retry with: gsa upload {p})", "warn")


def upload_file(path: Path) -> Optional[str]:
    report = json.loads(Path(path).read_text())
    link = upload(report)
    if link and PENDING_DIR in Path(path).resolve().parents:
        Path(path).unlink(missing_ok=True)
    return link
