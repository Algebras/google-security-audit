"""Interactive login: open a real browser, let the user sign in, then harvest the
session the same way you would from DevTools > Application (Cookies, Local/Session
Storage). Captured values are only used locally for authenticated scanning and are
never uploaded — the report only records cookie/storage *names*.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .util import log

TOKENISH = re.compile(r"token|auth|session|sess|sid|jwt|bearer|access|refresh|id_token|csrf|xsrf|remember", re.I)
JWT = re.compile(r"^eyJ[\w-]+\.[\w-]+\.[\w-]*$")


class AuthState:
    def __init__(self):
        self.cookies: Dict[str, str] = {}
        self.storage: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.method = "none"

    def build_headers(self) -> Dict[str, str]:
        h = dict(self.headers)
        if self.cookies and "Cookie" not in h:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        csrf = next((v for k, v in self.cookies.items() if re.search(r"csrf|xsrf", k, re.I)), None)
        if csrf:
            h.setdefault("X-CSRFToken", csrf)
            h.setdefault("X-XSRF-TOKEN", csrf)
        if "Authorization" not in h:
            bearer = self._find_bearer()
            if bearer:
                h["Authorization"] = f"Bearer {bearer}"
        return h

    def _find_bearer(self) -> Optional[str]:
        candidates = list(self.storage.items()) + list(self.cookies.items())
        for k, v in candidates:
            v = (v or "").strip().strip('"')
            if JWT.match(v):
                return v
            # JSON blobs like {"access_token": "..."} (Supabase, Auth0, Firebase)
            if v.startswith("{"):
                try:
                    obj = json.loads(v)
                except Exception:
                    continue
                for kk in ("access_token", "accessToken", "id_token", "idToken", "token"):
                    tok = _dig(obj, kk)
                    if isinstance(tok, str) and len(tok) > 20:
                        return tok
        for k, v in candidates:
            if re.search(r"access|bearer|jwt|id_token|auth_token|^token$", k, re.I) and v and len(v) > 15:
                return v.strip('"')
        return None

    def secrets(self) -> List[str]:
        vals = list(self.cookies.values()) + list(self.storage.values()) + list(self.headers.values())
        out = []
        for v in vals:
            if not v:
                continue
            out.append(v)
            if v.startswith("Bearer "):
                out.append(v[7:])
        bearer = self._find_bearer()
        if bearer:
            out.append(bearer)
        return [s for s in out if len(s) >= 6]

    def summary(self) -> dict:
        return {
            "method": self.method,
            "cookie_names": sorted(self.cookies.keys()),
            "storage_keys": sorted(k for k in self.storage.keys() if TOKENISH.search(k)),
            "header_names": sorted(self.build_headers().keys()),
            "bearer_detected": bool(self._find_bearer()),
        }


def _dig(obj, key):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            r = _dig(v, key)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _dig(v, key)
            if r:
                return r
    return None


def browser_login(login_url: str, target_url: str, timeout_min: int = 10) -> Optional[AuthState]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log("Playwright not installed (pip install 'google-security-audit[browser]' && playwright install chromium).", "warn")
        return None
    st = AuthState()
    st.method = "browser"
    target_host = urlparse(target_url).hostname or ""
    with sync_playwright() as p:
        browser = None
        headless = os.environ.get("GSA_BROWSER_HEADLESS") == "1"  # for CI/tests only
        for channel in ("chrome", None):  # prefer the user's installed Chrome
            try:
                browser = p.chromium.launch(headless=headless, channel=channel) if channel else p.chromium.launch(headless=headless)
                break
            except Exception:
                continue
        if browser is None:
            log("Could not launch a browser.", "err")
            return None
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(login_url)
        log(f"A browser window opened at {login_url}.", "head")
        log("Log in there (complete MFA if asked). When you're fully signed in, come back and press Enter.", "head")
        try:
            input()
        except EOFError:
            pass
        # Cookies (DevTools > Application > Cookies)
        for c in ctx.cookies():
            dom = (c.get("domain") or "").lstrip(".")
            if not target_host or target_host.endswith(dom) or dom.endswith(target_host) or dom in ("localhost", "127.0.0.1"):
                st.cookies[c["name"]] = c["value"]
        # Local / Session storage on every open page of the target origin
        for pg in ctx.pages:
            try:
                data = pg.evaluate(
                    "() => { const o = {}; for (const s of [localStorage, sessionStorage]) {"
                    " for (let i = 0; i < s.length; i++) { const k = s.key(i); o[k] = s.getItem(k); } } return o; }"
                )
                for k, v in (data or {}).items():
                    if TOKENISH.search(k) or (isinstance(v, str) and (JWT.match(v.strip('"')) or "access_token" in v)):
                        st.storage[k] = v
            except Exception:
                pass
        browser.close()
    log(f"Captured {len(st.cookies)} cookie(s) and {len(st.storage)} storage token(s).", "ok")
    return st


def manual_login(target_url: str) -> AuthState:
    st = AuthState()
    st.method = "manual"
    print(
        "\nManual token capture:\n"
        f"  1. Open {target_url} in Chrome and log in.\n"
        "  2. Open DevTools (Cmd+Opt+I) > Application > Cookies > your site.\n"
        "  3. Paste cookies below as 'name=value; name2=value2' (or leave blank).\n"
    )
    raw = input("Cookies: ").strip()
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            st.cookies[k.strip()] = v.strip()
    tok = input("Bearer token from Local Storage / network tab (optional): ").strip()
    if tok:
        st.headers["Authorization"] = tok if tok.lower().startswith("bearer ") else f"Bearer {tok}"
    return st


def from_cli(cookies: Optional[str], headers: List[str]) -> Optional[AuthState]:
    if not cookies and not headers:
        return None
    st = AuthState()
    st.method = "cli"
    for part in (cookies or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            st.cookies[k.strip()] = v.strip()
    for h in headers or []:
        if ":" in h:
            k, v = h.split(":", 1)
            st.headers[k.strip()] = v.strip()
    return st
