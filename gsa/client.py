"""HTTP client with pacing, a request budget and request building from Endpoints."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests
import urllib3

from .endpoints import Endpoint
from .values import value_for

UA = "google-security-audit/0.1 (+https://github.com/Algebras/google-security-audit)"


@dataclass
class Resp:
    status: int
    elapsed: float
    headers: Dict[str, str]
    text: str
    error: Optional[str] = None

    @property
    def ok(self):
        return 200 <= self.status < 300

    def json(self):
        try:
            return json.loads(self.text)
        except Exception:
            return None


@dataclass
class Client:
    base_url: str
    rps: float = 10.0
    timeout: float = 15.0
    max_requests: int = 5000
    verify_tls: bool = True
    auth_headers: Dict[str, str] = field(default_factory=dict)
    sent: int = 0
    _last: float = 0.0

    def __post_init__(self):
        self.base_url = self.base_url.rstrip("/")
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        if not self.verify_tls:
            urllib3.disable_warnings()

    def budget_left(self) -> bool:
        return self.sent < self.max_requests

    def request(self, method: str, path: str, *, params=None, json_body=None, data=None,
                headers=None, auth: bool = True, pace: bool = True, raw_body: Optional[str] = None) -> Resp:
        if not self.budget_left():
            return Resp(0, 0, {}, "", "request budget exhausted")
        if pace and self.rps > 0:
            wait = (1.0 / self.rps) - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
        self._last = time.time()
        h = {}
        if auth:
            h.update(self.auth_headers)
        if headers:
            h.update(headers)
        url = self.base_url + path if path.startswith("/") else path
        self.sent += 1
        t0 = time.time()
        try:
            r = self.s.request(method, url, params=params, json=json_body, data=raw_body if raw_body is not None else data,
                               headers=h, timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)
            body = r.text[:200_000]
            return Resp(r.status_code, time.time() - t0, {k.lower(): v for k, v in r.headers.items()}, body)
        except requests.RequestException as e:
            return Resp(0, time.time() - t0, {}, "", f"{type(e).__name__}: {str(e)[:200]}")


def build_request(ep: Endpoint, overrides: Optional[Dict[str, Any]] = None):
    """Return (path, query, body, headers) with params filled by name/type heuristics."""
    overrides = overrides or {}
    path = ep.path
    query, body, headers = {}, {}, {}
    for name, p in ep.params.items():
        val = overrides[name] if name in overrides else value_for(name, p.type)
        if p.location == "path":
            path = path.replace("{" + name + "}", quote(str(val), safe=""))
        elif p.location == "query":
            query[name] = val
        elif p.location == "header":
            headers[name] = str(val)
        else:
            body[name] = val
    # unresolved path params
    import re
    path = re.sub(r"\{\w+\}", "1", path)
    if ep.method in ("GET", "DELETE") and body:
        query.update({k: v for k, v in body.items() if not isinstance(v, (dict, list))})
        body = {}
    return path, query, body, headers


def send(client: Client, ep: Endpoint, overrides=None, auth=True, extra_headers=None) -> Resp:
    path, query, body, headers = build_request(ep, overrides)
    if extra_headers:
        headers.update(extra_headers)
    method = ep.method
    jb = body if method not in ("GET", "DELETE") else None
    if method in ("POST", "PUT", "PATCH") and jb is None:
        jb = {}
    return client.request(method, path, params=query or None, json_body=jb, headers=headers, auth=auth)
