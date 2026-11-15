"""Live phase: probe discovered endpoints, detect auth, fuzz, and check
headers / CORS / access control / input limits / rate limits."""
from __future__ import annotations

import json
import re
import time
from typing import Dict, List, Optional

from .client import Client, Resp, build_request, send
from .endpoints import Endpoint, endpoints_from_openapi, normalize_path
from .payloads import ERROR_SIGNATURES, MARK, get_payloads
from .util import Context, log

SPEC_PATHS = ["/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json", "/v3/api-docs",
              "/swagger/v1/swagger.json", "/api-docs", "/api/schema/", "/docs/openapi.json", "/api/docs/openapi.json"]
COMMON_PATHS = ["/admin", "/admin/", "/.env", "/.git/config", "/debug", "/graphql", "/api", "/api/health", "/health",
                "/metrics", "/actuator", "/actuator/env", "/server-status", "/phpinfo.php", "/wp-admin/", "/.well-known/security.txt",
                "/robots.txt", "/sitemap.xml", "/__debug__/", "/console", "/api/users", "/users"]
SENSITIVE_PATHS = {"/.env": r"[A-Z_]+=", "/.git/config": r"\[core\]", "/actuator/env": r"propertySources",
                   "/phpinfo.php": r"phpinfo\(\)|PHP Version", "/server-status": r"Apache Server Status",
                   "/__debug__/": r"djdt", "/console": r"Werkzeug|console"}
AUTHY_PATH = re.compile(r"login|signin|sign-in|auth|token|session|register|signup|sign-up|password|reset|otp|verify|2fa|mfa|forgot", re.I)


def summarize(r: Resp) -> dict:
    d = {"status": r.status, "ms": int(r.elapsed * 1000), "bytes": len(r.text), "content_type": r.headers.get("content-type", "")}
    if r.error:
        d["error"] = r.error
    return d


def check_errors(text: str) -> Optional[str]:
    for pat, name in ERROR_SIGNATURES:
        if re.search(pat, text, re.I):
            return name
    return None


# ---------------------------------------------------------------- discovery

def live_discover(c: Client, ctx: Context) -> List[Endpoint]:
    eps: List[Endpoint] = []
    for p in SPEC_PATHS:
        r = c.request("GET", p)
        if r.ok and r.text.lstrip().startswith("{") and ('"paths"' in r.text):
            try:
                spec = json.loads(r.text)
                found = endpoints_from_openapi(spec, f"live:{p}")
                for e in found:
                    e.source = "live"
                eps += found
                ctx.add("info", "exposure", f"API spec publicly reachable at {p}", f"{len(found)} operations listed.", endpoint=p,
                        recommendation="Fine for public APIs; otherwise restrict docs/spec routes in production.")
                break
            except Exception:
                pass
    for p in COMMON_PATHS:
        r = c.request("GET", p)
        if r.status and r.status < 400:
            ep = Endpoint("GET", normalize_path(p), "live-probe", source="live")
            eps.append(ep)
            sig = SENSITIVE_PATHS.get(p)
            if sig and re.search(sig, r.text):
                ctx.add("critical" if p in ("/.env", "/.git/config", "/actuator/env") else "high", "exposure",
                        f"Sensitive resource exposed: {p}", f"HTTP {r.status} with matching content.", endpoint=f"GET {p}",
                        recommendation="Block this path at the web server / platform and rotate any exposed secrets.")
    return eps


# ------------------------------------------------------------------ headers

def check_headers(c: Client, ctx: Context) -> dict:
    r = c.request("GET", "/", auth=False)
    h = r.headers
    https = c.base_url.startswith("https")
    checks = {
        "strict-transport-security": https,
        "content-security-policy": True,
        "x-content-type-options": True,
        "x-frame-options": "content-security-policy" not in h or "frame-ancestors" not in h.get("content-security-policy", ""),
        "referrer-policy": True,
    }
    missing = [k for k, needed in checks.items() if needed and k not in h]
    for k in missing:
        sev = "medium" if k in ("content-security-policy", "strict-transport-security") else "low"
        ctx.add(sev, "headers", f"Missing security header: {k}", endpoint="GET /",
                recommendation=f"Set the {k} response header.")
    for k in ("server", "x-powered-by", "x-aspnet-version"):
        if k in h and re.search(r"\d", h[k]):
            ctx.add("low", "headers", f"Version disclosure in {k} header", evidence=f"{k}: {h[k]}", endpoint="GET /")
    # cookies flags
    sc = h.get("set-cookie", "")
    if sc:
        for cookie in re.split(r",(?=\s*\w+=)", sc):
            name = cookie.split("=", 1)[0].strip()
            low = cookie.lower()
            miss = [f for f in ("httponly", "samesite") if f not in low] + (["secure"] if https and "secure" not in low else [])
            if miss:
                ctx.add("low", "cookies", f"Cookie '{name}' missing {', '.join(miss)}", endpoint="GET /")
    # CORS
    rc = c.request("GET", "/", headers={"Origin": "https://evil.gsa-test.example"}, auth=False)
    acao = rc.headers.get("access-control-allow-origin", "")
    acac = rc.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "https://evil.gsa-test.example":
        ctx.add("high" if acac else "medium", "cors", "CORS reflects arbitrary Origin" + (" with credentials" if acac else ""),
                evidence=f"Access-Control-Allow-Origin: {acao}", endpoint="GET /",
                recommendation="Use an explicit allow-list of origins.")
    elif acao == "*" and acac:
        ctx.add("medium", "cors", "CORS wildcard with credentials", endpoint="GET /")
    return {"status": r.status, "present": sorted(k for k in checks if k in h), "missing": missing,
            "server": h.get("server"), "x_powered_by": h.get("x-powered-by"), "cors_allow_origin": acao or None}


# ---------------------------------------------------------- probe & authz

def probe(c: Client, eps: List[Endpoint], ctx: Context, allow_destructive: bool) -> Dict[str, dict]:
    results: Dict[str, dict] = {}
    for ep in eps:
        if ep.method == "DELETE" and not allow_destructive:
            results[ep.key] = {"skipped": "DELETE skipped (use --allow-destructive)"}
            continue
        r = send(c, ep)
        res = summarize(r)
        js = r.json()
        if js is not None:
            res["json_shape"] = shape(js)
        err = check_errors(r.text)
        if err:
            res["error_signature"] = err
            ctx.add("medium", "error-handling", f"{err} leaked on baseline request", endpoint=ep.key,
                    file=ep.file, line=ep.line, evidence=_snip(r.text, err),
                    recommendation="Return generic errors in production; log details server-side.")
        results[ep.key] = res
    return results


def detect_auth_required(results: Dict[str, dict]) -> bool:
    statuses = [v.get("status") for v in results.values() if isinstance(v, dict)]
    authish = sum(1 for s in statuses if s in (401, 403))
    return authish >= 1


def access_control(c: Client, eps: List[Endpoint], baseline: Dict[str, dict], ctx: Context):
    """With auth captured: replay each 2xx endpoint without credentials."""
    out, public = {}, []
    for ep in eps:
        b = baseline.get(ep.key) or {}
        if not (200 <= (b.get("status") or 0) < 300) or ep.method == "DELETE":
            continue
        r = send(c, ep, auth=False)
        out[ep.key] = r.status
        same = r.ok and abs(len(r.text) - b.get("bytes", 0)) < max(50, b.get("bytes", 0) * 0.1)
        if same and ep.auth_hint:
            ctx.add("high", "access-control", "Auth-protected endpoint answers without credentials",
                    f"Code suggests this route requires auth, but an unauthenticated replay returned HTTP {r.status} with a near-identical body.",
                    endpoint=ep.key, file=ep.file, line=ep.line,
                    recommendation="Enforce authentication/authorization on this route.")
        elif same:
            public.append(ep.key)
    if public:
        ctx.add("info", "access-control", f"{len(public)} endpoint(s) respond identically without credentials",
                "Review that these are intended to be public: " + ", ".join(public[:25]))
    return out


# --------------------------------------------------------------------- fuzz

def fuzz(c: Client, eps: List[Endpoint], baseline: Dict[str, dict], ctx: Context, level: int, allow_destructive: bool) -> dict:
    payloads = get_payloads(level)
    stats = {"requests": 0, "endpoints": 0, "anomalies": 0}
    seen = set()
    for ep in eps:
        if not c.budget_left():
            log("Request budget exhausted; stopping fuzzing.", "warn")
            break
        if ep.method == "DELETE" and not allow_destructive:
            continue
        b = baseline.get(ep.key) or {}
        if b.get("status") in (404, 405, 0, None) and ep.source != "live":
            continue
        params = list(ep.params.values())
        if not params:
            continue
        stats["endpoints"] += 1
        base_ms = b.get("ms", 300)
        for p in params:
            for cat, plist in payloads.items():
                for pl in plist:
                    if not c.budget_left():
                        break
                    if p.location == "path" and isinstance(pl, (dict, list)):
                        continue
                    r = send(c, ep, overrides={p.name: pl})
                    stats["requests"] += 1
                    issue = analyze(r, b, base_ms, cat, pl)
                    if issue:
                        sev, title, ev = issue
                        k = (ep.key, title)
                        if k in seen:
                            continue
                        seen.add(k)
                        stats["anomalies"] += 1
                        ctx.add(sev, "fuzzing", title, f"Parameter '{p.name}' ({p.location}) with {cat} payload {_short(pl)}.",
                                endpoint=ep.key, file=ep.file, line=ep.line, evidence=ev,
                                recommendation=RECS.get(cat, "Validate and sanitize this input server-side."))
                        if sev in ("critical", "high"):
                            break  # move to next category once confirmed
    return stats


RECS = {
    "sqli": "Use parameterized queries / ORM bind parameters; never concatenate input into SQL.",
    "nosqli": "Reject objects/operators in user input; cast to expected types before querying.",
    "xss": "Contextually encode output and set a strict Content-Security-Policy.",
    "ssti": "Never render user input as a template; pass it as data.",
    "cmdi": "Avoid shell execution with user input; use argument arrays and allow-lists.",
    "traversal": "Resolve paths against a fixed base directory and reject '..' segments.",
    "ssrf": "Allow-list outbound hosts and block link-local / internal ranges.",
    "type": "Validate types with a schema (pydantic, zod, Joi, serializers) and return 400 on mismatch.",
    "overflow": "Enforce max lengths and reject control characters server-side.",
}


def analyze(r: Resp, b: dict, base_ms: int, cat: str, pl) -> Optional[tuple]:
    text = r.text or ""
    err = check_errors(text)
    if err and not b.get("error_signature"):
        sev = "high" if cat in ("sqli", "nosqli", "cmdi", "ssti") or cat.startswith("seclists") else "medium"
        return sev, f"{err} triggered by {cat} input", _snip(text, err)
    if r.status >= 500 and (b.get("status") or 0) < 500:
        return ("medium" if cat in ("sqli", "nosqli", "cmdi") else "low"), f"Server error (HTTP {r.status}) on {cat} input", f"HTTP {r.status}"
    if cat in ("sqli", "cmdi", "nosqli") and isinstance(pl, str) and re.search(r"sleep|SLEEP|WAITFOR|ping", pl):
        if r.elapsed * 1000 > base_ms + 4500:
            return "critical", f"Time-based {cat.upper()} indicator ({int(r.elapsed*1000)} ms vs {base_ms} ms baseline)", f"{int(r.elapsed*1000)} ms"
    if cat == "xss" and isinstance(pl, str) and pl in text and "html" in r.headers.get("content-type", ""):
        return "high", "Reflected XSS: payload echoed unencoded in HTML", _snip(text, MARK)
    if cat == "xss" and isinstance(pl, str) and pl in text:
        return "low", "Input reflected unencoded in non-HTML response", _snip(text, MARK)
    if cat == "ssti" and "1787569" in text:
        return "critical", "Server-side template injection (expression evaluated)", _snip(text, "1787569")
    if cat == "cmdi" and re.search(r"uid=\d+\(\w+\)", text):
        return "critical", "OS command injection (id output returned)", _snip(text, "uid=")
    if cat == "traversal" and re.search(r"root:.*:0:0:|\[fonts\]", text):
        return "critical", "Path traversal: system file content returned", _snip(text, "root:")
    if cat == "ssrf" and re.search(r"ami-id|instance-id|SSH-\d", text):
        return "critical", "SSRF: internal resource content returned", text[:200]
    if cat in ("sqli",) and isinstance(pl, str) and "OR" in pl and r.ok and b.get("status") in (401, 403):
        return "critical", "Possible SQL injection auth bypass (2xx where baseline was denied)", f"HTTP {r.status}"
    return None


def _snip(text: str, needle: str, n: int = 160) -> str:
    i = text.lower().find(needle.lower()[:20])
    if i < 0:
        return text[:n]
    return text[max(0, i - 60): i + n]


def _short(pl) -> str:
    s = repr(pl)
    return s if len(s) < 60 else s[:57] + "..."


def shape(js, depth=0):
    if depth > 3:
        return "…"
    if isinstance(js, dict):
        return {k: shape(v, depth + 1) for k, v in list(js.items())[:40]}
    if isinstance(js, list):
        return [shape(js[0], depth + 1)] if js else []
    return type(js).__name__


# ----------------------------------------------------- input limits & rate

def input_limits(c: Client, eps: List[Endpoint], baseline: Dict[str, dict], ctx: Context, max_eps: int = 15) -> List[dict]:
    rows = []
    tested = 0
    special = "<>'\"`;{}$%&|\\‮😀\x00"
    for ep in eps:
        if tested >= max_eps or not c.budget_left():
            break
        if ep.method not in ("POST", "PUT", "PATCH"):
            continue
        b = baseline.get(ep.key) or {}
        if not b.get("status") or b["status"] >= 400:
            continue
        str_params = [p for p in ep.params.values() if p.location in ("body", "query") and p.type in ("string", "email")]
        if not str_params:
            continue
        tested += 1
        for p in str_params[:4]:
            row = {"endpoint": ep.key, "param": p.name, "declared_max": p.max_length}
            accepted_len = 0
            for n in (256, 4096, 65536):
                r = send(c, ep, overrides={p.name: "a" * n})
                if r.ok:
                    accepted_len = n
                else:
                    row["rejected_at"] = n
                    row["reject_status"] = r.status
                    break
            row["max_accepted_tested"] = accepted_len
            r = send(c, ep, overrides={p.name: f"gsa{special}"})
            row["special_chars_status"] = r.status
            row["special_chars_reflected"] = special[:5] in (r.text or "")
            rows.append(row)
            if accepted_len >= 65536:
                ctx.add("low", "input-validation", f"No server-side length limit on '{p.name}'",
                        "A 64 KB string was accepted (2xx).", endpoint=ep.key, file=ep.file, line=ep.line,
                        recommendation="Enforce a max length in the server-side schema/model.")
            if r.ok and p.type == "email":
                ctx.add("low", "input-validation", f"Email field '{p.name}' accepts invalid characters", endpoint=ep.key)
    return rows


def rate_limits(c: Client, eps: List[Endpoint], baseline: Dict[str, dict], ctx: Context, burst: int = 30) -> List[dict]:
    targets = [e for e in eps if AUTHY_PATH.search(e.path) and e.method in ("POST", "GET") and (baseline.get(e.key) or {}).get("status")]
    if not targets:
        targets = [e for e in eps if e.method == "POST" and (baseline.get(e.key) or {}).get("status", 404) < 404][:2]
    rows = []
    for ep in targets[:6]:
        if not c.budget_left():
            break
        statuses, limited_at, hdrs = [], None, {}
        t0 = time.time()
        for i in range(burst):
            path, query, body, headers = build_request(ep)
            r = c.request(ep.method, path, params=query or None, json_body=body if ep.method != "GET" else None,
                          headers=headers, pace=False)
            statuses.append(r.status)
            for k, v in r.headers.items():
                if "ratelimit" in k or k == "retry-after":
                    hdrs[k] = v
            if r.status == 429 and limited_at is None:
                limited_at = i + 1
                break
        dur = time.time() - t0
        row = {"endpoint": ep.key, "burst": len(statuses), "seconds": round(dur, 2), "limited_at": limited_at,
               "rate_limit_headers": hdrs, "status_counts": {str(s): statuses.count(s) for s in set(statuses)}}
        rows.append(row)
        if limited_at is None and not hdrs:
            sev = "medium" if AUTHY_PATH.search(ep.path) else "low"
            ctx.add(sev, "rate-limiting", "No rate limiting observed",
                    f"{len(statuses)} requests in {dur:.1f}s with no 429 or rate-limit headers.", endpoint=ep.key,
                    file=ep.file, line=ep.line,
                    recommendation="Add per-IP/per-account throttling (e.g. express-rate-limit, django-ratelimit, slowapi, platform WAF).")
    return rows
