"""Static endpoint discovery across common web frameworks + OpenAPI specs.

Each endpoint carries the parameters we could infer from the handler body so the
prober can fill them with sensible values.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .util import SOURCE_EXT, iter_files, line_of, read_text, rel

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


@dataclass
class Param:
    name: str
    location: str = "body"  # body | query | path | header
    type: str = "string"
    required: bool = False
    max_length: Optional[int] = None

    def to_dict(self):
        d = {"name": self.name, "in": self.location, "type": self.type}
        if self.required:
            d["required"] = True
        if self.max_length:
            d["max_length"] = self.max_length
        return d


@dataclass
class Endpoint:
    method: str
    path: str
    framework: str
    file: Optional[str] = None
    line: Optional[int] = None
    params: Dict[str, Param] = field(default_factory=dict)
    auth_hint: bool = False
    source: str = "static"  # static | openapi | frontend | live

    @property
    def key(self):
        return f"{self.method} {self.path}"

    def add_param(self, name, location="body", type_="string", required=False, max_length=None):
        if not name or not re.match(r"^[A-Za-z_][\w\-\.]*$", name):
            return
        if name in self.params:
            return
        self.params[name] = Param(name, location, type_, required, max_length)

    def to_dict(self):
        return {
            "method": self.method,
            "path": self.path,
            "framework": self.framework,
            "file": self.file,
            "line": self.line,
            "auth_hint": self.auth_hint,
            "source": self.source,
            "params": [p.to_dict() for p in self.params.values()],
        }


# ---------------------------------------------------------------- path utils

def normalize_path(p: str) -> str:
    p = p.strip()
    if not p.startswith("/"):
        p = "/" + p
    # Django <int:id> / <id>, Flask <int:id>
    p = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", p)
    # Express / Rails :id
    p = re.sub(r":(\w+)", r"{\1}", p)
    # Next.js [id] / [...slug]
    p = re.sub(r"\[\.\.\.(\w+)\]", r"{\1}", p)
    p = re.sub(r"\[(\w+)\]", r"{\1}", p)
    # Django regex groups (?P<id>[0-9]+)
    p = re.sub(r"\(\?P<(\w+)>[^)]*\)", r"{\1}", p)
    p = p.replace("^", "").replace("$", "")
    p = re.sub(r"/+", "/", p)
    return p


def path_params(path: str) -> List[str]:
    return re.findall(r"\{(\w+)\}", path)


# ------------------------------------------------------- parameter inference

PARAM_PATTERNS = [
    # JS / TS
    (r"req\.body\.(\w+)", "body"),
    (r"req\.body\[['\"](\w+)['\"]\]", "body"),
    (r"req\.query\.(\w+)", "query"),
    (r"req\.query\[['\"](\w+)['\"]\]", "query"),
    (r"req\.headers\[['\"]([\w\-]+)['\"]\]", "header"),
    (r"searchParams\.get\(\s*['\"](\w+)['\"]", "query"),
    (r"formData\.get\(\s*['\"](\w+)['\"]", "body"),
    (r"ctx\.request\.body\.(\w+)", "body"),
    (r"body\.(\w+)", "body"),
    # Python
    (r"request\.(?:json|get_json\(\))\s*\[\s*['\"](\w+)['\"]", "body"),
    (r"request\.(?:json|get_json\(\))\.get\(\s*['\"](\w+)['\"]", "body"),
    (r"request\.form(?:\.get\(|\[)\s*['\"](\w+)['\"]", "body"),
    (r"request\.args(?:\.get\(|\[)\s*['\"](\w+)['\"]", "query"),
    (r"request\.(?:POST|data)(?:\.get\(|\[)\s*['\"](\w+)['\"]", "body"),
    (r"request\.(?:GET|query_params)(?:\.get\(|\[)\s*['\"](\w+)['\"]", "query"),
    (r"data(?:\.get\(|\[)\s*['\"](\w+)['\"]", "body"),
    # Ruby
    (r"params\[:(\w+)\]", "body"),
    (r"params\.require\(:\w+\)\.permit\(([^)]*)\)", "permit"),
    # Go
    (r"\.(?:PostForm|FormValue|DefaultPostForm)\(\s*\"(\w+)\"", "body"),
    (r"\.(?:Query|DefaultQuery)\(\s*\"(\w+)\"", "query"),
    # PHP
    (r"\$request->(?:input|get|post)\(\s*['\"](\w+)['\"]", "body"),
    (r"\$_POST\[['\"](\w+)['\"]\]", "body"),
    (r"\$_GET\[['\"](\w+)['\"]\]", "query"),
    # Java
    (r"@RequestParam\([^)]*?(?:value\s*=\s*|name\s*=\s*)?\"(\w+)\"", "query"),
    (r"@RequestHeader\(\s*\"([\w\-]+)\"", "header"),
]

DESTRUCTURE_PATTERNS = [
    (r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?req\.body", "body"),
    (r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?req\.query", "query"),
    (r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?(?:req|request)\.json\(\)", "body"),
    (r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?ctx\.request\.body", "body"),
    (r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?c\.req\.json\(\)", "body"),
]

AUTH_HINTS = re.compile(
    r"login_required|IsAuthenticated|permission_classes|Depends\(\s*get_current_user|"
    r"requireAuth|isAuthenticated|authenticate|authMiddleware|verifyToken|passport\.authenticate|"
    r"@PreAuthorize|@Secured|before_action\s*:authenticate|jwt_required|auth\(\)|withAuth|"
    r"getServerSession|currentUser|ensureLoggedIn|protect\b|requireUser|clerk|auth\.protect",
    re.I,
)

TYPE_HINTS = {
    "int": "integer", "integer": "integer", "float": "number", "number": "number",
    "bool": "boolean", "boolean": "boolean", "str": "string", "string": "string",
    "EmailStr": "email", "UUID": "uuid", "datetime": "datetime", "date": "date",
    "list": "array", "List": "array", "dict": "object", "Dict": "object",
}


def infer_params(ep: Endpoint, window: str, models: Dict[str, Dict[str, Param]]):
    for pat, loc in PARAM_PATTERNS:
        for m in re.finditer(pat, window):
            if loc == "permit":
                for name in re.findall(r":(\w+)", m.group(1)):
                    ep.add_param(name, "body")
            else:
                name = m.group(1)
                if loc == "body" and pat == r"body\.(\w+)" and name in {"json", "then", "length", "data"}:
                    continue
                ep.add_param(name, loc)
    for pat, loc in DESTRUCTURE_PATTERNS:
        for m in re.finditer(pat, window):
            for part in m.group(1).split(","):
                name = part.split(":")[0].split("=")[0].strip().strip(".")
                ep.add_param(name, loc)
    # FastAPI / typed python handler signature: def f(item: Item, q: str = None)
    sig = re.search(r"def\s+\w+\s*\(([^)]*)\)", window)
    if sig and ep.framework in {"fastapi", "flask"}:
        for part in sig.group(1).split(","):
            part = part.strip()
            m = re.match(r"(\w+)\s*:\s*([\w\[\]\.]+)(\s*=\s*(.+))?", part)
            if not m:
                continue
            name, typ = m.group(1), m.group(2)
            if name in {"self", "request", "req", "db", "session", "background_tasks", "response"}:
                continue
            if "Depends" in (m.group(4) or "") or typ in {"Request", "Session", "AsyncSession", "Response"}:
                continue
            base = typ.split(".")[-1]
            if base in models:
                for pn, p in models[base].items():
                    ep.params.setdefault(pn, Param(pn, "body", p.type, p.required, p.max_length))
            elif name in path_params(ep.path):
                continue
            else:
                ep.add_param(name, "query", TYPE_HINTS.get(base, "string"), required=m.group(3) is None)
    for pp in path_params(ep.path):
        ep.params.setdefault(pp, Param(pp, "path", "string", True))
        ep.params[pp].location = "path"
    if AUTH_HINTS.search(window[:1500]):
        ep.auth_hint = True


def collect_pydantic_models(root: Path) -> Dict[str, Dict[str, Param]]:
    models: Dict[str, Dict[str, Param]] = {}
    for f in iter_files(root, {".py"}):
        text = read_text(f)
        if "BaseModel" not in text and "SQLModel" not in text and "Schema" not in text:
            continue
        for m in re.finditer(r"class\s+(\w+)\s*\(([^)]*(?:BaseModel|SQLModel|Schema)[^)]*)\)\s*:\s*\n((?:[ \t]+.*\n?)+)", text):
            fields: Dict[str, Param] = {}
            for fm in re.finditer(r"^[ \t]+(\w+)\s*:\s*([\w\[\]\.\| ]+?)(\s*=\s*(.*))?$", m.group(3), re.M):
                name, typ, default = fm.group(1), fm.group(2).strip(), fm.group(4) or ""
                if name.startswith("_") or name in {"model_config", "Config"}:
                    continue
                base = re.sub(r"Optional\[|\]|\s*\|\s*None", "", typ).split("[")[0].split(".")[-1]
                ml = re.search(r"max_length\s*=\s*(\d+)", default)
                fields[name] = Param(name, "body", TYPE_HINTS.get(base, "string"), fm.group(3) is None,
                                     int(ml.group(1)) if ml else None)
            if fields:
                models[m.group(1)] = fields
    return models


# ------------------------------------------------------------ framework scans

ROUTE_START = re.compile(
    r"@\w+\.(?:route|get|post|put|patch|delete)\(|\b\w+\.(?:get|post|put|patch|delete|all)\(\s*['\"`]/|"
    r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping|Route::\w+\(|HandleFunc\(|\.(?:GET|POST|PUT|PATCH|DELETE)\(\s*\"/"
)


def _window(text: str, idx: int, size: int = 2500) -> str:
    """Handler body: from this route definition up to the next one (max `size` chars)."""
    nxt = ROUTE_START.search(text, idx + 5)
    end = min(idx + size, nxt.start()) if nxt else idx + size
    return text[idx:end]


def scan_express_like(root: Path, f: Path, text: str, out: List[Endpoint], models):
    prefix_map = {}
    # router mounted with a prefix in the same file: app.use('/api', router)
    for m in re.finditer(r"\.use\(\s*['\"`](/[^'\"`]*)['\"`]\s*,\s*(\w+)", text):
        prefix_map[m.group(2)] = m.group(1)
    pat = re.compile(r"\b(\w+)\.(get|post|put|patch|delete|all)\(\s*['\"`](/[^'\"`]*)['\"`]", re.I)
    for m in pat.finditer(text):
        obj, method, path = m.group(1), m.group(2).upper(), m.group(3)
        if obj in {"axios", "http", "https", "fetch", "client", "api", "request", "superagent", "$http", "ky", "got", "instance", "cy", "page", "headers", "params", "searchParams", "map", "cache", "store", "redis", "localStorage", "Object", "self", "this"}:
            continue
        path = prefix_map.get(obj, "") + path
        ep = Endpoint("POST" if method == "ALL" else method, normalize_path(path), "express", rel(root, f), line_of(text, m.start()))
        infer_params(ep, _window(text, m.start()), models)
        out.append(ep)
    # Hono / Fastify route objects: fastify.route({ method: 'POST', url: '/x' })
    for m in re.finditer(r"method\s*:\s*['\"](\w+)['\"][^}]{0,200}?url\s*:\s*['\"](/[^'\"]*)['\"]", text):
        ep = Endpoint(m.group(1).upper(), normalize_path(m.group(2)), "fastify", rel(root, f), line_of(text, m.start()))
        infer_params(ep, _window(text, m.start()), models)
        out.append(ep)


def scan_next(root: Path, f: Path, text: str, out: List[Endpoint], models):
    parts = f.relative_to(root).parts
    if "pages" in parts and "api" in parts:
        i = parts.index("pages")
        route = "/" + "/".join(parts[i + 1:])
        route = re.sub(r"\.(t|j)sx?$|\.mjs$", "", route)
        route = re.sub(r"/index$", "", route) or "/"
        methods = set(re.findall(r"req\.method\s*===?\s*['\"](\w+)['\"]", text)) or {"POST"}
        for meth in methods:
            ep = Endpoint(meth.upper(), normalize_path(route), "nextjs", rel(root, f), 1)
            infer_params(ep, text, models)
            out.append(ep)
    elif "app" in parts and re.match(r"route\.(t|j)sx?$", parts[-1]):
        i = len(parts) - 1 - list(reversed(parts)).index("app")
        segs = [s for s in parts[i + 1:-1] if not (s.startswith("(") and s.endswith(")")) and not s.startswith("@")]
        route = "/" + "/".join(segs)
        for meth in re.findall(r"export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE)\b", text):
            ep = Endpoint(meth, normalize_path(route), "nextjs", rel(root, f), line_of(text, text.find(meth)))
            infer_params(ep, text, models)
            out.append(ep)


def scan_python(root: Path, f: Path, text: str, out: List[Endpoint], models):
    prefixes = {}
    for m in re.finditer(r"(\w+)\s*=\s*(?:APIRouter|Blueprint)\(([^)]*)\)", text):
        pm = re.search(r"(?:prefix|url_prefix)\s*=\s*['\"]([^'\"]*)['\"]", m.group(2))
        prefixes[m.group(1)] = pm.group(1) if pm else ""
    # Flask style
    for m in re.finditer(r"@(\w+)\.route\(\s*['\"]([^'\"]+)['\"]([^)]*)\)", text):
        methods = re.findall(r"['\"](GET|POST|PUT|PATCH|DELETE)['\"]", m.group(3), re.I) or ["GET"]
        for meth in methods:
            ep = Endpoint(meth.upper(), normalize_path(prefixes.get(m.group(1), "") + m.group(2)), "flask", rel(root, f), line_of(text, m.start()))
            infer_params(ep, _window(text, m.start()), models)
            out.append(ep)
    # FastAPI / Flask 2 shortcuts
    for m in re.finditer(r"@(\w+)\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]*)['\"]", text):
        fw = "fastapi" if "fastapi" in text.lower() else "flask"
        ep = Endpoint(m.group(2).upper(), normalize_path(prefixes.get(m.group(1), "") + m.group(3)), fw, rel(root, f), line_of(text, m.start()))
        infer_params(ep, _window(text, m.start()), models)
        out.append(ep)


def scan_django(root: Path, out: List[Endpoint], models):
    url_files = list(iter_files(root, names={"urls.py"}))
    # module path -> prefix from include()
    include_prefix: Dict[str, str] = {}
    for f in url_files:
        text = read_text(f)
        for m in re.finditer(r"(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*include\(\s*['\"]([\w\.]+)['\"]", text):
            include_prefix[m.group(2)] = m.group(1)
    views_cache: Dict[str, str] = {}
    for f in url_files:
        text = read_text(f)
        modpath = ".".join(f.relative_to(root).with_suffix("").parts)
        prefix = ""
        for mod, pre in include_prefix.items():
            if modpath.endswith(mod):
                prefix = pre
        views_file = f.parent / "views.py"
        if str(views_file) not in views_cache:
            views_cache[str(views_file)] = read_text(views_file) if views_file.exists() else ""
        vtext = views_cache[str(views_file)]
        for m in re.finditer(r"(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([\w\.]+)", text):
            if m.group(2) == "include":
                continue
            view = m.group(2).split(".")[-1].replace("as_view", "")
            route = normalize_path(prefix + m.group(1))
            # locate the view body for params / methods
            vm = re.search(rf"(?:def|class)\s+{re.escape(view)}\b", vtext) if view else None
            window = vtext[max(0, vm.start() - 300): vm.start() + 3000] if vm else ""
            methods = re.findall(r"def\s+(get|post|put|patch|delete)\s*\(", window) or \
                re.findall(r"require_http_methods\(\s*\[([^\]]*)\]", window)
            meths = []
            for mm in methods:
                meths += re.findall(r"\w+", mm)
            meths = [x.upper() for x in meths if x.upper() in HTTP_METHODS] or (["POST"] if "request.POST" in window or "request.data" in window else ["GET"])
            for meth in sorted(set(meths)):
                ep = Endpoint(meth, route, "django", rel(root, f), line_of(text, m.start()))
                infer_params(ep, window, models)
                out.append(ep)
        # DRF routers
        for m in re.finditer(r"\.register\(\s*r?['\"]([^'\"]+)['\"]\s*,\s*(\w+)", text):
            base = normalize_path(prefix + m.group(1))
            for meth, p in [("GET", base + "/"), ("POST", base + "/"), ("GET", base + "/{id}/"), ("PUT", base + "/{id}/"), ("PATCH", base + "/{id}/"), ("DELETE", base + "/{id}/")]:
                ep = Endpoint(meth, normalize_path(p), "django-rest", rel(root, f), line_of(text, m.start()))
                infer_params(ep, "", models)
                out.append(ep)


def scan_rails(root: Path, out: List[Endpoint], models):
    for f in iter_files(root, names={"routes.rb"}):
        text = read_text(f)
        for m in re.finditer(r"^\s*(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]", text, re.M):
            out.append(Endpoint(m.group(1).upper(), normalize_path(m.group(2)), "rails", rel(root, f), line_of(text, m.start())))
        for m in re.finditer(r"^\s*resources?\s+:(\w+)", text, re.M):
            b = "/" + m.group(1)
            for meth, p in [("GET", b), ("POST", b), ("GET", b + "/{id}"), ("PATCH", b + "/{id}"), ("DELETE", b + "/{id}")]:
                out.append(Endpoint(meth, p, "rails", rel(root, f), line_of(text, m.start())))
    for ep in out:
        if ep.framework == "rails":
            for pp in path_params(ep.path):
                ep.add_param(pp, "path", required=True)


def scan_spring(root: Path, f: Path, text: str, out: List[Endpoint], models):
    cls = re.search(r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"", text)
    base = cls.group(1) if cls else ""
    for m in re.finditer(r"@(Get|Post|Put|Patch|Delete)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\"", text):
        ep = Endpoint(m.group(1).upper(), normalize_path(base + m.group(2)), "spring", rel(root, f), line_of(text, m.start()))
        infer_params(ep, _window(text, m.start(), 1200), models)
        out.append(ep)


def scan_go(root: Path, f: Path, text: str, out: List[Endpoint], models):
    for m in re.finditer(r"\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete)\(\s*\"(/[^\"]*)\"", text):
        ep = Endpoint(m.group(1).upper(), normalize_path(m.group(2)), "go", rel(root, f), line_of(text, m.start()))
        infer_params(ep, _window(text, m.start()), models)
        out.append(ep)
    for m in re.finditer(r"HandleFunc\(\s*\"(?:(GET|POST|PUT|PATCH|DELETE)\s+)?(/[^\"]*)\"", text):
        ep = Endpoint((m.group(1) or "POST").upper(), normalize_path(m.group(2)), "go-net/http", rel(root, f), line_of(text, m.start()))
        infer_params(ep, _window(text, m.start()), models)
        out.append(ep)


def scan_laravel(root: Path, f: Path, text: str, out: List[Endpoint], models):
    api = "routes/api.php" in str(f).replace("\\", "/")
    for m in re.finditer(r"Route::(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]", text):
        ep = Endpoint(m.group(1).upper(), normalize_path(("/api/" if api else "/") + m.group(2)), "laravel", rel(root, f), line_of(text, m.start()))
        infer_params(ep, "", models)
        out.append(ep)


def scan_openapi(root: Path, out: List[Endpoint]):
    for f in iter_files(root, {".json", ".yaml", ".yml"}):
        if not re.search(r"openapi|swagger|api[-_]?spec", f.name, re.I):
            continue
        try:
            text = read_text(f)
            spec = json.loads(text) if f.suffix == ".json" else yaml.safe_load(text)
        except Exception:
            continue
        if isinstance(spec, dict):
            out.extend(endpoints_from_openapi(spec, rel(root, f)))


def endpoints_from_openapi(spec: dict, source_file: str = "openapi") -> List[Endpoint]:
    eps: List[Endpoint] = []
    paths = spec.get("paths") or {}
    comps = (spec.get("components") or {}).get("schemas") or spec.get("definitions") or {}

    def resolve(s):
        if isinstance(s, dict) and "$ref" in s:
            return comps.get(s["$ref"].split("/")[-1], {})
        return s or {}

    global_sec = bool(spec.get("security"))
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for meth, op in item.items():
            if meth.upper() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            ep = Endpoint(meth.upper(), normalize_path(path), "openapi", source_file, None, source="openapi")
            ep.auth_hint = bool(op.get("security", global_sec))
            for prm in (op.get("parameters") or []) + (item.get("parameters") or []):
                prm = resolve(prm)
                if prm.get("in") in {"query", "path", "header"}:
                    sch = resolve(prm.get("schema") or {})
                    ep.add_param(prm.get("name"), prm["in"], sch.get("format") or sch.get("type", "string"),
                                 prm.get("required", False), sch.get("maxLength"))
                elif prm.get("in") == "body":
                    sch = resolve(prm.get("schema"))
                    for n, ps in (sch.get("properties") or {}).items():
                        ps = resolve(ps)
                        ep.add_param(n, "body", ps.get("format") or ps.get("type", "string"), n in (sch.get("required") or []), ps.get("maxLength"))
            body = ((op.get("requestBody") or {}).get("content") or {})
            for ctype, cval in body.items():
                sch = resolve(cval.get("schema"))
                for n, ps in (sch.get("properties") or {}).items():
                    ps = resolve(ps)
                    ep.add_param(n, "body", ps.get("format") or ps.get("type", "string"), n in (sch.get("required") or []), ps.get("maxLength"))
                break
            for pp in path_params(ep.path):
                ep.add_param(pp, "path", required=True)
            eps.append(ep)
    return eps


FRONTEND_CALL = re.compile(
    r"(?:fetch|axios(?:\.(get|post|put|patch|delete))?|\$http\.(get|post|put|patch|delete)|api\.(get|post|put|patch|delete)|ky\.(get|post|put|patch|delete))\(\s*[`'\"]((?:https?://[^/'\"`]+)?/[^'\"`\s]*)[`'\"]",
    re.I,
)


def scan_frontend_calls(root: Path, f: Path, text: str, out: List[Endpoint], models):
    for m in FRONTEND_CALL.finditer(text):
        meth = next((g for g in m.groups()[:4] if g), None)
        url = m.group(5)
        path = re.sub(r"^https?://[^/]+", "", url)
        path = re.sub(r"\$\{[^}]*\}", "{id}", path).split("?")[0]
        if not path or path == "/" or re.search(r"\.(png|jpe?g|svg|css|js|ico|woff2?|json)$", path):
            continue
        if not meth:
            mm = re.search(r"method\s*:\s*['\"](\w+)['\"]", text[m.end(): m.end() + 300])
            meth = mm.group(1) if mm else "GET"
        ep = Endpoint(meth.upper(), normalize_path(path), "frontend-call", rel(root, f), line_of(text, m.start()), source="frontend")
        # body: JSON.stringify({ a, b: c })
        bm = re.search(r"JSON\.stringify\(\s*\{([^}]*)\}", text[m.end(): m.end() + 600])
        if bm:
            for part in bm.group(1).split(","):
                name = part.split(":")[0].strip()
                ep.add_param(name, "body")
        for pp in path_params(ep.path):
            ep.add_param(pp, "path", required=True)
        out.append(ep)


# ------------------------------------------------------------------- driver

def discover(root: Path) -> List[Endpoint]:
    models = collect_pydantic_models(root)
    out: List[Endpoint] = []
    scan_django(root, out, models)
    scan_rails(root, out, models)
    scan_openapi(root, out)
    for f in iter_files(root, SOURCE_EXT):
        text = read_text(f)
        if not text:
            continue
        suf = f.suffix.lower()
        relp = str(f.relative_to(root)).replace("\\", "/")
        if suf in {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}:
            if "/pages/api/" in "/" + relp or re.search(r"(^|/)app/.*route\.(t|j)sx?$", relp):
                scan_next(root, f, text, out, models)
            elif re.search(r"express|router|fastify|koa|hono|app\.(get|post)", text):
                scan_express_like(root, f, text, out, models)
            scan_frontend_calls(root, f, text, out, models)
        elif suf in {".vue", ".svelte", ".astro"}:
            scan_frontend_calls(root, f, text, out, models)
        elif suf == ".py" and f.name != "urls.py":
            scan_python(root, f, text, out, models)
        elif suf in {".java", ".kt"}:
            scan_spring(root, f, text, out, models)
        elif suf == ".go":
            scan_go(root, f, text, out, models)
        elif suf == ".php":
            scan_laravel(root, f, text, out, models)
    return dedupe(out)


def dedupe(eps: List[Endpoint]) -> List[Endpoint]:
    merged: Dict[str, Endpoint] = {}
    rank = {"static": 0, "openapi": 1, "live": 2, "frontend": 3}
    for ep in eps:
        k = ep.key.rstrip("/") or ep.key
        if k in merged:
            cur = merged[k]
            for n, p in ep.params.items():
                cur.params.setdefault(n, p)
            cur.auth_hint = cur.auth_hint or ep.auth_hint
            if rank.get(ep.source, 9) < rank.get(cur.source, 9):
                cur.file, cur.line, cur.framework, cur.source = ep.file, ep.line, ep.framework, ep.source
        else:
            merged[k] = ep
    return sorted(merged.values(), key=lambda e: (e.path, e.method))
