"""Shared helpers: repo walking, findings, logging."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".cache", "coverage", "vendor",
    "target", ".idea", ".vscode", "bower_components", ".mypy_cache", ".pytest_cache",
    "site-packages", ".terraform", "out", ".output", ".vercel", "Pods",
}

SOURCE_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".rb",
    ".go", ".java", ".kt", ".php", ".cs", ".rs", ".html", ".htm", ".erb", ".ejs",
    ".hbs", ".astro",
}

MAX_FILE_BYTES = 1_500_000

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    endpoint: Optional[str] = None
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass
class Context:
    repo: Path
    findings: list = field(default_factory=list)
    verbose: bool = False

    def add(self, *args, **kwargs):
        f = Finding(*args, **kwargs)
        self.findings.append(f)
        return f


def iter_files(root: Path, exts: Optional[set] = None, names: Optional[set] = None) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") or d in {".github", ".env"}]
        for fn in filenames:
            p = Path(dirpath) / fn
            if names is not None and fn in names:
                yield p
                continue
            if exts is not None and p.suffix.lower() in exts:
                yield p
            elif exts is None and names is None:
                yield p


def read_text(p: Path) -> str:
    try:
        if p.stat().st_size > MAX_FILE_BYTES:
            return ""
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def rel(root: Path, p: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return str(p)


def line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


if os.name == "nt":  # enable ANSI colours in Windows consoles
    os.system("")

_COLORS = {"info": "36", "ok": "32", "warn": "33", "err": "31", "head": "1;35"}


def log(msg: str, kind: str = "info"):
    if sys.stdout.isatty():
        print(f"\033[{_COLORS.get(kind, '0')}m[gsa]\033[0m {msg}", flush=True)
    else:
        print(f"[gsa] {msg}", flush=True)
