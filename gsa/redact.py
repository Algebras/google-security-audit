"""Scrub captured credentials and secret-looking strings before a report leaves the machine."""
from __future__ import annotations

import re
from typing import Any, Iterable

PATTERNS = [
    re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),            # JWT
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-\._~\+/]{12,}=*"),                               # bearer
    re.compile(r"(?i)((?:session|sess|sid|token|csrftoken|auth)[\w\-]*=)[^;\s\"']{8,}"),    # cookie pairs
    re.compile(r"AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|sk_live_[0-9a-zA-Z]{20,}|sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,}"),
    re.compile(r"(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s/]+:)[^@\s]+(@)"),
]


def _scrub_str(s: str, secrets: Iterable[str]) -> str:
    for sec in secrets:
        if sec and len(sec) >= 6 and sec in s:
            s = s.replace(sec, "[REDACTED]")
    for rx in PATTERNS:
        def repl(m):
            if m.lastindex and m.lastindex >= 1 and rx.pattern.startswith("(?i)((?:postgres"):
                return m.group(1) + "[REDACTED]" + m.group(2)
            if m.lastindex:
                return m.group(1) + "[REDACTED]"
            return "[REDACTED]"
        s = rx.sub(repl, s)
    return s


def scrub(obj: Any, secrets: Iterable[str] = ()) -> Any:
    secrets = sorted({s for s in secrets if s}, key=len, reverse=True)
    if isinstance(obj, str):
        return _scrub_str(obj, secrets)
    if isinstance(obj, dict):
        return {k: scrub(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub(v, secrets) for v in obj]
    return obj
