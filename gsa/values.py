"""Generate plausible values for request parameters based on name and type."""
from __future__ import annotations

import re
import uuid
from typing import Any

RULES = [
    (r"e-?mail", lambda: "gsa.tester@example.com"),
    (r"pass(word)?|pwd|secret", lambda: "GsaTest!2345"),
    (r"^(user(name)?|login|handle|nick)", lambda: "gsa_tester"),
    (r"first_?name|given", lambda: "Gsa"),
    (r"last_?name|surname|family", lambda: "Tester"),
    (r"(full_?)?name|title|label", lambda: "GSA Test"),
    (r"phone|mobile|tel", lambda: "+15555550123"),
    (r"url|link|website|href|callback|redirect", lambda: "https://example.com/gsa"),
    (r"uuid|guid", lambda: str(uuid.uuid4())),
    (r"(^|_)id$|Id$|_pk$|^pk$", lambda: 1),
    (r"date|_at$|time|dob|birthday", lambda: "2024-01-01T00:00:00Z"),
    (r"amount|price|total|cost|balance|qty|quantity|count|age|limit|size|page|offset|number|num|rating|score|year", lambda: 1),
    (r"^(is|has|can|should|allow|enable)|active|enabled|verified|agree|accept|remember", lambda: True),
    (r"token|otp|code|nonce|key", lambda: "000000"),
    (r"zip|postal", lambda: "10001"),
    (r"country", lambda: "US"),
    (r"city", lambda: "New York"),
    (r"address|street", lambda: "1 Test Street"),
    (r"lang|locale", lambda: "en"),
    (r"currency", lambda: "USD"),
    (r"color|colour", lambda: "#336699"),
    (r"ip", lambda: "203.0.113.10"),
    (r"lat", lambda: 40.7128),
    (r"lng|lon", lambda: -74.006),
    (r"tags|ids|items|list", lambda: ["gsa"]),
    (r"message|comment|body|content|text|desc|note|bio|query|q|search|term|feedback", lambda: "gsa test input"),
    (r"slug", lambda: "gsa-test"),
    (r"role", lambda: "user"),
    (r"status|state|type|kind|category", lambda: "active"),
    (r"file|image|avatar|photo", lambda: "gsa.png"),
]

TYPE_DEFAULTS = {
    "integer": 1, "int": 1, "number": 1, "float": 1.0, "boolean": True, "bool": True,
    "email": "gsa.tester@example.com", "uuid": None, "date": "2024-01-01", "date-time": "2024-01-01T00:00:00Z",
    "datetime": "2024-01-01T00:00:00Z", "array": ["gsa"], "object": {"gsa": "test"}, "uri": "https://example.com/gsa",
}


def value_for(name: str, type_: str = "string") -> Any:
    t = (type_ or "string").lower()
    if t == "uuid":
        return str(uuid.uuid4())
    if t in TYPE_DEFAULTS and t != "string":
        return TYPE_DEFAULTS[t]
    for pat, fn in RULES:
        if re.search(pat, name, re.I):
            return fn()
    return "gsa-test"
