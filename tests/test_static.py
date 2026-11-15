from pathlib import Path

from gsa import endpoints, schema
from gsa.redact import scrub

FIX = Path(__file__).parent / "fixture_app"


def test_endpoints_discovered():
    keys = {e.key for e in endpoints.discover(FIX)}
    assert "POST /api/login" in keys
    assert "GET /search" in keys
    login = next(e for e in endpoints.discover(FIX) if e.key == "POST /api/login")
    assert {"email", "password"} <= set(login.params)


def test_schema_from_sql():
    t = schema.static_schema(FIX)
    assert "users" in t and "posts" in t
    assert any(c.get("fk") == "users.id" for c in t["posts"]["columns"])
    assert "erDiagram" in schema.to_mermaid(t)


def test_redaction():
    out = scrub({"h": "Authorization: Bearer abcdefghijklmnop1234", "c": "session=supersecret123"}, ["supersecret123"])
    assert "abcdefghijklmnop1234" not in str(out) and "supersecret123" not in str(out)
