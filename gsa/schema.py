"""Map the database schema from SQL files, ORM models and live endpoint responses."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from .util import iter_files, read_text, rel

QQ = '`"'


def _table(tables, name, source):
    key = name.strip('`"[]').split(".")[-1]
    t = tables.setdefault(key.lower(), {"name": key, "source": source, "columns": [], "relations": []})
    return t


def _col(t, name, typ, pk=False, fk=None, nullable=True):
    if any(c["name"] == name for c in t["columns"]):
        return
    c = {"name": name, "type": typ}
    if pk:
        c["pk"] = True
    if fk:
        c["fk"] = fk
        t["relations"].append({"column": name, "references": fk})
    if not nullable:
        c["required"] = True
    t["columns"].append(c)


def parse_sql(text, source, tables):
    for m in re.finditer(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"\[\]\w\.]+)\s*\((.*?)\)\s*;", text, re.I | re.S):
        t = _table(tables, m.group(1), source)
        body = m.group(2)
        parts, depth, cur = [], 0, ""
        for ch in body:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if ch == "," and depth == 0:
                parts.append(cur)
                cur = ""
            else:
                cur += ch
        parts.append(cur)
        pks = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            up = p.upper()
            if up.startswith("PRIMARY KEY"):
                pks += [x.strip('`" ') for x in re.findall(r"\(([^)]*)\)", p)[0].split(",")]
                continue
            fkm = re.match(r"(?:CONSTRAINT\s+\S+\s+)?FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+([`\"\w\.]+)\s*\(([^)]+)\)", p, re.I)
            if fkm:
                col = fkm.group(1).strip('`" ')
                ref = fkm.group(2).strip(QQ) + "." + fkm.group(3).strip(QQ + " ")
                for c in t["columns"]:
                    if c["name"] == col:
                        c["fk"] = ref
                t["relations"].append({"column": col, "references": ref})
                continue
            if re.match(r"(CONSTRAINT|UNIQUE|INDEX|KEY|CHECK)\b", up):
                continue
            cm = re.match(r"([`\"\[]?\w+[`\"\]]?)\s+([\w]+(?:\s*\([^)]*\))?)(.*)", p, re.S)
            if cm:
                rest = cm.group(3)
                ref = re.search(r"REFERENCES\s+([`\"\w\.]+)\s*\(([^)]+)\)", rest, re.I)
                _col(t, cm.group(1).strip('`"[]'), cm.group(2), "PRIMARY KEY" in rest.upper(),
                     (ref.group(1).strip(QQ) + "." + ref.group(2).strip(QQ + " ")) if ref else None, "NOT NULL" not in rest.upper())
        for c in t["columns"]:
            if c["name"] in pks:
                c["pk"] = True


def parse_prisma(text, source, tables):
    for m in re.finditer(r"model\s+(\w+)\s*\{(.*?)\n\}", text, re.S):
        t = _table(tables, m.group(1), source)
        for line in m.group(2).splitlines():
            lm = re.match(r"\s*(\w+)\s+(\w+)(\[\])?(\?)?(.*)", line)
            if not lm or lm.group(1).startswith("@@"):
                continue
            name, typ, arr, opt, rest = lm.groups()
            rel_m = re.search(r"@relation\([^)]*fields:\s*\[(\w+)\][^)]*references:\s*\[(\w+)\]", rest)
            if rel_m:
                t["relations"].append({"column": rel_m.group(1), "references": f"{typ}.{rel_m.group(2)}"})
                for c in t["columns"]:
                    if c["name"] == rel_m.group(1):
                        c["fk"] = f"{typ}.{rel_m.group(2)}"
                continue
            if arr and typ[0].isupper() and typ not in ("String", "Int", "Float", "Boolean", "DateTime", "Json", "Bytes", "Decimal", "BigInt"):
                continue
            _col(t, name, typ + (arr or ""), "@id" in rest, None, not opt)


def parse_django(text, source, tables):
    for m in re.finditer(r"class\s+(\w+)\s*\([^)]*models\.Model[^)]*\)\s*:\s*\n((?:[ \t]+.*\n?|\s*\n)+)", text):
        t = _table(tables, m.group(1), source)
        _col(t, "id", "AutoField", pk=True)
        for fm in re.finditer(r"^[ \t]+(\w+)\s*=\s*models\.(\w+)\(([^)]*)\)?", m.group(2), re.M):
            name, typ, args = fm.groups()
            fk = None
            if typ in ("ForeignKey", "OneToOneField", "ManyToManyField"):
                tgt = re.match(r"\s*['\"]?([\w\.]+)['\"]?", args or "")
                fk = f"{tgt.group(1).split('.')[-1]}.id" if tgt else None
                name = name + ("_id" if typ != "ManyToManyField" else "")
            ml = re.search(r"max_length\s*=\s*(\d+)", args or "")
            _col(t, name, typ + (f"({ml.group(1)})" if ml else ""), "primary_key=True" in (args or ""), fk, "null=True" in (args or ""))


def parse_sqlalchemy(text, source, tables):
    for m in re.finditer(r"class\s+(\w+)\s*\(([^)]*)\)\s*:\s*\n((?:[ \t]+.*\n?|\s*\n)+)", text):
        body = m.group(3)
        if "Column(" not in body and "mapped_column(" not in body and "Field(" not in body:
            continue
        if "table=True" not in m.group(2) and "__tablename__" not in body and "Base" not in m.group(2):
            continue
        tn = re.search(r"__tablename__\s*=\s*['\"](\w+)['\"]", body)
        t = _table(tables, tn.group(1) if tn else m.group(1), source)
        for fm in re.finditer(r"^[ \t]+(\w+)\s*(?::\s*[\w\[\]\. |]+)?\s*=\s*(?:Column|mapped_column|Field)\(([^\n]*)", body, re.M):
            name, args = fm.groups()
            typ = re.match(r"\s*(\w+)", args)
            fk = re.search(r"ForeignKey\(\s*['\"]([\w\.]+)['\"]", args) or re.search(r"foreign_key\s*=\s*['\"]([\w\.]+)['\"]", args)
            _col(t, name, typ.group(1) if typ else "?", "primary_key=True" in args, fk.group(1) if fk else None, "nullable=False" not in args)


def parse_rails(text, source, tables):
    for m in re.finditer(r'create_table\s+"(\w+)"(.*?)\n\s*end', text, re.S):
        t = _table(tables, m.group(1), source)
        if "id: false" not in m.group(2):
            _col(t, "id", "bigint", pk=True)
        for cm in re.finditer(r't\.(\w+)\s+"(\w+)"(.*)', m.group(2)):
            typ, name, rest = cm.groups()
            fk = f"{name[:-3]}s.id" if name.endswith("_id") else None
            _col(t, name, typ, False, fk, "null: false" not in rest)
    for m in re.finditer(r'add_foreign_key\s+"(\w+)",\s+"(\w+)"', text):
        if m.group(1).lower() in tables:
            tables[m.group(1).lower()]["relations"].append({"column": m.group(2).rstrip("s") + "_id", "references": f"{m.group(2)}.id"})


def parse_drizzle(text, source, tables):
    for m in re.finditer(r"(?:pgTable|mysqlTable|sqliteTable)\(\s*['\"](\w+)['\"]\s*,\s*\{(.*?)\}\s*[,)]", text, re.S):
        t = _table(tables, m.group(1), source)
        for cm in re.finditer(r"(\w+)\s*:\s*(\w+)\(([^)]*)\)([^,\n]*)", m.group(2)):
            name, typ, _, chain = cm.groups()
            ref = re.search(r"references\(\s*\(\)\s*=>\s*(\w+)\.(\w+)", chain)
            _col(t, name, typ, "primaryKey" in chain, f"{ref.group(1)}.{ref.group(2)}" if ref else None, ".notNull" not in chain)


def parse_mongoose(text, source, tables):
    for m in re.finditer(r"(?:const|let)\s+(\w+)\s*=\s*new\s+(?:mongoose\.)?Schema\(\s*\{(.*?)\}\s*(?:,|\))", text, re.S):
        name = re.sub(r"Schema$", "", m.group(1), flags=re.I) or m.group(1)
        t = _table(tables, name, source)
        _col(t, "_id", "ObjectId", pk=True)
        for cm in re.finditer(r"^\s*(\w+)\s*:\s*(\{[^}]*\}|\[?[\w\.]+\]?)", m.group(2), re.M):
            fname, spec = cm.groups()
            typ = re.search(r"type\s*:\s*\[?([\w\.]+)", spec)
            ref = re.search(r"ref\s*:\s*['\"](\w+)['\"]", spec)
            _col(t, fname, (typ.group(1) if typ else spec).split(".")[-1], False, f"{ref.group(1)}._id" if ref else None)


def parse_typeorm(text, source, tables):
    for m in re.finditer(r"@Entity\(([^)]*)\)\s*(?:export\s+)?class\s+(\w+)(.*?)\n\}", text, re.S):
        tn = re.search(r"['\"](\w+)['\"]", m.group(1))
        t = _table(tables, tn.group(1) if tn else m.group(2), source)
        for cm in re.finditer(r"@(PrimaryGeneratedColumn|PrimaryColumn|Column|ManyToOne|OneToOne)\(([^)]*)\)[^\n]*\n\s*(\w+)[!?]?\s*:\s*(\w+)", m.group(3)):
            deco, args, name, typ = cm.groups()
            fk = f"{typ}.id" if deco in ("ManyToOne", "OneToOne") else None
            _col(t, name + ("Id" if fk else ""), typ, deco.startswith("Primary"), fk)


def static_schema(root: Path) -> Dict[str, dict]:
    tables: Dict[str, dict] = {}
    for f in iter_files(root, {".sql", ".prisma", ".py", ".rb", ".ts", ".js"}):
        text = read_text(f)
        if not text:
            continue
        src = rel(root, f)
        suf = f.suffix
        if suf == ".sql" and re.search(r"CREATE\s+TABLE", text, re.I):
            parse_sql(text, src, tables)
        elif suf == ".prisma":
            parse_prisma(text, src, tables)
        elif suf == ".py":
            if "models.Model" in text:
                parse_django(text, src, tables)
            if "Column(" in text or "mapped_column(" in text or "table=True" in text:
                parse_sqlalchemy(text, src, tables)
        elif suf == ".rb" and "create_table" in text:
            parse_rails(text, src, tables)
        elif suf in (".ts", ".js"):
            if re.search(r"pgTable|mysqlTable|sqliteTable", text):
                parse_drizzle(text, src, tables)
            if "Schema(" in text and "mongoose" in text:
                parse_mongoose(text, src, tables)
            if "@Entity" in text:
                parse_typeorm(text, src, tables)
    for t in tables.values():
        for r in t["relations"]:
            for c in t["columns"]:
                if c["name"] == r["column"]:
                    c.setdefault("fk", r["references"])
    return tables


def infer_from_responses(probe_results: Dict[str, dict], tables: Dict[str, dict]):
    """Add tables inferred from JSON response shapes, e.g. GET /api/users -> users."""
    for key, res in probe_results.items():
        shp = res.get("json_shape") if isinstance(res, dict) else None
        if not shp:
            continue
        path = key.split(" ", 1)[1]
        segs = [s for s in path.strip("/").split("/") if s and not s.startswith("{") and s not in ("api", "v1", "v2", "v3")]
        if not segs:
            continue
        obj = shp
        if isinstance(obj, list):
            obj = obj[0] if obj else None
        if isinstance(obj, dict):
            for wrap in ("data", "results", "items", segs[-1]):
                if isinstance(obj.get(wrap), list) and obj[wrap] and isinstance(obj[wrap][0], dict):
                    obj = obj[wrap][0]
                    break
                if isinstance(obj.get(wrap), dict):
                    obj = obj[wrap]
                    break
        if not isinstance(obj, dict) or len(obj) < 2:
            continue
        name = segs[-1]
        if name.lower() in tables and tables[name.lower()]["source"] != "inferred":
            continue
        t = _table(tables, name, "inferred")
        t["source"] = "inferred"
        t.setdefault("from_endpoints", [])
        if key not in t["from_endpoints"]:
            t["from_endpoints"].append(key)
        for k, v in obj.items():
            typ = v if isinstance(v, str) else ("object" if isinstance(v, dict) else "array")
            fk = f"{k[:-3]}s.id" if k.endswith("_id") else (f"{k[:-2]}s.id" if k.endswith("Id") and len(k) > 2 else None)
            _col(t, k, typ, k in ("id", "_id", "uuid"), fk)


def to_mermaid(tables: Dict[str, dict]) -> str:
    def ident(s):
        return re.sub(r"\W", "_", s) or "x"
    lines = ["erDiagram"]
    names = {k: ident(v["name"]) for k, v in tables.items()}
    for k, t in tables.items():
        lines.append(f"  {names[k]} {{")
        for c in t["columns"][:40]:
            typ = ident(re.sub(r"\(.*", "", str(c["type"])) or "any")
            tag = " PK" if c.get("pk") else (" FK" if c.get("fk") else "")
            lines.append(f"    {typ} {ident(c['name'])}{tag}")
        lines.append("  }")
    for k, t in tables.items():
        for r in t["relations"]:
            target = r["references"].split(".")[0].lower()
            cand = [target, target.rstrip("s"), target + "s", target + "es"]
            tgt = next((names[c] for c in cand if c in names), None)
            if tgt:
                lines.append(f"  {tgt} ||--o{{ {names[k]} : \"{ident(r['column'])}\"")
    return "\n".join(lines)
