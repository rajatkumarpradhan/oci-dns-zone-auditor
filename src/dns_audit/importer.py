"""Convert a realistic zone export (OCI CLI `oci dns zone get`-style) into the simplified zone JSON.

Accepted shapes: an object with a "data" envelope holding "name" and "items" (the OCI
CLI response), or an unwrapped object with "name" and "items" directly. Each item
needs "domain", "rtype", "ttl" and "rdata"; extra OCI fields (is-protected,
record-hash, compartment-id, ...) are ignored. Items are passed through as written
(absolute names keep their trailing dot); the model canonicalises them on load.

Line numbers in errors are best-effort: the CLI pretty-prints by default, so each
record is located by searching the raw text for its domain (or rdata). A minified
file reports line 1. Row indexes (items[i]) are always exact.
"""
from __future__ import annotations

import json

from . import model


class ImportError(ValueError):
    pass


class _Lines:
    """Best-effort line lookup: find needles in the source text, scanning forward."""

    def __init__(self, text: str):
        self.text = text
        self.pos = 0

    def find(self, needle: str) -> int | None:
        i = self.text.find(needle, self.pos)
        if i < 0:
            return None
        self.pos = i + len(needle)
        return self.text.count("\n", 0, i) + 1


def _convert_row(row, where, zone, errors):
    if not isinstance(row, dict):
        errors.append(f"{where}: must be an object, got {type(row).__name__}")
        return None

    def err(msg):
        errors.append(f"{where}: {msg}")

    domain = row.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        err("domain must be a non-empty string")
        return None
    try:
        model._name(domain, zone, "domain")          # shape validation only; output keeps the original
    except model.ModelError as e:
        err(str(e))
        return None
    rtype = row.get("rtype")
    if not isinstance(rtype, str) or not model.TYPES.match(rtype.upper()):
        err(f"rtype must be a valid record type token, got {rtype!r}")
        return None
    ttl = row.get("ttl")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= 2147483647:
        err(f"ttl must be an integer in [0, 2147483647], got {ttl!r}")
        return None
    rdata = row.get("rdata")
    if not isinstance(rdata, str) or not rdata.strip():
        err("rdata must be a non-empty string")
        return None
    return {"name": domain, "type": rtype.upper(), "ttl": ttl, "rdata": rdata}


def convert(data, text: str = "") -> dict:
    """Convert one parsed export into simplified-zone data.

    Raises ImportError listing every row that could not be mapped.
    """
    body = data.get("data") if isinstance(data, dict) else None
    if not isinstance(body, dict):
        body = data
    if not isinstance(body, dict) or not isinstance(body.get("items"), list):
        raise ImportError('export must be an object with "name" and "items", optionally inside a "data" envelope')
    zone = body.get("name")
    if not isinstance(zone, str) or not zone.strip():
        raise ImportError('export "name" must be a non-empty zone name string')
    zone = zone.strip().lower().rstrip(".")
    try:
        model._name(zone, "", "name")
    except model.ModelError as e:
        raise ImportError(f'export "name" is not a valid zone: {e}') from None
    lines = _Lines(text)
    errors, records = [], []
    for i, row in enumerate(body["items"]):
        anchor = None
        if isinstance(row, dict):
            for key in ("domain", "rdata"):
                raw = row.get(key)
                if isinstance(raw, str) and raw:
                    anchor = lines.find(json.dumps(raw))
                    if anchor:
                        break
        where = f"items[{i}]" + (f" (line {anchor})" if anchor else "")
        r = _convert_row(row, where, zone, errors)
        if r is not None:
            records.append(r)
    if errors:
        raise ImportError("cannot import export:\n" + "\n".join(f"  {e}" for e in errors))
    return {"zone": zone, "records": records}


def load_export(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return convert(json.loads(text), text)
