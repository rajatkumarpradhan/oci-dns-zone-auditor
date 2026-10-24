"""Load and validate a DNS zone export (this project's own schema, not the OCI DNS API shape).

One file holds the zone name, optional config and the records. Names may be "@"
(the apex), relative ("www") or absolute with a trailing dot ("www.example.com.");
they are stored canonicalised to a lower-case fully-qualified name without the
trailing dot. The data is expected to come from an export a user already has;
the auditor makes no DNS queries.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


class ModelError(ValueError):
    pass


TYPES = re.compile(r"^[A-Z][A-Z0-9]{0,9}$")
LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")


@dataclass
class Record:
    name: str        # canonical fqdn, lower-case, no trailing dot
    type: str        # upper-case record type
    ttl: int
    rdata: str


@dataclass
class Zone:
    name: str        # canonical zone name
    min_ttl: int = 60
    records: list[Record] = field(default_factory=list)
    expected_ns: list[str] = field(default_factory=list)  # canonical nameserver hostnames


def _str(v, what):
    if not isinstance(v, str) or not v.strip():
        raise ModelError(f"{what} must be a non-empty string")
    return v


def _name(v, zone, what):
    """Canonicalise @ / relative / absolute names against the zone."""
    v = _str(v, what).strip().lower()
    if v == "@":
        return zone
    if v.endswith("."):
        v = v[:-1]
    elif zone:
        v = f"{v}.{zone}"
    labels = v.split(".")
    wild = labels[0] == "*"
    if (len(v) > 253 or (wild and len(labels) == 1)
            or not all(LABEL.match(p) for p in labels[1 if wild else 0:])):
        raise ModelError(f"{what} is not a valid DNS name: {v!r}")
    return v


def _host(v, what):
    """Canonicalise an absolute hostname (nameserver target): lower-case, no trailing dot."""
    v = _str(v, what).strip().lower().rstrip(".")
    if len(v) > 253 or not all(LABEL.match(p) for p in v.split(".")):
        raise ModelError(f"{what} is not a valid DNS name: {v!r}")
    return v


def load(data: dict) -> Zone:
    try:
        zone = _str(data.get("zone"), "zone").strip().lower().rstrip(".")
        if len(zone) > 253 or not all(LABEL.match(p) for p in zone.split(".")):
            raise ModelError(f"zone is not a valid DNS name: {zone!r}")
        cfg = data.get("config", {})
        if not isinstance(cfg, dict):
            raise ModelError("config must be an object")
        min_ttl = cfg.get("min_ttl", 60)
        if isinstance(min_ttl, bool) or not isinstance(min_ttl, int) or not 1 <= min_ttl <= 86400:
            raise ModelError(f"config.min_ttl must be an integer in [1, 86400], got {min_ttl!r}")
        expected_ns = cfg.get("expected_ns", [])
        if not isinstance(expected_ns, list):
            raise ModelError("config.expected_ns must be a list of nameserver hostnames")
        expected_ns = [_host(v, f"config.expected_ns[{i}]") for i, v in enumerate(expected_ns)]
        records = []
        for i, r in enumerate(data.get("records", [])):
            w = f"records[{i}]"
            if not isinstance(r, dict):
                raise ModelError(f"{w} must be an object")
            rtype = _str(r.get("type"), f"{w}.type").upper()
            if not TYPES.match(rtype):
                raise ModelError(f"{w}.type is not a valid record type: {rtype!r}")
            ttl = r.get("ttl")
            if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= 2147483647:
                raise ModelError(f"{w}.ttl must be an integer in [0, 2147483647], got {ttl!r}")
            records.append(Record(_name(r.get("name"), zone, f"{w}.name"), rtype, ttl,
                                  _str(r.get("rdata"), f"{w}.rdata")))
    except (TypeError, AttributeError) as e:
        raise ModelError(f"invalid model: {e!r}") from e
    return Zone(zone, min_ttl, records, expected_ns)


def load_file(path: str) -> Zone:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
