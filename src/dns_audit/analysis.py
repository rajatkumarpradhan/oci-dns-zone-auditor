"""DNS zone hygiene rules. Findings are review priorities from offline zone data, not a security verdict."""
from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass

from .model import Zone

SEV = {"high": 0, "medium": 1, "low": 2}

# Explicit leak ranges (RFC1918, loopback, link-local, CGNAT). Broader "not globally
# routable" sets like documentation prefixes are NOT flagged on purpose.
PRIVATE_V4 = [ipaddress.ip_network(c) for c in
              ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
               "169.254.0.0/16", "100.64.0.0/10")]
PRIVATE_V6 = [ipaddress.ip_network(c) for c in ("::1/128", "fc00::/7", "fe80::/10")]

# Suffixes where a dangling CNAME can mean an unclaimed resource (subdomain takeover
# candidate). A match is a hint only: whether the target is actually unclaimed cannot
# be checked offline.
CLOUD_SUFFIXES = ("amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "azurewebsites.net",
                  "cloudapp.net", "trafficmanager.net", "azureedge.net", "github.io",
                  "herokuapp.com", "herokudns.com", "fastly.net", "appspot.com", "web.app")


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = PRIVATE_V4 if addr.version == 4 else PRIVATE_V6
    return any(addr in n for n in nets)


def _target(fqdn_rdata: str) -> str:
    return fqdn_rdata.strip().lower().rstrip(".")


def analyze(zone: Zone) -> list[Finding]:
    out: list[Finding] = []
    names = {r.name for r in zone.records}
    by_name: dict[str, list] = {}
    for r in zone.records:
        by_name.setdefault(r.name, []).append(r)

    apex_txt = [r for r in by_name.get(zone.name, []) if r.type == "TXT"]
    apex_mx = [r for r in by_name.get(zone.name, []) if r.type == "MX"]
    apex_ns = [r for r in by_name.get(zone.name, []) if r.type == "NS"]

    if not apex_ns:
        out.append(Finding("DZ010", "low", f"zone:{zone.name}",
                           "Zone has no NS records at the apex; delegations usually need at least two.", {}))

    if zone.expected_ns:
        expected = set(zone.expected_ns)
        actual = {_target(r.rdata) for r in apex_ns}
        for ns in sorted(actual - expected):
            out.append(Finding("DZ011", "medium", f"zone:{zone.name}",
                               f"Apex NS record {ns} is not in the expected nameserver set; "
                               "the delegation may be stale or misconfigured.", {"ns": ns}))
        for ns in sorted(expected - actual):
            out.append(Finding("DZ011", "medium", f"zone:{zone.name}",
                               f"Expected nameserver {ns} has no NS record at the apex; "
                               "the delegation looks incomplete against the expected set.", {"ns": ns}))

    if apex_mx and not any("v=spf1" in r.rdata.lower() for r in apex_txt):
        out.append(Finding("DZ004", "medium", f"zone:{zone.name}",
                           "Zone has MX records but no SPF TXT record at the apex; spoofed mail is harder to reject.", {}))

    dmarc = f"_dmarc.{zone.name}"
    has_dmarc = any(r.type == "TXT" and r.rdata.lower().startswith("v=dmarc1")
                    for r in by_name.get(dmarc, []))
    if (apex_mx or any("v=spf1" in r.rdata.lower() for r in apex_txt)) and not has_dmarc:
        out.append(Finding("DZ005", "medium", f"zone:{zone.name}",
                           f"Mail records exist but there is no DMARC TXT record at {dmarc}.", {"expected": dmarc}))

    for name, recs in sorted(by_name.items()):
        types = {r.type for r in recs}
        sub = f"record:{name}"

        if "CNAME" in types:
            if name == zone.name:
                out.append(Finding("DZ001", "high", sub,
                                   "CNAME at the zone apex is not valid; an apex needs NS and SOA and cannot be an alias.", {}))
            if len(types) > 1:
                out.append(Finding("DZ002", "high", sub,
                                   f"CNAME coexists with other record types ({', '.join(sorted(types - {'CNAME'}))}) at one name; "
                                   "a CNAME must be the only record at its name.", {"types": sorted(types)}))

        if name.split(".")[0] == "*":
            out.append(Finding("DZ008", "low", sub,
                               "Wildcard record answers for every unmatched name; check the coverage is intended.", {}))

        seen = set()
        for r in recs:
            key = (r.type, r.rdata)
            if key in seen:
                out.append(Finding("DZ009", "low", sub,
                                   f"Duplicate {r.type} record with identical data {r.rdata!r}.",
                                   {"type": r.type, "rdata": r.rdata}))
            seen.add(key)

            if r.ttl < zone.min_ttl:
                out.append(Finding("DZ007", "low", f"{sub}/{r.type}",
                                   f"TTL {r.ttl}s is below the policy minimum of {zone.min_ttl}s; "
                                   "very short TTLs churn resolvers and can raise query volume.",
                                   {"ttl": r.ttl, "min_ttl": zone.min_ttl}))

            if r.type in ("A", "AAAA") and _is_private(r.rdata):
                out.append(Finding("DZ003", "high", f"{sub}/{r.type}",
                                   f"{r.type} record points at private/internal address {r.rdata}; "
                                   "publishing internal ranges leaks topology and resolves nowhere outside.",
                                   {"rdata": r.rdata}))

            if r.type == "CNAME":
                t = _target(r.rdata)
                if t not in names and any(t == s or t.endswith("." + s) for s in CLOUD_SUFFIXES):
                    out.append(Finding("DZ006", "medium", sub,
                                       f"CNAME points at {t}, which is outside this zone and matches a cloud-service suffix; "
                                       "if that resource was deleted the name may be claimable. "
                                       "This is an offline hint only - it was not verified against the provider.",
                                       {"target": t}))

    out.sort(key=lambda f: (SEV[f.severity], f.rule, f.subject, f.message))
    return out
