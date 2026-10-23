# oci-dns-zone-auditor

Offline DNS zone hygiene auditor. It reads one JSON file with a zone's records (an export you already have), applies 10 rules and prints findings by severity. It can also write a JSON report. An `import` subcommand converts an OCI-style zone export into the zone schema.

This is a portfolio project. The zone format is a simplified schema I made up, not the OCI DNS API shape. The data in `examples/` is synthetic. The auditor makes **no DNS queries** and calls no cloud API: it reasons only over the records in the file. Nothing here has been run against a real zone, and a clean result is not a security certification.

## Run

```
python -m pip install -e .
dns-audit examples/risky.json
dns-audit examples/risky.json --output report.json --fail-on high
```

Exit codes: 0 ok, 1 bad input, 2 a finding at or above `--fail-on`.

## Import from an export

`dns-audit import` converts an OCI-style zone response into this tool's zone JSON, so a real export can be audited without rewriting it by hand. It reads a file you already have; it makes no DNS queries and calls no API.

```
dns-audit import examples/export.json                     # writes zone JSON to stdout
dns-audit import examples/export.json -o zone.json
dns-audit zone.json
```

Accepted shape: an object with `name` and `items`, optionally inside a `data` envelope (the shape of `oci dns zone get` output). Each item needs `domain`, `rtype`, `ttl` and `rdata`; extra OCI fields (`is-protected`, `record-hash`, ...) are ignored. Records pass through as written - absolute names keep their trailing dot and the model canonicalises them when the zone is audited.

Records that cannot be mapped stop the import, and every bad record is reported as `items[i]` with a best-effort line number (the line where that record's domain or rdata appears; a minified file reports line 1, the row index is always exact).

## Zone format

```json
{
  "zone": "example.com",
  "config": {"min_ttl": 60},
  "records": [
    {"name": "@", "type": "NS", "ttl": 86400, "rdata": "ns1.dns-vendor.net."},
    {"name": "www", "type": "A", "ttl": 300, "rdata": "203.0.113.10"},
    {"name": "api", "type": "CNAME", "ttl": 300, "rdata": "www.example.com."}
  ]
}
```

- `name`: `@` for the apex, a relative name (`www`), or an absolute name with a trailing dot (`www.example.com.`). Names are canonicalised to lower-case fully-qualified form.
- `type`: any valid record-type token; unknown types are accepted and only checked by the generic rules (duplicates, TTL).
- `config.min_ttl` defaults to 60 seconds (my policy assumption, not a DNS constant).

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| DZ001 | high | CNAME at the zone apex (invalid; an apex cannot be an alias) |
| DZ002 | high | CNAME coexisting with other record types at one name |
| DZ003 | high | A/AAAA record pointing at a private/internal address (RFC1918, loopback, link-local, CGNAT) |
| DZ004 | medium | MX records but no SPF TXT record at the apex |
| DZ005 | medium | mail records but no DMARC TXT record at `_dmarc.<zone>` |
| DZ006 | medium | CNAME to a target outside the zone that matches a cloud-service suffix (takeover candidate - offline hint only) |
| DZ007 | low | TTL below the policy minimum |
| DZ008 | low | wildcard record (broad catch-all) |
| DZ009 | low | duplicate record (same name, type and data) |
| DZ010 | low | no NS records at the apex |

## Limits

- No DNS queries. DZ006 is a pattern match against a built-in suffix list; whether the target is actually unclaimed is **not** verified and needs a live lookup.
- The private-address ranges are an explicit list (RFC1918, 127.0.0.0/8, 169.254.0.0/16, 100.64.0.0/10, ::1, fc00::/7, fe80::/10). Documentation prefixes like 192.0.2.0/24 are deliberately not flagged.
- Record data (`rdata`) is treated as an opaque string except for A/AAAA addresses, CNAME targets and the SPF/DMARC prefixes. No per-type syntax validation.
- Rules check the records as written. They cannot tell whether a zone is actually delegated, reachable or correctly served.
- The importer validates shape, not meaning: it passes records through and the audit rules judge them. Importer line numbers are best-effort (a text search for the record's domain or rdata), not a real JSON parse position.

## Tests

```
python -m unittest discover -s tests -v
```

Tests cover each rule and boundary (TTL exactly at the minimum vs one below, private ranges vs documentation prefixes, DMARC at the exact `_dmarc` name vs elsewhere, one DZ002 finding per name, duplicates counted per extra copy), name canonicalisation, validation errors, CLI exit codes and the importer (OCI-style conversion, envelope variants, malformed rows with line numbers). `examples/good.json` must produce zero findings and `examples/risky.json` must trigger all 10 rules.
