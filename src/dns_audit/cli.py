from __future__ import annotations

import argparse
import json
import sys

from . import analysis, importer, model

DISCLAIMER = ("Review priorities from offline DNS zone data. No DNS queries are made and nothing is "
              "verified against live DNS or a cloud provider; a clean result is not a security certification.")


def _import_main(argv) -> int:
    ap = argparse.ArgumentParser(prog="dns-audit import",
                                 description="Convert an OCI-style zone export into the simplified zone JSON. "
                                             "Reads a file you already have; makes no DNS or API calls.")
    ap.add_argument("export")
    ap.add_argument("--output", "-o", help="write the zone here (default stdout)")
    a = ap.parse_args(argv)
    try:
        zone = importer.load_export(a.export)
    except (OSError, json.JSONDecodeError, importer.ImportError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    out = json.dumps(zone, indent=1) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"wrote {len(zone['records'])} record(s) to {a.output}", file=sys.stderr)
    else:
        sys.stdout.write(out)
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["import"]:
        return _import_main(argv[1:])
    ap = argparse.ArgumentParser(prog="dns-audit", description="Offline DNS zone hygiene audit (synthetic/exported data).")
    ap.add_argument("zone")
    ap.add_argument("--output")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(argv)
    try:
        zone = model.load_file(a.zone)
    except (OSError, json.JSONDecodeError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = analysis.analyze(zone)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.subject}: {f.message}")
    print(f"{len(fs)} finding(s) across {len(zone.records)} record(s) in zone {zone.name}.")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump({"disclaimer": DISCLAIMER, "zone": zone.name,
                       "findings": [f.to_dict() for f in fs]}, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
