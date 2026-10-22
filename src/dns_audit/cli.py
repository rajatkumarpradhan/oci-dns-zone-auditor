from __future__ import annotations

import argparse
import json
import sys

from . import analysis, model

DISCLAIMER = ("Review priorities from offline DNS zone data. No DNS queries are made and nothing is "
              "verified against live DNS or a cloud provider; a clean result is not a security certification.")


def main(argv=None) -> int:
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
