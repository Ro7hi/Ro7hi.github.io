"""Compare findings and scan coverage in two pip-audit JSON reports."""

import argparse
import json
from pathlib import Path
import re


def load_report(path):
    with path.open(encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or not isinstance(data.get("dependencies"), list):
        raise ValueError("{} needs a pip-audit JSON dependencies list".format(path.name))
    packages = {}
    for row in data["dependencies"]:
        name = re.sub(r"[-_.]+", "-", row["name"]).lower()
        if name in packages:
            raise ValueError("Duplicate package {} in {}".format(name, path.name))
        if not row.get("skip_reason") and not isinstance(row.get("vulns"), list):
            raise ValueError("Missing finding list for {}".format(name))
        packages[name] = row
    return packages


def identities(finding):
    """Advisory identifiers are comparable only within the same package."""
    return {finding["id"], *(finding.get("aliases") or [])}


def compare(before, after):
    for name in sorted(before.keys() | after.keys()):
        old, new = before.get(name), after.get(name)
        if new is None:
            yield ("Missing from second inventory", name, "verify removal or scan scope")
            continue
        if new.get("skip_reason"):
            yield ("Coverage gap in second audit", name, new["skip_reason"])
            continue
        new_ids = {v["id"] for v in new["vulns"]}
        if old is None or old.get("skip_reason"):
            yield ("Newly covered package", name, "version " + new["version"])
            for advisory in sorted(new_ids):
                yield ("Current finding, baseline unavailable", name, advisory)
            continue
        earlier = [(item["id"], identities(item)) for item in old["vulns"]]
        current = [(item["id"], identities(item)) for item in new["vulns"]]
        change = "{} to {}".format(old["version"], new["version"])
        matched_old = set()
        for current_id, current_aliases in sorted(current, key=lambda item: item[0]):
            matches = {old_id for old_id, old_aliases in earlier if old_aliases & current_aliases}
            matched_old.update(matches)
            status = "Still reported" if matches else "Newly reported"
            detail = current_id
            if matches and current_id not in matches:
                detail += " [previously {}]".format(", ".join(sorted(matches)))
            yield status, name, "{} ({})".format(detail, change)
        for old_id in sorted({item[0] for item in earlier} - matched_old):
            yield "No longer reported", name, "{} ({})".format(old_id, change)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path, nargs="?", default=Path(__file__).with_name("before.json"))
    parser.add_argument("after", type=Path, nargs="?", default=Path(__file__).with_name("after.json"))
    args = parser.parse_args()
    try:
        before, after = load_report(args.before), load_report(args.after)
        findings = list(compare(before, after))
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, "Could not compare reports: {}\n".format(error))
    print("Inventory: {} packages before, {} after".format(len(before), len(after)))
    if not findings:
        print("No advisory or coverage changes and no findings reported for these packages.")
    for row in findings:
        print(" | ".join(row))
