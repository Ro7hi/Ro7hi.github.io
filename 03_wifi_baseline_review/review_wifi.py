"""Compare connected-client Wi-Fi observations with a local approved inventory."""

import argparse
import csv
import json
from pathlib import Path
import re


def radio_id(value):
    compact = value.strip().lower().replace(":", "").replace("-", "")
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise ValueError("Expected a 12-digit BSSID, got {!r}".format(value))
    return ":".join(compact[i:i + 2] for i in range(0, 12, 2))


def read_policy(path):
    with path.open(encoding="utf-8-sig") as stream:
        policy = json.load(stream)
    result = {}
    for ssid, rules in policy.items():
        radios = {radio_id(bssid) for bssid in rules["approved_bssids"]}
        modes = {(pair["authentication"].strip().casefold(), pair["cipher"].strip().casefold())
                 for pair in rules["approved_modes"]}
        result[ssid] = (radios, modes)
    return result


def analyze(policy, path):
    readings = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        rows = csv.DictReader(stream)
        fields = {"timestamp", "ssid", "bssid", "authentication", "cipher"}
        if not fields.issubset(rows.fieldnames or []):
            raise ValueError("CSV requires columns: " + ", ".join(sorted(fields)))
        for row in rows:
            entry = {"timestamp": row["timestamp"], "ssid": row["ssid"], "bssid": row["bssid"] or "",
                     "in_scope": row["ssid"] in policy, "findings": [], "missing": []}
            readings.append(entry)
            if not entry["in_scope"]:
                continue
            radios, modes = policy[row["ssid"]]
            for name in ("bssid", "authentication", "cipher"):
                if not (row[name] or "").strip():
                    entry["missing"].append(name)
            if "bssid" not in entry["missing"]:
                entry["bssid"] = radio_id(row["bssid"])
                if entry["bssid"] not in radios:
                    entry["findings"].append("BSSID missing from inventory")
            if (row["authentication"] or "").strip() and (row["cipher"] or "").strip():
                auth, cipher = row["authentication"].strip(), row["cipher"].strip()
                if (auth.casefold(), cipher.casefold()) not in modes:
                    entry["findings"].append("unexpected connection mode {}/{}".format(auth, cipher))
    return readings


def review(policy, path):
    readings = analyze(policy, path)
    for item in readings:
        notes = list(item["findings"])
        if item["missing"]:
            notes.append("collect missing " + ", ".join(item["missing"]))
        if notes:
            print("{} | {} | {} | {}".format(item["timestamp"], item["ssid"], item["bssid"], ", ".join(notes)))
    counts = "Observations: {} | Flagged: {} | Outside policy scope: {}".format(
        len(readings), sum(bool(r["findings"]) for r in readings), sum(not r["in_scope"] for r in readings))
    incomplete = sum(bool(r["missing"]) for r in readings)
    if incomplete:
        counts += " | Incomplete: {}".format(incomplete)
    print(counts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observations", type=Path, nargs="?", default=Path(__file__).with_name("observations.csv"))
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("baseline.json"))
    args = parser.parse_args()
    try:
        review(read_policy(args.policy), args.observations)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, csv.Error) as error:
        parser.exit(2, "Could not review observations: {}\n".format(error))
