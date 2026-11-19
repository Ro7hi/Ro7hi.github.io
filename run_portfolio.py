"""Replay the three placement cases offline. Optionally save the structured results."""

import argparse
import csv
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CASES = ROOT / "cases"


def module(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    item = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(item)
    return item


windows = module("triage", "01_windows_logon_triage/triage.py")
audits = module("compare_audits", "02_chatbot_dependency_review/compare_audits.py")
network = module("review_wifi", "03_wifi_baseline_review/review_wifi.py")


def windows_case():
    events, total = windows.load_events(CASES / "windows_events.xml")
    with (CASES / "windows_case_notes.csv").open(newline="", encoding="utf-8") as stream:
        labels = {int(row["success_record"]): row["label"] for row in csv.DictReader(stream)}
    scenarios = []
    for threshold in (5, 4, 2):
        sequences = list(windows.sequences(events, threshold, 5))
        hits = {row["success_record"] for row in sequences}
        scenarios.append({
            "threshold": threshold, "sequences": sequences,
            "review_cases_found": sum(labels.get(i) == "review" for i in hits),
            "benign_alerts": sum(labels.get(i) == "benign" for i in hits),
            "missed_review": [i for i, label in labels.items() if label == "review" and i not in hits],
        })
    return {"raw_records": total, "eligible_unique_records": len(events), "thresholds": scenarios}


def audit_case():
    old = audits.load_report(CASES / "audit_before.json")
    new = audits.load_report(CASES / "audit_after.json")
    decisions = [{"status": status, "package": package, "detail": detail}
                 for status, package, detail in audits.compare(old, new)]
    return {"before_packages": len(old), "after_packages": len(new), "decisions": decisions}


def wifi_case():
    views = {}
    folder = ROOT / "03_wifi_baseline_review"
    for title, path in (("before", "baseline.json"), ("after", "approved_change.json")):
        rows = network.analyze(network.read_policy(folder / path), CASES / "wifi_observations.csv")
        views[title] = {
            "observations": len(rows), "flagged": sum(bool(row["findings"]) for row in rows),
            "incomplete": sum(bool(row["missing"]) for row in rows),
            "outside": sum(not row["in_scope"] for row in rows), "rows": rows,
        }
    return views


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, help="Optional file for full evidence")
    args = parser.parse_args()
    report = {"windows": windows_case(), "dependencies": audit_case(), "wifi": wifi_case()}
    data = report["windows"]
    print("WINDOWS | {} records, {} eligible unique".format(data["raw_records"], data["eligible_unique_records"]))
    for row in data["thresholds"]:
        ids = ", ".join(str(alert["success_record"]) for alert in row["sequences"])
        print("  Threshold {} | {} review cases | {} benign | success records {}".format(
            row["threshold"], row["review_cases_found"], row["benign_alerts"], ids))
    print("DEPENDENCIES | Two four-package inventories")
    for row in report["dependencies"]["decisions"]:
        print("  {package} | {status} | {detail}".format(**row))
    print("WI-FI | Simulated change CHG-17")
    for stage, row in report["wifi"].items():
        print("  {} | {} observations | {} flagged | {} incomplete | {} outside scope".format(
            stage, row["observations"], row["flagged"], row["incomplete"], row["outside"]))
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
