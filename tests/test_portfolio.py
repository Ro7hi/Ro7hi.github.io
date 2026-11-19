"""Regression cases for the investigation decisions, all runnable offline."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run_portfolio as lab


class WindowsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events, cls.total = lab.windows.load_events(lab.CASES / "windows_events.xml")

    def test_duplicate_record_and_reverse_time_order(self):
        self.assertEqual((self.total, len(self.events)), (17, 16))
        self.assertEqual(self.events, sorted(self.events))

    def test_exact_five_minute_boundary_included(self):
        alert = list(lab.windows.sequences(self.events, 5, 5))[0]
        self.assertEqual(alert["success_record"], 2107)
        self.assertEqual(alert["failed_records"], [2101, 2102, 2103, 2104, 2105])

    def test_one_second_outside_window(self):
        alerts = list(lab.windows.sequences(self.events, 4, 5))
        self.assertEqual(alerts[1]["failed_records"], [2202, 2203, 2204, 2205])

    def test_other_source_success_keeps_window_open(self):
        alerts = list(lab.windows.sequences(self.events, 5, 5))
        self.assertEqual([(a["source"], a["success_record"]) for a in alerts], [("192.0.2.44", 2107)])

    def test_lower_threshold_adds_known_benign_case(self):
        self.assertEqual([a["success_record"] for a in lab.windows.sequences(self.events, 2, 5)], [2107, 2206, 2303])

    def test_success_closes_history(self):
        t, record, _, key = self.events[0]
        events = [(t, record, "4625", key), (t, record+1, "4624", key), (t, record+2, "4624", key)]
        self.assertEqual(len(list(lab.windows.sequences(events, 1, 5))), 1)


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = {row["package"]: row for row in lab.audit_case()["decisions"]}

    def test_known_alias_persists_across_normalized_package_name(self):
        row = self.rows["demo-parser"]
        self.assertEqual(row["status"], "Still reported")
        self.assertIn("previously LAB-02-A", row["detail"])

    def test_skipped_package_remains_coverage_gap(self):
        self.assertEqual(self.rows["demo-bridge"]["status"], "Coverage gap in second audit")

    def test_removed_finding_on_rescanned_package(self):
        self.assertEqual(self.rows["demo-session"]["status"], "No longer reported")

    def test_new_advisory_on_same_version(self):
        self.assertEqual(self.rows["demo-utils"]["status"], "Newly reported")

    def test_missing_package_cannot_prove_a_fix(self):
        row = list(lab.audits.compare({"pkg":{"version":"1","vulns":[]}}, {}))[0]
        self.assertEqual(row[0], "Missing from second inventory")

    def test_finding_on_newly_covered_package_has_no_baseline(self):
        row = {"version":"1","vulns":[{"id":"LAB-X"}]}
        self.assertEqual([r[0] for r in lab.audits.compare({}, {"pkg":row})],
                         ["Newly covered package", "Current finding, baseline unavailable"])


class WifiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = lab.wifi_case()
        cls.rows = cls.report["after"]["rows"]

    def test_expected_roaming_is_accepted(self):
        self.assertTrue(all(r["in_scope"] and not r["findings"] and not r["missing"] for r in self.rows[:2]))

    def test_change_closes_one_inventory_finding(self):
        self.assertEqual((self.report["before"]["flagged"], self.report["after"]["flagged"]), (3, 2))
        self.assertEqual(self.rows[2]["findings"], [])

    def test_two_findings_on_one_observation(self):
        self.assertEqual(len(self.rows[3]["findings"]), 2)

    def test_known_radio_unexpected_mode(self):
        self.assertEqual(self.rows[4]["findings"], ["unexpected connection mode Open/None"])

    def test_missing_fields_distinct_from_observed_deviation(self):
        self.assertEqual([self.rows[i]["missing"] for i in (5,7)], [["cipher"], ["bssid"]])
        self.assertFalse(self.rows[5]["findings"] or self.rows[7]["findings"])

    def test_external_ssid_reported_separately(self):
        self.assertEqual(self.report["after"]["outside"], 1)
        self.assertFalse(self.rows[6]["in_scope"])


class ReplayTests(unittest.TestCase):
    def test_replay_matches_saved_results(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "results.json"
            cmd = [sys.executable, str(lab.ROOT / "run_portfolio.py"), "--json-out", str(path)]
            subprocess.run(cmd, cwd=folder, check=True, stdout=subprocess.PIPE)
            self.assertEqual(json.loads(path.read_text()), json.loads((lab.ROOT/"evidence/results.json").read_text()))


if __name__ == "__main__":
    unittest.main()
