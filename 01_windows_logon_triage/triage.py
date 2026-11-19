"""Review failures followed by a success in a saved Windows Security event log."""

import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import xml.etree.ElementTree as ET


def load_events(path):
    root = ET.parse(path).getroot()
    nodes = [root] if root.tag.rsplit("}", 1)[-1] == "Event" else root.findall("{*}Event")
    events = []
    seen = set()
    for node in nodes:
        system = node.find("{*}System")
        if system is None or system.findtext("{*}Channel") != "Security":
            continue
        if system.findtext("{*}EventID") not in {"4624", "4625"}:
            continue
        provider = system.find("{*}Provider")
        if provider is None or provider.get("Name") != "Microsoft-Windows-Security-Auditing":
            continue
        data = {item.get("Name"): (item.text or "").strip()
                for item in node.findall("{*}EventData/{*}Data")}
        host = system.findtext("{*}Computer", "").strip().lower()
        account = data.get("TargetUserName", "").casefold()
        domain = data.get("TargetDomainName", "").casefold()
        source = data.get("IpAddress", "").lower()
        kind = data.get("LogonType", "")
        if kind not in {"3", "10"} or any(x in {"", "-"} for x in (host, domain, account, source)):
            continue
        record = int(system.findtext("{*}EventRecordID", ""))
        if (host, record) in seen:
            continue
        seen.add((host, record))
        stamp = system.find("{*}TimeCreated")
        if stamp is None:
            raise ValueError("Missing TimeCreated for record {}".format(record))
        raw = stamp.get("SystemTime", "").replace("Z", "+00:00")
        # Windows can store seven fractional digits. Python datetimes store six.
        raw = re.sub(r"\.(\d+)(?=[+-])", lambda m: "." + m[1][:6].ljust(6, "0"), raw)
        when = datetime.fromisoformat(raw)
        if when.utcoffset() is None:
            raise ValueError("Timestamp needs a UTC offset for record {}".format(record))
        key = (host, domain, account, source, kind)
        events.append((when.astimezone(timezone.utc), record, system.findtext("{*}EventID"), key))
    return sorted(events), len(nodes)


def sequences(events, threshold, minutes):
    failures = defaultdict(deque)
    window = timedelta(minutes=minutes)
    for when, record, event_id, key in events:
        history = failures[key]
        while history and when - history[0][0] > window:
            history.popleft()
        if event_id == "4625":
            history.append((when, record))
            continue
        if len(history) >= threshold:
            host, domain, account, source, kind = key
            yield {
                "host": host, "domain": domain, "account": account, "source": source,
                "logon_type": kind, "first_failure": history[0][0].isoformat(),
                "success_at": when.isoformat(), "success_record": record,
                "failed_records": [row[1] for row in history],
            }
        # A success ends a sequence for this identity and source.
        del failures[key]


def review(events, threshold, minutes):
    alerts = list(sequences(events, threshold, minutes))
    for alert in alerts:
        print("REVIEW {success_at} | {domain}/{account} on {host} | source {source} | logon type {logon_type}".format(**alert))
        print("  First failure {}. Failed record IDs {}. Success record ID {}.".format(
            alert["first_failure"], ", ".join(map(str, alert["failed_records"])), alert["success_record"]))
    return len(alerts)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("xml", type=Path, nargs="?", default=Path(__file__).with_name("sample.xml"))
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--minutes", type=int, default=5)
    args = parser.parse_args()
    if min(args.threshold, args.minutes) < 1:
        parser.error("Threshold and minutes must be positive.")
    try:
        events, total = load_events(args.xml)
    except (OSError, ValueError, ET.ParseError) as error:
        parser.exit(2, "Could not read events: {}\n".format(error))
    count = review(events, args.threshold, args.minutes)
    print("Input events: {} | Eligible unique events: {} | Alerts: {}".format(total, len(events), count))
