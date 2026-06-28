# run_pipeline.py
# Full pipeline: parse logs -> run detection -> save alerts to SQLite

from src.parsers.evtx_parser import parse_evtx
from src.detection.engine import run_engine
from src.database.models import init_db, Alert
from sqlalchemy.orm import Session
from datetime import datetime
from collections import Counter
import json, sys


def parse_ts(ts_str):
    try:
        return datetime.fromisoformat(str(ts_str))
    except Exception:
        return datetime.utcnow()


def extract_ip(raw_event_json):
    try:
        data = json.loads(raw_event_json) if raw_event_json else {}
    except Exception:
        return None
    ip = data.get("IpAddress")
    return ip if ip and ip not in ("-", "::1", "127.0.0.1", "") else None


def run_pipeline(evtx_path: str):
    print(f"[*] Parsing {evtx_path}...")
    events = parse_evtx(evtx_path)
    print(f"[+] Parsed {len(events)} events")

    print("[*] Running detection engine...")
    alerts = run_engine(events)
    print(f"[+] {len(alerts)} alerts fired")

    print("[*] Saving alerts to database...")
    engine = init_db()
    with Session(engine) as session:
        for a in alerts:
            record = Alert(
                id                   = a.get("alert_id"),
                timestamp            = parse_ts(a.get("timestamp")),
                host                 = a.get("host", "UNKNOWN"),
                user                 = a.get("user", "UNKNOWN"),
                source_ip            = extract_ip(a.get("raw_event")),
                event_id             = a.get("event_id", ""),
                rule_name            = a.get("rule_name", "Unknown"),
                mitre_technique_id   = a.get("mitre_technique_id", "UNKNOWN"),
                mitre_technique_name = a.get("mitre_technique_name", "Unknown"),
                mitre_tactic         = a.get("mitre_tactic", "Unknown"),
                severity             = a.get("severity", "medium"),
                confidence           = a.get("confidence", 0.5),
                raw_event            = a.get("raw_event", "{}"),
            )
            session.add(record)
        session.commit()
    print(f"[+] {len(alerts)} alerts saved to soc_copilot.db")

    print("\n--- DETECTION SUMMARY ---")
    tactics = Counter(a.get("mitre_tactic", "Unknown") for a in alerts)
    severities = Counter(a.get("severity", "unknown") for a in alerts)

    print("\nBy Tactic:")
    for tactic, count in tactics.most_common():
        print(f"  {tactic}: {count}")

    print("\nBy Severity:")
    for sev, count in severities.most_common():
        print(f"  {sev.upper()}: {count}")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/samples/Security.evtx"
    run_pipeline(path)