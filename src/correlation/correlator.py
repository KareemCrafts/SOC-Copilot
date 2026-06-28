# src/correlation/correlator.py
from sqlalchemy.orm import Session
from src.database.models import Alert, Incident, init_db
from datetime import timedelta
import json, uuid

TIME_WINDOW_MINUTES = 10
SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

def correlate(db_path="soc_copilot.db"):
    engine = init_db(db_path)
    with Session(engine) as session:
        alerts = session.query(Alert).filter(Alert.incident_id.is_(None)).all()
        if not alerts:
            print("[*] No new alerts to correlate.")
            return []

        groups = {}
        for a in alerts:
            key = (a.host, a.source_ip or "none")
            groups.setdefault(key, []).append(a)

        incidents_created = []

        for (host, ip), group_alerts in groups.items():
            group_alerts.sort(key=lambda x: x.timestamp)
            chunk = [group_alerts[0]]

            def flush(chunk):
                inc = Incident(
                    id=str(uuid.uuid4()),
                    host=host,
                    source_ip=None if ip == "none" else ip,
                    user=chunk[0].user,
                    start_time=chunk[0].timestamp,
                    end_time=chunk[-1].timestamp,
                    alert_count=len(chunk),
                    max_severity=max((c.severity for c in chunk), key=lambda s: SEVERITY_RANK.get(s, 0)),
                   mitre_tactics=", ".join(sorted({
                        t.strip() for c in chunk for t in c.mitre_tactic.split(",")
                    })),
                    mitre_techniques=", ".join(sorted(set(c.mitre_technique_id for c in chunk))),
                    rule_names=", ".join(sorted(set(c.rule_name for c in chunk))),
                )
                session.add(inc)
                for c in chunk:
                    c.incident_id = inc.id
                incidents_created.append(inc)

            for alert in group_alerts[1:]:
                if alert.timestamp - chunk[-1].timestamp <= timedelta(minutes=TIME_WINDOW_MINUTES):
                    chunk.append(alert)
                else:
                    flush(chunk)
                    chunk = [alert]
            flush(chunk)

        session.commit()
        return incidents_created


if __name__ == "__main__":
    incidents = correlate()
    print(f"\n[+] {len(incidents)} incidents created from raw alerts\n")

    engine = init_db()
    with Session(engine) as session:
        all_incidents = session.query(Incident).all()
        for inc in sorted(all_incidents, key=lambda i: SEVERITY_RANK.get(i.max_severity, 0), reverse=True):
            print(f"[{inc.max_severity.upper()}] {inc.host} ({inc.source_ip or 'no IP'}) — {inc.alert_count} alerts")
            print(f"   {inc.start_time} -> {inc.end_time}")
            print(f"   Tactics: {inc.mitre_tactics}")
            print(f"   Techniques: {inc.mitre_techniques}")
            print(f"   Rules: {inc.rule_names}\n")