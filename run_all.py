# run_all.py
# One command: parse -> detect -> correlate -> AI triage -> report
# Usage: python run_all.py path\to\file.evtx

import os, sys, json, time, subprocess
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from src.parsers.evtx_parser import parse_evtx
from src.detection.engine import run_engine
from src.database.models import init_db, Alert, Incident
from src.correlation.correlator import correlate
from src.triage.llm_triage import triage_incidents

DATA_FILE = "data/enterprise-attack.json"
RULES_DIR = "rules/sigma"
OLLAMA_URL = "http://localhost:11434"
MODEL_NAME = "llama3.2"


def ensure_detection_data():
    have_mitre = os.path.exists(DATA_FILE)
    have_sigma = os.path.isdir(RULES_DIR) and len(os.listdir(RULES_DIR)) > 0
    if have_mitre and have_sigma:
        return
    print("[*] First-time setup: downloading MITRE + Sigma data...")
    subprocess.run([sys.executable, "setup_data.py"], check=True)


def ensure_ollama_running():
    import requests
    try:
        requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return True
    except Exception:
        pass
    print("[*] Starting local AI engine (Ollama)...")
    try:
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[!] Ollama not installed. Get it free: https://ollama.com/download")
        return False
    for _ in range(15):
        time.sleep(1)
        try:
            requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
            return True
        except Exception:
            continue
    print("[!] Ollama did not respond in time. Skipping AI triage.")
    return False


def ensure_model_present():
    import requests
    try:
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        names = [m["name"] for m in resp.json().get("models", [])]
        if any(MODEL_NAME in n for n in names):
            return True
    except Exception:
        pass
    print(f"[*] Downloading AI model {MODEL_NAME} (~2GB, one-time)...")
    try:
        subprocess.run(["ollama", "pull", MODEL_NAME], check=True)
        return True
    except Exception as e:
        print(f"[!] Could not pull model: {e}")
        return False


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


def save_alerts(alerts, db_path="soc_copilot.db"):
    engine = init_db(db_path)
    with Session(engine) as session:
        for a in alerts:
            session.add(Alert(
                id=a.get("alert_id"),
                timestamp=parse_ts(a.get("timestamp")),
                host=a.get("host", "UNKNOWN"),
                user=a.get("user", "UNKNOWN"),
                source_ip=extract_ip(a.get("raw_event")),
                event_id=a.get("event_id", ""),
                rule_name=a.get("rule_name", "Unknown"),
                mitre_technique_id=a.get("mitre_technique_id", "UNKNOWN"),
                mitre_technique_name=a.get("mitre_technique_name", "Unknown"),
                mitre_tactic=a.get("mitre_tactic", "Unknown"),
                severity=a.get("severity", "medium"),
                confidence=a.get("confidence", 0.5),
                raw_event=a.get("raw_event", "{}"),
            ))
        session.commit()


def find_evtx_files(path: str):
    p = Path(path)
    if p.is_file():
        return [str(p)]
    if p.is_dir():
        return [str(f) for f in p.glob("*.evtx")]
    return []


def write_report(db_path="soc_copilot.db"):
    engine = init_db(db_path)
    with Session(engine) as session:
        incidents = session.query(Incident).order_by(Incident.start_time).all()
        os.makedirs("reports", exist_ok=True)
        report_path = f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

        rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        lines = [
            "SOC COPILOT - INCIDENT REPORT",
            f"Generated: {datetime.now()}",
            f"Total incidents: {len(incidents)}",
            "=" * 60,
        ]
        for inc in sorted(incidents, key=lambda i: rank.get(i.max_severity, 0), reverse=True):
            lines.append("")
            lines.append(f"[{inc.max_severity.upper()}] {inc.host} ({inc.source_ip or 'no IP'}) - {inc.alert_count} alerts")
            lines.append(f"Time: {inc.start_time} -> {inc.end_time}")
            lines.append(f"MITRE Tactics: {inc.mitre_tactics}")
            lines.append(f"MITRE Techniques: {inc.mitre_techniques}")
            lines.append(f"Rules: {inc.rule_names}")
            if inc.ai_summary:
                lines.append(f"Analyst note: {inc.ai_summary}")

        text = "\n".join(lines)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(text)
        print(text)
        print(f"\n[+] Full report saved to {report_path}")


def already_processed(filepath, tracker="processed_files.json"):
    import hashlib
    h = hashlib.md5(open(filepath, "rb").read()).hexdigest()
    seen = {}
    if os.path.exists(tracker):
        with open(tracker) as f:
            seen = json.load(f)
    if seen.get(filepath) == h:
        return True
    seen[filepath] = h
    with open(tracker, "w") as f:
        json.dump(seen, f)
    return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python run_all.py <evtx file or folder> [--force]")
        sys.exit(1)
    if sys.argv[1] == "--setup-only":
        ensure_detection_data()
        print("[+] Setup complete.")
        return

    force = "--force" in sys.argv
    files = find_evtx_files(sys.argv[1])
    if not files:
        print(f"[!] No .evtx files found at {sys.argv[1]}")
        sys.exit(1)

    if not force:
        new_files = [f for f in files if not already_processed(f)]
        skipped = len(files) - len(new_files)
        if skipped:
            print(f"[*] Skipping {skipped} already-processed file(s). Use --force to redo them.")
        files = new_files
        if not files:
            print("[*] Nothing new to process.")
            write_report()
            return

    ensure_detection_data()

    total = 0
    for f in files:
        print(f"\n[*] Processing {f}...")
        events = parse_evtx(f)
        alerts = run_engine(events)
        save_alerts(alerts)
        total += len(alerts)
        print(f"[+] {len(alerts)} alerts from {len(events)} events")

    print(f"\n[*] Correlating {total} alerts into incidents...")
    new_incidents = correlate()
    print(f"[+] {len(new_incidents)} new incidents created")

    if ensure_ollama_running() and ensure_model_present():
        print("\n[*] Running AI triage...")
        triage_incidents()
    else:
        print("[!] Skipping AI triage.")

    print("\n[*] Building final report...")
    write_report()


if __name__ == "__main__":
    main()