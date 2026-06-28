# src/triage/llm_triage.py
# Sends correlated incidents to a local LLM (Ollama) for plain-English explanation.
# The LLM only EXPLAINS facts already determined by Sigma/MITRE — it never decides severity or maliciousness.

import requests
from sqlalchemy.orm import Session
from src.database.models import init_db, Incident

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2"

PROMPT_TEMPLATE = """You are a SOC analyst writing a short case note for a security incident.
The detection engine (Sigma rules + MITRE ATT&CK) already determined the facts below. Your only job is to explain them clearly. Do not invent an attack method, attacker motive, IP address, or technique that is not explicitly listed below. If source IP is "none / internal", say no external IP was involved -- do not invent one. Do not use words like phishing, insider threat, or credential stuffing unless those exact words appear in the rules listed.

Incident facts:
- Host: {host}
- Source IP: {source_ip}
- Time window: {start_time} to {end_time}
- Number of alerts: {alert_count}
- Severity (already determined): {severity}
- MITRE Tactics: {tactics}
- MITRE Techniques: {techniques}
- Rules that fired: {rules}

Write a 3-4 sentence analyst case note using only the facts above, then one recommended next action. Plain English, no headers."""


def build_prompt(inc: Incident) -> str:
    return PROMPT_TEMPLATE.format(
        host=inc.host,
        source_ip=inc.source_ip or "none / internal",
        start_time=inc.start_time,
        end_time=inc.end_time,
        alert_count=inc.alert_count,
        severity=inc.max_severity,
        tactics=inc.mitre_tactics,
        techniques=inc.mitre_techniques,
        rules=inc.rule_names,
    )


def query_llm(prompt: str) -> str:
    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception as e:
        return f"[LLM error: {e}]"


def triage_incidents(db_path="soc_copilot.db"):
    engine = init_db(db_path)
    with Session(engine) as session:
        incidents = session.query(Incident).filter(Incident.ai_summary.is_(None)).all()
        if not incidents:
            print("[*] No incidents need triage.")
            return []

        print(f"[*] Triaging {len(incidents)} incidents with {MODEL}...\n")
        for inc in incidents:
            prompt = build_prompt(inc)
            summary = query_llm(prompt)
            inc.ai_summary = summary
            session.commit()
            print(f"[{inc.max_severity.upper()}] {inc.host} ({inc.source_ip or 'no IP'})")
            print(f"   {summary}\n")
        return incidents


if __name__ == "__main__":
    triage_incidents()