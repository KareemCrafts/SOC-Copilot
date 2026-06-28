# src/dashboard/app.py
import os, threading, time
from flask import Flask, render_template_string, request, redirect, jsonify
from werkzeug.utils import secure_filename
from sqlalchemy.orm import Session
from collections import defaultdict
from src.database.models import init_db, Alert, Incident

app = Flask(__name__)
UPLOAD_DIR = "uploads_web"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# shared job status for the progress indicator
JOB = {"running": False, "stage": "", "done": False, "error": None}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SEVERITY_COLOR = {
    "critical": "#E0483E", "high": "#E2602E", "medium": "#D9B44A",
    "low": "#4C8BA8", "informational": "#6B7280",
}

STAGE_DEFS = [
    ("Initial Access", ["initial-access"]), ("Persistence", ["persistence"]),
    ("Priv Esc", ["privilege-escalation"]),
    ("Defense Evasion", ["defense-impairment", "defense-evasion", "stealth"]),
    ("Cred Access", ["credential-access"]), ("Discovery", ["discovery"]),
    ("Lateral Move", ["lateral-movement"]), ("Collection", ["collection"]),
    ("C2", ["command-and-control"]), ("Impact", ["impact"]),
]

MATRIX = [
    ("Initial Access", ["T1078", "T1190", "T1133", "T1566"]),
    ("Execution", ["T1059", "T1059.001", "T1053", "T1204", "T1569"]),
    ("Persistence", ["T1098", "T1136", "T1136.001", "T1543", "T1547", "T1053.005"]),
    ("Priv Esc", ["T1068", "T1134", "T1134.001", "T1484", "T1548"]),
    ("Defense Evasion", ["T1070", "T1070.001", "T1070.006", "T1112", "T1562", "T1685", "T1685.005"]),
    ("Cred Access", ["T1003", "T1003.002", "T1110", "T1558", "T1558.003", "T1552"]),
    ("Discovery", ["T1087", "T1018", "T1046", "T1082", "T1083", "T1135"]),
    ("Lateral Move", ["T1021", "T1021.002", "T1550", "T1550.002", "T1570"]),
    ("Collection", ["T1005", "T1039", "T1056", "T1113", "T1114"]),
    ("C2", ["T1071", "T1090", "T1095", "T1105", "T1219"]),
    ("Impact", ["T1486", "T1489", "T1490", "T1531", "T1485"]),
]


def build_chain(tactics_str):
    present = set(t.strip() for t in (tactics_str or "").split(",") if t.strip())
    return [(label, any(s in present for s in slugs)) for label, slugs in STAGE_DEFS]


def run_pipeline_job(filepath):
    """Background worker: full pipeline on an uploaded file."""
    global JOB
    try:
        from src.parsers.evtx_parser import parse_evtx
        from src.detection.engine import run_engine
        from src.correlation.correlator import correlate

        JOB.update(stage="Parsing log file...", running=True, done=False, error=None)
        events = parse_evtx(filepath)

        JOB.update(stage=f"Running detection on {len(events)} events...")
        alerts = run_engine(events)

        JOB.update(stage=f"Saving {len(alerts)} alerts...")
        import json
        from datetime import datetime
        def parse_ts(ts):
            try: return datetime.fromisoformat(str(ts))
            except Exception: return datetime.utcnow()
        def extract_ip(raw):
            try: d = json.loads(raw) if raw else {}
            except Exception: return None
            ip = d.get("IpAddress")
            return ip if ip and ip not in ("-", "::1", "127.0.0.1", "") else None
        engine = init_db()
        with Session(engine) as s:
            for a in alerts:
                s.add(Alert(
                    id=a.get("alert_id"), timestamp=parse_ts(a.get("timestamp")),
                    host=a.get("host", "UNKNOWN"), user=a.get("user", "UNKNOWN"),
                    source_ip=extract_ip(a.get("raw_event")), event_id=a.get("event_id", ""),
                    rule_name=a.get("rule_name", "Unknown"),
                    mitre_technique_id=a.get("mitre_technique_id", "UNKNOWN"),
                    mitre_technique_name=a.get("mitre_technique_name", "Unknown"),
                    mitre_tactic=a.get("mitre_tactic", "Unknown"),
                    severity=a.get("severity", "medium"), confidence=a.get("confidence", 0.5),
                    raw_event=a.get("raw_event", "{}"),
                ))
            s.commit()

        JOB.update(stage="Correlating into incidents...")
        correlate()

        # AI triage is optional - only if Ollama is up
        try:
            import requests
            requests.get("http://localhost:11434/api/tags", timeout=2)
            JOB.update(stage="AI triage (writing case notes)...")
            from src.triage.llm_triage import triage_incidents
            triage_incidents()
        except Exception:
            JOB.update(stage="AI engine offline - skipping case notes")
            time.sleep(1)

        JOB.update(stage="Done", running=False, done=True)
    except Exception as e:
        JOB.update(running=False, done=True, error=str(e))


@app.route("/upload", methods=["POST"])
def upload():
    if JOB["running"]:
        return jsonify({"error": "A job is already running"}), 409
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".evtx"):
        return jsonify({"error": "Please upload a .evtx file"}), 400
    path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
    f.save(path)
    JOB.update(running=True, done=False, error=None, stage="Starting...")
    threading.Thread(target=run_pipeline_job, args=(path,), daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/status")
def status():
    return jsonify(JOB)

@app.route("/clear", methods=["POST"])
def clear():
    engine = init_db()
    with Session(engine) as s:
        s.query(Alert).delete()
        s.query(Incident).delete()
        s.commit()
    return jsonify({"status": "cleared"})


TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Copilot</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Serif:wght@500;700&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root { --bg:#11151C; --surface:#1A2029; --inset:#0D1014; --ink:#E7E2D6; --meta:#8B92A1; --rule:#2A313D; --gold:#D9B44A; }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font-family:'IBM Plex Sans',sans-serif; padding:32px 24px 80px; }
  .folder-tab { display:inline-block; font-family:'IBM Plex Mono',monospace; font-size:11px; letter-spacing:3px; color:var(--meta); border:1px solid var(--rule); border-bottom:none; padding:4px 14px; border-radius:6px 6px 0 0; }
  h1 { font-family:'IBM Plex Serif',serif; font-weight:700; font-size:clamp(26px,4vw,38px); margin:0 0 4px; border-bottom:1px solid var(--rule); padding-bottom:18px; }
  .subtitle { font-family:'IBM Plex Mono',monospace; font-size:12px; color:var(--meta); letter-spacing:1px; margin:10px 0 28px; }

  .dropzone { border:2px dashed var(--rule); border-radius:8px; padding:36px; text-align:center; margin-bottom:28px; transition:all 0.15s; cursor:pointer; background:var(--surface); }
  .dropzone.drag { border-color:var(--gold); background:#1f2630; }
  .dropzone h3 { font-family:'IBM Plex Serif',serif; margin:0 0 6px; font-size:20px; }
  .dropzone p { color:var(--meta); font-size:13px; margin:4px 0; }
  .browse-btn { display:inline-block; margin-top:14px; background:var(--gold); color:#11151C; font-weight:600; font-family:'IBM Plex Mono',monospace; font-size:13px; letter-spacing:1px; border:none; padding:11px 26px; border-radius:4px; cursor:pointer; }
  .browse-btn:hover { filter:brightness(1.08); }
  #fileInput { display:none; }
  .progress { display:none; margin-bottom:28px; background:var(--inset); border:1px solid var(--rule); border-radius:6px; padding:18px 22px; font-family:'IBM Plex Mono',monospace; font-size:13px; }
  .progress.show { display:block; }
  .spinner { display:inline-block; width:12px; height:12px; border:2px solid var(--rule); border-top-color:var(--gold); border-radius:50%; animation:spin 0.7s linear infinite; margin-right:10px; vertical-align:middle; }
  @keyframes spin { to { transform:rotate(360deg); } }

  .stats { display:flex; gap:14px; flex-wrap:wrap; margin-bottom:28px; }
  .stat-box { background:var(--surface); border:1px solid var(--rule); padding:16px 26px; border-radius:4px; flex:1; min-width:140px; }
  .stat-box .num { font-family:'IBM Plex Mono',monospace; font-size:30px; font-weight:600; }
  .stat-box .label { font-size:12px; color:var(--meta); margin-top:4px; }
  .section-label { font-family:'IBM Plex Mono',monospace; font-size:11px; letter-spacing:2px; color:var(--meta); text-transform:uppercase; margin:8px 0 14px; }

  .matrix { display:flex; gap:6px; overflow-x:auto; padding-bottom:8px; margin-bottom:36px; }
  .col { min-width:132px; flex:1; }
  .col-head { font-family:'IBM Plex Mono',monospace; font-size:10px; color:var(--ink); text-align:center; padding:8px 4px; border-bottom:2px solid var(--rule); margin-bottom:6px; min-height:42px; display:flex; align-items:center; justify-content:center; }
  .cell { font-family:'IBM Plex Mono',monospace; font-size:10px; padding:6px; border-radius:3px; margin-bottom:4px; background:var(--inset); color:#4A5160; text-align:center; }
  .cell.hit { color:#11151C; font-weight:600; }
  .cell .count { display:block; font-size:9px; opacity:0.75; }

  .controls { display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:24px; }
  .pill { font-family:'IBM Plex Mono',monospace; font-size:11px; letter-spacing:1px; text-transform:uppercase; background:transparent; border:1px solid var(--rule); color:var(--meta); padding:6px 14px; border-radius:16px; cursor:pointer; }
  .pill.active { border-color:var(--ink); color:var(--ink); }
  .search { background:var(--surface); border:1px solid var(--rule); color:var(--ink); padding:7px 12px; border-radius:16px; font-family:'IBM Plex Sans',sans-serif; font-size:13px; min-width:220px; }

  .case { background:var(--surface); border:1px solid var(--rule); border-radius:6px; padding:20px 22px; margin-bottom:16px; }
  .case-head { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }
  .stamp { display:inline-block; font-family:'IBM Plex Mono',monospace; font-weight:600; font-size:12px; letter-spacing:2px; text-transform:uppercase; border:2px solid currentColor; border-radius:3px; padding:3px 10px; transform:rotate(-2deg); }
  .host-line { font-size:16px; margin-top:8px; }
  .case-id { font-family:'IBM Plex Mono',monospace; font-size:12px; color:var(--meta); }
  .meta-row { font-family:'IBM Plex Mono',monospace; font-size:12px; color:var(--meta); margin:8px 0 4px; }
  .tags { font-size:12px; color:var(--meta); line-height:1.6; margin-bottom:12px; }
  .tags b { color:var(--ink); font-weight:500; }
  .chain { display:flex; gap:4px; overflow-x:auto; margin:14px 0; padding-bottom:2px; }
  .stage { flex:1; min-width:78px; text-align:center; font-family:'IBM Plex Mono',monospace; font-size:9px; color:var(--meta); border-top:3px solid var(--rule); padding-top:5px; white-space:nowrap; }
  .stage.active { border-top-color:var(--gold); color:var(--ink); }
  .note { background:var(--inset); border-left:3px solid var(--rule); padding:12px 16px; font-size:14px; line-height:1.6; border-radius:0 4px 4px 0; }
  .note-label { font-family:'IBM Plex Mono',monospace; font-size:10px; letter-spacing:1px; color:var(--meta); text-transform:uppercase; display:block; margin-bottom:6px; }
  .hidden { display:none; }
  .empty { text-align:center; color:var(--meta); padding:40px; font-family:'IBM Plex Mono',monospace; font-size:13px; }
</style>
</head>
<body>
  <span class="folder-tab">SOC-COPILOT</span>
  <h1>SOC Copilot</h1>
  <div class="subtitle">DROP A WINDOWS .EVTX LOG &mdash; DETECTION &rarr; CORRELATION &rarr; AI TRIAGE</div>

  <div class="dropzone" id="dropzone">
    <h3>Drop a .evtx log file here</h3>
    <p>or click to browse &mdash; runs entirely on your machine, nothing is uploaded online</p>
    <button class="browse-btn" type="button" id="browseBtn">Choose File</button>
   <input type="file" id="fileInput" accept=".evtx">
    {% if total_alerts > 0 %}
    <div style="margin-top:16px;"><button class="pill" type="button" id="clearBtn" style="border-color:#E0483E55; color:#E0483E;">Clear & Start New Analysis</button></div>
    {% endif %}
  </div>

  <div class="progress" id="progress"><span class="spinner"></span><span id="stageText">Working...</span></div>

  {% if total_alerts == 0 %}
  <div class="empty">No analysis yet. Drop a .evtx file above to begin.</div>
  {% else %}
  <div class="stats">
    <div class="stat-box"><div class="num">{{ total_alerts }}</div><div class="label">Raw Signals</div></div>
    <div class="stat-box"><div class="num">{{ total_incidents }}</div><div class="label">Case Files Opened</div></div>
    <div class="stat-box"><div class="num">{{ reduction }}%</div><div class="label">Noise Filtered</div></div>
    <div class="stat-box"><div class="num">{{ techniques_seen }}</div><div class="label">ATT&CK Techniques Hit</div></div>
  </div>

  <div class="section-label">MITRE ATT&CK Coverage &mdash; lit cells = detected, colored by highest severity</div>
  <div class="matrix">
    {% for col in matrix %}
    <div class="col">
      <div class="col-head">{{ col.tactic }}</div>
      {% for tech in col.techniques %}
      <div class="cell {{ 'hit' if tech.hit else '' }}" {% if tech.hit %}style="background:{{ tech.color }};" title="{{ tech.id }} — {{ tech.count }} alert(s)"{% endif %}>
        {{ tech.id }}{% if tech.hit %}<span class="count">{{ tech.count }}</span>{% endif %}
      </div>
      {% endfor %}
    </div>
    {% endfor %}
  </div>

  <div class="section-label">Incident Case Files</div>
  <div class="controls">
    <button class="pill active" data-sev="all">All</button>
    {% for s in severities %}
    <button class="pill" data-sev="{{ s }}" style="color:{{ colors[s] }}; border-color:{{ colors[s] }}33;">{{ s }}</button>
    {% endfor %}
    <input class="search" id="search" placeholder="Filter by host or IP...">
  </div>

  <div id="cases">
  {% for inc in incidents %}
  <div class="case" data-sev="{{ inc.max_severity }}" data-host="{{ (inc.host ~ ' ' ~ (inc.source_ip or '')) | lower }}">
    <div class="case-head">
      <div>
        <span class="stamp" style="color:{{ colors[inc.max_severity] }};">{{ inc.max_severity }}</span>
        <div class="host-line"><strong>{{ inc.host }}</strong> &middot; {{ inc.source_ip or 'no external IP' }} &middot; {{ inc.alert_count }} alerts</div>
      </div>
      <span class="case-id">CASE-{{ "%03d"|format(inc.case_number) }}</span>
    </div>
    <div class="meta-row">{{ inc.start_time }} &rarr; {{ inc.end_time }}</div>
    <div class="tags"><b>Techniques:</b> {{ inc.mitre_techniques }}<br><b>Rules:</b> {{ inc.rule_names }}</div>
    <div class="chain">
      {% for label, active in inc.chain %}<div class="stage {{ 'active' if active else '' }}">{{ label }}</div>{% endfor %}
    </div>
    {% if inc.ai_summary %}<div class="note"><span class="note-label">Analyst note &middot; AI-drafted, verify before acting</span>{{ inc.ai_summary }}</div>{% endif %}
  </div>
  {% endfor %}
  </div>
  {% endif %}

<script>
  const dz = document.getElementById('dropzone');
  const input = document.getElementById('fileInput');
  const browseBtn = document.getElementById('browseBtn');
  const progress = document.getElementById('progress');
  const stageText = document.getElementById('stageText');

  browseBtn.addEventListener('click', () => input.click());
  dz.addEventListener('click', (e) => { if (e.target === dz || e.target.tagName === 'H3' || e.target.tagName === 'P') input.click(); });
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => { e.preventDefault(); dz.classList.remove('drag'); if (e.dataTransfer.files.length) sendFile(e.dataTransfer.files[0]); });
  input.addEventListener('change', () => { if (input.files.length) sendFile(input.files[0]); });

  function sendFile(file) {
    if (!file.name.toLowerCase().endsWith('.evtx')) { alert('Please choose a .evtx file'); return; }
    const fd = new FormData(); fd.append('file', file);
    progress.classList.add('show'); stageText.textContent = 'Uploading ' + file.name + '...';
    fetch('/upload', { method:'POST', body:fd })
      .then(r => r.json())
      .then(d => { if (d.error) { stageText.textContent = 'Error: ' + d.error; } else { poll(); } })
      .catch(() => stageText.textContent = 'Upload failed');
  }

  function poll() {
    fetch('/status').then(r => r.json()).then(j => {
      stageText.textContent = j.stage || 'Working...';
      if (j.done) {
        if (j.error) { stageText.textContent = 'Error: ' + j.error; }
        else { stageText.textContent = 'Done. Loading results...'; setTimeout(() => location.reload(), 800); }
      } else { setTimeout(poll, 1000); }
    });
  }

  // filters
  const pills = document.querySelectorAll('.pill');
  const search = document.getElementById('search');
  let activeSev = 'all';
  function applyFilters() {
    const q = (search && search.value || '').toLowerCase();
    document.querySelectorAll('.case').forEach(c => {
      const sevOk = activeSev === 'all' || c.dataset.sev === activeSev;
      const hostOk = c.dataset.host.includes(q);
      c.classList.toggle('hidden', !(sevOk && hostOk));
    });
  }
  pills.forEach(p => p.addEventListener('click', () => {
    pills.forEach(x => x.classList.remove('active')); p.classList.add('active');
    activeSev = p.dataset.sev; applyFilters();
  }));
  if (search) search.addEventListener('input', applyFilters);
const clearBtn = document.getElementById('clearBtn');
  if (clearBtn) clearBtn.addEventListener('click', () => {
    if (confirm('Clear all current results and start fresh?')) {
      fetch('/clear', { method: 'POST' }).then(() => location.reload());
    }
  });
</script>
</body>
</html>
"""


@app.route("/")
def dashboard():
    engine = init_db()
    with Session(engine) as session:
        incidents = session.query(Incident).all()
        alerts = session.query(Alert).all()
        total_alerts = len(alerts)
        total_incidents = len(incidents)
        reduction = round((1 - total_incidents / total_alerts) * 100, 1) if total_alerts else 0

        tech_sev, tech_count = {}, defaultdict(int)
        for a in alerts:
            tid = a.mitre_technique_id
            tech_count[tid] += 1
            cur = tech_sev.get(tid)
            if cur is None or SEVERITY_RANK.get(a.severity, 0) > SEVERITY_RANK.get(cur, 0):
                tech_sev[tid] = a.severity

        matrix = []
        for tactic, techniques in MATRIX:
            cells = [{"id": tid, "hit": tid in tech_sev,
                      "color": SEVERITY_COLOR.get(tech_sev.get(tid, ""), "#333"),
                      "count": tech_count.get(tid, 0)} for tid in techniques]
            matrix.append({"tactic": tactic, "techniques": cells})

        chrono = sorted(incidents, key=lambda i: i.start_time)
        nums = {inc.id: idx + 1 for idx, inc in enumerate(chrono)}
        for inc in incidents:
            inc.case_number = nums[inc.id]
            inc.chain = build_chain(inc.mitre_tactics)

        incidents_sorted = sorted(incidents, key=lambda i: SEVERITY_RANK.get(i.max_severity, 0), reverse=True)
        severities_present = sorted({i.max_severity for i in incidents}, key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True)

        return render_template_string(
            TEMPLATE, incidents=incidents_sorted, total_alerts=total_alerts,
            total_incidents=total_incidents, reduction=reduction,
            techniques_seen=len(tech_sev), matrix=matrix,
            colors=SEVERITY_COLOR, severities=severities_present,
        )


if __name__ == "__main__":
    app.run(debug=False, port=5000)