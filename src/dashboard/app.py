# src/dashboard/app.py
from flask import Flask, render_template_string
from sqlalchemy.orm import Session
from collections import defaultdict
from src.database.models import init_db, Alert, Incident

app = Flask(__name__)

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
SEVERITY_COLOR = {
    "critical": "#E0483E",
    "high": "#E2602E",
    "medium": "#D9B44A",
    "low": "#4C8BA8",
    "informational": "#6B7280",
}

STAGE_DEFS = [
    ("Initial Access", ["initial-access"]),
    ("Persistence", ["persistence"]),
    ("Priv Esc", ["privilege-escalation"]),
    ("Defense Evasion", ["defense-impairment", "defense-evasion", "stealth"]),
    ("Cred Access", ["credential-access"]),
    ("Discovery", ["discovery"]),
    ("Lateral Move", ["lateral-movement"]),
    ("Collection", ["collection"]),
    ("C2", ["command-and-control"]),
    ("Impact", ["impact"]),
]

# ATT&CK matrix columns (tactic -> ordered technique IDs commonly seen in Windows)
MATRIX = [
    ("Initial Access", ["initial-access"], ["T1078", "T1190", "T1133", "T1566"]),
    ("Execution", ["execution"], ["T1059", "T1059.001", "T1053", "T1204", "T1569"]),
    ("Persistence", ["persistence"], ["T1098", "T1136", "T1136.001", "T1543", "T1547", "T1053.005"]),
    ("Priv Esc", ["privilege-escalation"], ["T1068", "T1134", "T1134.001", "T1484", "T1548"]),
    ("Defense Evasion", ["defense-impairment", "defense-evasion", "stealth"], ["T1070", "T1070.001", "T1070.006", "T1112", "T1562", "T1685", "T1685.005"]),
    ("Cred Access", ["credential-access"], ["T1003", "T1003.002", "T1110", "T1558", "T1558.003", "T1552"]),
    ("Discovery", ["discovery"], ["T1087", "T1018", "T1046", "T1082", "T1083", "T1135"]),
    ("Lateral Move", ["lateral-movement"], ["T1021", "T1021.002", "T1550", "T1550.002", "T1570"]),
    ("Collection", ["collection"], ["T1005", "T1039", "T1056", "T1113", "T1114"]),
    ("C2", ["command-and-control"], ["T1071", "T1090", "T1095", "T1105", "T1219"]),
    ("Impact", ["impact"], ["T1486", "T1489", "T1490", "T1531", "T1485"]),
]


def build_chain(tactics_str):
    present = set(t.strip() for t in (tactics_str or "").split(",") if t.strip())
    return [(label, any(s in present for s in slugs)) for label, slugs in STAGE_DEFS]


TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SOC Copilot — Case Log</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Serif:wght@500;700&family=IBM+Plex+Sans:wght@400;500&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #11151C;
    --surface: #1A2029;
    --inset: #0D1014;
    --ink: #E7E2D6;
    --meta: #8B92A1;
    --rule: #2A313D;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font-family: 'IBM Plex Sans', sans-serif;
    padding: 32px 24px 80px;
  }
  .folder-tab {
    display: inline-block;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 11px; letter-spacing: 3px; color: var(--meta);
    border: 1px solid var(--rule); border-bottom: none;
    padding: 4px 14px; border-radius: 6px 6px 0 0;
  }
  h1 {
    font-family: 'IBM Plex Serif', serif; font-weight: 700;
    font-size: clamp(26px, 4vw, 38px); margin: 0 0 4px;
    border-bottom: 1px solid var(--rule); padding-bottom: 18px;
  }
  .subtitle {
    font-family: 'IBM Plex Mono', monospace; font-size: 12px;
    color: var(--meta); letter-spacing: 1px; margin: 10px 0 28px;
  }
  .stats { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 28px; }
  .stat-box {
    background: var(--surface); border: 1px solid var(--rule);
    padding: 16px 26px; border-radius: 4px; flex: 1; min-width: 140px;
  }
  .stat-box .num { font-family: 'IBM Plex Mono', monospace; font-size: 30px; font-weight: 600; }
  .stat-box .label { font-size: 12px; color: var(--meta); margin-top: 4px; }

  .section-label {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 2px;
    color: var(--meta); text-transform: uppercase; margin: 8px 0 14px;
  }

  /* ATT&CK heatmap */
  .matrix { display: flex; gap: 6px; overflow-x: auto; padding-bottom: 8px; margin-bottom: 36px; }
  .col { min-width: 132px; flex: 1; }
  .col-head {
    font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 0.5px;
    color: var(--ink); text-align: center; padding: 8px 4px; border-bottom: 2px solid var(--rule);
    margin-bottom: 6px; min-height: 42px; display: flex; align-items: center; justify-content: center;
  }
  .cell {
    font-family: 'IBM Plex Mono', monospace; font-size: 10px;
    padding: 6px 6px; border-radius: 3px; margin-bottom: 4px;
    background: var(--inset); color: #4A5160; border: 1px solid transparent;
    text-align: center; cursor: default; transition: transform 0.08s;
  }
  .cell.hit { color: #11151C; font-weight: 600; }
  .cell.hit:hover { transform: scale(1.06); }
  .cell .count { display: block; font-size: 9px; opacity: 0.75; }

  .controls { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 24px; }
  .pill {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 1px;
    text-transform: uppercase; background: transparent; border: 1px solid var(--rule);
    color: var(--meta); padding: 6px 14px; border-radius: 16px; cursor: pointer;
  }
  .pill.active { border-color: var(--ink); color: var(--ink); }
  .pill:focus-visible, .search:focus-visible { outline: 2px solid #4C8BA8; outline-offset: 2px; }
  .search {
    background: var(--surface); border: 1px solid var(--rule); color: var(--ink);
    padding: 7px 12px; border-radius: 16px; font-family: 'IBM Plex Sans', sans-serif;
    font-size: 13px; min-width: 220px;
  }

  .case { background: var(--surface); border: 1px solid var(--rule); border-radius: 6px; padding: 20px 22px; margin-bottom: 16px; }
  .case-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; flex-wrap: wrap; }
  .stamp {
    display: inline-block; font-family: 'IBM Plex Mono', monospace; font-weight: 600;
    font-size: 12px; letter-spacing: 2px; text-transform: uppercase;
    border: 2px solid currentColor; border-radius: 3px; padding: 3px 10px; transform: rotate(-2deg);
  }
  .host-line { font-size: 16px; margin-top: 8px; }
  .case-id { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--meta); }
  .meta-row { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--meta); margin: 8px 0 4px; }
  .tags { font-size: 12px; color: var(--meta); line-height: 1.6; margin-bottom: 12px; }
  .tags b { color: var(--ink); font-weight: 500; }

  .chain { display: flex; gap: 4px; overflow-x: auto; margin: 14px 0; padding-bottom: 2px; }
  .stage {
    flex: 1; min-width: 78px; text-align: center; font-family: 'IBM Plex Mono', monospace;
    font-size: 9px; letter-spacing: 0.5px; color: var(--meta);
    border-top: 3px solid var(--rule); padding-top: 5px; white-space: nowrap;
  }
  .stage.active { border-top-color: #D9B44A; color: var(--ink); }

  .note { background: var(--inset); border-left: 3px solid var(--rule); padding: 12px 16px; font-size: 14px; line-height: 1.6; border-radius: 0 4px 4px 0; }
  .note-label { font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 1px; color: var(--meta); text-transform: uppercase; display: block; margin-bottom: 6px; }
  .hidden { display: none; }
</style>
</head>
<body>
  <span class="folder-tab">SOC-COPILOT / CASE-LOG</span>
  <h1>Incident Case Log</h1>
  <div class="subtitle">DETECTION ENGINE &rarr; CORRELATION &rarr; AI TRIAGE &mdash; {{ total_incidents }} CASES OPEN</div>

  <div class="stats">
    <div class="stat-box"><div class="num">{{ total_alerts }}</div><div class="label">Raw Signals</div></div>
    <div class="stat-box"><div class="num">{{ total_incidents }}</div><div class="label">Case Files Opened</div></div>
    <div class="stat-box"><div class="num">{{ reduction }}%</div><div class="label">Noise Filtered</div></div>
    <div class="stat-box"><div class="num">{{ techniques_seen }}</div><div class="label">ATT&CK Techniques Hit</div></div>
  </div>

  <div class="section-label">MITRE ATT&CK Coverage &mdash; lit cells = detected, colored by highest severity seen</div>
  <div class="matrix">
    {% for col in matrix %}
    <div class="col">
      <div class="col-head">{{ col.tactic }}</div>
      {% for tech in col.techniques %}
      <div class="cell {{ 'hit' if tech.hit else '' }}"
           {% if tech.hit %}style="background: {{ tech.color }}; border-color: {{ tech.color }};"
           title="{{ tech.id }} — {{ tech.count }} alert(s)"{% endif %}>
        {{ tech.id }}
        {% if tech.hit %}<span class="count">{{ tech.count }}</span>{% endif %}
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
        <span class="stamp" style="color: {{ colors[inc.max_severity] }};">{{ inc.max_severity }}</span>
        <div class="host-line"><strong>{{ inc.host }}</strong> &middot; {{ inc.source_ip or 'no external IP' }} &middot; {{ inc.alert_count }} alerts</div>
      </div>
      <span class="case-id">CASE-{{ "%03d"|format(inc.case_number) }}</span>
    </div>
    <div class="meta-row">{{ inc.start_time }} &rarr; {{ inc.end_time }}</div>
    <div class="tags"><b>Techniques:</b> {{ inc.mitre_techniques }}<br><b>Rules:</b> {{ inc.rule_names }}</div>
    <div class="chain">
      {% for label, active in inc.chain %}
      <div class="stage {{ 'active' if active else '' }}">{{ label }}</div>
      {% endfor %}
    </div>
    {% if inc.ai_summary %}
    <div class="note">
      <span class="note-label">Analyst note &middot; AI-drafted, verify before acting</span>
      {{ inc.ai_summary }}
    </div>
    {% endif %}
  </div>
  {% endfor %}
  </div>

<script>
  const pills = document.querySelectorAll('.pill');
  const search = document.getElementById('search');
  const cases = document.querySelectorAll('.case');
  let activeSev = 'all';
  function applyFilters() {
    const q = search.value.toLowerCase();
    cases.forEach(c => {
      const sevOk = activeSev === 'all' || c.dataset.sev === activeSev;
      const hostOk = c.dataset.host.includes(q);
      c.classList.toggle('hidden', !(sevOk && hostOk));
    });
  }
  pills.forEach(p => p.addEventListener('click', () => {
    pills.forEach(x => x.classList.remove('active'));
    p.classList.add('active');
    activeSev = p.dataset.sev;
    applyFilters();
  }));
  search.addEventListener('input', applyFilters);
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

        # Build per-technique: highest severity + count, from raw alerts
        tech_sev = {}
        tech_count = defaultdict(int)
        for a in alerts:
            tid = a.mitre_technique_id
            tech_count[tid] += 1
            cur = tech_sev.get(tid)
            if cur is None or SEVERITY_RANK.get(a.severity, 0) > SEVERITY_RANK.get(cur, 0):
                tech_sev[tid] = a.severity

        matrix = []
        for tactic, _slugs, techniques in MATRIX:
            cells = []
            for tid in techniques:
                hit = tid in tech_sev
                cells.append({
                    "id": tid,
                    "hit": hit,
                    "color": SEVERITY_COLOR.get(tech_sev.get(tid, ""), "#333"),
                    "count": tech_count.get(tid, 0),
                })
            matrix.append({"tactic": tactic, "techniques": cells})

        techniques_seen = len(tech_sev)

        chrono = sorted(incidents, key=lambda i: i.start_time)
        case_numbers = {inc.id: idx + 1 for idx, inc in enumerate(chrono)}
        for inc in incidents:
            inc.case_number = case_numbers[inc.id]
            inc.chain = build_chain(inc.mitre_tactics)

        incidents_sorted = sorted(incidents, key=lambda i: SEVERITY_RANK.get(i.max_severity, 0), reverse=True)
        severities_present = sorted({i.max_severity for i in incidents}, key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True)

        return render_template_string(
            TEMPLATE,
            incidents=incidents_sorted,
            total_alerts=total_alerts,
            total_incidents=total_incidents,
            reduction=reduction,
            techniques_seen=techniques_seen,
            matrix=matrix,
            colors=SEVERITY_COLOR,
            severities=severities_present,
        )


if __name__ == "__main__":
    app.run(debug=False, port=5000)