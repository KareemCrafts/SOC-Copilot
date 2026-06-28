\# SOC Copilot



An AI-augmented SOC analyst pipeline that turns raw Windows event logs into

prioritized, explained security incidents — running fully offline, for free.



It parses logs, detects threats with real Sigma rules, maps every hit to the

live MITRE ATT\&CK framework, correlates the noise into incidents, and uses a

local LLM to draft analyst case notes — then presents everything on a

browser dashboard with an ATT\&CK coverage heatmap.



\## Why it exists



A real SOC analyst drowns in alerts. One attack can throw thousands of raw

signals. SOC Copilot collapses that flood into a handful of human-readable

incidents — in testing, \*\*10,685 raw alerts became a single incident\*\*, and a

full day of mixed activity dropped from 158 signals to 32 reviewable cases

(\~80% noise reduction).



The design principle: \*\*the LLM never decides what is malicious.\*\* Detection is

done deterministically by Sigma rules and the MITRE STIX database. The LLM only

explains incidents that have already been confirmed — keeping it accurate and

auditable.



\## Architecture

EVTX logs



|



v



\[1] Detection Engine    2,500+ real Sigma rules + live MITRE ATT\&CK (STIX)



|                    -> tags each alert with the correct technique ID



v



\[2] Correlation Engine  groups alerts by host + IP + time window



|                    -> turns thousands of signals into incidents



v



\[3] LLM Triage          local model (Ollama) writes an analyst case note



|                    per incident -- offline, no data leaves the machine



v



\[4] Dashboard           browser UI: ATT\&CK heatmap + severity-ranked cases

\## Quick start (Windows)



1\. Install \[Python 3.10+](https://python.org) (check "Add to PATH")

2\. Install \[Ollama](https://ollama.com/download) (free local AI engine)

3\. Double-click \*\*`install.bat`\*\* — sets up everything automatically

4\. Analyze a log: `analyze.bat path\\to\\Security.evtx`

5\. View results: `dashboard.bat` (opens http://localhost:5000)



\## What's under the hood



\- \*\*Detection:\*\* Sigma rule engine matching against normalized Windows events

\- \*\*Threat intel:\*\* MITRE ATT\&CK Enterprise STIX (downloaded live, not hardcoded)

\- \*\*Correlation:\*\* time-windowed grouping by host and source IP

\- \*\*AI triage:\*\* Llama 3.2 via Ollama — runs locally, fully offline

\- \*\*Storage:\*\* SQLite

\- \*\*Dashboard:\*\* Flask + an ATT\&CK coverage heatmap



\## Privacy



Everything runs on your machine. Logs are never uploaded anywhere. The AI model

runs locally through Ollama — which is exactly why a tool like this can be used

in environments where sending security logs to a cloud API isn't allowed.



\## Known limitations



\- The local LLM occasionally over-describes low-severity background noise; case

&#x20; notes are explicitly labeled "AI-drafted, verify before acting."

\- Custom baseline rules (a small set alongside the 2,500+ Sigma rules) have

&#x20; hand-authored MITRE mappings — the same way Sigma's own authors map theirs.



\## Tech stack



Python · Flask · Sigma · MITRE ATT\&CK · Ollama (Llama 3.2) · SQLite

