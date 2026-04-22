# my_seims — macOS Security Information & Event Management System

A full-featured, locally-hosted SIEM for macOS. Scans system logs every 15 minutes, detects suspicious activity using configurable rules, and generates human-readable PDF reports. Accessible via a dark-themed web dashboard at `http://localhost:5001`.

---

## Features

- **Dashboard** — Live stat cards, 24-hour event timeline, severity distribution chart, system health gauges, and recent alerts
- **Events** — Searchable, filterable event log with plain-English descriptions. Click any row for full detail
- **Alerts** — Tabbed view (New / Acknowledged / Resolved), bulk actions, per-alert detail modal
- **Detection Rules** — 20 built-in rules covering authentication, privilege escalation, network anomalies, malware, persistence, and more. Full CRUD via the UI
- **PDF Reports** — On-demand reports with executive summary, human-readable event log grouped by category, alert details, and recommendations. Saved to `reports/`
- **Live Monitor** — Real-time CPU / Memory / Disk gauges, top processes by CPU, active network connections
- **Settings** — Configurable scan interval (5–60 min), lookback window, event retention, auto-report toggle
- **Auto-scan** — APScheduler runs a full scan every 15 minutes in the background
- **Scan Now** — Trigger an immediate scan from the sidebar at any time
- **Auto-refresh** — Dashboard and pages refresh every 30 seconds (toggle in topbar)

---

## Requirements

- macOS 11 or later
- Python 3.9+
- pip3

---

## Quick Start

```bash
bash ~/Desktop/my_seims/run.sh
```

Then open **http://localhost:5001** in your browser.

`run.sh` installs all Python dependencies and starts the server. It is safe to run multiple times.

---

## Manual Setup

### 1. Install dependencies

```bash
pip3 install -r /Users/joefabre/Desktop/my_seims/requirements.txt
```

### 2. Start the server

```bash
cd /Users/joefabre/Desktop/my_seims
python3 app.py
```

### 3. Open the dashboard

Navigate to **http://localhost:5001** in any browser.

---

## Running in the Background

To run my_seims persistently in the background (survives closing the terminal):

```bash
cd /Users/joefabre/Desktop/my_seims
nohup python3 app.py > /tmp/seims.log 2>&1 &
echo "my_seims running — PID $!"
```

To stop it:

```bash
lsof -ti :5001 | xargs kill
```

To check the log:

```bash
tail -f /tmp/seims.log
```

---

## Auto-start on Login (launchd)

To have my_seims start automatically when you log in, create a launch agent:

```bash
cat > ~/Library/LaunchAgents/com.local.myseims.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.local.myseims</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/joefabre/Desktop/my_seims/app.py</string>
    </array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>/tmp/seims.log</string>
    <key>StandardErrorPath</key> <string>/tmp/seims.log</string>
    <key>WorkingDirectory</key>  <string>/Users/joefabre/Desktop/my_seims</string>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.local.myseims.plist
echo "my_seims registered as a login item"
```

To unload:

```bash
launchctl unload ~/Library/LaunchAgents/com.local.myseims.plist
```

---

## Project Structure

```
my_seims/
├── app.py                  # Flask backend — scanner, detection engine, API, scheduler, PDF generator
├── requirements.txt        # Python dependencies
├── run.sh                  # One-command startup script
├── README.md               # This file
├── templates/
│   └── index.html          # SPA shell (sidebar, topbar, modal, toast)
├── static/
│   ├── css/style.css       # Dark SIEM theme
│   └── js/app.js           # Frontend SPA — all pages, charts, API client
├── data/
│   └── seims.db            # SQLite database (auto-created on first run)
└── reports/                # Generated PDF reports
```

---

## Log Sources

| Source | Description |
|---|---|
| macOS Unified Log | Auth failures, sandbox violations, SSH, keychain, firewall, sudo, launchd |
| System Log | `/var/log/system.log` — errors and warnings |
| Install Log | `/var/log/install.log` — software installations |
| Login History | `last` / `lastb` — login sessions and failed attempts |
| Network Monitor | `netstat` — connections on suspicious ports |
| Process Scanner | `psutil` — known offensive tool process names |

---

## Detection Rules (Built-in)

| Rule | Severity | Category |
|---|---|---|
| Authentication Failure | HIGH | Authentication |
| Failed Login | HIGH | Authentication |
| Brute Force Detected | CRITICAL | Authentication |
| Password Changed | HIGH | Authentication |
| SSH Activity | MEDIUM | Authentication |
| Sudo Usage | MEDIUM | Privilege Escalation |
| Root Access | CRITICAL | Privilege Escalation |
| New User Created | CRITICAL | System Activity |
| Software Installed | LOW | System Activity |
| Config Change | MEDIUM | System Activity |
| Kernel Extension Loaded | HIGH | System Activity |
| LaunchAgent Added | HIGH | Persistence |
| Sandbox Violation | MEDIUM | Security |
| Permission Denied | LOW | Security |
| Keychain Access | MEDIUM | Security |
| Gatekeeper Block | HIGH | Security |
| FileVault Change | CRITICAL | Security |
| Firewall Block | MEDIUM | Network Activity |
| Suspicious Port | HIGH | Network Activity |
| Suspicious Process | CRITICAL | Malware / Suspicious |

Custom rules can be added, edited, enabled/disabled, or deleted via the **Detection Rules** page in the dashboard.

---

## Generating PDF Reports

1. Open **http://localhost:5001** and navigate to **Reports**
2. Click **Generate Report**
3. Set a title and time range (6h to 30 days)
4. Click **Generate** — the PDF downloads automatically and is saved to `my_seims/reports/`

PDF reports include:
- Overall status banner (CLEAN / MEDIUM / HIGH / CRITICAL)
- Summary stat cards
- Scan information (sources, interval, rules active)
- **Executive summary** in plain English
- **Alert details** — grouped by severity with "What Happened" plain-English descriptions
- **Event log** — grouped by category, with human-readable timestamps, source labels, and plain-English message translations
- Actionable recommendations

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/dashboard` | Dashboard stats, charts data, system health |
| GET | `/api/events` | Events list (paginated, filterable) |
| GET | `/api/events/:id` | Single event with human-readable fields |
| GET | `/api/alerts` | Alerts list (filterable by status/severity) |
| POST | `/api/alerts/:id/acknowledge` | Acknowledge an alert |
| POST | `/api/alerts/:id/resolve` | Resolve an alert |
| POST | `/api/alerts/bulk` | Bulk acknowledge or resolve |
| GET | `/api/rules` | All detection rules |
| POST | `/api/rules` | Create a new rule |
| PUT | `/api/rules/:id` | Update a rule |
| DELETE | `/api/rules/:id` | Delete a rule |
| POST | `/api/rules/:id/toggle` | Enable / disable a rule |
| POST | `/api/scan` | Trigger an immediate scan |
| GET | `/api/scan/history` | Last 20 scan records |
| GET | `/api/reports` | List generated reports |
| POST | `/api/reports/generate` | Generate a new PDF report |
| GET | `/api/reports/:filename/download` | Download a report |
| DELETE | `/api/reports/:id` | Delete a report |
| GET | `/api/settings` | Current settings |
| POST | `/api/settings` | Update settings |
| GET | `/api/system/health` | CPU, memory, disk, processes, connections |

---

## Dependencies

| Package | Purpose |
|---|---|
| `flask` | Web framework and REST API |
| `apscheduler` | Background scan scheduler |
| `reportlab` | PDF report generation |
| `psutil` | System metrics and process inspection |

---

## Maintenance Guide

### Routine tasks

**Check the app is running**
```bash
curl -s http://localhost:5001/api/dashboard | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK — events today:', d['stats']['total_today'])"
```

**View live server log**
```bash
tail -f /tmp/seims.log
```

**Restart the app**
```bash
lsof -ti :5001 | xargs kill 2>/dev/null
nohup python3 ~/Desktop/my_seims/app.py > /tmp/seims.log 2>&1 &
```

**Trigger an immediate scan from the command line**
```bash
curl -s -X POST http://localhost:5001/api/scan
```

---

### Database maintenance

The SQLite database lives at `data/seims.db`. It is never committed to git.

**Manually purge events older than 30 days**
```bash
sqlite3 ~/Desktop/my_seims/data/seims.db \
  "DELETE FROM events WHERE created_at < datetime('now', '-30 days');"
```

**Purge resolved alerts older than 60 days**
```bash
sqlite3 ~/Desktop/my_seims/data/seims.db \
  "DELETE FROM alerts WHERE status='resolved' AND resolved_at < datetime('now', '-60 days');"
```

**Compact the database after purging**
```bash
sqlite3 ~/Desktop/my_seims/data/seims.db "VACUUM;"
```

**Backup the database**
```bash
cp ~/Desktop/my_seims/data/seims.db ~/Desktop/my_seims/data/seims.db.bak
```

**Reset everything (wipe all events, alerts, and history)**
```bash
rm ~/Desktop/my_seims/data/seims.db
# Restart the app — the database is recreated automatically with default rules and settings
```

---

### Updating dependencies

```bash
pip3 install --upgrade flask apscheduler reportlab psutil
```

Test after upgrading:
```bash
curl -s http://localhost:5001/api/dashboard | python3 -c "import sys,json; print(json.load(sys.stdin)['stats'])"
```

---

### Granting Full Disk Access for complete log coverage

`log show` (used for unified log scanning) returns limited results without Full Disk Access.

1. Open **System Settings → Privacy & Security → Full Disk Access**
2. Click **+** and add your terminal app (Terminal, iTerm2, or Warp)
3. Restart the app

You will immediately see significantly more events per scan cycle.

---

### Auto-start on login

Create a launchd agent so my_seims starts automatically at login:

```bash
cat > ~/Library/LaunchAgents/com.local.myseims.plist << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.local.myseims</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Users/joefabre/Desktop/my_seims/app.py</string>
    </array>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>/tmp/seims.log</string>
    <key>StandardErrorPath</key> <string>/tmp/seims.log</string>
    <key>WorkingDirectory</key>  <string>/Users/joefabre/Desktop/my_seims</string>
</dict>
</plist>
PLIST
launchctl load ~/Library/LaunchAgents/com.local.myseims.plist
```

To remove it:
```bash
launchctl unload ~/Library/LaunchAgents/com.local.myseims.plist
rm ~/Library/LaunchAgents/com.local.myseims.plist
```

---

### Contributing changes

```bash
cd ~/Desktop/my_seims
git checkout -b feature/my-change
# make edits
git add -A && git commit -m "describe change"
git push -u origin feature/my-change
gh pr create --fill
```

---

## Detection Rule Guide

### How rules work

During each scan, every log event is tested against all enabled rules in sequence.
A rule matches when **either** its regex pattern matches the event message **or** its process name matches the event's process field.
When the match count within the configured time window reaches the threshold, an alert is created and stored in the database.

```
Event message  ──► regex pattern match? ──┐
Event process  ──► process name match?  ──┴──► threshold reached? ──► Alert created
```

---

### Rule fields

| Field | Type | Description |
|---|---|---|
| **Name** | string | Short display name shown in alerts and reports |
| **Description** | string | Plain-English explanation used in alert details and PDF reports |
| **Severity** | enum | `critical` / `high` / `medium` / `low` / `info` |
| **Category** | enum | Groups related rules — see categories below |
| **Pattern** | regex | Extended regex matched against the log message (case-insensitive). Leave blank to match by process only |
| **Process Name** | string | Exact process name substring match (e.g. `sudo`, `sshd`). Leave blank to match by pattern only |
| **Log Source** | enum | `unified` / `install` / `system` / `network` / `login` |
| **Threshold** | integer | Number of matches within the time window before an alert fires. Use `1` to alert on every match |
| **Time Window** | seconds | Rolling window for threshold counting. e.g. `300` = 5 matches in 5 minutes triggers once |
| **Enabled** | toggle | Disabled rules are skipped entirely during scanning |

---

### Categories

| Category | When to use |
|---|---|
| `authentication` | Login attempts, password events, SSH, MFA |
| `privilege_escalation` | sudo, su, root access, privilege grants |
| `network` | Suspicious connections, port scans, firewall events |
| `security` | Sandbox violations, Gatekeeper, keychain, FileVault |
| `system` | Software installs, config changes, kernel extensions |
| `persistence` | LaunchAgents, LaunchDaemons, startup items |
| `malware` | Known offensive tools, reverse shells, C2 patterns |

---

### Writing a pattern

Patterns are Python-compatible Extended Regular Expressions, matched case-insensitively against the full log message.

**Match a single keyword**
```
fileVault
```

**Match any of several keywords (OR)**
```
failed login|authentication failed|invalid password
```

**Match a keyword near another word**
```
sudo.*failed|failed.*sudo
```

**Match a specific process and action**
```
sshd.*invalid user
```

**Match an IP address pattern**
```
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*refused
```

**Test your pattern before saving** — paste it into a Python shell:
```python
import re, sqlite3
conn = sqlite3.connect('/Users/joefabre/Desktop/my_seims/data/seims.db')
pattern = r'your_pattern_here'
rows = conn.execute('SELECT message FROM events LIMIT 500').fetchall()
matches = [r[0] for r in rows if re.search(pattern, r[0], re.IGNORECASE)]
print(f'{len(matches)} matches'); [print(' -', m[:120]) for m in matches[:5]]
```

---

### Threshold and time window

| Goal | Threshold | Time Window |
|---|---|---|
| Alert on the very first occurrence | 1 | 60 |
| Alert only if it happens 3+ times in 5 minutes (brute force) | 3 | 300 |
| Alert if it happens 10+ times in an hour | 10 | 3600 |
| Suppress noisy low-signal events | 20 | 3600 |

---

### Example rules

**Detect curl or wget being run (data exfiltration indicator)**

| Field | Value |
|---|---|
| Name | Outbound Transfer Tool |
| Severity | medium |
| Category | network |
| Pattern | `\bcurl\b\|\bwget\b` |
| Process Name | *(leave blank)* |
| Threshold | 1 |
| Time Window | 60 |

**Alert on repeated permission denials from a single process (anomaly detection)**

| Field | Value |
|---|---|
| Name | Repeated Permission Denials |
| Severity | high |
| Category | security |
| Pattern | `[Pp]ermission denied` |
| Process Name | *(leave blank)* |
| Threshold | 10 |
| Time Window | 120 |

**Detect any attempt to modify /etc/hosts**

| Field | Value |
|---|---|
| Name | /etc/hosts Modified |
| Severity | critical |
| Category | system |
| Pattern | `/etc/hosts` |
| Process Name | *(leave blank)* |
| Threshold | 1 |
| Time Window | 60 |

**Detect Homebrew package installs**

| Field | Value |
|---|---|
| Name | Homebrew Install |
| Severity | low |
| Category | system |
| Pattern | `brew install\|brew upgrade` |
| Process Name | `brew` |
| Threshold | 1 |
| Time Window | 300 |

**Alert on any screen recording or screenshot tool**

| Field | Value |
|---|---|
| Name | Screen Capture Activity |
| Severity | medium |
| Category | security |
| Pattern | `screencapture\|screenshot\|screen recording` |
| Process Name | *(leave blank)* |
| Threshold | 1 |
| Time Window | 60 |

---

### Adding a rule via the API (scripting / automation)

```bash
curl -s -X POST http://localhost:5001/api/rules \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "My Custom Rule",
    "description": "Detects XYZ activity",
    "severity": "high",
    "category": "security",
    "pattern": "your_pattern_here",
    "process_name": "",
    "log_source": "unified",
    "threshold": 1,
    "time_window": 60,
    "enabled": 1
  }'
```

---

### Tuning existing rules

**A rule is too noisy (too many alerts)** 
Raise the threshold, narrow the pattern, or temporarily disable it while investigating.

**A rule is missing real events** 
Widen the pattern with `|` alternatives, or lower the threshold to 1 to ensure every match fires.

**A rule fires on the wrong process** 
Add the correct process name to restrict matching, or prefix the pattern with the process: `sudo.*your_term`.

**Viewing what a rule has caught so far**
```bash
sqlite3 ~/Desktop/my_seims/data/seims.db \
  "SELECT created_at, title, event_count FROM alerts WHERE rule_id=<ID> ORDER BY created_at DESC LIMIT 20;"
```

---

## Notes

- The server binds to `127.0.0.1:5001` only — not accessible from other machines on the network.
- The SQLite database and all reports are stored locally in `my_seims/data/` and `my_seims/reports/`.
- `log show` returns limited results without Full Disk Access — see Maintenance Guide above.
- This tool is for personal/local use and is not a replacement for enterprise security tooling.
