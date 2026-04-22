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

## Notes

- The server binds to `127.0.0.1:5001` only — it is not accessible from other machines on your network.
- The SQLite database and all reports are stored locally in `my_seims/data/` and `my_seims/reports/`.
- `log show` (used for unified log scanning) may return limited results without Full Disk Access. Grant it via **System Settings → Privacy & Security → Full Disk Access → Terminal**.
- This tool is for personal/local use. It is not a replacement for enterprise security tooling.
