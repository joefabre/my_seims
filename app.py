#!/usr/bin/env python3
"""
my_seims — macOS Security Information and Event Management System
"""

import json, re, sqlite3, subprocess, threading
from datetime import datetime, timedelta
from pathlib import Path

import psutil
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask import Flask, jsonify, request, render_template, send_file
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DB_PATH    = BASE_DIR / "data" / "seims.db"
REPORTS_DIR = BASE_DIR / "reports"
(BASE_DIR / "data").mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)

# ── Human-readable helpers ────────────────────────────────────────────────────
SOURCE_LABELS = {
    "unified_log":    "macOS Unified Log",
    "login_history":  "Login History",
    "network":        "Network Monitor",
    "process_scan":   "Process Scanner",
    "install_log":    "Software Install Log",
    "system_log":     "System Log",
}
CATEGORY_LABELS = {
    "authentication":       "Authentication",
    "privilege_escalation": "Privilege Escalation",
    "network":              "Network Activity",
    "system":               "System Activity",
    "security":             "Security",
    "malware":              "Malware / Suspicious",
    "persistence":          "Persistence",
}
SEV_LABELS = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
    "info":     "INFO",
}
SEV_DESCRIPTIONS = {
    "critical": "Requires immediate investigation.",
    "high":     "Should be reviewed promptly.",
    "medium":   "Warrants attention when possible.",
    "low":      "Informational; low risk.",
    "info":     "Routine activity.",
}

def fmt_ts(ts_str):
    """Convert ISO/syslog timestamp to human-readable string."""
    if not ts_str:
        return "Unknown time"
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
                "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str[:26], fmt)
            return dt.strftime("%A, %B %-d, %Y at %-I:%M %p")
        except ValueError:
            continue
    return ts_str[:19]

def humanize_message(message, process, category):
    """Rewrite raw log messages into plain English where possible."""
    if not message:
        return "No details available."
    msg = message.strip()
    lo  = msg.lower()

    # Auth patterns
    if "authentication failed" in lo or "auth failure" in lo:
        return f"An authentication attempt failed for process '{process}'."
    if "invalid password" in lo:
        return f"An invalid password was submitted to '{process}'."
    if "failed login" in lo or "login failed" in lo:
        return f"A login attempt failed on the system."
    if "su:" in lo or (process and "sudo" in process.lower()):
        return f"A privileged command was run via sudo by process '{process}': {msg}"
    if "permission denied" in lo:
        return f"Access was denied: {msg}"
    if "sandbox" in lo and "denied" in lo:
        return f"The macOS sandbox blocked a resource access request from '{process}'."
    if "installed" in lo and category == "system":
        return f"Software installation event recorded: {msg}"
    if "firewall" in lo and ("block" in lo or "deny" in lo):
        return f"The firewall blocked a network connection attempt."
    if "gatekeeper" in lo and "block" in lo:
        return f"Gatekeeper prevented an unauthorized application from opening."
    if "keychain" in lo:
        return f"A process accessed the system keychain: '{process}'. Message: {msg}"
    if "sshd" in (process or "").lower() or "sshd" in lo:
        return f"SSH daemon activity detected: {msg}"
    if "launchagent" in lo or "launchdaemon" in lo:
        return f"A new launch agent or daemon was registered on the system: {msg}"
    if "kextload" in lo or "kernel extension" in lo:
        return f"A kernel extension was loaded: {msg}"
    if "password changed" in lo or "changepassword" in lo:
        return f"A user password was changed on this system."
    if "new user" in lo or "useradd" in lo or "adduser" in lo:
        return f"A new user account was created on this system."
    if category == "malware":
        return f"A potentially malicious process was detected: '{process}'. {msg}"
    if category == "network":
        return f"Network anomaly detected: {msg}"
    # fallback — still cleaned
    return msg[:300]

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TEXT NOT NULL,
            source     TEXT NOT NULL DEFAULT 'system',
            process    TEXT,
            message    TEXT NOT NULL,
            severity   TEXT NOT NULL DEFAULT 'info',
            category   TEXT DEFAULT 'system',
            rule_id    INTEGER,
            raw        TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            title           TEXT NOT NULL,
            description     TEXT,
            severity        TEXT NOT NULL DEFAULT 'medium',
            category        TEXT DEFAULT 'system',
            status          TEXT DEFAULT 'new',
            event_count     INTEGER DEFAULT 1,
            rule_id         INTEGER,
            acknowledged_at TEXT,
            resolved_at     TEXT,
            created_at      TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS rules (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            description  TEXT,
            severity     TEXT NOT NULL DEFAULT 'medium',
            category     TEXT DEFAULT 'system',
            pattern      TEXT,
            process_name TEXT,
            log_source   TEXT DEFAULT 'unified',
            enabled      INTEGER DEFAULT 1,
            action       TEXT DEFAULT 'alert',
            threshold    INTEGER DEFAULT 1,
            time_window  INTEGER DEFAULT 300,
            created_at   TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            filename     TEXT NOT NULL,
            title        TEXT,
            generated_at TEXT DEFAULT (datetime('now')),
            size         INTEGER DEFAULT 0,
            event_count  INTEGER DEFAULT 0,
            alert_count  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS scan_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at       TEXT,
            completed_at     TEXT,
            events_found     INTEGER DEFAULT 0,
            alerts_generated INTEGER DEFAULT 0,
            status           TEXT DEFAULT 'running'
        );
        CREATE INDEX IF NOT EXISTS idx_ev_ts  ON events(created_at);
        CREATE INDEX IF NOT EXISTS idx_ev_sev ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_al_st  ON alerts(status);
        """)

def seed_defaults():
    with get_db() as c:
        for k, v in {"scan_interval": "15", "retention_days": "30",
                     "last_scan": "", "scan_lookback": "15m",
                     "auto_report": "false"}.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))

        if c.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0:
            rules = [
                ("Authentication Failure","Detects failed authentication attempts","high","authentication",
                 r"authentication failed|invalid password|failed to authenticate|auth failure","","unified",1,"alert",3,300),
                ("Failed Login","Failed login event","high","authentication",
                 r"failed login|login failed|LOGIN_FAILED","","unified",1,"alert",1,60),
                ("Sudo Usage","Tracks sudo command execution","medium","privilege_escalation",
                 "","sudo","unified",1,"alert",1,60),
                ("Root Access","Root account activity detected","critical","privilege_escalation",
                 r"root.*access|uid=0|as root","","unified",1,"alert",1,60),
                ("Brute Force Detected","Many auth failures in short window","critical","authentication",
                 r"authentication failed|invalid password","","unified",1,"alert",5,300),
                ("Software Installed","New software package installed","low","system",
                 r"Installed|PackageKit.*End install","installd","install",1,"alert",1,60),
                ("Sandbox Violation","macOS sandbox restriction triggered","medium","security",
                 r"[Ss]andbox.*denied|denied.*[Ss]andbox|Sandbox restriction","","unified",1,"alert",1,60),
                ("Permission Denied","Filesystem or resource access denied","low","security",
                 r"[Pp]ermission denied","","unified",1,"alert",5,120),
                ("SSH Activity","SSH login or access event","medium","authentication",
                 r"sshd|openssh|ssh.*accept|ssh.*fail","sshd","unified",1,"alert",1,60),
                ("Firewall Block","Firewall blocked a connection","medium","network",
                 r"firewall.*block|blocked.*firewall|pf.*deny|ipfw.*deny","","unified",1,"alert",1,60),
                ("Config Change","System configuration was modified","medium","system",
                 r"configuration.*changed|plist.*modified|launchctl.*load","","unified",1,"alert",1,60),
                ("Suspicious Process","Known offensive/malicious tool running","critical","malware",
                 r"netcat|ncat|nmap|masscan|hydra|meterpreter|metasploit|reverse.*shell","","unified",1,"alert",1,60),
                ("New User Created","A new user account was created","critical","system",
                 r"useradd|dscl.*create.*Users|sysadminctl.*addUser","","unified",1,"alert",1,60),
                ("Password Changed","User password was changed","high","authentication",
                 r"password.*changed|passwd.*changed|changePassword","","unified",1,"alert",1,60),
                ("Kernel Extension Loaded","Kernel extension (kext) was loaded","high","system",
                 r"kextload|kext.*loaded|kernel.*extension.*load","","unified",1,"alert",1,60),
                ("FileVault Change","Disk encryption status changed","critical","security",
                 r"FileVault|CoreStorage.*enable|diskutil.*cs","","unified",1,"alert",1,60),
                ("LaunchAgent Added","New persistence agent registered","high","persistence",
                 r"LaunchAgent.*install|LaunchDaemon.*install|launchd.*added","","unified",1,"alert",1,60),
                ("Keychain Access","Process accessed the system keychain","medium","security",
                 r"[Kk]eychain.*access|securityd.*keychain","","unified",1,"alert",3,120),
                ("Gatekeeper Block","App blocked by Gatekeeper","high","security",
                 r"Gatekeeper.*block|not.*permitted.*open|blocked.*Gatekeeper","","unified",1,"alert",1,60),
                ("Suspicious Port","Connection on a known suspicious port","high","network",
                 r"suspicious port","","network",1,"alert",1,60),
            ]
            c.executemany("""INSERT INTO rules(name,description,severity,category,pattern,
                process_name,log_source,enabled,action,threshold,time_window)
                VALUES(?,?,?,?,?,?,?,?,?,?,?)""", rules)

# ── Scanner ───────────────────────────────────────────────────────────────────
def run_cmd(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""

SYSLOG_RE = re.compile(
    r"^(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$"
)

def scan_unified_log(lookback="15m"):
    predicate = (
        'eventMessage contains[c] "authentication" OR '
        'eventMessage contains[c] "login" OR '
        'eventMessage contains[c] "password" OR '
        'eventMessage contains[c] "denied" OR '
        'eventMessage contains[c] "sandbox" OR '
        'eventMessage contains[c] "blocked" OR '
        'eventMessage contains[c] "firewall" OR '
        'eventMessage contains[c] "keychain" OR '
        'eventMessage contains[c] "gatekeeper" OR '
        'process == "sudo" OR process == "sshd" OR '
        'process == "installd" OR process == "launchd"'
    )
    output = run_cmd(
        ["log", "show", f"--last", lookback, "--predicate", predicate, "--style", "syslog"],
        timeout=25,
    )
    events = []
    for line in output.splitlines():
        m = SYSLOG_RE.match(line)
        if m:
            events.append({
                "timestamp": datetime.now().isoformat(),
                "source": "unified_log",
                "process": m.group(2),
                "message": m.group(4),
                "severity": "info",
                "category": "system",
                "raw": line,
            })
    return events

def scan_login_history():
    events = []
    for line in run_cmd(["last", "-20"]).splitlines():
        if line and not line.startswith("wtmp") and len(line.split()) >= 3:
            events.append({
                "timestamp": datetime.now().isoformat(),
                "source": "login_history",
                "process": "loginwindow",
                "message": f"Login session: {line.strip()}",
                "severity": "info", "category": "authentication", "raw": line,
            })
    for line in run_cmd(["lastb"]).splitlines():
        if line and not line.startswith("btmp") and len(line.split()) >= 3:
            events.append({
                "timestamp": datetime.now().isoformat(),
                "source": "login_history",
                "process": "loginwindow",
                "message": f"Failed login attempt: {line.strip()}",
                "severity": "high", "category": "authentication", "raw": line,
            })
    return events

def scan_network():
    events = []
    SUSP_PORTS = {4444, 1337, 31337, 6666, 8888, 9999, 1234, 5555, 12345}
    for line in run_cmd(["netstat", "-an", "-p", "tcp"], timeout=8).splitlines():
        if "ESTABLISHED" in line or "LISTEN" in line:
            parts = line.split()
            if len(parts) >= 5:
                try:
                    port = int(parts[3].rsplit(".", 1)[-1])
                    if port in SUSP_PORTS:
                        events.append({
                            "timestamp": datetime.now().isoformat(),
                            "source": "network",
                            "process": "netstat",
                            "message": f"suspicious port {port} active: {parts[3]} → {parts[4]} [{parts[-1]}]",
                            "severity": "high", "category": "network", "raw": line,
                        })
                except (ValueError, IndexError):
                    pass
    return events

def scan_processes():
    events = []
    SUSP = {"netcat","ncat","nmap","masscan","hydra","hashcat",
            "aircrack","kismet","msfconsole","meterpreter"}
    try:
        for p in psutil.process_iter(["pid","name","username"]):
            if p.info["name"] and p.info["name"].lower() in SUSP:
                events.append({
                    "timestamp": datetime.now().isoformat(),
                    "source": "process_scan",
                    "process": p.info["name"],
                    "message": (f"Suspicious process '{p.info['name']}' running "
                                f"(PID {p.info['pid']}, user: {p.info['username']})"),
                    "severity": "critical", "category": "malware", "raw": str(p.info),
                })
    except Exception:
        pass
    return events

def scan_install_log():
    events = []
    for line in run_cmd(["tail", "-20", "/var/log/install.log"], timeout=5).splitlines():
        if any(k in line for k in ["Installed", "PackageKit: ----- End"]):
            events.append({
                "timestamp": datetime.now().isoformat(),
                "source": "install_log",
                "process": "installd",
                "message": line.strip(),
                "severity": "low", "category": "system", "raw": line,
            })
    return events

def scan_system_log():
    events = []
    for line in run_cmd(["tail", "-30", "/var/log/system.log"], timeout=5).splitlines():
        lo = line.lower()
        if any(w in lo for w in ["critical","error","fail","warn"]):
            sev = "critical" if "critical" in lo else "medium" if ("error" in lo or "fail" in lo) else "low"
            events.append({
                "timestamp": datetime.now().isoformat(),
                "source": "system_log",
                "process": "system",
                "message": line.strip(),
                "severity": sev, "category": "system", "raw": line,
            })
    return events

# ── Detection Engine ──────────────────────────────────────────────────────────
def apply_rules_and_alert(events):
    conn = get_db()
    rules = conn.execute("SELECT * FROM rules WHERE enabled=1").fetchall()
    now   = datetime.now().isoformat()
    alerts_created = 0

    for ev in events:
        for rule in rules:
            matched = False
            pattern  = rule["pattern"]  or ""
            procname = rule["process_name"] or ""

            if pattern:
                try:
                    if re.search(pattern, ev.get("message",""), re.IGNORECASE):
                        matched = True
                except re.error:
                    if pattern.lower() in ev.get("message","").lower():
                        matched = True

            if procname and not matched:
                if procname.lower() in (ev.get("process") or "").lower():
                    matched = True

            if not matched:
                continue

            ev["severity"] = rule["severity"]
            ev["category"] = rule["category"]
            ev["rule_id"]   = rule["id"]

            window_start = (datetime.now() - timedelta(seconds=rule["time_window"] or 300)).isoformat()
            recent_count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE rule_id=? AND created_at>?",
                (rule["id"], window_start)
            ).fetchone()[0]

            threshold = rule["threshold"] or 1
            if threshold <= 1 or recent_count >= threshold - 1:
                conn.execute(
                    """INSERT INTO alerts(timestamp,title,description,severity,category,rule_id,event_count)
                       VALUES(?,?,?,?,?,?,?)""",
                    (now, rule["name"],
                     f"{rule['description'] or rule['name']}\n\n{ev.get('message','')}",
                     rule["severity"], rule["category"], rule["id"],
                     max(1, recent_count + 1))
                )
                alerts_created += 1

    conn.commit()
    conn.close()
    return alerts_created

def store_events(events):
    conn   = get_db()
    cutoff = (datetime.now() - timedelta(minutes=15)).isoformat()
    stored = 0
    for ev in events:
        msg = (ev.get("message") or "")[:500]
        if not conn.execute("SELECT id FROM events WHERE message=? AND created_at>?",
                            (msg, cutoff)).fetchone():
            conn.execute(
                """INSERT INTO events(timestamp,source,process,message,severity,category,rule_id,raw)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (ev.get("timestamp", datetime.now().isoformat()),
                 ev.get("source","system"),
                 (ev.get("process") or "")[:100],
                 msg,
                 ev.get("severity","info"),
                 ev.get("category","system"),
                 ev.get("rule_id"),
                 (ev.get("raw") or "")[:2000])
            )
            stored += 1
    conn.commit()
    conn.close()
    return stored

def run_scan():
    conn    = get_db()
    scan_id = conn.execute(
        "INSERT INTO scan_history(started_at,status) VALUES(?,?)",
        (datetime.now().isoformat(), "running")
    ).lastrowid
    conn.commit(); conn.close()

    try:
        conn2    = get_db()
        _row = conn2.execute("SELECT value FROM settings WHERE key='scan_lookback'").fetchone()
        lookback = _row["value"] if _row else "15m"
        conn2.close()

        all_events  = []
        all_events += scan_unified_log(lookback)
        all_events += scan_login_history()
        all_events += scan_network()
        all_events += scan_processes()
        all_events += scan_install_log()
        all_events += scan_system_log()

        n_alerts = apply_rules_and_alert(all_events)
        n_stored = store_events(all_events)

        with get_db() as c:
            c.execute("UPDATE scan_history SET completed_at=?,events_found=?,alerts_generated=?,status='completed' WHERE id=?",
                      (datetime.now().isoformat(), n_stored, n_alerts, scan_id))
            c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('last_scan',?)",
                      (datetime.now().isoformat(),))
        return {"events": n_stored, "alerts": n_alerts}
    except Exception as e:
        with get_db() as c:
            c.execute("UPDATE scan_history SET completed_at=?,status='failed' WHERE id=?",
                      (datetime.now().isoformat(), scan_id))
        return {"error": str(e)}

# ── PDF Report ────────────────────────────────────────────────────────────────
def generate_pdf(title=None, hours=24):
    with get_db() as c:
        cutoff  = (datetime.now() - timedelta(hours=hours)).isoformat()
        events  = [dict(r) for r in c.execute(
            "SELECT * FROM events WHERE created_at>? ORDER BY created_at DESC LIMIT 500", (cutoff,))]
        alerts  = [dict(r) for r in c.execute(
            "SELECT * FROM alerts WHERE created_at>? ORDER BY CASE severity WHEN 'critical' THEN 1 "
            "WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC",
            (cutoff,))]
        _ls = c.execute("SELECT value FROM settings WHERE key='last_scan'").fetchone()
        last_scan = _ls["value"] if _ls else ""
        all_rules = {r["id"]: r["name"] for r in c.execute("SELECT id,name FROM rules")}

    if not title:
        title = f"Security Report — {datetime.now().strftime('%B %-d, %Y')}"

    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = REPORTS_DIR / filename

    doc = SimpleDocTemplate(str(filepath), pagesize=letter,
                            rightMargin=0.75*inch, leftMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)

    # ── Styles ───────────────────────────────────────────────────────────────
    S      = getSampleStyleSheet()
    DARK   = colors.HexColor("#1a1a2e")
    MUTED  = colors.HexColor("#555555")
    BLUE   = colors.HexColor("#2962ff")

    def ps(name, **kw):
        return ParagraphStyle(name, parent=S["Normal"], **kw)

    title_s   = ps("T",  fontSize=22, textColor=DARK, spaceAfter=4, fontName="Helvetica-Bold")
    brand_s   = ps("Br", fontSize=10, textColor=BLUE, spaceAfter=2, fontName="Helvetica-Bold")
    sub_s     = ps("Su", fontSize=9,  textColor=MUTED, spaceAfter=14, alignment=TA_CENTER)
    h2_s      = ps("H2", fontSize=13, textColor=DARK, spaceBefore=16, spaceAfter=5,
                   fontName="Helvetica-Bold")
    h3_s      = ps("H3", fontSize=10, textColor=DARK, spaceBefore=10, spaceAfter=3,
                   fontName="Helvetica-Bold")
    body_s    = ps("Bo", fontSize=9,  leading=14, spaceAfter=5)
    bullet_s  = ps("Bu", fontSize=9,  leading=14, leftIndent=14, spaceAfter=3)
    italic_s  = ps("It", fontSize=9,  leading=14, spaceAfter=5, fontName="Helvetica-Oblique",
                   textColor=MUTED)
    # A "log block" style — monospaced, shaded, for showing clean structured data
    log_s     = ps("Lo", fontName="Courier", fontSize=8, leading=12,
                   backColor=colors.HexColor("#f5f7fa"),
                   leftIndent=10, rightIndent=10,
                   borderPadding=6, spaceAfter=6)
    label_s   = ps("La", fontName="Helvetica-Bold", fontSize=8,
                   textColor=colors.HexColor("#333333"), spaceAfter=1, spaceBefore=8)

    SEV_C = {
        "critical": colors.HexColor("#d32f2f"),
        "high":     colors.HexColor("#e64a19"),
        "medium":   colors.HexColor("#f9a825"),
        "low":      colors.HexColor("#388e3c"),
        "info":     colors.HexColor("#1565c0"),
    }
    SEV_BG = {
        "critical": colors.HexColor("#ffebee"),
        "high":     colors.HexColor("#fbe9e7"),
        "medium":   colors.HexColor("#fffde7"),
        "low":      colors.HexColor("#e8f5e9"),
        "info":     colors.HexColor("#e3f2fd"),
    }

    def hr(): return HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc"))
    def thick_hr(): return HRFlowable(width="100%", thickness=1.5, color=DARK)

    # ── Compute summary stats ─────────────────────────────────────────────────
    sev_counts  = {}
    cat_counts  = {}
    for ev in events:
        sev_counts[ev["severity"]] = sev_counts.get(ev["severity"], 0) + 1
        cat_counts[ev["category"]] = cat_counts.get(ev["category"], 0) + 1

    alert_sev = {"critical":0, "high":0, "medium":0, "low":0, "info":0}
    for al in alerts:
        if al["severity"] in alert_sev:
            alert_sev[al["severity"]] += 1

    new_alerts = sum(1 for a in alerts if a["status"] == "new")
    overall    = ("CRITICAL" if alert_sev["critical"] > 0
                  else "HIGH"   if alert_sev["high"]     > 0
                  else "MEDIUM" if alert_sev["medium"]   > 0
                  else "CLEAN")
    overall_c  = SEV_C.get(overall.lower(), colors.HexColor("#2e7d32"))
    overall_bg = SEV_BG.get(overall.lower(), colors.HexColor("#e8f5e9"))

    # ── Build story ───────────────────────────────────────────────────────────
    story = []

    # ─ Cover ──────────────────────────────────────────────────────────────────
    story += [
        Paragraph("my_seims", brand_s),
        Paragraph(title, title_s),
        Paragraph(
            f"Generated: {datetime.now().strftime('%A, %B %-d, %Y at %-I:%M %p')}&nbsp;&nbsp;|&nbsp;&nbsp;"
            f"Period: Last {hours} hours&nbsp;&nbsp;|&nbsp;&nbsp;"
            f"Host: {__import__('socket').gethostname()}", sub_s),
        thick_hr(), Spacer(1, 10),
    ]

    # Overall status banner
    banner = Table([[
        Paragraph("OVERALL STATUS", ps("bs", fontName="Helvetica-Bold", fontSize=10,
                                       textColor=colors.white)),
        Paragraph(f"{overall} — {len(alerts)} alert(s), {len(events)} event(s) in period",
                  ps("bv", fontName="Helvetica-Bold", fontSize=10, textColor=overall_c))
    ]], colWidths=[1.4*inch, 5.6*inch])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), DARK),
        ("BACKGROUND", (1,0), (1,0), overall_bg),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",    (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("BOX",        (0,0), (-1,-1), 1, DARK),
    ]))
    story += [banner, Spacer(1, 16)]

    # ─ Stat cards ─────────────────────────────────────────────────────────────
    stat_data = [
        ["Total Events", "Active Alerts", "Critical", "High", "Medium"],
        [str(len(events)), str(new_alerts),
         str(alert_sev["critical"]), str(alert_sev["high"]), str(alert_sev["medium"])]
    ]
    st = Table(stat_data, colWidths=[1.4*inch]*5)
    st.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (-1,0),  DARK),
        ("TEXTCOLOR",    (0,0), (-1,0),  colors.white),
        ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("ALIGN",        (0,0), (-1,-1), "CENTER"),
        ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0), (-1,-1), 8),
        ("BOTTOMPADDING",(0,0), (-1,-1), 8),
        ("FONTNAME",     (0,1), (-1,1),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,1), (-1,1),  16),
        ("TEXTCOLOR",    (1,1), (1,1),   SEV_C.get(overall.lower(), colors.black)),
        ("TEXTCOLOR",    (2,1), (2,1),   SEV_C["critical"]),
        ("TEXTCOLOR",    (3,1), (3,1),   SEV_C["high"]),
        ("TEXTCOLOR",    (4,1), (4,1),   SEV_C["medium"]),
        ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
    ]))
    story += [st, Spacer(1, 18)]

    # ─ Executive Summary ──────────────────────────────────────────────────────
    story += [Paragraph("Executive Summary", h2_s), hr(), Spacer(1, 6)]
    if not alerts:
        story.append(Paragraph(
            f"No security alerts were generated during the last {hours}-hour reporting period. "
            "All monitored log sources were scanned and activity appears consistent with normal "
            "system operation.", body_s))
    else:
        top_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        cat_str  = ", ".join(CATEGORY_LABELS.get(c, c) for c, _ in top_cats)
        story.append(Paragraph(
            f"During the last <b>{hours} hours</b>, my_seims recorded <b>{len(events)} events</b> "
            f"and generated <b>{len(alerts)} alert(s)</b> across {len(set(a['category'] for a in alerts))} "
            f"categories. The most active categories were: <b>{cat_str}</b>. "
            f"There are currently <b>{new_alerts} unacknowledged alert(s)</b> requiring attention.",
            body_s))
        if alert_sev["critical"] > 0:
            story.append(Paragraph(
                f"⚠  <b>{alert_sev['critical']} CRITICAL alert(s)</b> were detected and require "
                "immediate review.", ps("crit", fontSize=9, leading=14, spaceAfter=5,
                                        textColor=SEV_C["critical"])))
        if alert_sev["high"] > 0:
            story.append(Paragraph(
                f"  {alert_sev['high']} HIGH severity alert(s) should be reviewed promptly.", body_s))
    story.append(Spacer(1, 8))

    # ─ Scan Information ───────────────────────────────────────────────────────
    story += [Paragraph("Scan Information", h2_s), hr(), Spacer(1, 6)]
    scan_info = [
        ["Reporting Period",  f"Last {hours} hours ({datetime.now().strftime('%B %-d, %Y %-I:%M %p')} and prior)"],
        ["Last Scan Run",     fmt_ts(last_scan) if last_scan else "No scan recorded"],
        ["Scan Interval",     "Every 15 minutes (configurable)"],
        ["Log Sources",       "macOS Unified Log, System Log, Install Log, Login History, Network Monitor, Process Scanner"],
        ["Detection Rules",   f"{len(all_rules)} rules active"],
        ["Events Collected",  str(len(events))],
        ["Alerts Generated",  str(len(alerts))],
    ]
    si = Table(scan_info, colWidths=[1.8*inch, 5.2*inch])
    si.setStyle(TableStyle([
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",         (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
        ("TOPPADDING",   (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0), (-1,-1), 6),
        ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ("VALIGN",       (0,0), (-1,-1), "TOP"),
    ]))
    story += [si, Spacer(1, 16)]

    # ─ Alert Details (human-readable, grouped by severity) ────────────────────
    story += [Paragraph("Alert Details", h2_s), hr(), Spacer(1, 6)]

    if not alerts:
        story.append(Paragraph("No alerts were generated in this reporting period.", italic_s))
    else:
        for sev in ["critical", "high", "medium", "low", "info"]:
            sev_alerts = [a for a in alerts if a["severity"] == sev]
            if not sev_alerts:
                continue

            # Severity section header
            sev_header = Table([[
                Paragraph(f" {SEV_LABELS[sev]}", ps("sh", fontName="Helvetica-Bold",
                          fontSize=10, textColor=colors.white)),
                Paragraph(f"{len(sev_alerts)} alert(s)  —  {SEV_DESCRIPTIONS[sev]}",
                          ps("sd", fontSize=9, textColor=SEV_C[sev]))
            ]], colWidths=[1.0*inch, 6.0*inch])
            sev_header.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (0,0), SEV_C[sev]),
                ("BACKGROUND",  (1,0), (1,0), SEV_BG[sev]),
                ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",  (0,0), (-1,-1), 7),
                ("BOTTOMPADDING",(0,0),(-1,-1), 7),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("BOX",         (0,0), (-1,-1), 0.5, SEV_C[sev]),
            ]))
            story += [sev_header, Spacer(1, 6)]

            for al in sev_alerts:
                rule_name  = all_rules.get(al["rule_id"], "Manual")
                human_desc = humanize_message(
                    al["description"], al.get("category",""), al.get("category",""))
                status_str  = al["status"].upper()
                ack_str     = ""
                if al.get("acknowledged_at"):
                    ack_str = f" (Acknowledged: {fmt_ts(al['acknowledged_at'])})"
                elif al.get("resolved_at"):
                    ack_str = f" (Resolved: {fmt_ts(al['resolved_at'])})"

                block = KeepTogether([
                    Paragraph(f"<b>{al['title']}</b>", h3_s),
                    Table([[
                        Paragraph("Time Detected",  label_s),
                        Paragraph("Detection Rule", label_s),
                        Paragraph("Category",       label_s),
                        Paragraph("Status",         label_s),
                    ],[
                        Paragraph(fmt_ts(al["created_at"]), body_s),
                        Paragraph(rule_name, body_s),
                        Paragraph(CATEGORY_LABELS.get(al["category"], al["category"]), body_s),
                        Paragraph(f"{status_str}{ack_str}", body_s),
                    ]], colWidths=[1.75*inch, 1.75*inch, 1.75*inch, 1.75*inch],
                    style=TableStyle([
                        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#f0f0f0")),
                        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                        ("FONTSIZE",    (0,0), (-1,-1), 8),
                        ("GRID",        (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
                        ("TOPPADDING",  (0,0), (-1,-1), 5),
                        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
                        ("LEFTPADDING", (0,0), (-1,-1), 6),
                        ("VALIGN",      (0,0), (-1,-1), "TOP"),
                    ])),
                    Paragraph("<b>What happened:</b>", label_s),
                    Paragraph(human_desc, body_s),
                    Spacer(1, 8),
                ])
                story.append(block)

    story += [PageBreak()]

    # ─ Event Log (human-readable table) ───────────────────────────────────────
    story += [Paragraph("Event Log", h2_s), hr(), Spacer(1, 4)]
    story.append(Paragraph(
        "Each row below represents one security-relevant event captured from system log sources. "
        "Events are shown in reverse chronological order. The 'What Happened' column contains a "
        "plain-English interpretation of the raw log entry.", italic_s))
    story.append(Spacer(1, 8))

    if not events:
        story.append(Paragraph("No events recorded in this period.", italic_s))
    else:
        # Group events by category for readability
        cats_present = list(dict.fromkeys(ev["category"] for ev in events))
        for cat in cats_present:
            cat_events = [ev for ev in events if ev["category"] == cat]
            story += [
                Paragraph(CATEGORY_LABELS.get(cat, cat.title()), h3_s),
                Spacer(1, 4),
            ]

            ev_data = [["Date & Time", "Severity", "Source", "Process", "What Happened"]]
            for ev in cat_events[:60]:   # max 60 per category
                human = humanize_message(ev["message"], ev["process"], ev["category"])
                sev   = ev["severity"]
                ev_data.append([
                    Paragraph(fmt_ts(ev["created_at"]), ps("et", fontSize=7, leading=10)),
                    Paragraph(SEV_LABELS.get(sev, sev.upper()),
                              ps("es", fontSize=7, leading=10, fontName="Helvetica-Bold",
                                 textColor=SEV_C.get(sev, colors.black))),
                    Paragraph(SOURCE_LABELS.get(ev["source"], ev["source"]),
                              ps("eso", fontSize=7, leading=10)),
                    Paragraph((ev["process"] or "—")[:20],
                              ps("ep", fontSize=7, leading=10, fontName="Courier")),
                    Paragraph(human[:180],
                              ps("em", fontSize=7, leading=10)),
                ])

            ev_tbl = Table(ev_data, colWidths=[1.2*inch, 0.6*inch, 1.0*inch, 0.85*inch, 3.35*inch])
            ts = [
                ("BACKGROUND",    (0,0), (-1,0), DARK),
                ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
                ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,0), 8),
                ("GRID",          (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
                ("TOPPADDING",    (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING",   (0,0), (-1,-1), 4),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ]
            for i in range(1, len(ev_data)):
                bg = colors.white if i % 2 == 0 else colors.HexColor("#fafafa")
                ts.append(("BACKGROUND", (0,i), (-1,i), bg))
                sev = ev_data[i][1].text if hasattr(ev_data[i][1], "text") else ""

            ev_tbl.setStyle(TableStyle(ts))
            story += [ev_tbl, Spacer(1, 12)]

    # ─ Recommendations ────────────────────────────────────────────────────────
    story += [Paragraph("Recommendations", h2_s), hr(), Spacer(1, 6)]
    recs = [
        ("Keep macOS up to date",
         "Ensure macOS and all applications are on the latest versions. "
         "Microsoft AutoUpdate is active — keep it running."),
        ("Review unacknowledged alerts",
         f"There are currently {new_alerts} unacknowledged alert(s). Log in to my_seims "
         "at http://localhost:5001 and review them in the Alerts section."),
        ("Enable macOS Firewall",
         "Verify the firewall is active: System Settings → Network → Firewall."),
        ("Audit Login History Regularly",
         "Check the Login History section in my_seims after each scan to verify "
         "only authorized users are accessing the system."),
        ("Review Detection Rules",
         "Tune the detection rules in my_seims to match your environment and "
         "reduce false positives while ensuring coverage of real threats."),
        ("Schedule Automated Reports",
         "Enable auto-reporting in my_seims Settings to receive a daily PDF "
         "summary of security activity."),
    ]
    for rec_title, rec_body in recs:
        story += [
            Paragraph(f"→ {rec_title}", ps("rt", fontSize=9, fontName="Helvetica-Bold",
                                            spaceAfter=2, spaceBefore=6)),
            Paragraph(rec_body, bullet_s),
        ]

    # ─ Footer ─────────────────────────────────────────────────────────────────
    story += [
        Spacer(1, 20), thick_hr(), Spacer(1, 6),
        Paragraph("Generated by my_seims — macOS Security Information &amp; Event Management System "
                  "— for informational purposes only.", sub_s),
    ]

    doc.build(story)

    size = filepath.stat().st_size
    with get_db() as c:
        c.execute("INSERT INTO reports(filename,title,size,event_count,alert_count) VALUES(?,?,?,?,?)",
                  (filename, title, size, len(events), len(alerts)))

    return filename, str(filepath)

# ── API Routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/dashboard")
def api_dashboard():
    conn = get_db()
    now  = datetime.now()
    today     = now.replace(hour=0, minute=0, second=0).isoformat()
    h24_ago   = (now - timedelta(hours=24)).isoformat()
    h1_ago    = (now - timedelta(hours=1)).isoformat()

    total_today   = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>?", (today,)).fetchone()[0]
    active_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='new'").fetchone()[0]
    crit_alerts   = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status='new'").fetchone()[0]
    high_alerts   = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='high' AND status='new'").fetchone()[0]
    events_1h     = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>?", (h1_ago,)).fetchone()[0]

    _ls_row = conn.execute("SELECT value FROM settings WHERE key='last_scan'").fetchone()
    last_scan = _ls_row["value"] if _ls_row else ""

    sev_rows  = conn.execute(
        "SELECT severity, COUNT(*) cnt FROM events WHERE created_at>? GROUP BY severity", (h24_ago,)
    ).fetchall()
    sev_dist  = {r["severity"]: r["cnt"] for r in sev_rows}

    hourly = []
    for i in range(23, -1, -1):
        s = (now - timedelta(hours=i+1)).isoformat()
        e = (now - timedelta(hours=i)).isoformat()
        cnt = conn.execute("SELECT COUNT(*) FROM events WHERE created_at>? AND created_at<=?", (s,e)).fetchone()[0]
        hourly.append({"hour": (now - timedelta(hours=i)).strftime("%H:00"), "count": cnt})

    recent_alerts = [dict(r) for r in conn.execute(
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 8")]
    top_cats = [dict(r) for r in conn.execute(
        "SELECT category, COUNT(*) cnt FROM alerts WHERE created_at>? GROUP BY category ORDER BY cnt DESC LIMIT 6",
        (h24_ago,))]
    scan_hist = [dict(r) for r in conn.execute(
        "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 10")]

    try:
        cpu  = psutil.cpu_percent(interval=0.1)
        mem  = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
    except Exception:
        cpu = mem = disk = 0

    conn.close()
    return jsonify({
        "stats": {"total_today": total_today, "active_alerts": active_alerts,
                  "critical_alerts": crit_alerts, "high_alerts": high_alerts,
                  "events_1h": events_1h},
        "last_scan": last_scan,
        "severity_distribution": sev_dist,
        "hourly_events": hourly,
        "recent_alerts": recent_alerts,
        "top_categories": top_cats,
        "scan_history": scan_hist,
        "system_health": {"cpu": cpu, "memory": mem, "disk": disk},
    })

@app.route("/api/events")
def api_events():
    conn    = get_db()
    page    = int(request.args.get("page", 1))
    pp      = int(request.args.get("per_page", 50))
    sev     = request.args.get("severity", "")
    cat     = request.args.get("category", "")
    src     = request.args.get("source", "")
    search  = request.args.get("search", "")
    hours   = int(request.args.get("hours", 24))
    cutoff  = (datetime.now() - timedelta(hours=hours)).isoformat()
    offset  = (page - 1) * pp
    where   = ["created_at>?"]; params = [cutoff]
    if sev:    where.append("severity=?");  params.append(sev)
    if cat:    where.append("category=?");  params.append(cat)
    if src:    where.append("source=?");    params.append(src)
    if search: where.append("message LIKE ?"); params.append(f"%{search}%")
    wc = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM events WHERE {wc}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM events WHERE {wc} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [pp, offset]).fetchall()
    conn.close()
    return jsonify({
        "events": [dict(r) for r in rows],
        "total": total, "page": page,
        "pages": max(1, (total + pp - 1) // pp),
    })

@app.route("/api/events/<int:eid>")
def api_event_detail(eid):
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    conn.close()
    if not ev:
        return jsonify({"error": "Not found"}), 404
    d = dict(ev)
    d["human_message"] = humanize_message(d["message"], d["process"], d["category"])
    d["source_label"]  = SOURCE_LABELS.get(d["source"], d["source"])
    d["category_label"]= CATEGORY_LABELS.get(d["category"], d["category"])
    d["timestamp_human"]= fmt_ts(d["created_at"])
    return jsonify(d)

@app.route("/api/alerts")
def api_alerts():
    conn   = get_db()
    page   = int(request.args.get("page", 1))
    pp     = int(request.args.get("per_page", 50))
    status = request.args.get("status", "")
    sev    = request.args.get("severity", "")
    offset = (page - 1) * pp
    where  = ["1=1"]; params = []
    if status: where.append("status=?");   params.append(status)
    if sev:    where.append("severity=?"); params.append(sev)
    wc    = " AND ".join(where)
    total = conn.execute(f"SELECT COUNT(*) FROM alerts WHERE {wc}", params).fetchone()[0]
    rows  = conn.execute(
        f"SELECT * FROM alerts WHERE {wc} ORDER BY "
        "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
        "WHEN 'low' THEN 4 ELSE 5 END, created_at DESC LIMIT ? OFFSET ?",
        params + [pp, offset]).fetchall()
    conn.close()
    return jsonify({
        "alerts": [dict(r) for r in rows],
        "total": total, "page": page,
        "pages": max(1, (total + pp - 1) // pp),
    })

@app.route("/api/alerts/<int:aid>/acknowledge", methods=["POST"])
def api_ack(aid):
    with get_db() as c:
        c.execute("UPDATE alerts SET status='acknowledged',acknowledged_at=? WHERE id=?",
                  (datetime.now().isoformat(), aid))
    return jsonify({"status": "ok"})

@app.route("/api/alerts/<int:aid>/resolve", methods=["POST"])
def api_resolve(aid):
    with get_db() as c:
        c.execute("UPDATE alerts SET status='resolved',resolved_at=? WHERE id=?",
                  (datetime.now().isoformat(), aid))
    return jsonify({"status": "ok"})

@app.route("/api/alerts/bulk", methods=["POST"])
def api_bulk():
    data   = request.json or {}
    action = data.get("action")
    ids    = data.get("ids", [])
    if not ids or action not in ("acknowledge","resolve"):
        return jsonify({"error": "Invalid"}), 400
    now = datetime.now().isoformat()
    with get_db() as c:
        for aid in ids:
            if action == "acknowledge":
                c.execute("UPDATE alerts SET status='acknowledged',acknowledged_at=? WHERE id=?", (now,aid))
            else:
                c.execute("UPDATE alerts SET status='resolved',resolved_at=? WHERE id=?", (now,aid))
    return jsonify({"status": "ok", "count": len(ids)})

@app.route("/api/rules", methods=["GET"])
def api_rules_get():
    conn = get_db()
    rows = conn.execute("SELECT * FROM rules ORDER BY CASE severity WHEN 'critical' THEN 1 "
                        "WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, name").fetchall()
    conn.close()
    return jsonify({"rules": [dict(r) for r in rows]})

@app.route("/api/rules", methods=["POST"])
def api_rules_create():
    d = request.json or {}
    with get_db() as c:
        c.execute("""INSERT INTO rules(name,description,severity,category,pattern,
                     process_name,log_source,enabled,action,threshold,time_window)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                  (d.get("name"), d.get("description"), d.get("severity","medium"),
                   d.get("category","system"), d.get("pattern"), d.get("process_name"),
                   d.get("log_source","unified"), d.get("enabled",1),
                   d.get("action","alert"), d.get("threshold",1), d.get("time_window",300)))
    return jsonify({"status": "ok"})

@app.route("/api/rules/<int:rid>", methods=["PUT"])
def api_rules_update(rid):
    d = request.json or {}
    with get_db() as c:
        c.execute("""UPDATE rules SET name=?,description=?,severity=?,category=?,pattern=?,
                     process_name=?,log_source=?,enabled=?,action=?,threshold=?,time_window=?
                     WHERE id=?""",
                  (d.get("name"), d.get("description"), d.get("severity"),
                   d.get("category"), d.get("pattern"), d.get("process_name"),
                   d.get("log_source"), d.get("enabled"), d.get("action"),
                   d.get("threshold"), d.get("time_window"), rid))
    return jsonify({"status": "ok"})

@app.route("/api/rules/<int:rid>", methods=["DELETE"])
def api_rules_delete(rid):
    with get_db() as c:
        c.execute("DELETE FROM rules WHERE id=?", (rid,))
    return jsonify({"status": "ok"})

@app.route("/api/rules/<int:rid>/toggle", methods=["POST"])
def api_rules_toggle(rid):
    with get_db() as c:
        c.execute("UPDATE rules SET enabled=CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?", (rid,))
    return jsonify({"status": "ok"})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    result = run_scan()
    return jsonify(result)

@app.route("/api/scan/history")
def api_scan_history():
    conn = get_db()
    rows = conn.execute("SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 20").fetchall()
    conn.close()
    return jsonify({"history": [dict(r) for r in rows]})

@app.route("/api/reports", methods=["GET"])
def api_reports_get():
    conn = get_db()
    rows = conn.execute("SELECT * FROM reports ORDER BY generated_at DESC").fetchall()
    conn.close()
    return jsonify({"reports": [dict(r) for r in rows]})

@app.route("/api/reports/generate", methods=["POST"])
def api_reports_generate():
    d = request.json or {}
    try:
        filename, _ = generate_pdf(title=d.get("title"), hours=int(d.get("hours", 24)))
        return jsonify({"status": "ok", "filename": filename})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/reports/<filename>/download")
def api_reports_download(filename):
    fp = REPORTS_DIR / filename
    if fp.exists():
        return send_file(str(fp), as_attachment=True)
    return jsonify({"error": "Not found"}), 404

@app.route("/api/reports/<int:rid>", methods=["DELETE"])
def api_reports_delete(rid):
    conn = get_db()
    row  = conn.execute("SELECT filename FROM reports WHERE id=?", (rid,)).fetchone()
    if row:
        fp = REPORTS_DIR / row["filename"]
        if fp.exists(): fp.unlink()
        conn.execute("DELETE FROM reports WHERE id=?", (rid,))
        conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    conn = get_db()
    rows = conn.execute("SELECT * FROM settings").fetchall()
    conn.close()
    return jsonify({r["key"]: r["value"] for r in rows})

@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    data = request.json or {}
    with get_db() as c:
        for k, v in data.items():
            c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (k, str(v)))
    if "scan_interval" in data:
        try:
            scheduler.reschedule_job("scan_job",
                trigger=IntervalTrigger(minutes=int(data["scan_interval"])))
        except Exception:
            pass
    return jsonify({"status": "ok"})

@app.route("/api/system/health")
def api_health():
    cpu  = psutil.cpu_percent(interval=0.5)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net  = psutil.net_io_counters()

    procs = []
    try:
        for p in sorted(psutil.process_iter(["pid","name","cpu_percent","memory_percent"]),
                        key=lambda x: x.info.get("cpu_percent") or 0, reverse=True)[:12]:
            try:
                procs.append({"pid": p.info["pid"], "name": p.info["name"],
                              "cpu": round(p.info.get("cpu_percent") or 0, 1),
                              "mem": round(p.info.get("memory_percent") or 0, 1)})
            except Exception:
                pass
    except Exception:
        pass

    conns = []
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                if c.status == "ESTABLISHED" and c.raddr:
                    conns.append({
                        "local":  f"{c.laddr.ip}:{c.laddr.port}",
                        "remote": f"{c.raddr.ip}:{c.raddr.port}",
                        "status": c.status,
                        "pid":    c.pid,
                    })
            except Exception:
                pass
    except Exception:
        pass

    return jsonify({
        "cpu": cpu,
        "memory":  {"percent": mem.percent,  "used": mem.used,  "total": mem.total},
        "disk":    {"percent": disk.percent,  "used": disk.used, "total": disk.total},
        "network": {"sent": net.bytes_sent, "recv": net.bytes_recv},
        "top_processes":  procs,
        "connections":    conns[:20],
    })

# ── Scheduler ──────────────────────────────────────────────────────────────────
scheduler = BackgroundScheduler(daemon=True)

if __name__ == "__main__":
    init_db()
    seed_defaults()
    with get_db() as c:
        _iv = c.execute("SELECT value FROM settings WHERE key='scan_interval'").fetchone()
        iv = _iv["value"] if _iv else "15"
    scheduler.add_job(run_scan, IntervalTrigger(minutes=int(iv)), id="scan_job", replace_existing=True)
    scheduler.start()
    threading.Thread(target=run_scan, daemon=True).start()
    print("\n" + "═"*55)
    print("  my_seims  ·  macOS SIEM")
    print("  http://localhost:5001")
    print("═"*55 + "\n")
    app.run(host="127.0.0.1", port=5001, debug=False)
