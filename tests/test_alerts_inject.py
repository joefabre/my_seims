#!/usr/bin/env python3
"""
test_alerts_inject.py
Injects synthetic test events and alerts at ALL five severity levels
(critical, high, medium, low, info) directly into the database.
Use this to populate the UI and verify rendering at every level.

Usage:
    python3 ~/Desktop/my_seims/tests/test_alerts_inject.py          # inject
    python3 ~/Desktop/my_seims/tests/test_alerts_inject.py --clean  # remove test data
"""

import sqlite3, sys, json, urllib.request
from datetime import datetime, timedelta
from pathlib import Path

DB   = Path.home() / 'Desktop/my_seims/data/seims.db'
BASE = 'http://localhost:5001'

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())

C = {
    'critical':'\033[91m','high':'\033[93m','medium':'\033[94m',
    'low':'\033[92m','info':'\033[37m','reset':'\033[0m',
    'bold':'\033[1m','dim':'\033[2m','green':'\033[32m',
}

MARKER = '[TEST]'   # all injected rows carry this prefix for easy cleanup

# ── Test data at every level ──────────────────────────────────────────────────
TEST_EVENTS = [
    # (source, process, message, severity, category)
    ('unified_log',   'sudo',          f'{MARKER} joefabre ran: sudo rm -rf /private/tmp/testdir',
     'critical', 'privilege_escalation'),
    ('login_history', 'loginwindow',   f'{MARKER} Failed login attempt: badactor   tty0    Tue Apr 22 03:00',
     'critical', 'authentication'),
    ('process_scan',  'meterpreter',   f'{MARKER} Suspicious process meterpreter running (PID 99999, user: nobody)',
     'critical', 'malware'),

    ('unified_log',   'sshd',          f'{MARKER} sshd: Invalid user admin from 192.168.1.50 port 54321',
     'high', 'authentication'),
    ('unified_log',   'installd',      f'{MARKER} Installed kernel extension: com.test.unsigned.kext',
     'high', 'system'),
    ('unified_log',   'launchd',       f'{MARKER} LaunchAgent installed: ~/Library/LaunchAgents/com.suspicious.plist',
     'high', 'persistence'),
    ('unified_log',   'Gatekeeper',    f'{MARKER} Gatekeeper blocked untrusted application: /tmp/backdoor.app',
     'high', 'security'),

    ('unified_log',   'sudo',          f'{MARKER} sudo: joefabre ran command as root: /usr/bin/dscl',
     'medium', 'privilege_escalation'),
    ('unified_log',   'accountsd',     f'{MARKER} Sandbox restriction: accountsd denied access to com.apple.contacts',
     'medium', 'security'),
    ('unified_log',   'securityd',     f'{MARKER} Keychain access: Chrome accessed login.keychain-db',
     'medium', 'security'),
    ('unified_log',   'socketfilterfw',f'{MARKER} Firewall blocked inbound connection from 10.0.0.99:4444',
     'medium', 'network'),

    ('install_log',   'installd',      f'{MARKER} PackageKit: Installed "Homebrew 4.2.1" successfully',
     'low', 'system'),
    ('unified_log',   'bash',          f'{MARKER} Permission denied: /etc/sudoers.d/override (uid=501)',
     'low', 'security'),
    ('unified_log',   'curl',          f'{MARKER} Permission denied: /Library/Preferences/SystemConfiguration',
     'low', 'security'),

    ('login_history', 'loginwindow',   f'{MARKER} Login session: joefabre   console   Tue Apr 22 03:00 still logged in',
     'info', 'authentication'),
    ('system_log',    'system',        f'{MARKER} kernel[0]: standard system startup complete',
     'info', 'system'),
]

TEST_ALERTS = [
    # (title, description, severity, category)
    ('CRITICAL — Root Command Executed',
     'A privileged command was executed as root via sudo. This requires immediate review to confirm it was authorized.',
     'critical', 'privilege_escalation'),

    ('CRITICAL — Brute Force Login Detected',
     'Multiple failed login attempts were recorded from an unknown source within a short time window. Possible automated attack.',
     'critical', 'authentication'),

    ('CRITICAL — Malicious Process Running',
     'A known offensive tool (meterpreter) was detected running on this system. Immediate investigation required.',
     'critical', 'malware'),

    ('HIGH — SSH Invalid User Attempt',
     'The SSH daemon received a login attempt for a user that does not exist on this system.',
     'high', 'authentication'),

    ('HIGH — Unsigned Kernel Extension Loaded',
     'A kernel extension not signed by a trusted developer was loaded. This can indicate rootkit activity.',
     'high', 'system'),

    ('HIGH — New LaunchAgent Registered',
     'A new persistence agent was added to LaunchAgents. This is a common technique for maintaining access after reboot.',
     'high', 'persistence'),

    ('HIGH — Gatekeeper Blocked Application',
     'Gatekeeper prevented an application from running because it could not be verified. Possible malware delivery attempt.',
     'high', 'security'),

    ('MEDIUM — Sudo Command Executed',
     'A user ran a command with elevated privileges via sudo. Normal for admin tasks but should be reviewed.',
     'medium', 'privilege_escalation'),

    ('MEDIUM — Sandbox Restriction Triggered',
     'The macOS sandbox blocked a resource access request. May indicate a misconfigured or probing application.',
     'medium', 'security'),

    ('MEDIUM — Keychain Accessed by Browser',
     'Chrome accessed the system login keychain. Normal for credential retrieval but logged for audit purposes.',
     'medium', 'security'),

    ('MEDIUM — Firewall Blocked Inbound Connection',
     'The macOS firewall blocked an inbound TCP connection attempt on a suspicious port (4444).',
     'medium', 'network'),

    ('LOW — Software Package Installed',
     'A new software package was installed via Homebrew. Informational — verify the install was intentional.',
     'low', 'system'),

    ('LOW — Permission Denied on System File',
     'A process attempted to access a restricted system file and was denied. Likely benign but recorded for audit.',
     'low', 'security'),

    ('INFO — User Login Session',
     'A normal interactive login session was recorded for the primary user account.',
     'info', 'authentication'),

    ('INFO — System Startup Complete',
     'The system completed its startup sequence successfully. Routine informational event.',
     'info', 'system'),
]

# ── Clean mode ────────────────────────────────────────────────────────────────
def clean():
    conn = sqlite3.connect(str(DB))
    ev_del = conn.execute(f"DELETE FROM events WHERE message LIKE '{MARKER}%'").rowcount
    al_del = conn.execute(f"DELETE FROM alerts WHERE title LIKE '{MARKER}%' OR description LIKE '{MARKER}%'").rowcount
    conn.commit(); conn.close()
    print(f"\n  Removed {ev_del} test events and {al_del} test alerts.\n")

# ── Inject mode ───────────────────────────────────────────────────────────────
def inject():
    conn = sqlite3.connect(str(DB))
    now  = datetime.now()
    ev_ids = []

    print(f"\n  {C['bold']}Injecting test events...{C['reset']}\n")

    for i, (source, process, message, severity, category) in enumerate(TEST_EVENTS):
        ts = (now - timedelta(minutes=len(TEST_EVENTS)-i)).isoformat()
        cur = conn.execute(
            "INSERT INTO events(timestamp,source,process,message,severity,category,raw,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ts, source, process, message, severity, category, message, ts)
        )
        ev_ids.append(cur.lastrowid)
        col = C.get(severity,'')
        print(f"  {col}{severity.upper():<10}{C['reset']} {message[:70]}")

    print(f"\n  {C['bold']}Injecting test alerts...{C['reset']}\n")

    for i, (title, description, severity, category) in enumerate(TEST_ALERTS):
        ts = (now - timedelta(minutes=len(TEST_ALERTS)-i)).isoformat()
        conn.execute(
            "INSERT INTO alerts(timestamp,title,description,severity,category,status,event_count,created_at) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ts, f"{MARKER} {title}", f"{MARKER} {description}", severity, category, 'new', 1, ts)
        )
        col = C.get(severity,'')
        print(f"  {col}{severity.upper():<10}{C['reset']} {title}")

    conn.commit(); conn.close()

    print(f"\n  {C['green']}Done.{C['reset']} {len(TEST_EVENTS)} events and {len(TEST_ALERTS)} alerts injected.")

# ── Summary via API ───────────────────────────────────────────────────────────
def show_summary():
    try:
        al = get('/api/alerts?status=new&per_page=200')
        ev = get('/api/events?hours=1&per_page=100')
    except Exception:
        print(f"\n  {C['dim']}(Server not reachable — data is in DB but dashboard may need a refresh){C['reset']}")
        return

    sev_order = ['critical','high','medium','low','info']
    sev_counts = {s: 0 for s in sev_order}
    for a in al['alerts']:
        if a['title'].startswith(MARKER):
            sev_counts[a.get('severity','info')] = sev_counts.get(a.get('severity','info'),0) + 1

    print(f"\n  {'─'*55}")
    print(f"  {C['bold']}Alert Verification — All Levels{C['reset']}\n")
    all_ok = True
    for sev in sev_order:
        cnt  = sev_counts[sev]
        col  = C.get(sev,'')
        mark = f"{C['green']}✓{C['reset']}" if cnt > 0 else f"{C['dim']}–{C['reset']}"
        print(f"  {mark} {col}{sev.upper():<10}{C['reset']} {cnt} test alert(s) in New tab")
        if cnt == 0: all_ok = False

    print()
    if all_ok:
        print(f"  {C['green']}{C['bold']}All severity levels represented.{C['reset']}")
    else:
        print(f"  {C['dim']}Some levels missing — check if server is running and alerts tab is refreshed.{C['reset']}")

    print(f"\n  Open the dashboard to inspect: http://localhost:5001")
    print(f"  Run with --clean to remove all test data.\n")
    print(f"  {'─'*55}\n")

# ── Main ──────────────────────────────────────────────────────────────────────
if not DB.exists():
    print(f"  ERROR: Database not found at {DB}")
    print("  Start the app first: bash ~/Desktop/my_seims/run.sh")
    sys.exit(1)

if '--clean' in sys.argv:
    clean()
else:
    inject()
    show_summary()
