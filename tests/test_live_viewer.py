#!/usr/bin/env python3
"""
test_live_viewer.py
Polls my_seims every 10 seconds and prints any new events and alerts
to the terminal in real time. Press Ctrl+C to stop.

Usage:
    python3 ~/Desktop/my_seims/tests/test_live_viewer.py
"""

import urllib.request, json, time, sys, os
from datetime import datetime

BASE     = 'http://localhost:5001'
INTERVAL = 10  # seconds between polls

# ── ANSI colours ───────────────────────────────────────────────────────────────
C = {
    'critical': '\033[91m', 'high':   '\033[93m',
    'medium':   '\033[94m', 'low':    '\033[92m',
    'info':     '\033[37m', 'reset':  '\033[0m',
    'bold':     '\033[1m',  'dim':    '\033[2m',
    'green':    '\033[32m', 'cyan':   '\033[36m',
}

CAT_SHORT = {
    'authentication':       'AUTH    ',
    'privilege_escalation': 'PRIV-ESC',
    'network':              'NETWORK ',
    'system':               'SYSTEM  ',
    'security':             'SECURITY',
    'malware':              'MALWARE ',
    'persistence':          'PERSIST ',
}
SRC_SHORT = {
    'unified_log':   'unified ',
    'login_history': 'login   ',
    'network':       'network ',
    'process_scan':  'process ',
    'install_log':   'install ',
    'system_log':    'syslog  ',
}

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())

def sev_col(s):
    return C.get(s, '') + s.upper()[:8].ljust(8) + C['reset']

def fmt_ts(ts):
    return (ts or '')[:16].replace('T', ' ')

def header():
    w = os.get_terminal_size().columns if hasattr(os, 'get_terminal_size') else 100
    print(C['bold'] + C['cyan'] + ' my_seims Live Event Viewer' + C['reset'])
    print(C['dim'] + f' Polling every {INTERVAL}s — Ctrl+C to stop' + C['reset'])
    print(C['dim'] + '─' * min(w, 110) + C['reset'])
    print(f" {'TIME':<16} {'SEV':<10} {'CATEGORY':<10} {'SOURCE':<10} {'PROCESS':<16} WHAT HAPPENED")
    print(C['dim'] + '─' * min(w, 110) + C['reset'])

def print_event(e):
    ts   = fmt_ts(e.get('created_at'))
    sev  = e.get('severity', 'info')
    cat  = CAT_SHORT.get(e.get('category',''), (e.get('category','') or '')[:8].ljust(8))
    src  = SRC_SHORT.get(e.get('source',''),   (e.get('source','') or '')[:8].ljust(8))
    proc = (e.get('process') or '—')[:15].ljust(15)
    msg  = (e.get('message') or '')[:65]
    col  = C.get(sev, '')
    print(f" {ts:<16} {col}{sev.upper()[:8]:<10}{C['reset']} {cat:<10} {src:<10} {proc:<16} {msg}")

def print_alert(a):
    sev  = a.get('severity', 'info')
    col  = C.get(sev, '')
    ts   = fmt_ts(a.get('created_at'))
    print(f"\n {C['bold']}🔔 ALERT [{col}{sev.upper()}{C['reset']}{C['bold']}]{C['reset']}"
          f"  {a['title']}  {C['dim']}({ts}){C['reset']}")
    desc = (a.get('description') or '').split('\n\n')[0][:120]
    if desc:
        print(f"   {C['dim']}{desc}{C['reset']}")

# ── Main loop ─────────────────────────────────────────────────────────────────
def main():
    # Check server
    try:
        get('/api/dashboard')
    except Exception:
        print(f"  ERROR: Cannot reach {BASE}")
        print("  Start the app with: bash ~/Desktop/my_seims/run.sh")
        sys.exit(1)

    header()

    seen_events = set()
    seen_alerts = set()
    poll        = 0

    # Seed seen sets with current IDs so we only show NEW ones going forward
    try:
        existing = get('/api/events?per_page=200&hours=24')
        seen_events = {e['id'] for e in existing['events']}
        existing_al = get('/api/alerts?per_page=200')
        seen_alerts  = {a['id'] for a in existing_al['alerts']}
        print(f" {C['dim']} Baseline: {len(seen_events)} events, {len(seen_alerts)} alerts already known. Watching for new…{C['reset']}\n")
    except Exception as ex:
        print(f" {C['dim']} Could not baseline: {ex}{C['reset']}\n")

    try:
        while True:
            poll += 1
            now = datetime.now().strftime('%H:%M:%S')
            try:
                # Fetch recent events
                ev_data = get('/api/events?per_page=100&hours=1')
                new_events = [e for e in ev_data['events'] if e['id'] not in seen_events]
                for e in reversed(new_events):
                    print_event(e)
                    seen_events.add(e['id'])

                # Fetch new alerts
                al_data = get('/api/alerts?per_page=50')
                new_alerts = [a for a in al_data['alerts'] if a['id'] not in seen_alerts]
                for a in new_alerts:
                    print_alert(a)
                    seen_alerts.add(a['id'])

                # Status line every 6 polls (~1 min)
                if poll % 6 == 0:
                    dash = get('/api/dashboard')
                    s    = dash['stats']
                    sh   = dash['system_health']
                    print(f"\n {C['dim']}[{now}] poll#{poll}  "
                          f"events/today={s['total_today']}  active_alerts={s['active_alerts']}  "
                          f"cpu={sh['cpu']}%  mem={sh['memory']}%{C['reset']}\n")

            except Exception as e:
                print(f" {C['dim']}[{now}] Poll error: {e}{C['reset']}")

            time.sleep(INTERVAL)

    except KeyboardInterrupt:
        print(f"\n\n {C['dim']}Stopped. {len(seen_events)} events seen this session.{C['reset']}\n")

if __name__ == '__main__':
    main()
