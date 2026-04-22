#!/usr/bin/env python3
"""
test_snapshot.py
Prints a full formatted snapshot of the last 24 hours of my_seims
activity directly to the terminal — no browser needed.

Usage:
    python3 ~/Desktop/my_seims/tests/test_snapshot.py
    python3 ~/Desktop/my_seims/tests/test_snapshot.py --hours 6
"""

import urllib.request, json, sys
from datetime import datetime

BASE  = 'http://localhost:5001'
HOURS = 24
if '--hours' in sys.argv:
    idx = sys.argv.index('--hours')
    HOURS = int(sys.argv[idx + 1])

C = {
    'critical': '\033[91m', 'high':   '\033[93m',
    'medium':   '\033[94m', 'low':    '\033[92m',
    'info':     '\033[37m', 'reset':  '\033[0m',
    'bold':     '\033[1m',  'dim':    '\033[2m',
    'green':    '\033[32m', 'red':    '\033[31m',
    'cyan':     '\033[36m', 'yellow': '\033[33m',
}

SEV_LABELS = {'critical':'CRITICAL','high':'HIGH','medium':'MEDIUM','low':'LOW','info':'INFO'}
CAT_LABELS = {
    'authentication':       'Authentication',
    'privilege_escalation': 'Privilege Escalation',
    'network':              'Network Activity',
    'system':               'System Activity',
    'security':             'Security',
    'malware':              'Malware / Suspicious',
    'persistence':          'Persistence',
}
SRC_LABELS = {
    'unified_log':   'macOS Unified Log',
    'login_history': 'Login History',
    'network':       'Network Monitor',
    'process_scan':  'Process Scanner',
    'install_log':   'Install Log',
    'system_log':    'System Log',
}

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=15) as r:
        return json.loads(r.read())

def sc(sev, text):
    return C.get(sev, '') + text + C['reset']

def fmt_ts(ts):
    if not ts: return '—'
    try:
        d = datetime.fromisoformat(ts.replace(' ', 'T').split('.')[0])
        return d.strftime('%b %-d  %-I:%M %p')
    except Exception:
        return ts[:16]

def bar(pct, width=20, char='█'):
    filled = int(pct / 100 * width)
    return char * filled + '░' * (width - filled)

def divider(title='', char='─', width=80):
    if title:
        pad = (width - len(title) - 2) // 2
        print(C['dim'] + char * pad + C['reset'] + C['bold'] + f' {title} ' + C['reset'] + C['dim'] + char * pad + C['reset'])
    else:
        print(C['dim'] + char * width + C['reset'])

# ── Fetch all data ─────────────────────────────────────────────────────────────
try:
    dash    = get('/api/dashboard')
    events  = get(f'/api/events?hours={HOURS}&per_page=500')
    alerts  = get(f'/api/alerts?per_page=200')
    health  = get('/api/system/health')
    history = get('/api/scan/history')
except Exception as e:
    print(f"ERROR: Cannot reach {BASE} — {e}")
    print("Start the app with: bash ~/Desktop/my_seims/run.sh")
    sys.exit(1)

s      = dash['stats']
sh     = dash['system_health']
ev     = events['events']
al     = [a for a in alerts['alerts']]
al_new = [a for a in al if a['status'] == 'new']

# ── Overall status ────────────────────────────────────────────────────────────
crit = s['critical_alerts']
high = s['high_alerts']
overall     = 'CRITICAL' if crit  > 0 else 'HIGH' if high > 0 else 'MEDIUM' if s['active_alerts'] > 0 else 'CLEAN'
overall_sev = 'critical' if crit  > 0 else 'high' if high > 0 else 'medium' if s['active_alerts'] > 0 else 'low'

print()
divider(char='═', width=80)
print(f"  {C['bold']}{C['cyan']}my_seims  ·  Security Snapshot{C['reset']}")
print(f"  {C['dim']}Generated: {datetime.now().strftime('%A, %B %-d, %Y at %-I:%M %p')}"
      f"  |  Period: last {HOURS}h{C['reset']}")
divider(char='═', width=80)

status_col = C.get(overall_sev, C['green'])
print(f"\n  Overall Status: {status_col}{C['bold']}{overall}{C['reset']}"
      f"  —  {len(al_new)} unacknowledged alert(s),  {len(ev)} event(s) in period\n")

# ── Stat cards ────────────────────────────────────────────────────────────────
divider('Summary')
print(f"  {'Events today':<22} {C['bold']}{s['total_today']}{C['reset']}")
print(f"  {'Events last hour':<22} {s['events_1h']}")
print(f"  {'Active alerts':<22} {C['bold']}{s['active_alerts']}{C['reset']}")
print(f"  {'Critical alerts':<22} {sc('critical', str(crit)) if crit else '0'}")
print(f"  {'High alerts':<22} {sc('high', str(high)) if high else '0'}")
last = dash.get('last_scan','')
print(f"  {'Last scan':<22} {fmt_ts(last) if last else 'No scan recorded'}")

# ── System health ─────────────────────────────────────────────────────────────
divider('System Health')
for label, pct, cls in [
    ('CPU',    health['cpu'],              'high'   if health['cpu']>70            else 'low'),
    ('Memory', health['memory']['percent'],'high'   if health['memory']['percent']>85 else 'low'),
    ('Disk',   health['disk']['percent'],  'critical'if health['disk']['percent']>90 else 'low'),
]:
    col  = C.get(cls, C['low'])
    used = health['disk']['used'] if label == 'Disk' else health['memory']['used'] if label == 'Memory' else None
    total= health['disk']['total'] if label == 'Disk' else health['memory']['total'] if label == 'Memory' else None
    extra = f"  {used//1024//1024//1024:.1f}/{total//1024//1024//1024:.1f} GB" if used else ''
    print(f"  {label:<8} {col}{bar(pct)}{C['reset']} {pct:.1f}%{extra}")

# ── Severity distribution ─────────────────────────────────────────────────────
divider('Events by Severity')
sev_counts = {}
for e in ev:
    s2 = e.get('severity','info')
    sev_counts[s2] = sev_counts.get(s2, 0) + 1
total_ev = len(ev) or 1
for sev in ['critical','high','medium','low','info']:
    cnt = sev_counts.get(sev, 0)
    if cnt:
        pct  = cnt / total_ev * 100
        blen = int(pct / 100 * 30)
        col  = C.get(sev,'')
        print(f"  {sev.upper():<10} {col}{'█'*blen}{C['reset']}{'░'*(30-blen)} {cnt:>4}  ({pct:.1f}%)")

# ── Active alerts ─────────────────────────────────────────────────────────────
divider(f'Active Alerts ({len(al_new)} new)')
if not al_new:
    print(f"  {C['green']}No unacknowledged alerts.{C['reset']}")
else:
    print(f"  {'SEVERITY':<10} {'TITLE':<36} {'CATEGORY':<22} {'DETECTED'}")
    print(f"  {C['dim']}{'-'*9} {'-'*35} {'-'*21} {'-'*15}{C['reset']}")
    for a in al_new[:20]:
        sev  = a.get('severity','info')
        col  = C.get(sev,'')
        title= a.get('title','')[:35]
        cat  = CAT_LABELS.get(a.get('category',''), a.get('category',''))[:21]
        ts   = fmt_ts(a.get('created_at'))
        print(f"  {col}{sev.upper():<10}{C['reset']} {title:<36} {C['dim']}{cat:<22}{C['reset']} {ts}")

# ── Top sources ───────────────────────────────────────────────────────────────
divider('Events by Source')
src_counts = {}
for e in ev:
    src = SRC_LABELS.get(e.get('source',''), e.get('source',''))
    src_counts[src] = src_counts.get(src, 0) + 1
for src, cnt in sorted(src_counts.items(), key=lambda x: x[1], reverse=True):
    pct  = cnt / total_ev * 100
    blen = int(pct / 100 * 25)
    print(f"  {src:<22} {'█'*blen}{'░'*(25-blen)} {cnt:>4}")

# ── Recent events ─────────────────────────────────────────────────────────────
divider(f'Recent Events (latest 25 of {len(ev)})')
if not ev:
    print(f"  {C['dim']}No events in this period.{C['reset']}")
else:
    print(f"  {'TIME':<15} {'SEV':<10} {'SOURCE':<20} {'PROCESS':<16} WHAT HAPPENED")
    print(f"  {C['dim']}{'-'*14} {'-'*9} {'-'*19} {'-'*15} {'-'*35}{C['reset']}")
    for e in ev[:25]:
        ts   = fmt_ts(e.get('created_at'))
        sev  = e.get('severity','info')
        col  = C.get(sev,'')
        src  = SRC_LABELS.get(e.get('source',''), e.get('source',''))[:19]
        proc = (e.get('process') or '—')[:15]
        msg  = (e.get('message') or '')[:55]
        print(f"  {ts:<15} {col}{sev.upper()[:9]:<10}{C['reset']} {src:<20} {proc:<16} {msg}")

# ── Scan history ──────────────────────────────────────────────────────────────
divider('Scan History (last 5)')
scans = history.get('history', [])[:5]
if not scans:
    print(f"  {C['dim']}No scans recorded.{C['reset']}")
else:
    print(f"  {'STARTED':<18} {'DURATION':<10} {'EVENTS':<8} {'ALERTS':<8} STATUS")
    for sc2 in scans:
        started = fmt_ts(sc2.get('started_at'))
        dur = '—'
        if sc2.get('completed_at') and sc2.get('started_at'):
            try:
                s1 = datetime.fromisoformat(sc2['started_at'].replace(' ','T').split('.')[0])
                s2_dt = datetime.fromisoformat(sc2['completed_at'].replace(' ','T').split('.')[0])
                dur = f"{int((s2_dt-s1).total_seconds())}s"
            except Exception:
                pass
        status = sc2.get('status','?')
        scol   = C['green'] if status=='completed' else C['red'] if status=='failed' else C['yellow']
        print(f"  {started:<18} {dur:<10} {sc2['events_found']:<8} {sc2['alerts_generated']:<8} {scol}{status}{C['reset']}")

# ── Footer ────────────────────────────────────────────────────────────────────
divider(char='═', width=80)
print(f"  Dashboard: {BASE}")
print(f"  Reports:   {BASE}/#reports")
print(f"  Generate PDF: curl -s -X POST {BASE}/api/reports/generate")
print()
