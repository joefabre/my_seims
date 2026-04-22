#!/bin/bash
# test_activity.sh
# Generates real macOS activity that my_seims should detect,
# triggers a scan, then prints what was captured.

BASE="http://localhost:5001"
SEP="────────────────────────────────────────────────────"

echo ""
echo "  my_seims Activity Test"
echo "  $SEP"

# ── Verify server is up ───────────────────────────────────────────────────────
if ! curl -s "$BASE/api/dashboard" > /dev/null 2>&1; then
  echo "  ERROR: my_seims is not running at $BASE"
  echo "  Start it with: bash ~/Desktop/my_seims/run.sh"
  exit 1
fi
echo "  Server: OK ($BASE)"
echo ""

# ── Snapshot event count before activity ─────────────────────────────────────
BEFORE=$(curl -s "$BASE/api/events?hours=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
echo "  Events in last hour BEFORE activity: $BEFORE"
echo ""

# ── Generate detectable activity ─────────────────────────────────────────────
echo "  Generating activity..."
echo ""

echo "  [1] Sudo usage (privilege escalation)"
sudo -n true 2>/dev/null || true                   # triggers sudo process
sudo ls /tmp > /dev/null 2>&1 || true

echo "  [2] Failed authentication attempt"
su -c "exit" nonexistentuser 2>/dev/null || true   # known-bad user triggers auth failure

echo "  [3] Permission denied — access restricted path"
cat /etc/sudoers 2>/dev/null || true               # permission denied on restricted file

echo "  [4] Network connection check (normal outbound)"
curl -s --max-time 2 https://example.com > /dev/null 2>&1 || true

echo "  [5] Software check (triggers install log touch)"
pkgutil --pkgs 2>/dev/null | head -5 > /dev/null

echo "  [6] SSH client activity"
ssh -o ConnectTimeout=2 -o BatchMode=yes localhost exit 2>/dev/null || true

echo "  [7] Keychain access"
security find-generic-password -l "nonexistent_test_entry" 2>/dev/null || true

echo "  [8] Process list (scanned for suspicious names)"
ps aux > /dev/null 2>&1

echo ""
echo "  Done. Waiting 3 seconds for logs to flush..."
sleep 3

# ── Trigger scan ─────────────────────────────────────────────────────────────
echo ""
echo "  Triggering scan..."
SCAN=$(curl -s -X POST "$BASE/api/scan")
EVENTS_FOUND=$(echo "$SCAN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('events',0))")
ALERTS_FOUND=$(echo "$SCAN" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alerts',0))")
echo "  Scan complete — $EVENTS_FOUND events stored, $ALERTS_FOUND alerts generated"

# ── Show results ──────────────────────────────────────────────────────────────
AFTER=$(curl -s "$BASE/api/events?hours=1" | python3 -c "import sys,json; print(json.load(sys.stdin)['total'])")
NEW=$((AFTER - BEFORE))
echo ""
echo "  Events in last hour AFTER activity: $AFTER (+$NEW new)"
echo ""
echo "  $SEP"

python3 - <<'PYEOF'
import urllib.request, json
BASE = 'http://localhost:5001'

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())

CAT = {'authentication':'Auth','privilege_escalation':'PrivEsc','network':'Network',
       'system':'System','security':'Security','malware':'Malware','persistence':'Persist'}
SEV_COLOR = {'critical':'\033[91m','high':'\033[93m','medium':'\033[94m','low':'\033[92m','info':'\033[37m'}
RESET = '\033[0m'

print("  Recent Events (last hour)\n")
ev = get('/api/events?hours=1&per_page=20')
if not ev['events']:
    print("  No events captured yet. Try running the script again or check Full Disk Access.")
else:
    print(f"  {'TIME':<16} {'SEV':<8} {'CATEGORY':<10} {'PROCESS':<18} WHAT HAPPENED")
    print(f"  {'-'*15} {'-'*7} {'-'*9} {'-'*17} {'-'*35}")
    for e in ev['events']:
        ts   = (e.get('created_at') or '')[:16].replace('T',' ')
        sev  = e.get('severity','info')
        col  = SEV_COLOR.get(sev, '')
        cat  = CAT.get(e.get('category',''), e.get('category',''))[:9]
        proc = (e.get('process') or '—')[:17]
        msg  = (e.get('message') or '')[:60]
        print(f"  {ts:<16} {col}{sev.upper():<8}{RESET} {cat:<10} {proc:<18} {msg}")

print()
al = get('/api/alerts?status=new&per_page=10')
if al['total']:
    print(f"  Active Alerts ({al['total']} new)\n")
    for a in al['alerts']:
        sev = a.get('severity','info')
        col = SEV_COLOR.get(sev,'')
        print(f"  {col}[{sev.upper()}]{RESET} {a['title']}  —  {(a.get('created_at') or '')[:16]}")
else:
    print("  No new alerts.")
print()
PYEOF

echo "  $SEP"
echo "  Full dashboard: $BASE"
echo ""
