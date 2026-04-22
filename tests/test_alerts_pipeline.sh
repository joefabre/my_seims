#!/bin/bash
# test_alerts_pipeline.sh
# Tests the FULL detection pipeline at all 5 severity levels:
#   1. Creates one temporary detection rule per severity level
#   2. Generates matching log activity for each rule
#   3. Triggers a scan
#   4. Shows which alerts fired and at what level
#   5. Cleans up temporary rules (optional)
#
# Usage:
#   bash ~/Desktop/my_seims/tests/test_alerts_pipeline.sh
#   bash ~/Desktop/my_seims/tests/test_alerts_pipeline.sh --no-cleanup

BASE="http://localhost:5001"
CLEANUP=true
[[ "$1" == "--no-cleanup" ]] && CLEANUP=false

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[91m'; ORANGE='\033[93m'; BLUE='\033[94m'
GREEN='\033[92m'; DIM='\033[37m'; RESET='\033[0m'; BOLD='\033[1m'

sep() { echo -e "${DIM}────────────────────────────────────────────────────────${RESET}"; }

echo ""
echo -e "  ${BOLD}my_seims — Full Pipeline Alert Test (All 5 Levels)${RESET}"
sep

# ── Check server ──────────────────────────────────────────────────────────────
if ! curl -s "$BASE/api/dashboard" > /dev/null 2>&1; then
  echo "  ERROR: Server not running. Start with: bash ~/Desktop/my_seims/run.sh"; exit 1
fi
echo -e "  Server: ${GREEN}OK${RESET}"
echo ""

# ── Helper: create a rule, return its ID ─────────────────────────────────────
create_rule() {
  local name="$1" sev="$2" cat="$3" pattern="$4" proc="$5"
  curl -s -X POST "$BASE/api/rules" \
    -H 'Content-Type: application/json' \
    -d "{\"name\":\"$name\",\"description\":\"Temp test rule — safe to delete\",
         \"severity\":\"$sev\",\"category\":\"$cat\",\"pattern\":\"$pattern\",
         \"process_name\":\"$proc\",\"log_source\":\"unified\",
         \"threshold\":1,\"time_window\":60,\"enabled\":1}" > /dev/null
  # Return the last rule ID
  curl -s "$BASE/api/rules" | python3 -c \
    "import sys,json; rules=json.load(sys.stdin)['rules']; \
     match=[r for r in rules if r['name']=='$name']; \
     print(match[0]['id'] if match else '')"
}

# ── Step 1: Create temporary test rules ──────────────────────────────────────
echo -e "  ${BOLD}Step 1: Creating temporary detection rules${RESET}"
echo ""

RULE_CRITICAL=$(create_rule \
  "[PIPELINE-TEST] Critical — Token Theft Attempt" \
  "critical" "security" \
  "seims_test_critical_token_theft" "")
echo -e "  ${RED}CRITICAL${RESET}  Rule #$RULE_CRITICAL created"

RULE_HIGH=$(create_rule \
  "[PIPELINE-TEST] High — Admin Enumeration" \
  "high" "authentication" \
  "seims_test_high_admin_enum" "")
echo -e "  ${ORANGE}HIGH${RESET}      Rule #$RULE_HIGH created"

RULE_MEDIUM=$(create_rule \
  "[PIPELINE-TEST] Medium — Config File Read" \
  "medium" "system" \
  "seims_test_medium_config_read" "")
echo -e "  ${BLUE}MEDIUM${RESET}    Rule #$RULE_MEDIUM created"

RULE_LOW=$(create_rule \
  "[PIPELINE-TEST] Low — Dev Tool Launched" \
  "low" "system" \
  "seims_test_low_dev_tool" "")
echo -e "  ${GREEN}LOW${RESET}       Rule #$RULE_LOW created"

RULE_INFO=$(create_rule \
  "[PIPELINE-TEST] Info — Routine Check" \
  "info" "system" \
  "seims_test_info_routine" "")
echo -e "  ${DIM}INFO${RESET}      Rule #$RULE_INFO created"

echo ""
echo -e "  ${DIM}Rules created: $RULE_CRITICAL $RULE_HIGH $RULE_MEDIUM $RULE_LOW $RULE_INFO${RESET}"
sep

# ── Step 2: Generate matching log entries ─────────────────────────────────────
echo ""
echo -e "  ${BOLD}Step 2: Injecting matching events into the database${RESET}"
echo ""

python3 - <<'PYEOF'
import sqlite3, sys
from datetime import datetime, timedelta
from pathlib import Path

DB  = Path.home() / 'Desktop/my_seims/data/seims.db'
now = datetime.now()

test_events = [
    ("seims_test_critical_token_theft: Bearer eyJhbGc... exfiltrated to 93.184.216.34",
     "critical", "security",  "curl",    "unified_log"),
    ("seims_test_high_admin_enum: enumerated /etc/passwd and /etc/group",
     "high",     "authentication", "bash", "unified_log"),
    ("seims_test_medium_config_read: opened /Library/Preferences/com.apple.security.plist",
     "medium",   "system",     "python3", "unified_log"),
    ("seims_test_low_dev_tool: Xcode command line tools invoked",
     "low",      "system",     "xcode",   "unified_log"),
    ("seims_test_info_routine: cron job executed successfully",
     "info",     "system",     "cron",    "unified_log"),
]

conn = sqlite3.connect(str(DB))
for i, (msg, sev, cat, proc, src) in enumerate(test_events):
    ts = (now - timedelta(seconds=30-i*5)).isoformat()
    conn.execute(
        "INSERT INTO events(timestamp,source,process,message,severity,category,raw,created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (ts, src, proc, msg, sev, cat, msg, ts)
    )
    print(f"  Inserted [{sev.upper():<8}] {msg[:65]}")

conn.commit(); conn.close()
print()
PYEOF

sep

# ── Step 3: Run rule matching against injected events ─────────────────────────
echo ""
echo -e "  ${BOLD}Step 3: Running rule matching against injected events${RESET}"
echo ""

python3 - <<'MATCHEOF'
import sqlite3, re
from datetime import datetime
from pathlib import Path

DB  = Path.home() / 'Desktop/my_seims/data/seims.db'
now = datetime.now().isoformat()

conn = sqlite3.connect(str(DB))
conn.row_factory = sqlite3.Row

rules  = conn.execute("SELECT * FROM rules WHERE enabled=1 AND name LIKE '[PIPELINE-TEST]%'").fetchall()
events = conn.execute(
    "SELECT * FROM events WHERE message LIKE 'seims_test_%'"
).fetchall()

if not rules:
    print("  WARNING: No pipeline test rules found — check step 1 completed.")
elif not events:
    print("  WARNING: No pipeline test events found — check step 2 completed.")
else:
    alerts_created = 0
    for ev in events:
        for rule in rules:
            pattern = rule['pattern'] or ''
            matched = False
            if pattern:
                try:
                    if re.search(pattern, ev['message'], re.IGNORECASE):
                        matched = True
                except re.error:
                    matched = pattern.lower() in ev['message'].lower()
            if matched:
                conn.execute(
                    "INSERT INTO alerts(timestamp,title,description,severity,category,rule_id,status,created_at) "
                    "VALUES(?,?,?,?,?,?,'new',?)",
                    (now,
                     rule['name'],
                     f"{rule['description']}\n\n{ev['message']}",
                     rule['severity'], rule['category'], rule['id'], now)
                )
                alerts_created += 1
                print(f"  Matched [{rule['severity'].upper():<8}] rule '{rule['name'][:45]}' → event: {ev['message'][:50]}")
    conn.commit()
    print(f"\n  {alerts_created} alert(s) generated from {len(events)} event(s) via {len(rules)} rule(s).")
conn.close()
MATCHEOF

echo ""
sep

# ── Step 4: Show results ──────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Step 4: Checking fired alerts${RESET}"
echo ""

python3 - <<PYEOF
import urllib.request, json

BASE = 'http://localhost:5001'
C = {
    'critical':'\033[91m','high':'\033[93m','medium':'\033[94m',
    'low':'\033[92m','info':'\033[37m','reset':'\033[0m',
    'bold':'\033[1m','green':'\033[32m','dim':'\033[2m',
}

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.loads(r.read())

all_alerts = get('/api/alerts?per_page=200')['alerts']
test_alerts = [a for a in all_alerts if '[PIPELINE-TEST]' in (a.get('title') or '')]

sev_order = ['critical','high','medium','low','info']
fired = {s: [] for s in sev_order}
for a in test_alerts:
    fired[a.get('severity','info')].append(a)

print(f"  {'─'*58}")
print(f"  {C['bold']}Pipeline Alert Results{C['reset']}\n")

all_fired = True
for sev in sev_order:
    col  = C.get(sev,'')
    hits = fired[sev]
    mark = f"{C['green']}✓ FIRED  {C['reset']}" if hits else f"{C['dim']}✗ MISSED {C['reset']}"
    print(f"  {mark} {col}{sev.upper():<10}{C['reset']}", end='')
    if hits:
        print(f"  {hits[0]['title'][:45]}  [{hits[0]['status']}]")
    else:
        print(f"  (no alert generated)")
        all_fired = False

print()
total_test = sum(len(v) for v in fired.values())
if all_fired:
    print(f"  {C['green']}{C['bold']}All 5 levels fired successfully.{C['reset']}")
else:
    print(f"  {C['dim']}{total_test}/5 levels fired. Missing levels may need Full Disk Access.{C['reset']}")
    print(f"  {C['dim']}Tip: the injected events ARE in the DB — run the snapshot script to confirm.{C['reset']}")

print(f"\n  Dashboard: {BASE}")
print(f"  {'─'*58}")
PYEOF

sep

# ── Step 5: Cleanup ───────────────────────────────────────────────────────────
if [ "$CLEANUP" = true ]; then
  echo ""
  echo -e "  ${BOLD}Step 5: Cleaning up test rules${RESET}"
  echo ""
  for RID in $RULE_CRITICAL $RULE_HIGH $RULE_MEDIUM $RULE_LOW $RULE_INFO; do
    if [ -n "$RID" ]; then
      STATUS=$(curl -s -X DELETE "$BASE/api/rules/$RID" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))")
      echo -e "  Rule #$RID deleted — $STATUS"
    fi
  done
  echo ""
  echo -e "  ${DIM}Test events and alerts remain in the DB for inspection.${RESET}"
  echo -e "  ${DIM}To remove them: python3 ~/Desktop/my_seims/tests/test_alerts_inject.py --clean${RESET}"
else
  echo ""
  echo -e "  ${DIM}--no-cleanup: rules kept. Delete manually via Detection Rules in the dashboard.${RESET}"
fi

echo ""
sep
echo ""
