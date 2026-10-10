#!/usr/bin/env python3
"""AI Health Advisor & Personal Assistant — Flask backend"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path

import anthropic
from flask import Flask, jsonify, request, render_template, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "health.db"
REPORTS_DIR = BASE_DIR / "reports"
(BASE_DIR / "data").mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS profile (
                id INTEGER PRIMARY KEY,
                name TEXT, age INTEGER, gender TEXT,
                height_cm REAL, weight_kg REAL, blood_type TEXT,
                allergies TEXT, conditions TEXT, emergency_contact TEXT,
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS vitals (
                id INTEGER PRIMARY KEY,
                type TEXT NOT NULL, value REAL NOT NULL,
                unit TEXT, notes TEXT,
                recorded_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS medications (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL, dosage TEXT, frequency TEXT,
                start_date TEXT, end_date TEXT, notes TEXT,
                active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS symptoms (
                id INTEGER PRIMARY KEY,
                description TEXT NOT NULL, severity INTEGER,
                body_area TEXT, notes TEXT,
                recorded_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL, doctor TEXT, location TEXT,
                date TEXT, time TEXT, notes TEXT,
                completed INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY,
                role TEXT NOT NULL, content TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS health_notes (
                id INTEGER PRIMARY KEY,
                title TEXT, content TEXT NOT NULL, tags TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
        """)


init_db()

SYSTEM_PROMPT = """You are HealthBot, a compassionate AI health advisor and personal assistant. You help users:
- Understand their health data and trends
- Learn about symptoms, conditions, and wellness
- Prepare questions for doctor visits
- Stay on top of medications and appointments
- Build healthy habits

Always:
- Remind users you are an AI, not a licensed physician
- Recommend professional consultation for diagnosis or treatment
- Direct emergencies to 911 or emergency services immediately
- Be empathetic, encouraging, and non-judgmental"""


def build_health_context():
    try:
        with get_db() as db:
            profile = db.execute("SELECT * FROM profile LIMIT 1").fetchone()
            vitals = db.execute(
                "SELECT type, value, unit, recorded_at FROM vitals ORDER BY recorded_at DESC LIMIT 15"
            ).fetchall()
            meds = db.execute(
                "SELECT name, dosage, frequency FROM medications WHERE active=1"
            ).fetchall()
            symptoms = db.execute(
                "SELECT description, severity, recorded_at FROM symptoms ORDER BY recorded_at DESC LIMIT 8"
            ).fetchall()
            appts = db.execute(
                "SELECT title, doctor, date, time FROM appointments WHERE completed=0 AND date >= date('now') ORDER BY date LIMIT 3"
            ).fetchall()
    except Exception:
        return ""

    lines = ["[User Health Context]"]
    if profile:
        if profile["name"]: lines.append(f"Name: {profile['name']}")
        if profile["age"]: lines.append(f"Age: {profile['age']}")
        if profile["conditions"]: lines.append(f"Conditions: {profile['conditions']}")
        if profile["allergies"]: lines.append(f"Allergies: {profile['allergies']}")
    if meds:
        lines.append("Medications: " + "; ".join(f"{m['name']} {m['dosage'] or ''}" for m in meds))
    if vitals:
        lines.append("Recent vitals:")
        for v in vitals[:8]:
            lines.append(f"  {v['type']}: {v['value']} {v['unit'] or ''} ({v['recorded_at'][:10]})")
    if symptoms:
        lines.append("Recent symptoms: " + "; ".join(s["description"] for s in symptoms))
    if appts:
        lines.append("Upcoming appointments: " + "; ".join(f"{a['title']} {a['date']}" for a in appts))
    return "\n".join(lines)


def get_ai_response(user_message: str) -> str:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return (
            "⚠️ No API key found. Set ANTHROPIC_API_KEY in your environment to enable AI responses.\n\n"
            "Example: `export ANTHROPIC_API_KEY=your-key-here`"
        )
    try:
        client = anthropic.Anthropic(api_key=api_key)
        health_ctx = build_health_context()

        with get_db() as db:
            history = db.execute(
                "SELECT role, content FROM chat_history ORDER BY created_at DESC LIMIT 16"
            ).fetchall()

        messages = [{"role": r["role"], "content": r["content"]} for r in reversed(list(history))]
        messages.append({"role": "user", "content": user_message})

        system = SYSTEM_PROMPT + (f"\n\n{health_ctx}" if health_ctx else "")
        resp = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            system=system,
            messages=messages,
        )
        return resp.content[0].text
    except anthropic.AuthenticationError:
        return "⚠️ Invalid API key. Please check your ANTHROPIC_API_KEY."
    except Exception as e:
        return f"⚠️ Error contacting AI: {e}"


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("health_advisor.html")


@app.route("/api/chat", methods=["POST"])
def chat():
    msg = (request.get_json() or {}).get("message", "").strip()
    if not msg:
        return jsonify({"error": "Empty message"}), 400
    with get_db() as db:
        db.execute("INSERT INTO chat_history (role, content) VALUES ('user', ?)", (msg,))
    response = get_ai_response(msg)
    with get_db() as db:
        db.execute("INSERT INTO chat_history (role, content) VALUES ('assistant', ?)", (response,))
    return jsonify({"response": response})


@app.route("/api/chat/history")
def chat_history():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, role, content, created_at FROM chat_history ORDER BY created_at LIMIT 100"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/chat/clear", methods=["POST"])
def clear_chat():
    with get_db() as db:
        db.execute("DELETE FROM chat_history")
    return jsonify({"success": True})


@app.route("/api/profile", methods=["GET", "POST"])
def profile():
    if request.method == "GET":
        with get_db() as db:
            row = db.execute("SELECT * FROM profile LIMIT 1").fetchone()
        return jsonify(dict(row) if row else {})
    d = request.get_json() or {}
    with get_db() as db:
        existing = db.execute("SELECT id FROM profile LIMIT 1").fetchone()
        if existing:
            db.execute(
                "UPDATE profile SET name=?,age=?,gender=?,height_cm=?,weight_kg=?,blood_type=?,"
                "allergies=?,conditions=?,emergency_contact=?,updated_at=datetime('now') WHERE id=?",
                (d.get("name"), d.get("age"), d.get("gender"), d.get("height_cm"), d.get("weight_kg"),
                 d.get("blood_type"), d.get("allergies"), d.get("conditions"),
                 d.get("emergency_contact"), existing["id"])
            )
        else:
            db.execute(
                "INSERT INTO profile (name,age,gender,height_cm,weight_kg,blood_type,allergies,conditions,emergency_contact)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (d.get("name"), d.get("age"), d.get("gender"), d.get("height_cm"), d.get("weight_kg"),
                 d.get("blood_type"), d.get("allergies"), d.get("conditions"), d.get("emergency_contact"))
            )
    return jsonify({"success": True})


@app.route("/api/vitals", methods=["GET", "POST"])
def vitals():
    if request.method == "GET":
        vtype = request.args.get("type")
        with get_db() as db:
            if vtype:
                rows = db.execute(
                    "SELECT * FROM vitals WHERE type=? ORDER BY recorded_at DESC LIMIT 100", (vtype,)
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM vitals ORDER BY recorded_at DESC LIMIT 200"
                ).fetchall()
        return jsonify([dict(r) for r in rows])
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "INSERT INTO vitals (type, value, unit, notes, recorded_at) VALUES (?,?,?,?,?)",
            (d["type"], d["value"], d.get("unit"), d.get("notes"),
             d.get("recorded_at") or datetime.now().isoformat())
        )
    return jsonify({"success": True})


@app.route("/api/vitals/<int:vid>", methods=["DELETE"])
def delete_vital(vid):
    with get_db() as db:
        db.execute("DELETE FROM vitals WHERE id=?", (vid,))
    return jsonify({"success": True})


@app.route("/api/medications", methods=["GET", "POST"])
def medications():
    if request.method == "GET":
        with get_db() as db:
            rows = db.execute("SELECT * FROM medications ORDER BY active DESC, name").fetchall()
        return jsonify([dict(r) for r in rows])
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "INSERT INTO medications (name, dosage, frequency, start_date, end_date, notes) VALUES (?,?,?,?,?,?)",
            (d["name"], d.get("dosage"), d.get("frequency"), d.get("start_date"), d.get("end_date"), d.get("notes"))
        )
    return jsonify({"success": True})


@app.route("/api/medications/<int:mid>", methods=["PUT", "DELETE"])
def medication(mid):
    if request.method == "DELETE":
        with get_db() as db:
            db.execute("DELETE FROM medications WHERE id=?", (mid,))
        return jsonify({"success": True})
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "UPDATE medications SET name=?,dosage=?,frequency=?,start_date=?,end_date=?,notes=?,active=? WHERE id=?",
            (d["name"], d.get("dosage"), d.get("frequency"), d.get("start_date"),
             d.get("end_date"), d.get("notes"), d.get("active", 1), mid)
        )
    return jsonify({"success": True})


@app.route("/api/symptoms", methods=["GET", "POST"])
def symptoms():
    if request.method == "GET":
        with get_db() as db:
            rows = db.execute("SELECT * FROM symptoms ORDER BY recorded_at DESC LIMIT 100").fetchall()
        return jsonify([dict(r) for r in rows])
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "INSERT INTO symptoms (description, severity, body_area, notes, recorded_at) VALUES (?,?,?,?,?)",
            (d["description"], d.get("severity"), d.get("body_area"), d.get("notes"),
             d.get("recorded_at") or datetime.now().isoformat())
        )
    return jsonify({"success": True})


@app.route("/api/symptoms/<int:sid>", methods=["DELETE"])
def delete_symptom(sid):
    with get_db() as db:
        db.execute("DELETE FROM symptoms WHERE id=?", (sid,))
    return jsonify({"success": True})


@app.route("/api/appointments", methods=["GET", "POST"])
def appointments():
    if request.method == "GET":
        with get_db() as db:
            rows = db.execute("SELECT * FROM appointments ORDER BY completed, date, time").fetchall()
        return jsonify([dict(r) for r in rows])
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "INSERT INTO appointments (title, doctor, location, date, time, notes) VALUES (?,?,?,?,?,?)",
            (d["title"], d.get("doctor"), d.get("location"), d.get("date"), d.get("time"), d.get("notes"))
        )
    return jsonify({"success": True})


@app.route("/api/appointments/<int:aid>", methods=["PUT", "DELETE"])
def appointment(aid):
    if request.method == "DELETE":
        with get_db() as db:
            db.execute("DELETE FROM appointments WHERE id=?", (aid,))
        return jsonify({"success": True})
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "UPDATE appointments SET title=?,doctor=?,location=?,date=?,time=?,notes=?,completed=? WHERE id=?",
            (d["title"], d.get("doctor"), d.get("location"), d.get("date"),
             d.get("time"), d.get("notes"), d.get("completed", 0), aid)
        )
    return jsonify({"success": True})


@app.route("/api/notes", methods=["GET", "POST"])
def notes():
    if request.method == "GET":
        with get_db() as db:
            rows = db.execute("SELECT * FROM health_notes ORDER BY updated_at DESC").fetchall()
        return jsonify([dict(r) for r in rows])
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "INSERT INTO health_notes (title, content, tags) VALUES (?,?,?)",
            (d.get("title"), d["content"], d.get("tags"))
        )
    return jsonify({"success": True})


@app.route("/api/notes/<int:nid>", methods=["PUT", "DELETE"])
def note(nid):
    if request.method == "DELETE":
        with get_db() as db:
            db.execute("DELETE FROM health_notes WHERE id=?", (nid,))
        return jsonify({"success": True})
    d = request.get_json() or {}
    with get_db() as db:
        db.execute(
            "UPDATE health_notes SET title=?,content=?,tags=?,updated_at=datetime('now') WHERE id=?",
            (d.get("title"), d["content"], d.get("tags"), nid)
        )
    return jsonify({"success": True})


@app.route("/api/dashboard")
def dashboard():
    with get_db() as db:
        profile_row = db.execute("SELECT * FROM profile LIMIT 1").fetchone()
        stats = {
            "vitals": db.execute("SELECT COUNT(*) c FROM vitals").fetchone()["c"],
            "medications": db.execute("SELECT COUNT(*) c FROM medications WHERE active=1").fetchone()["c"],
            "symptoms_30d": db.execute(
                "SELECT COUNT(*) c FROM symptoms WHERE recorded_at >= date('now','-30 days')"
            ).fetchone()["c"],
            "upcoming_appts": db.execute(
                "SELECT COUNT(*) c FROM appointments WHERE completed=0 AND date >= date('now')"
            ).fetchone()["c"],
        }
        latest_vitals = {}
        for vt in ["blood_pressure_systolic", "blood_pressure_diastolic", "heart_rate",
                   "weight", "blood_glucose", "oxygen_saturation", "temperature", "bmi"]:
            row = db.execute(
                "SELECT value, unit, recorded_at FROM vitals WHERE type=? ORDER BY recorded_at DESC LIMIT 1", (vt,)
            ).fetchone()
            if row:
                latest_vitals[vt] = dict(row)
        upcoming = db.execute(
            "SELECT title,doctor,date,time FROM appointments WHERE completed=0 AND date >= date('now') ORDER BY date,time LIMIT 5"
        ).fetchall()
        recent_symptoms = db.execute(
            "SELECT description,severity,recorded_at FROM symptoms ORDER BY recorded_at DESC LIMIT 5"
        ).fetchall()
    return jsonify({
        "profile": dict(profile_row) if profile_row else {},
        "stats": stats,
        "latest_vitals": latest_vitals,
        "upcoming_appointments": [dict(a) for a in upcoming],
        "recent_symptoms": [dict(s) for s in recent_symptoms],
    })


@app.route("/api/report")
def report():
    fname = f"health_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    fpath = REPORTS_DIR / fname
    with get_db() as db:
        profile_row = db.execute("SELECT * FROM profile LIMIT 1").fetchone()
        vitals_rows = db.execute("SELECT * FROM vitals ORDER BY type,recorded_at DESC LIMIT 100").fetchall()
        meds_rows = db.execute("SELECT * FROM medications WHERE active=1").fetchall()
        symp_rows = db.execute("SELECT * FROM symptoms ORDER BY recorded_at DESC LIMIT 50").fetchall()
        appt_rows = db.execute("SELECT * FROM appointments ORDER BY date DESC LIMIT 20").fetchall()

    doc = SimpleDocTemplate(str(fpath), pagesize=letter,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    blue = colors.HexColor("#2563eb")
    alt_row = colors.HexColor("#f0f9ff")
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=blue, spaceBefore=12, spaceAfter=6)
    story = []

    title_style = ParagraphStyle("T", parent=styles["Title"], fontSize=22, textColor=blue)
    story.append(Paragraph("HealthBot — Health Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y %I:%M %p')}", styles["Normal"]))
    story.append(Spacer(1, 0.3*inch))

    def make_table(data, col_widths):
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), blue),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 9),
            ("GRID", (0,0), (-1,-1), 0.5, colors.lightgrey),
            ("PADDING", (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, alt_row]),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ]))
        return t

    if profile_row and any(profile_row[k] for k in ["name","age","gender","blood_type","conditions","allergies"]):
        story.append(Paragraph("Personal Profile", h2))
        rows = [["Field", "Value"]]
        for label, key in [("Name","name"),("Age","age"),("Gender","gender"),("Blood Type","blood_type"),
                           ("Height","height_cm"),("Weight","weight_kg"),("Conditions","conditions"),
                           ("Allergies","allergies"),("Emergency Contact","emergency_contact")]:
            if profile_row[key]:
                val = str(profile_row[key])
                if key == "height_cm": val += " cm"
                if key == "weight_kg": val += " kg"
                rows.append([label, val])
        story.append(make_table(rows, [2*inch, 4.5*inch]))
        story.append(Spacer(1, 0.2*inch))

    if meds_rows:
        story.append(Paragraph("Active Medications", h2))
        rows = [["Medication", "Dosage", "Frequency", "Start Date", "Notes"]]
        for m in meds_rows:
            rows.append([m["name"], m["dosage"] or "—", m["frequency"] or "—",
                         m["start_date"] or "—", m["notes"] or ""])
        story.append(make_table(rows, [1.8*inch, 1.2*inch, 1.2*inch, 1*inch, 1.3*inch]))
        story.append(Spacer(1, 0.2*inch))

    if vitals_rows:
        story.append(Paragraph("Vitals History", h2))
        rows = [["Type", "Value", "Unit", "Date", "Notes"]]
        for v in vitals_rows[:40]:
            rows.append([v["type"].replace("_"," ").title(), str(v["value"]),
                         v["unit"] or "—", v["recorded_at"][:10], v["notes"] or ""])
        story.append(make_table(rows, [2*inch, 1*inch, 0.8*inch, 1*inch, 1.7*inch]))
        story.append(Spacer(1, 0.2*inch))

    if symp_rows:
        story.append(Paragraph("Symptom Journal", h2))
        rows = [["Symptom", "Severity", "Body Area", "Date", "Notes"]]
        for s in symp_rows[:30]:
            rows.append([s["description"],
                         f"{s['severity']}/10" if s["severity"] else "—",
                         s["body_area"] or "—", s["recorded_at"][:10], s["notes"] or ""])
        story.append(make_table(rows, [2*inch, 0.8*inch, 1.2*inch, 1*inch, 1.5*inch]))
        story.append(Spacer(1, 0.2*inch))

    if appt_rows:
        story.append(Paragraph("Appointments", h2))
        rows = [["Title", "Doctor", "Date", "Time", "Status"]]
        for a in appt_rows[:20]:
            rows.append([a["title"], a["doctor"] or "—", a["date"] or "—",
                         a["time"] or "—", "✓ Done" if a["completed"] else "Upcoming"])
        story.append(make_table(rows, [2*inch, 1.5*inch, 1*inch, 0.8*inch, 1.2*inch]))

    doc.build(story)
    return send_file(str(fpath), as_attachment=True, download_name=fname, mimetype="application/pdf")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="HealthBot AI Health Advisor")
    p.add_argument("--port", type=int, default=5001)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()
    print(f"\n✅ HealthBot running at http://{args.host}:{args.port}")
    print("   Open this URL in your browser to use the app.\n")
    app.run(host=args.host, port=args.port, debug=args.debug)
