"""
VHC Backend API — Flask + SQLite
Run:  python3 app.py
Port: 5000
"""
import json
import os
import random
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, jsonify, request, g
from flask.wrappers import Response

from firebase_sync import init_firebase, sync_user, sync_reading, sync_report
from database import get_db, hash_password, verify_password, init_db

# ── Config ──────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("VHC_SECRET", "vhc-super-secret-jwt-key-2025")
TOKEN_EXPIRY_HOURS = 24 * 7   # 7 days

# ── Ollama config ────────────────────────────────────────────────────────────
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = "llama-3.3-70b-versatile"
OLLAMA_TIMEOUT = 60  # seconds — LLM inference can be slow on CPU

SYSTEM_PROMPT = (
    "You are a helpful AI health companion that analyzes user health data "
    "such as heart rate, sleep, glucose, exercise, and nutrition. "
    "You have access to the user's recent health readings provided in the prompt. "
    "When users ask about their health, activity, sleep, heart rate, or progress, "
    "analyze their recent data and provide helpful insights and recommendations. "
    "Give clear, concise, friendly responses. "
    "Never provide medical diagnosis. "
    "Always recommend consulting a qualified healthcare professional for medical concerns."
)

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# ── CORS (manual, no flask-cors needed) ─────────────────────────────────────
@app.after_request
def add_cors(response: Response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    return response

@app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
@app.route("/<path:path>", methods=["OPTIONS"])
def options_handler(path):
    return jsonify({}), 200


# ── JWT helpers ──────────────────────────────────────────────────────────────
def make_token(user_id: int) -> str:
    """
    Create a JWT token with the user_id as the subject.
    Uses Unix timestamps (integers) for exp/iat as per JWT standard.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),  # Must be string for PyJWT 2.7+
        "exp": int((now + timedelta(hours=TOKEN_EXPIRY_HOURS)).timestamp()),
        "iat": int(now.timestamp()),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def require_auth(f):
    """
    Decorator to enforce JWT authentication.
    Validates Bearer token, extracts user_id into g.user_id
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "").strip()
        
        # Check for Bearer prefix
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing or malformed Authorization header"}), 401
        
        # Extract token
        try:
            token = auth.split(" ", 1)[1]
        except IndexError:
            return jsonify({"error": "Malformed Authorization header"}), 401
        
        # Decode and validate token
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            
            # Ensure "sub" (user_id) exists in payload
            if "sub" not in data:
                return jsonify({"error": "Invalid token structure"}), 401
            
            # Convert sub from string back to int
            g.user_id = int(data["sub"])
            
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidSignatureError:
            return jsonify({"error": "Invalid token signature"}), 401
        except jwt.InvalidTokenError as e:
            app.logger.warning(f"Token validation error: {e}")
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            app.logger.error(f"Unexpected auth error: {e}")
            return jsonify({"error": "Authentication failed"}), 500
        
        return f(*args, **kwargs)
    
    return decorated


def row_to_dict(row):
    return dict(row) if row else None


def rows_to_list(rows):
    return [dict(r) for r in rows]


# ══════════════════════════════════════════════════════════════════════════════
#  AUTH
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/auth/register", methods=["POST"])
def register():
    body = request.get_json() or {}
    first = body.get("first_name", "").strip()
    last  = body.get("last_name", "").strip()
    email = body.get("email", "").strip().lower()
    pwd   = body.get("password", "")

    if not all([first, last, email, pwd]):
        return jsonify({"error": "All fields are required"}), 400
    if len(pwd) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    with get_db() as conn:
        if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            return jsonify({"error": "Email already registered"}), 409
        conn.execute(
            "INSERT INTO users (first_name, last_name, email, password) VALUES (?,?,?,?)",
            (first, last, email, hash_password(pwd))
        )
        uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()

    sync_user(uid, {"first_name": first, "last_name": last, "email": email, "password": pwd})
    sync_user(uid, {"first_name": first, "last_name": last, "email": email, "password": pwd})
    sync_user(uid, {"first_name": first, "last_name": last, "email": email, "password": pwd})
    return jsonify({"token": make_token(uid), "message": "Account created"}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    body  = request.get_json() or {}
    email = body.get("email", "").strip().lower()
    pwd   = body.get("password", "")

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if not user or not verify_password(pwd, user["password"]):
        return jsonify({"error": "Invalid email or password"}), 401

    return jsonify({
        "token": make_token(user["id"]),
        "user": {
            "id": user["id"],
            "first_name": user["first_name"],
            "last_name":  user["last_name"],
            "email":      user["email"],
        }
    })


# ══════════════════════════════════════════════════════════════════════════════
#  USER / PROFILE
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/user/profile", methods=["GET"])
@require_auth
def get_profile():
    with get_db() as conn:
        user = conn.execute(
            "SELECT id,first_name,last_name,email,dob,gender,blood_type,height_cm,weight_kg,"
            "activity_level,theme,color_scheme,language,timezone,units,"
            "goal_steps,goal_calories,goal_sleep,"
            "notif_health_alerts,notif_daily_summary,notif_achievements,notif_device_sync"
            " FROM users WHERE id=?", (g.user_id,)
        ).fetchone()
    return jsonify(row_to_dict(user))


@app.route("/api/user/profile", methods=["PUT"])
@require_auth
def update_profile():
    body = request.get_json() or {}
    allowed = [
        "first_name","last_name","dob","gender","blood_type",
        "height_cm","weight_kg","activity_level",
        "theme","color_scheme","language","timezone","units",
        "goal_steps","goal_calories","goal_sleep",
        "notif_health_alerts","notif_daily_summary","notif_achievements","notif_device_sync"
    ]
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return jsonify({"error": "Nothing to update"}), 400

    set_clause = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [g.user_id]
    with get_db() as conn:
        conn.execute(f"UPDATE users SET {set_clause} WHERE id=?", vals)
        conn.commit()
    return jsonify({"message": "Profile updated"})


@app.route("/api/user/change-password", methods=["POST"])
@require_auth
def change_password():
    body    = request.get_json() or {}
    current = body.get("current_password", "")
    new_pwd = body.get("new_password", "")
    if len(new_pwd) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    with get_db() as conn:
        user = conn.execute("SELECT password FROM users WHERE id=?", (g.user_id,)).fetchone()
        if not verify_password(current, user["password"]):
            return jsonify({"error": "Current password is incorrect"}), 401
        conn.execute("UPDATE users SET password=? WHERE id=?", (hash_password(new_pwd), g.user_id))
        conn.commit()
    return jsonify({"message": "Password changed"})


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/dashboard", methods=["GET"])
@require_auth
def dashboard():
    today = datetime.utcnow().strftime("%Y-%m-%d")
    with get_db() as conn:
        # Today's summary
        summary = conn.execute(
            "SELECT * FROM daily_summaries WHERE user_id=? AND date=?",
            (g.user_id, today)
        ).fetchone()

        # Latest readings for each metric today
        metrics_raw = conn.execute("""
            SELECT metric, value, value2, unit, status, recorded_at
            FROM health_readings
            WHERE user_id=? AND date(recorded_at)=?
            ORDER BY recorded_at DESC
        """, (g.user_id, today)).fetchall()

        # Unread notifications count
        unread = conn.execute(
            "SELECT COUNT(*) as cnt FROM notifications WHERE user_id=? AND is_read=0",
            (g.user_id,)
        ).fetchone()["cnt"]

        # Recent notifications (top 2)
        notifs = conn.execute(
            "SELECT id,title,body,category,is_read,created_at FROM notifications "
            "WHERE user_id=? ORDER BY created_at DESC LIMIT 2",
            (g.user_id,)
        ).fetchall()

        # Weekly steps trend (last 7 days)
        weekly = conn.execute("""
            SELECT date(recorded_at) as day, SUM(value) as steps
            FROM health_readings
            WHERE user_id=? AND metric='steps'
              AND date(recorded_at) >= date('now','-6 days')
            GROUP BY date(recorded_at)
            ORDER BY date(recorded_at)
        """, (g.user_id,)).fetchall()

        # User goals
        user = conn.execute(
            "SELECT goal_steps,goal_calories,goal_sleep FROM users WHERE id=?",
            (g.user_id,)
        ).fetchone()

    # Build latest readings dict (most recent per metric)
    seen = {}
    for r in metrics_raw:
        m = r["metric"]
        if m not in seen:
            seen[m] = dict(r)

    return jsonify({
        "summary": row_to_dict(summary) or {"health_score": None, "cardiovascular": 92,
            "activity": 85, "sleep_score": 78, "nutrition": 88, "mental_health": 90},
        "today_metrics": seen,
        "unread_notifications": unread,
        "notifications": rows_to_list(notifs),
        "weekly_steps": rows_to_list(weekly),
        "goals": row_to_dict(user),
    })


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH READINGS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/health/readings", methods=["GET"])
@require_auth
def get_readings():
    metric = request.args.get("metric", "heart_rate")
    period = request.args.get("period", "week")

    days_map = {"day": 1, "week": 7, "month": 30, "year": 365}
    days = days_map.get(period, 7)

    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, metric, value, value2, unit, status, recorded_at
            FROM health_readings
            WHERE user_id=? AND metric=?
              AND recorded_at >= datetime('now', ?)
            ORDER BY recorded_at ASC
        """, (g.user_id, metric, f"-{days} days")).fetchall()

    return jsonify(rows_to_list(rows))


@app.route("/api/health/readings", methods=["POST"])
@require_auth
def add_reading():
    body = request.get_json() or {}
    metric = body.get("metric")
    value  = body.get("value")
    if not metric or value is None:
        return jsonify({"error": "metric and value are required"}), 400

    # Auto-determine status and trigger notifications on threshold breach
    status = body.get("status", "normal")
    thresholds = {
        "heart_rate":     {"elevated": 100, "high": 120},
        "glucose":        {"elevated": 100, "high": 126},
        "blood_pressure": {"elevated": 120, "high": 140},
    }
    auto_notif = None
    if metric in thresholds:
        t = thresholds[metric]
        unit = body.get("unit", "")
        if float(value) >= t["high"]:
            status = "high"
            auto_notif = (
                f"High {metric.replace('_',' ').title()} Reading",
                f"Your {metric.replace('_',' ')} reached {value} {unit} — above the high threshold of {t['high']}.",
                "warning"
            )
        elif float(value) >= t["elevated"]:
            status = "elevated"
            auto_notif = (
                f"Elevated {metric.replace('_',' ').title()}",
                f"Your {metric.replace('_',' ')} is {value} {unit} — slightly above normal range.",
                "info"
            )

    with get_db() as conn:
        conn.execute("""
            INSERT INTO health_readings (user_id, metric, value, value2, unit, status, notes)
            VALUES (?,?,?,?,?,?,?)
        """, (g.user_id, metric, value,
              body.get("value2"), body.get("unit"), status, body.get("notes")))
        if auto_notif:
            conn.execute(
                "INSERT INTO notifications (user_id, title, body, category) VALUES (?,?,?,?)",
                (g.user_id, auto_notif[0], auto_notif[1], auto_notif[2])
            )
        conn.commit()
    sync_reading(g.user_id, body)
    sync_reading(g.user_id, body)
    sync_reading(g.user_id, body)
    return jsonify({"message": "Reading saved", "status": status}), 201


@app.route("/api/health/summary", methods=["GET"])
@require_auth
def health_summary():
    """Daily summaries for the last N days (for chart)."""
    days = int(request.args.get("days", 7))
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM daily_summaries
            WHERE user_id=? AND date >= date('now', ?)
            ORDER BY date ASC
        """, (g.user_id, f"-{days} days")).fetchall()
    return jsonify(rows_to_list(rows))


@app.route("/api/health/stats", methods=["GET"])
@require_auth
def health_stats():
    """Aggregate stats per metric for overview cards."""
    period = request.args.get("period", "week")
    days_map = {"day": 1, "week": 7, "month": 30}
    days = days_map.get(period, 7)

    with get_db() as conn:
        stats = conn.execute("""
            SELECT metric,
                   ROUND(AVG(value),1) as avg_val,
                   MIN(value) as min_val,
                   MAX(value) as max_val,
                   COUNT(*) as reading_count
            FROM health_readings
            WHERE user_id=? AND recorded_at >= datetime('now', ?)
            GROUP BY metric
        """, (g.user_id, f"-{days} days")).fetchall()
    return jsonify(rows_to_list(stats))


# ══════════════════════════════════════════════════════════════════════════════
#  DEVICES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/devices", methods=["GET"])
@require_auth
def get_devices():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM devices WHERE user_id=? ORDER BY created_at",
            (g.user_id,)
        ).fetchall()
    return jsonify(rows_to_list(rows))


@app.route("/api/devices", methods=["POST"])
@require_auth
def add_device():
    body = request.get_json() or {}
    name = body.get("name", "").strip()
    dtype = body.get("type", "").strip()
    if not name or not dtype:
        return jsonify({"error": "name and type are required"}), 400

    with get_db() as conn:
        conn.execute("""
            INSERT INTO devices (user_id, name, type, model, firmware, battery_pct, status, tracking_metrics)
            VALUES (?,?,?,?,?,?,?,?)
        """, (g.user_id, name, dtype,
              body.get("model"), body.get("firmware"), body.get("battery_pct", 100),
              "connected", body.get("tracking_metrics", "")))
        conn.commit()
        device_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    return jsonify({"message": "Device added", "id": device_id}), 201


@app.route("/api/devices/<int:device_id>", methods=["DELETE"])
@require_auth
def remove_device(device_id):
    with get_db() as conn:
        conn.execute("DELETE FROM devices WHERE id=? AND user_id=?", (device_id, g.user_id))
        conn.commit()
    return jsonify({"message": "Device removed"})

@app.route("/api/devices/<int:device_id>", methods=["PUT"])
@require_auth
def update_device(device_id):
    body = request.get_json() or {}
    allowed = ["name", "status", "battery_pct", "tracking_metrics", "firmware", "model"]
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return jsonify({"error": "Nothing to update"}), 400
    set_clause = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [device_id, g.user_id]
    with get_db() as conn:
        conn.execute(f"UPDATE devices SET {set_clause} WHERE id=? AND user_id=?", vals)
        conn.commit()
    return jsonify({"message": "Device updated"})


@app.route("/api/health/weekly", methods=["GET"])
@require_auth
def weekly_readings():
    """Return last 7 days of daily avg values per metric — for dashboard charts."""
    metric = request.args.get("metric", "heart_rate")
    with get_db() as conn:
        rows = conn.execute("""
            SELECT date(recorded_at) as day,
                   ROUND(AVG(value), 1) as avg_val,
                   MAX(value) as max_val
            FROM health_readings
            WHERE user_id=? AND metric=?
              AND recorded_at >= datetime('now', '-7 days')
            GROUP BY date(recorded_at)
            ORDER BY date(recorded_at) ASC
        """, (g.user_id, metric)).fetchall()
    return jsonify(rows_to_list(rows))


@app.route("/api/devices/<int:device_id>/sync", methods=["POST"])
@require_auth
def sync_device(device_id):
    now = datetime.utcnow().isoformat()
    # Simulate battery drain
    with get_db() as conn:
        dev = conn.execute(
            "SELECT battery_pct FROM devices WHERE id=? AND user_id=?",
            (device_id, g.user_id)
        ).fetchone()
        if not dev:
            return jsonify({"error": "Device not found"}), 404
        new_bat = max(10, dev["battery_pct"] - random.randint(1, 3))
        conn.execute(
            "UPDATE devices SET last_sync=?, battery_pct=?, status='connected' WHERE id=? AND user_id=?",
            (now, new_bat, device_id, g.user_id)
        )
        conn.commit()
    return jsonify({"message": "Synced", "last_sync": now, "battery_pct": new_bat})


# ══════════════════════════════════════════════════════════════════════════════
#  NOTIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/notifications", methods=["GET"])
@require_auth
def get_notifications():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
            (g.user_id,)
        ).fetchall()
    return jsonify(rows_to_list(rows))


@app.route("/api/notifications/<int:notif_id>/read", methods=["POST"])
@require_auth
def mark_read(notif_id):
    with get_db() as conn:
        conn.execute(
            "UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?",
            (notif_id, g.user_id)
        )
        conn.commit()
    return jsonify({"message": "Marked as read"})


@app.route("/api/notifications/read-all", methods=["POST"])
@require_auth
def mark_all_read():
    with get_db() as conn:
        conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (g.user_id,))
        conn.commit()
    return jsonify({"message": "All marked as read"})


# ══════════════════════════════════════════════════════════════════════════════
#  CHAT / AI COMPANION  (Ollama — llama3)
# ══════════════════════════════════════════════════════════════════════════════

def call_ollama(user_message: str, history: list[dict], health_data: list[dict] = None) -> str:
    """Call Groq API with LLaMA 3.3 model using requests library."""
    import requests as _requests
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if health_data:
        health_text = "RECENT HEALTH DATA:\n"
        for reading in health_data:
            metric = reading.get("metric", "Unknown")
            value = reading.get("value", "N/A")
            value2 = reading.get("value2")
            unit = reading.get("unit", "")
            recorded_at = reading.get("recorded_at", "Unknown time")
            if value2 is not None:
                health_text += f"- {metric}: {value}/{value2} {unit} (recorded: {recorded_at})\n"
            else:
                health_text += f"- {metric}: {value} {unit} (recorded: {recorded_at})\n"
        messages.append({"role": "user", "content": health_text})
        messages.append({"role": "assistant", "content": "I have reviewed your health data and I am ready to help."})
    for msg in history[-10:]:
        messages.append({"role": msg["role"], "content": msg["content"]})
    messages.append({"role": "user", "content": user_message})
    response = _requests.post(
        "https://api.groq.com/openai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": GROQ_MODEL,
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.7,
        },
        timeout=30
    )
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"].strip()


@app.route("/api/chat/history", methods=["GET"])
@require_auth
def get_chat_history():
    """Return the last 50 messages for the authenticated user (oldest first)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, role, content, created_at FROM chat_messages "
            "WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
            (g.user_id,)
        ).fetchall()
    # Reverse so the client receives them in chronological order
    return jsonify(list(reversed(rows_to_list(rows))))


# ── GET /api/chat/messages  (kept for backwards compatibility) ───────────────

@app.route("/api/chat/messages", methods=["GET"])
@require_auth
def get_messages():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, role, content, created_at FROM chat_messages "
            "WHERE user_id=? ORDER BY created_at ASC LIMIT 100",
            (g.user_id,)
        ).fetchall()
    return jsonify(rows_to_list(rows))


# ── POST /api/chat/send ──────────────────────────────────────────────────────

@app.route("/api/chat/send", methods=["POST"])
@require_auth
def send_message():
    body    = request.get_json() or {}
    content = body.get("message", "").strip()
    if not content:
        return jsonify({"error": "Message is required"}), 400

    # ── Fetch recent history to give the model conversational context ─────
    with get_db() as conn:
        history_rows = conn.execute(
            "SELECT role, content FROM chat_messages "
            "WHERE user_id=? ORDER BY created_at DESC LIMIT 20",
            (g.user_id,)
        ).fetchall()
    # Reverse so history is chronological (oldest → newest)
    history = list(reversed(rows_to_list(history_rows)))

    # ── Fetch recent health readings for AI analysis ─────────────────────
    with get_db() as conn:
        health_rows = conn.execute(
            "SELECT metric, value, value2, unit, recorded_at "
            "FROM health_readings "
            "WHERE user_id=? "
            "ORDER BY recorded_at DESC LIMIT 20",
            (g.user_id,)
        ).fetchall()
    health_data = rows_to_list(health_rows)

    # ── Call Ollama with health data context ─────────────────────────────
    try:
        ai_reply = call_ollama(content, history, health_data)
    except urllib.error.URLError:
        # Ollama process is not running or unreachable
        return jsonify({"error": "AI service unavailable"}), 503
    except Exception as exc:
        app.logger.error("Ollama error: %s", exc)
        return jsonify({"error": "AI service unavailable"}), 503

    # ── Persist both turns to the database ───────────────────────────────
    now      = datetime.utcnow().isoformat()
    ai_time  = datetime.utcnow().isoformat()   # same second is fine; ordering by id is stable

    with get_db() as conn:
        conn.execute(
            "INSERT INTO chat_messages (user_id, role, content, created_at) VALUES (?,?,?,?)",
            (g.user_id, "user", content, now)
        )
        conn.execute(
            "INSERT INTO chat_messages (user_id, role, content, created_at) VALUES (?,?,?,?)",
            (g.user_id, "assistant", ai_reply, ai_time)
        )
        conn.commit()

    return jsonify({
        "reply": ai_reply,                              # primary field requested by spec
        "user_message": {"role": "user",      "content": content,  "created_at": now},
        "ai_message":   {"role": "assistant", "content": ai_reply, "created_at": ai_time},
    })


@app.route("/api/chat/clear", methods=["DELETE"])
@require_auth
def clear_chat():
    with get_db() as conn:
        conn.execute("DELETE FROM chat_messages WHERE user_id=?", (g.user_id,))
        conn.commit()
    return jsonify({"message": "Chat cleared"})


# ══════════════════════════════════════════════════════════════════════════════
#  REPORTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/reports", methods=["GET"])
@require_auth
def get_reports():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC",
            (g.user_id,)
        ).fetchall()
    return jsonify(rows_to_list(rows))


@app.route("/api/reports", methods=["POST"])
@require_auth
def create_report():
    body = request.get_json() or {}
    with get_db() as conn:
        conn.execute("""
            INSERT INTO reports (user_id, name, report_type, period_start, period_end, metrics, status)
            VALUES (?,?,?,?,?,?,?)
        """, (g.user_id,
              body.get("name", "Custom Report"),
              body.get("report_type", "custom"),
              body.get("period_start"), body.get("period_end"),
              body.get("metrics", ""),
              "ready"))  # Changed from "generating" to "ready"
        conn.commit()
        rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    sync_report(g.user_id, body)
    sync_report(g.user_id, body)
    sync_report(g.user_id, body)
    return jsonify({"message": "Report created successfully", "id": rid}), 201


# ══════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "service": "VHC Backend API",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    })


# ══════════════════════════════════════════════════════════════════════════════
#  STARTUP
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  Virtual Health Companion — Backend API")
    print("=" * 60)
    init_db()
    init_firebase()
    print("[API] Starting on http://localhost:5000")
    print("[API] Demo user: alex@example.com / demo123")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=True)







