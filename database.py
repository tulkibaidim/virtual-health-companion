"""
VHC Database Layer — SQLite (drop-in for PostgreSQL)
All tables, seed data, and helper functions live here.
"""
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
import random

DB_PATH = os.path.join(os.path.dirname(__file__), "vhc.db")


def get_db():
    """Return a connection with row_factory = sqlite3.Row."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$")
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    except Exception:
        return False


# ─────────────────────────────────────────
#  SCHEMA
# ─────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name  TEXT NOT NULL,
    last_name   TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    dob         TEXT,
    gender      TEXT,
    blood_type  TEXT,
    height_cm   REAL,
    weight_kg   REAL,
    activity_level TEXT DEFAULT 'moderate',
    theme       TEXT DEFAULT 'light',
    color_scheme TEXT DEFAULT 'blue',
    language    TEXT DEFAULT 'en',
    timezone    TEXT DEFAULT 'UTC',
    units       TEXT DEFAULT 'metric',
    goal_steps  INTEGER DEFAULT 10000,
    goal_calories INTEGER DEFAULT 2000,
    goal_sleep  REAL DEFAULT 8.0,
    notif_health_alerts  INTEGER DEFAULT 1,
    notif_daily_summary  INTEGER DEFAULT 1,
    notif_achievements   INTEGER DEFAULT 1,
    notif_device_sync    INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS devices (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    type            TEXT NOT NULL,
    model           TEXT,
    firmware        TEXT,
    battery_pct     INTEGER DEFAULT 100,
    status          TEXT DEFAULT 'connected',
    last_sync       TEXT,
    tracking_metrics TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS health_readings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    metric      TEXT NOT NULL,
    value       REAL NOT NULL,
    value2      REAL,
    unit        TEXT,
    status      TEXT DEFAULT 'normal',
    notes       TEXT,
    recorded_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS daily_summaries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date            TEXT NOT NULL,
    health_score    INTEGER,
    cardiovascular  INTEGER,
    activity        INTEGER,
    sleep_score     INTEGER,
    nutrition       INTEGER,
    mental_health   INTEGER,
    steps           INTEGER,
    calories        INTEGER,
    sleep_hrs       REAL,
    UNIQUE(user_id, date)
);

CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    body        TEXT,
    category    TEXT DEFAULT 'info',
    is_read     INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL CHECK(role IN ('user','assistant')),
    content     TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    report_type     TEXT NOT NULL,
    period_start    TEXT,
    period_end      TEXT,
    metrics         TEXT,
    status          TEXT DEFAULT 'ready',
    created_at      TEXT DEFAULT (datetime('now'))
);
"""


def init_db():
    """Create tables and seed demo user if not present."""
    with get_db() as conn:
        conn.executescript(SCHEMA)

        # Check if demo user exists
        row = conn.execute("SELECT id FROM users WHERE email=?", ("alex@example.com",)).fetchone()
        if row:
            return

        # ── Seed demo user ──
        pwd = hash_password("demo123")
        conn.execute("""
            INSERT INTO users (first_name, last_name, email, password, dob, gender,
                blood_type, height_cm, weight_kg, activity_level,
                goal_steps, goal_calories, goal_sleep)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, ("Alex", "Johnson", "alex@example.com", pwd,
              "1990-05-15", "male", "O+", 178, 75, "moderate",
              10000, 2000, 8.0))
        uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # ── Devices ──
        devices = [
            (uid, "Apple Watch Series 9", "Smartwatch", "Apple Watch Series 9", "v10.1.1", 87, "connected",
             "Heart Rate,Steps,Calories,Activity Minutes,Stand Hours"),
            (uid, "Fitbit Charge 6", "Fitness Tracker", "Fitbit Charge 6", "v2.4.8", 65, "connected",
             "Activity,Sleep,SpO2,Stress Management,Skin Temperature"),
            (uid, "Dexcom G7", "Glucose Monitor", "Dexcom G7", "v1.8.2", 92, "connected",
             "Glucose,Glucose Trends,Time in Range"),
            (uid, "Omron BP Monitor", "Blood Pressure Cuff", "Omron HEM-7156T", "v3.1.0", 45, "inactive",
             "Systolic BP,Diastolic BP,Pulse"),
        ]
        now_str = datetime.utcnow().isoformat()
        for d in devices:
            conn.execute("""
                INSERT INTO devices (user_id, name, type, model, firmware, battery_pct, status, last_sync, tracking_metrics)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (*d[:7], now_str, d[7]))

        # ── Health readings — last 14 days ──
        base = datetime.utcnow()
        readings = []
        for i in range(14):
            day = base - timedelta(days=i)
            for hour in [9, 13, 18, 21]:
                dt = day.replace(hour=hour, minute=random.randint(0, 59))
                # Heart rate
                hr = random.randint(62, 82)
                if i == 0 and hour == 15:
                    hr = 145  # the spike
                readings.append((uid, "heart_rate", hr, None, "bpm",
                                  "elevated" if hr > 100 else "normal", dt.isoformat()))
                # Glucose
                glu = random.randint(85, 105)
                readings.append((uid, "glucose", glu, None, "mg/dL",
                                  "high" if glu > 100 else "normal", dt.isoformat()))
            # Daily BP
            sys = random.randint(115, 128)
            dia = random.randint(74, 82)
            readings.append((uid, "blood_pressure", sys, dia, "mmHg",
                              "normal", (base - timedelta(days=i)).replace(hour=8).isoformat()))
            # Steps
            steps = random.randint(6000, 12000)
            readings.append((uid, "steps", steps, None, "steps",
                              "normal", (base - timedelta(days=i)).replace(hour=23, minute=59).isoformat()))
            # Calories
            calories = random.randint(1800, 2500)
            readings.append((uid, "calories", calories, None, "kcal",
                              "normal", (base - timedelta(days=i)).replace(hour=23, minute=59).isoformat()))

        conn.executemany("""
            INSERT INTO health_readings (user_id, metric, value, value2, unit, status, recorded_at)
            VALUES (?,?,?,?,?,?,?)
        """, readings)

        # ── Daily summaries ──
        for i in range(7):
            d = (base - timedelta(days=i)).strftime("%Y-%m-%d")
            conn.execute("""
                INSERT OR IGNORE INTO daily_summaries
                (user_id, date, health_score, cardiovascular, activity, sleep_score, nutrition, mental_health, steps, calories, sleep_hrs)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (uid, d,
                  random.randint(80, 92), random.randint(85, 96), random.randint(78, 92),
                  random.randint(70, 85), random.randint(82, 95), random.randint(84, 96),
                  random.randint(7000, 11500), random.randint(1700, 2100), round(random.uniform(6.5, 8.5), 1)))

        # ── Notifications ──
        notifs = [
            (uid, "Elevated Heart Rate", "Your heart rate reached 145 bpm during your evening walk.", "warning", 0),
            (uid, "Daily Goal Achievement", "Congratulations! You reached your step goal for today.", "info", 0),
            (uid, "Medication Reminder", "Time to take your evening medication.", "reminder", 0),
            (uid, "Weekly Report Ready", "Your weekly health report is now available.", "report", 0),
            (uid, "Device Sync Complete", "Apple Watch Series 9 synced successfully.", "device", 1),
            (uid, "Blood Pressure Normal", "Your latest blood pressure reading is within normal range.", "health", 1),
        ]
        conn.executemany("""
            INSERT INTO notifications (user_id, title, body, category, is_read)
            VALUES (?,?,?,?,?)
        """, notifs)

        # ── Reports ──
        reps = [
            (uid, "Monthly Health Summary", "monthly", "2025-11-01", "2025-11-30",
             "Heart Rate,Steps,Sleep,Activity", "ready"),
            (uid, "Weekly Activity Report", "weekly", "2025-11-11", "2025-11-18",
             "Steps,Calories,Activity Minutes", "ready"),
            (uid, "Glucose Monitoring Report", "specialty", "2025-10-01", "2025-10-31",
             "Glucose,Time in Range,Trends", "ready"),
            (uid, "Cardiovascular Health Q4", "quarterly", "2025-10-01", "2025-12-31",
             "Heart Rate,Blood Pressure,HRV", "generating"),
        ]
        conn.executemany("""
            INSERT INTO reports (user_id, name, report_type, period_start, period_end, metrics, status)
            VALUES (?,?,?,?,?,?,?)
        """, reps)

        conn.commit()
        print("[DB] Database initialised with demo data ✓")


if __name__ == "__main__":
    init_db()
    print(f"[DB] DB file: {DB_PATH}")
