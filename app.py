from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO
from analyzer import analyze_logs
import sqlite3
import requests
import os

app = Flask(__name__)

app.secret_key = "siem_secret"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DB = os.path.join(
    BASE_DIR,
    "siem.db"
)

# -------------------------
# DATABASE INIT
# -------------------------

def init_db():

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute("""

    CREATE TABLE IF NOT EXISTS quarantined(

        ip TEXT PRIMARY KEY

    )

    """)

    cur.execute("""

    CREATE TABLE IF NOT EXISTS alerts(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        time TEXT,

        ip TEXT,

        severity TEXT,

        rule TEXT,

        status TEXT

    )

    """)

    conn.commit()

    conn.close()


init_db()

# -------------------------
# COUNTRY LOOKUP
# -------------------------

def get_country(ip):

    if ip.startswith(

        ("192.168", "127.", "10.")

    ):

        return "Local Network"

    try:

        response = requests.get(

            f"http://ip-api.com/json/{ip}",

            timeout=2

        )

        data = response.json()

        return data.get(

            "country",

            "Unknown"

        )

    except:

        return "Unknown"


# -------------------------
# QUARANTINE CHECK
# -------------------------

def is_quarantined(ip):

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(

        "SELECT ip FROM quarantined WHERE ip=?",

        (ip,)

    )

    result = cur.fetchone()

    conn.close()

    return result is not None


# -------------------------
# ANALYZER WRAPPER
# -------------------------

def analyze():

    return analyze_logs(

        get_country,

        is_quarantined

    )


# -------------------------
# LOGIN
# -------------------------

@app.route(

    "/login",

    methods=[

        "GET",

        "POST"

    ]

)
def login():

    if request.method == "POST":

        username = request.form.get(

            "username"

        )

        password = request.form.get(

            "password"

        )

        if (

            username == "admin"

            and

            password == "admin123"

        ):

            session["logged"] = True

            return redirect("/")

    return render_template(

        "login.html"

    )


# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(

        "/login"

    )


# -------------------------
# DASHBOARD
# -------------------------

@app.route("/")
def dashboard():

    if not session.get(

        "logged"

    ):

        return redirect(

            "/login"

        )

    data, timeline = analyze()

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    for item in data:

        if item["severity"] != "LOW":

            cur.execute(

                """

                INSERT INTO alerts(

                time,

                ip,

                severity,

                rule,

                status

                )

                VALUES(

                datetime('now'),

                ?,?,?,?

                )

                """,

                (

                    item["ip"],

                    item["severity"],

                    item["rule"],

                    item["status"]

                )

            )

    conn.commit()

    conn.close()

    return render_template(

        "dashboard.html",

        data=data,

        timeline=timeline

    )


# -------------------------
# ALERT HISTORY
# -------------------------

@app.route("/alerts")
def alerts():

    if not session.get(

        "logged"

    ):

        return redirect(

            "/login"

        )

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(

        """

        SELECT *

        FROM alerts

        ORDER BY id DESC

        LIMIT 500

        """

    )

    alerts = cur.fetchall()

    conn.close()

    return render_template(

        "alerts.html",

        alerts=alerts

    )


# -------------------------
# ATTACK MAP
# -------------------------

@app.route("/map")
def attack_map():

    if not session.get(

        "logged"

    ):

        return redirect(

            "/login"

        )

    data, timeline = analyze()

    return render_template(

        "attack_map.html",

        data=data

    )


# -------------------------
# QUARANTINE
# -------------------------

@app.route("/quarantine/<ip>")
def quarantine(ip):

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(

        """

        INSERT OR IGNORE

        INTO quarantined

        VALUES(?)

        """,

        (ip,)

    )

    conn.commit()

    conn.close()

    return redirect("/")


# -------------------------
# REMOVE QUARANTINE
# -------------------------

@app.route("/unquarantine/<ip>")
def unquarantine(ip):

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    cur.execute(

        """

        DELETE FROM quarantined

        WHERE ip=?

        """,

        (ip,)

    )

    conn.commit()

    conn.close()

    return redirect("/")


# -------------------------
# API
# -------------------------

@app.route("/api")
def api():

    data, timeline = analyze()

    return jsonify({

        "data": data,

        "timeline": timeline

    })


# -------------------------
# SOCKET CONNECT
# -------------------------

@socketio.on("connect")
def connected():

    print(

        "SOC CLIENT CONNECTED"

    )


# -------------------------
# RUN APP
# -------------------------

if __name__ == "__main__":

    print(

        "🚀 SOC SIEM DASHBOARD RUNNING"

    )

    socketio.run(

        app,

        host="0.0.0.0",

        port=5000,

        debug=False

    )