from flask import Flask, render_template, request, redirect, session, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import re
import sqlite3

app = Flask(__name__)
app.secret_key = "secret123"

# ---------------- ADMIN ----------------
ADMIN_EMAIL = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"

# ---------------- LOAD MODEL ----------------
vector = pickle.load(open("vectorizer.pkl", "rb"))
model = pickle.load(open("phishing.pkl", "rb"))

# ---------------- DATABASE ----------------
def get_db():
    return sqlite3.connect("users.db")

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT,
        url TEXT,
        result TEXT,
        status TEXT,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ---------------- URL VALIDATION ----------------
def is_valid_url(url):
    pattern = re.compile(
        r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})'
    )
    return re.match(pattern, url)

# ---------------- HOME ----------------
@app.route("/")
def home():
    return render_template("home.html")

# ---------------- FEATURES ----------------
@app.route("/features")
def features():
    return render_template("features.html")

# ---------------- ABOUT ----------------
@app.route("/about")
def about():
    return render_template("about.html")

# ---------------- CONTACT ----------------
@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")

        if not name or not email or not subject or not message:
            flash("All fields are required!")
        else:
            # For now just print (you can store in DB later)
            print("New Contact Message:")
            print(name, email, subject, message)

            flash("Message sent successfully!")

        return redirect("/contact")

    return render_template("contact.html")

# =====================================================
# REGISTER
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, password)
            )
            conn.commit()
            flash("Registration successful! Please login.")
            return redirect("/login")

        except sqlite3.IntegrityError:
            flash("Email already exists!")

        conn.close()

    return render_template("register.html")

# =====================================================
# URL SCANNER
# =====================================================
@app.route("/url-scanner", methods=["GET", "POST"])
def url_scanner():

    if "user" not in session:
        return redirect("/login")

    prediction = None
    status = None

    if request.method == "POST":
        url = request.form.get("url")

        if not url:
            prediction = "Please enter a URL!"
            status = "error"

        elif not is_valid_url(url):
            prediction = "Invalid URL format!"
            status = "error"

        else:
            clean_url = re.sub(r'https?://|www\.', '', url)

            try:
                X = vector.transform([clean_url])
                pred = model.predict(X)[0]

                confidence = 1.0
                if hasattr(model, "predict_proba"):
                    confidence = max(model.predict_proba(X)[0])

                if confidence < 0.75:
                    prediction = f"⚠️ Suspicious URL ({confidence*100:.2f}%)"
                    status = "suspicious"
                else:
                    if pred == 'bad':
                        prediction = f"🚨 Phishing URL Detected ({confidence*100:.2f}%)"
                        status = "phishing"
                    else:
                        prediction = f"✅ Legitimate URL ({confidence*100:.2f}%)"
                        status = "safe"

            except Exception as e:
                prediction = "Error processing URL!"
                status = "error"
                print(e)

        if prediction and status != "error":
            conn = get_db()
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO history (user_email, url, result, status)
            VALUES (?, ?, ?, ?)
            """, (session["email"], url, prediction, status))

            conn.commit()
            conn.close()

    return render_template("url_scanner.html",
                           prediction=prediction,
                           status=status)

# =====================================================
# EMAIL SCANNER
# =====================================================
@app.route("/email-scanner", methods=["GET", "POST"])
def email_scanner():

    if "user" not in session:
        return redirect("/login")

    result = None
    status = None

    if request.method == "POST":
        content = request.form.get("content")

        if not content:
            result = "Please enter email content!"
            status = "error"
        else:
            content = content.lower()

            keywords = ["urgent", "verify", "password", "click", "login", "bank", "account", "update"]

            score = 0
            for word in keywords:
                if word in content:
                    score += 1

            if "http://" in content or "https://" in content:
                score += 2

            if score >= 4:
                result = "🚨 Phishing Email Detected!"
                status = "phishing"
            elif score >= 2:
                result = "⚠️ Suspicious Email!"
                status = "suspicious"
            else:
                result = "✅ Safe Email"
                status = "safe"

    return render_template("email_scanner.html",
                           result=result,
                           status=status)

# =====================================================
# DOMAIN ANALYSIS
# =====================================================
@app.route("/domain-analysis", methods=["GET", "POST"])
def domain_analysis():

    if "user" not in session:
        return redirect("/login")

    result = None

    if request.method == "POST":
        url = request.form.get("url")

        if not url:
            result = {"error": "Please enter a domain!"}
        else:
            domain = re.sub(r'https?://|www\.', '', url).split('/')[0]

            risk = "Low"
            reasons = []

            if not url.startswith("https"):
                risk = "Medium"
                reasons.append("No HTTPS")

            suspicious_words = ["login", "secure", "bank", "verify", "update"]
            for word in suspicious_words:
                if word in domain:
                    risk = "High"
                    reasons.append(f"Suspicious keyword: {word}")

            if domain.count('.') > 2:
                risk = "High"
                reasons.append("Too many subdomains")

            if len(domain) > 25:
                risk = "Medium"
                reasons.append("Long domain")

            if re.search(r'\d', domain):
                reasons.append("Contains numbers")

            if not reasons:
                reasons.append("Looks safe")

            result = {
                "domain": domain,
                "risk": risk,
                "reason": reasons
            }

    return render_template("domain_analysis.html", result=result)

# =====================================================
# ALERTS
# =====================================================
@app.route("/alerts")
def alerts():

    alerts = [
        {
            "type": "URL",
            "source": "http://fake-site.com",
            "threat": "Phishing detected",
            "severity": "High",
            "date": "2026-05-04",
            "status": "New"
        },
        {
            "type": "Email",
            "source": "spam@mail.com",
            "threat": "Suspicious email",
            "severity": "Medium",
            "date": "2026-05-04",
            "status": "New"
        },
        {
            "type": "URL",
            "source": "http://safe-site.com",
            "threat": "Clean",
            "severity": "Low",
            "date": "2026-05-04",
            "status": "New"
        }
    ]

    high = len([a for a in alerts if a["severity"] == "High"])
    medium = len([a for a in alerts if a["severity"] == "Medium"])
    low = len([a for a in alerts if a["severity"] == "Low"])
    total = len(alerts)

    return render_template("alerts.html",
                           alerts=alerts,
                           high=high,
                           medium=medium,
                           low=low,
                           total=total)

# =====================================================
# HISTORY
# =====================================================
@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT url, result, status, date
    FROM history
    WHERE user_email=?
    ORDER BY date DESC
    """, (session["email"],))

    rows = cursor.fetchall()
    conn.close()

    logs = []

    for row in rows:
        url, result, status, date = row

        logs.append({
            "date": date,
            "type": "URL",
            "source": url,
            "status": status,
            "result": result
        })

    total = len(logs)
    safe = len([l for l in logs if l["status"] == "safe"])
    suspicious = len([l for l in logs if l["status"] == "suspicious"])
    phishing = len([l for l in logs if l["status"] == "phishing"])

    return render_template("history.html",
                           logs=logs,
                           total=total,
                           safe=safe,
                           suspicious=suspicious,
                           phishing=phishing)

# =====================================================
# DASHBOARD
# =====================================================
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT url, status, date
    FROM history
    WHERE user_email=?
    ORDER BY date DESC
    LIMIT 10
    """, (session["email"],))

    history = cursor.fetchall()
    conn.close()

    return render_template("dashboard.html", history=history)

# =====================================================
# THREAT INTELLIGENCE
# =====================================================
@app.route("/threat-intelligence")
def threat_intelligence():

    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT url, status, date
    FROM history
    WHERE user_email=? AND status IN ('phishing', 'suspicious')
    ORDER BY date DESC
    LIMIT 20
    """, (session["email"],))

    threats = cursor.fetchall()

    cursor.execute("""
    SELECT status, COUNT(*)
    FROM history
    WHERE user_email=?
    GROUP BY status
    """, (session["email"],))

    data = cursor.fetchall()
    conn.close()

    stats = {"safe": 0, "suspicious": 0, "phishing": 0}

    for row in data:
        stats[row[0]] = row[1]

    return render_template(
        "threat_intelligence.html",
        threats=threats,
        stats=stats
    )

# =====================================================
# SETTINGS
# =====================================================
@app.route("/settings", methods=["GET", "POST"])
def settings():

    if "user" not in session:
        return redirect("/login")

    conn = get_db()
    cursor = conn.cursor()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        if password:
            password = generate_password_hash(password)
            cursor.execute("""
                UPDATE users
                SET username=?, password=?
                WHERE email=?
            """, (username, password, session["email"]))
        else:
            cursor.execute("""
                UPDATE users
                SET username=?
                WHERE email=?
            """, (username, session["email"]))

        conn.commit()
        flash("Settings updated successfully!")

    cursor.execute("SELECT username, email FROM users WHERE email=?", (session["email"],))
    user = cursor.fetchone()

    conn.close()

    return render_template("settings.html",
                           username=user[0],
                           email=user[1])

# =====================================================
# LOGIN
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session["user"] = user[1]
            session["email"] = user[2]
            return redirect("/dashboard")
        else:
            flash("Invalid Credentials")

    return render_template("login.html")

# =====================================================
# LOGOUT
# =====================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# =====================================================
# ✅ ADMIN LOGIN
# =====================================================
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin")
        else:
            flash("Invalid admin credentials")

    return render_template("admin_login.html")

# =====================================================
# ✅ ADMIN DASHBOARD
# =====================================================
@app.route("/admin")
def admin_dashboard():

    if "admin" not in session:
        return redirect("/admin-login")

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, email FROM users")
    users = cursor.fetchall()

    cursor.execute("""
        SELECT user_email, url, result, status, date
        FROM history
        ORDER BY date DESC
        LIMIT 20
    """)
    logs = cursor.fetchall()

    conn.close()

    return render_template(
    "admin_dashboard.html",
    users=users,
    history=logs,
    total_users=len(users),
    total_scans=len(logs),
    safe_count=len([l for l in logs if l[3] == "safe"]),
    phishing_count=len([l for l in logs if l[3] == "phishing"])
)

# =====================================================
# RUN
# =====================================================
if __name__ == "__main__":
    app.run(debug=True)