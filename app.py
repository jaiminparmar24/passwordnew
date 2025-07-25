from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

import os
import time
import sqlite3
import requests
import pytz
import random
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')

# ✅ Mail Configuration
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME', 'your_email@gmail.com'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD', 'your_app_password'),
    MAIL_DEFAULT_SENDER=os.environ.get('MAIL_USERNAME', 'your_email@gmail.com')
)
mail = Mail(app)

# ✅ Encryption Key Setup
if not os.path.exists("encryption.key"):
    with open("encryption.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())
with open("encryption.key", "rb") as key_file:
    key = key_file.read()
fernet = Fernet(key)

# ✅ Database Initialization
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT,
                        last_login TEXT
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        website TEXT,
                        login_email TEXT,
                        saved_password TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
init_db()

# ✅ Helper: Get & Update Last Login
def get_last_login(email):
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT last_login FROM users WHERE email=?", (email,))
        row = c.fetchone()
        return datetime.strptime(row[0], '%Y-%m-%d %H:%M:%S') if row and row[0] else None

def update_last_login(email):
    now = datetime.now(pytz.timezone("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET last_login=? WHERE email=?", (now, email))
        conn.commit()

# ✅ Google Script Logging
def send_to_google_script(email, status):
    try:
        url = "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec"
        login_time = session.get('login_time') or datetime.now(pytz.timezone("Asia/Kolkata"))
        requests.post(url, json={
            "email": email,
            "time": login_time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": status
        })
    except Exception as e:
        print("Google logging failed:", e)


    # ✅ OTP Email Sender
def send_otp(email):
    session.pop('otp', None)
    session.pop('otp_time', None)

    otp = str(random.randint(1000, 9999))
    session.update({
        'otp': otp,
        'otp_time': time.time(),
        'email': email,
        'otp_attempts': 0
    })

    time_now = datetime.now(pytz.timezone("Asia/Kolkata")).strftime("%d %B %Y, %I:%M %p")
    subject = f"🔐 Your OTP for JAIMIN's Login – {time_now}"

    msg = Message(
        subject=subject,
        recipients=[email],
        reply_to="jaiminparmar024@gmail.com",
        extra_headers={"X-Priority": "1", "X-MSMail-Priority": "High"}
    )

    msg.body = f"Your OTP is: {otp}"

    msg.html = f"""<!DOCTYPE html>
    <html><head><style>
    body {{ font-family: 'Segoe UI'; background: #f4f4f4; margin: 0; padding: 0; }}
    .container {{
      background: #fff; padding: 30px; max-width: 600px; margin: 30px auto;
      border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1);
    }}
    .otp-box {{
      font-size: 26px; letter-spacing: 8px; background: #222; color: #fff;
      padding: 15px; border-radius: 10px; text-align: center; margin: 20px 0;
    }}
    .footer {{ font-size: 13px; color: #888; text-align: center; margin-top: 30px; }}
    </style></head>
    <body>
    <div class="container">
      <h2 style="color:#20B2AA;">🔐 JAIMIN PARMAR's Login OTP</h2>
      <p>Hello,</p>
      <p>We received a login request for: <b>{email}</b></p>
      <p>Enter this OTP to continue:</p>
      <div class="otp-box">{otp}</div>
      <p>This OTP is valid for 5 minutes.</p>
      <p>If you didn’t request this, you can safely ignore this email.</p>
      <div class="footer">Securely sent by JAIMIN 🚀</div>
    </div></body></html>"""

    mail.send(msg)


# ✅ Maintenance Mode
@app.before_request
def check_maintenance():
    if os.environ.get('MAINTENANCE_MODE') == 'on' and request.endpoint != 'maintenance':
        return render_template("maintenance.html"), 503

# ✅ Routes
@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect('/dashboard')

    if request.method == 'POST':
        email = request.form.get('email', '').strip()

        if not email:
            flash("Enter your email.", "error")
            return render_template('login.html')

        session['email'] = email

        with sqlite3.connect("database.db") as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email=?", (email,))
            user = c.fetchone()
            if not user:
                c.execute("INSERT INTO users (email) VALUES (?)", (email,))
                conn.commit()

        send_otp(email)
        flash("OTP sent to your email.", "info")
        return redirect('/verify')

    return render_template('login.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        otp_input = request.form.get('otp', '').strip()
        if not session.get('otp') or time.time() - session.get('otp_time', 0) > 300:
            return render_template('verify.html', error="OTP expired.")

        if otp_input == session['otp']:
            session['logged_in'] = True
            session['verified'] = True
            session['login_time'] = datetime.now(pytz.timezone("Asia/Kolkata"))
            update_last_login(session['email'])
            send_to_google_script(session['email'], "Login")
            return redirect('/dashboard')
        else:
            return render_template('verify.html', error="Wrong OTP.")

    return render_template('verify.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('logged_in'):
        return redirect('/login')

    email = session['email']
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        user_row = c.fetchone()

        if not user_row:
            flash("User not found.")
            return redirect('/logout')

        user_id = user_row[0]

        # ✅ Handle form submission
        if request.method == 'POST':
            website = request.form.get('website')
            login_email = request.form.get('login_email')
            saved_password = request.form.get('saved_password')

            if website and login_email and saved_password:
                encrypted = fernet.encrypt(saved_password.encode()).decode()
                c.execute("INSERT INTO passwords (user_id, website, login_email, saved_password) VALUES (?, ?, ?, ?)",
                          (user_id, website, login_email, encrypted))
                conn.commit()
                flash("Credential Saved", "success")
            else:
                flash("All fields required", "error")

            # ✅ Redirect after POST to prevent re-submission on refresh
            return redirect(url_for('dashboard'))

        # ✅ Continue with GET
        c.execute("SELECT id, website, login_email, saved_password FROM passwords WHERE user_id=?", (user_id,))
        rows = c.fetchall()
        saved_data = []
        for row in rows:
            try:
                decrypted = fernet.decrypt(row[3].encode()).decode()
            except:
                decrypted = "Error"
            saved_data.append({
                'id': row[0],
                'website': row[1],
                'email': row[2],
                'password': decrypted
            })

    last_login = get_last_login(email)
    return render_template('dashboard.html', saved_data=saved_data, email=email, last_login=last_login)


@app.route('/delete', methods=['POST'])
def delete():
    if not session.get('logged_in'):
        return redirect('/login')

    email = session['email']
    website = request.form.get('website')
    login_email = request.form.get('login_email')
    password_to_delete = request.form.get('saved_password')

    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        user_row = c.fetchone()

        if not user_row:
            flash("User not found.")
            return redirect('/logout')

        user_id = user_row[0]
        c.execute("SELECT id, saved_password FROM passwords WHERE user_id=? AND website=? AND login_email=?",
                  (user_id, website, login_email))
        rows = c.fetchall()

        deleted = False
        for row in rows:
            try:
                decrypted = fernet.decrypt(row[1].encode()).decode()
                if decrypted == password_to_delete:
                    c.execute("DELETE FROM passwords WHERE id=?", (row[0],))
                    conn.commit()
                    deleted = True
                    break
            except:
                continue

        if deleted:
            flash("Credential deleted.")
        else:
            flash("Credential not found or password mismatch.")

    return redirect('/dashboard')

@app.route('/logout')
def logout():
    email = session.get('email')
    session.clear()
    if email:
        send_to_google_script(email, "Logout")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
