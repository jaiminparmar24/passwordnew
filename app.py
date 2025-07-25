from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import sqlite3, os

app = Flask(__name__)
app.secret_key = "supersecret"

# Create encryption key if not exists
if not os.path.exists("secret.key"):
    with open("secret.key", "wb") as f:
        f.write(Fernet.generate_key())
fernet = Fernet(open("secret.key", "rb").read())

# Initialize database
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            website TEXT,
            email TEXT,
            password TEXT
        )""")

init_db()

# Routes
@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        try:
            with sqlite3.connect("users.db") as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
                flash("Registered successfully. Please login.")
                return redirect('/login')
        except sqlite3.IntegrityError:
            flash("Email already exists.")
    return render_template("register.html")

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect("users.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            user = cur.fetchone()
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                return redirect('/dashboard')
            flash("Invalid credentials.")
    return render_template("login.html")

@app.route('/dashboard', methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect('/login')

    search = request.args.get('search', '').strip()

    if request.method == "POST":
        website = request.form['website']
        email = request.form['email']
        password = fernet.encrypt(request.form['password'].encode()).decode()
        with sqlite3.connect("users.db") as conn:
            conn.execute("INSERT INTO passwords (user_id, website, email, password) VALUES (?, ?, ?, ?)",
                         (session['user_id'], website, email, password))
            flash("Password saved!")

    with sqlite3.connect("users.db") as conn:
        cur = conn.cursor()
        if search:
            cur.execute("SELECT id, website, email, password FROM passwords WHERE user_id = ? AND website LIKE ?",
                        (session['user_id'], f"%{search}%"))
        else:
            cur.execute("SELECT id, website, email, password FROM passwords WHERE user_id = ?",
                        (session['user_id'],))
        entries = [(i, w, e, fernet.decrypt(p.encode()).decode()) for i, w, e, p in cur.fetchall()]
    return render_template("dashboard.html", entries=entries, search=search)

@app.route('/delete/<int:entry_id>')
def delete(entry_id):
    if "user_id" not in session:
        return redirect('/login')
    with sqlite3.connect("users.db") as conn:
        conn.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (entry_id, session['user_id']))
    flash("Entry deleted.")
    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == "__main__":
    app.run(debug=True)
