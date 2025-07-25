from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Generate key once and keep safe
key = Fernet.generate_key()
fernet = Fernet(key)

# ------------------ DB INIT ------------------
def init_db():
    with sqlite3.connect("passwords.db") as con:
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                website TEXT,
                email TEXT,
                password TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
init_db()

# ------------------ ROUTES ------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        try:
            with sqlite3.connect("passwords.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
                con.commit()
                return redirect('/login')
        except sqlite3.IntegrityError:
            return "Email already exists."

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with sqlite3.connect("passwords.db") as con:
            cur = con.cursor()
            cur.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            user = cur.fetchone()

            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                return redirect('/dashboard')
            else:
                return "Invalid login."

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']

    if request.method == 'POST':
        website = request.form['website']
        email = request.form['email']
        password = fernet.encrypt(request.form['password'].encode()).decode()

        with sqlite3.connect("passwords.db") as con:
            cur = con.cursor()
            cur.execute("INSERT INTO passwords (user_id, website, email, password) VALUES (?, ?, ?, ?)",
                        (user_id, website, email, password))
            con.commit()
        return redirect('/dashboard')

    with sqlite3.connect("passwords.db") as con:
        cur = con.cursor()
        cur.execute("SELECT id, website, email, password FROM passwords WHERE user_id = ?", (user_id,))
        entries = [
            {"id": i, "website": w, "email": e, "password": fernet.decrypt(p.encode()).decode()}
            for i, w, e, p in cur.fetchall()
        ]

    return render_template('dashboard.html', entries=entries)

@app.route('/delete/<int:entry_id>')
def delete(entry_id):
    if 'user_id' not in session:
        return redirect('/login')

    with sqlite3.connect("passwords.db") as con:
        cur = con.cursor()
        cur.execute("DELETE FROM passwords WHERE id = ?", (entry_id,))
        con.commit()

    return redirect('/dashboard')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
