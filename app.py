from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your_default_secret_key')

# Create encryption key file if not exist
if not os.path.exists("encryption.key"):
    with open("encryption.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("encryption.key", "rb") as key_file:
    key = key_file.read()
fernet = Fernet(key)

# Initialize DB
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    website TEXT,
                    login_email TEXT,
                    saved_password TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            conn.commit()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "User already exists"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        user = c.fetchone()
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['email'] = user[1]
            return redirect('/dashboard')
        else:
            return "Invalid credentials"
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        website = request.form['website']
        login_email = request.form['login_email']
        saved_password = request.form['saved_password']
        encrypted_password = fernet.encrypt(saved_password.encode()).decode()
        c.execute("INSERT INTO passwords (user_id, website, login_email, saved_password) VALUES (?, ?, ?, ?)",
                  (user_id, website, login_email, encrypted_password))
        conn.commit()

    c.execute("SELECT website, login_email, saved_password FROM passwords WHERE user_id=?", (user_id,))
    rows = c.fetchall()

    # Decrypt passwords
    saved_data = []
    for row in rows:
        decrypted_password = fernet.decrypt(row[2].encode()).decode()
        saved_data.append((row[0], row[1], decrypted_password))

    return render_template('dashboard.html', saved_data=saved_data, email=session['email'])

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
