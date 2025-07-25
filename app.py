from flask import Flask, render_template, request, redirect, flash
from cryptography.fernet import Fernet
import json, os

app = Flask(__name__)
app.secret_key = "supersecret"

# === Generate or Load Key ===
def create_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as f:
            f.write(key)

def load_key():
    with open("secret.key", "rb") as f:
        return f.read()

create_key()
fernet = Fernet(load_key())

# === Routes ===
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        website = request.form['website']
        email = request.form['email']
        password = request.form['password']

        if not website or not email or not password:
            flash("All fields are required!", "error")
            return redirect('/add')

        new_data = {
            website: {
                "email": email,
                "password": fernet.encrypt(password.encode()).decode()
            }
        }

        try:
            with open("data.json", "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {}

        data.update(new_data)

        with open("data.json", "w") as f:
            json.dump(data, f, indent=4)

        flash("Password saved successfully!", "success")
        return redirect('/add')

    return render_template('add.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        website = request.form['website']
        try:
            with open("data.json", "r") as f:
                data = json.load(f)

            if website in data:
                email = data[website]['email']
                password = fernet.decrypt(data[website]['password'].encode()).decode()
                return render_template('search.html', website=website, email=email, password=password)
            else:
                flash("Website not found!", "error")
        except FileNotFoundError:
            flash("No data found.", "error")

    return render_template('search.html')

if __name__ == "__main__":
    app.run(debug=True)
