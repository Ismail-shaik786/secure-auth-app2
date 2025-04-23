from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Initialize DB
def init_db():
    if not os.path.exists('database.db'):
        with sqlite3.connect('database.db') as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                email TEXT UNIQUE NOT NULL,
                                password TEXT NOT NULL
                            )''')
init_db()

# Home redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

# Sign Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if not email or not password:
            flash('Please fill all fields.')
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password)
        try:
            with sqlite3.connect('database.db') as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_pw))
                flash('Account created successfully!')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered.')
            return redirect(url_for('signup'))
    return render_template('signup.html')

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with sqlite3.connect('database.db') as conn:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if user and check_password_hash(user[2], password):
                session['user'] = email
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials.')
                return redirect(url_for('login'))
    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=escape(session['user']))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

