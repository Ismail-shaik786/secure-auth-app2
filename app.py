import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
from datetime import timedelta
import re

# Create a Flask app
app = Flask(__name__)

# Set a strong secret key
app.secret_key = secrets.token_hex(16)

# Set session timeout (30 minutes)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True  # Send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection

# Initialize the SQLite database
def init_db():
    if not os.path.exists('database.db'):
        with sqlite3.connect('database.db') as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS users (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                email TEXT UNIQUE NOT NULL,
                                password TEXT NOT NULL
                            )''')
init_db()

# Home redirects to login page
@app.route('/')
def home():
    return redirect(url_for('login'))

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Input Validation: Check email and password format
        if not email or not password:
            flash('Please fill in all fields.')
            return redirect(url_for('signup'))
        
        # Simple email validation using regex
        email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
        if not re.match(email_pattern, email):
            flash('Invalid email format.')
            return redirect(url_for('signup'))

        # Hash the password for storage
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

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Input validation for email and password
        if not email or not password:
            flash('Please fill in all fields.')
            return redirect(url_for('login'))

        # Fetch user from DB using parameterized query to avoid SQL injection
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user[2], password):
                session.permanent = True  # Enable session timeout
                session['user'] = email  # Store user email in the session
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials.')
                return redirect(url_for('login'))
    return render_template('login.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=escape(session['user']))

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear the session
    return redirect(url_for('login'))

# Force HTTPS for all HTTP requests (redirect them to HTTPS)
@app.before_request
def enforce_https():
    if not request.is_secure:
        return redirect(request.url.replace('http://', 'https://', 1))

if __name__ == '__main__':
    app.run(debug=True)
