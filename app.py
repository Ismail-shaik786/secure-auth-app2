import re
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

# Email and Password Validation Regex
EMAIL_REGEX = r"(^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$)"
PASSWORD_REGEX = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'

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

        # Validate email format using regex
        if not re.match(EMAIL_REGEX, email):
            flash('Invalid email format. Please enter a valid email (e.g., example@example.com).')
            return redirect(url_for('signup'))

        # Validate password strength using regex
        if not re.match(PASSWORD_REGEX, password):
            flash('Password must be at least 8 characters long and contain letters, numbers, and a special character (e.g., @, $, %, *).')
            return redirect(url_for('signup'))

        # Ensure both email and password are not empty
        if not email or not password:
            flash('Please fill all fields.')
            return redirect(url_for('signup'))
        
        # Hash the password for security
        hashed_pw = generate_password_hash(password)
        
        # Try to insert into the database
        try:
            with sqlite3.connect('database.db') as conn:
                conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_pw))
                flash('Account created successfully!')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already registered. Please use a different email.')
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
    app.run(debug=True)
