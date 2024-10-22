from flask import Flask, render_template, request, redirect, url_for, flash, session
from email.message import EmailMessage
import smtplib
import random
import string
import json
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your own secret key

# Email regex pattern
EMAIL_REGEX = r'^z\d{7}@ad\.unsw\.edu\.au$'
USER_DATA_FILE = 'users.json'

# Email configuration (Change this to your own email and app-specific password)
EMAIL_ADDRESS = 'flexiweb@163.com'  # Replace with your email
EMAIL_PASSWORD = 'DVaimcZvTbwrqkGh'    # Replace with your email password

# Function to load user data from JSON file
def load_users():
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, 'r') as f:
            return json.load(f)
    else:
        return {}

# Function to save user data to JSON file
def save_users(users):
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(users, f)

# Function to send a verification email
def send_verification_email(to_email, verification_code):
    msg = EmailMessage()
    msg['Subject'] = 'Email Verification Code'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(f'Your verification code is: {verification_code}')

    with smtplib.SMTP_SSL('smtp.163.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

# Function to generate a verification code
def generate_verification_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

# Home route - Redirect to login
@app.route('/')
def index():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        users = load_users()
        user = users.get(email)
        if user and check_password_hash(user['password'], password):
            if user.get('verified'):
                session['user'] = email
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Your email has not been verified.')
        else:
            flash('Incorrect email or password.')
    return render_template('login.html')

# Register route with email verification
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Custom email format validation
        if not re.match(EMAIL_REGEX, email):
            flash('Invalid email format, must be z followed by 7 digits @ad.unsw.edu.au')
            return render_template('register.html')

        # Standard email format validation using email_validator library
        try:
            validate_email(email)
        except EmailNotValidError as e:
            flash(str(e))
            return render_template('register.html')

        # Password validation
        if len(password) < 8:
            flash('Password must be at least 8 characters long.')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html')

        users = load_users()
        if email in users:
            flash('This email has already been registered.')
            return render_template('register.html')

        # Generate verification code
        verification_code = generate_verification_code()

        # Send verification email
        try:
            send_verification_email(email, verification_code)
            flash('Verification email has been sent, please check your mailbox.')
        except Exception as e:
            flash(f'Failed to send verification email: {e}')
            return render_template('register.html')

        # Temporarily store data in session
        session['temp_user'] = {
            'email': email,
            'password': generate_password_hash(password),
            'verification_code': verification_code
        }
        return redirect(url_for('verify'))
    return render_template('register.html')

# Verification route to handle email verification
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    temp_user = session.get('temp_user')
    if not temp_user:
        return redirect(url_for('register'))

    if request.method == 'POST':
        user_code = request.form['code']
        if user_code == temp_user['verification_code']:
            users = load_users()
            users[temp_user['email']] = {
                'password': temp_user['password'],
                'verified': True
            }
            save_users(users)
            session.pop('temp_user', None)
            flash('Email verification successful, please log in.')
            return redirect(url_for('login'))
        else:
            flash('Verification code is incorrect.')
    return render_template('verify.html')

# Forgot Password route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        if not re.match(EMAIL_REGEX, email):
            return render_template('forgot_password.html', email_error="Invalid email format. Please enter a valid email address.")

        flash("Reset link has been sent! Please check your email and follow the instructions.")
        return render_template('forgot_password.html', success_message="Reset link has been sent! Please check your email and follow the instructions.")
    return render_template('forgot_password.html')

# Dashboard route
@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome, {session['user']}! This is your dashboard.<br><a href='/logout'>Logout</a>"
    else:
        return redirect(url_for('login'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have successfully logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
