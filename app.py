from flask import Flask, render_template, request, redirect, url_for, session, flash
import hashlib
import sqlite3
import os
import logging

import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to connect to the SQLite database
def connect_db():
    conn = sqlite3.connect('database.db')
    return conn

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? OR email = ?', (username, email))
        user = cursor.fetchone()
        if user:
            flash('Username or Email already taken', 'error')
            conn.close()
            return redirect(url_for('signup'))
        
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                       (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Signup successful, please login', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            flash('Username and password cannot be empty', 'error')
            return redirect(url_for('login'))

        hashed_password = hash_password(password)

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
        user = cursor.fetchone()
        
        if user:
            session['username'] = user[0]
            if user[1].endswith('@student.rmit.edu.au'):
                session['role'] = 'plus user'
                flash('Login successful as Plus User', 'success')
                return redirect(url_for('dashboard2'))
            else:
                session['role'] = 'normal user'
                flash('Login successful as Normal User', 'success')
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

import requests

def fetch_books(query=None):
    url = "https://www.googleapis.com/books/v1/volumes"
    params = {
        'q': query if query else 'free+ebooks',
        'filter': 'free-ebooks'
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json().get('items', [])
    return []

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        flash('You need to login first', 'error')
        return redirect(url_for('login'))
    
    query = request.form.get('query')
    books = fetch_books(query)
    
    return render_template('dashboard.html', books=books)

    
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['reset_email'] = email
            flash('Email found, proceed to reset password', 'success')
            return redirect(url_for('reset_password_step2'))
        else:
            flash('Email not found', 'error')
            return redirect(url_for('reset_password'))
    return render_template('reset_password.html')

@app.route('/dashboard2')
def dashboard2():
    if 'username' in session:
        if session.get('role') == 'plus user':
            return render_template('dashboard2.html')
        else:
            flash('You are not authorized to access this page', 'error')
            return redirect(url_for('dashboard'))
    else:
        flash('You need to login first', 'error')
        return redirect(url_for('login'))

@app.route('/reset_password_step2', methods=['GET', 'POST'])
def reset_password_step2():
    if 'reset_email' not in session:
        flash('You need to provide your email first', 'error')
        return redirect(url_for('reset_password'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not new_password or not confirm_password:
            flash('All fields are required', 'error')
            return redirect(url_for('reset_password_step2'))

        if new_password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('reset_password_step2'))

        hashed_password = hash_password(new_password)
        logging.debug(f'Hashed new password: {hashed_password}')

        try:
            conn = connect_db()
            cursor = conn.cursor()
            email = session["reset_email"]
            logging.debug(f'Email to update: {email}')
            cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
            conn.commit()
            
            if cursor.rowcount == 0:
                logging.debug('No rows were updated.')
                flash('Failed to reset password. User not found.', 'error')
                return redirect(url_for('reset_password_step2'))
            else:
                logging.debug('Password updated successfully.')

            conn.close()

            session.pop('reset_email', None)

            flash('Password reset successful, please login', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f'Error updating password: {e}')
            flash('There was an error resetting your password. Please try again.', 'error')
            return redirect(url_for('reset_password_step2'))

    return render_template('reset_password_step2.html')

if __name__ == '__main__':
    app.run(debug=True)
