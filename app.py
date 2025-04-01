from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
import base64
import psycopg2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Database file
DATABASE_URL = os.getenv("postgresql://postgres:[YOUR-PASSWORD]@db.ssojqqnicfcktsczyziv.supabase.co:5432/postgres")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    c = conn.cursor()
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            site_username TEXT NOT NULL,
            site_password TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

# Constant salt for key derivation – in production, use a secure, per‑user salt stored safely.
SALT = b'some_constant_salt'

def derive_key(master_password):
    """Derive a 32-byte encryption key from the master password using PBKDF2 with SHA512."""
    password_bytes = master_password.encode()
    kdf_instance = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf_instance.derive(password_bytes))
    return key

def get_fernet():
    """Return a Fernet instance using the master password stored in session."""
    master_password = session.get('master_password')
    if not master_password:
        return None
    key = derive_key(master_password)
    return Fernet(key)

@app.route('/')
def index():
    # Redirect to dashboard if logged in, otherwise to login page
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        master_password = request.form.get('master_password')
        confirm_password = request.form.get('confirm_password')
        if master_password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template('signup.html')
        password_hash = generate_password_hash(master_password, method='pbkdf2:sha512')
        try:
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', 
                          (username, password_hash))
                conn.commit()
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another.", "error")
            return render_template('signup.html')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        master_password = request.form.get('master_password')
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
            user = c.fetchone()
        if user and check_password_hash(user[1], master_password):
            session['user_id'] = user[0]
            session['username'] = username
            # Store the master password in session for encryption key derivation
            session['master_password'] = master_password
            return redirect(url_for('dashboard'))
        else:
            flash("Incorrect username or password", "error")
            return render_template('login.html')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    fernet = get_fernet()
    user_id = session['user_id']
    
    if request.method == 'POST':
        # Adding a new credential
        website = request.form.get('website')
        site_username = request.form.get('site_username')
        site_password = request.form.get('site_password')
        encrypted_password = fernet.encrypt(site_password.encode()).decode()
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO credentials (user_id, website, site_username, site_password)
                VALUES (?, ?, ?, ?)
            ''', (user_id, website, site_username, encrypted_password))
            conn.commit()
        flash("Credential added successfully!", "success")
        return redirect(url_for('dashboard'))
    
    # Retrieve credentials for the logged-in user
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''
            SELECT id, website, site_username, site_password FROM credentials
            WHERE user_id = ?
        ''', (user_id,))
        rows = c.fetchall()
    
    credentials = []
    for row in rows:
        try:
            decrypted_password = fernet.decrypt(row[3].encode()).decode()
        except Exception:
            decrypted_password = "Decryption Error"
        credentials.append({
            'id': row[0],
            'website': row[1],
            'site_username': row[2],
            'site_password': decrypted_password
        })
    
    return render_template('dashboard.html', credentials=credentials, username=session.get('username'))

@app.route('/delete/<int:cred_id>', methods=['POST'])
def delete_credential(cred_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # Ensure the credential belongs to the current user before deleting
        c.execute('SELECT id FROM credentials WHERE id = ? AND user_id = ?', (cred_id, user_id))
        credential = c.fetchone()
        if credential:
            c.execute('DELETE FROM credentials WHERE id = ?', (cred_id,))
            conn.commit()
            flash("Credential deleted successfully.", "success")
        else:
            flash("Unauthorized action.", "error")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
