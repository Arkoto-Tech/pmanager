from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import base64
import psycopg2
from psycopg2.extras import DictCursor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Retrieve DATABASE_URL from environment variable
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Ensure you have it in your environment variables.")

def get_db_connection():
    """Establish a connection to PostgreSQL."""
    try:
        return psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor)
    except psycopg2.OperationalError as e:
        print("Database connection failed:", e)
        return None

def init_db():
    """Initialize database tables."""
    conn = get_db_connection()
    if conn is None:
        print("Database connection failed. Cannot initialize database.")
        return

    with conn:
        with conn.cursor() as c:
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
    conn.close()

# Run DB initialization
init_db()

# Constant salt for key derivation
SALT = b'some_constant_salt'

def derive_key(master_password):
    """Derive a 32-byte encryption key from the master password."""
    password_bytes = master_password.encode()
    kdf_instance = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf_instance.derive(password_bytes))

def get_fernet():
    """Return a Fernet instance using the master password stored in session."""
    master_password = session.get('master_password')
    if not master_password:
        return None
    return Fernet(derive_key(master_password))

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user_id' in session else url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_password']
        confirm_password = request.form['confirm_password']

        if master_password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template('signup.html')

        password_hash = generate_password_hash(master_password, method='pbkdf2:sha512')
        
        conn = get_db_connection()
        if conn:
            try:
                with conn:
                    with conn.cursor() as c:
                        c.execute('INSERT INTO users (username, password_hash) VALUES (%s, %s)',
                                  (username, password_hash))
                flash("Account created successfully! Please log in.", "success")
                return redirect(url_for('login'))
            except psycopg2.IntegrityError:
                flash("Username already exists. Please choose another.", "error")
        conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        master_password = request.form['master_password']
        
        conn = get_db_connection()
        if conn:
            with conn:
                with conn.cursor() as c:
                    c.execute('SELECT id, password_hash FROM users WHERE username = %s', (username,))
                    user = c.fetchone()
        conn.close()
        
@app.route('/delete_credential/<int:cred_id>', methods=['POST'])
def delete_credential(cred_id):
    # Your logic to delete the credential
    pass

        if user and check_password_hash(user['password_hash'], master_password):
            session['user_id'] = user['id']
            session['username'] = username
            session['master_password'] = master_password
            return redirect(url_for('dashboard'))
        flash("Incorrect username or password", "error")
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    fernet = get_fernet()
    user_id = session['user_id']

    if request.method == 'POST':
        website = request.form['website']
        site_username = request.form['site_username']
        site_password = request.form['site_password']
        encrypted_password = fernet.encrypt(site_password.encode()).decode()

        conn = get_db_connection()
        with conn:
            with conn.cursor() as c:
                c.execute('''
                    INSERT INTO credentials (user_id, website, site_username, site_password)
                    VALUES (%s, %s, %s, %s)
                ''', (user_id, website, site_username, encrypted_password))
        conn.close()
        flash("Credential added successfully!", "success")
    
    conn = get_db_connection()
    with conn:
        with conn.cursor() as c:
            c.execute('SELECT id, website, site_username, site_password FROM credentials WHERE user_id = %s', (user_id,))
            credentials = [{
                'id': row['id'],
                'website': row['website'],
                'site_username': row['site_username'],
                'site_password': fernet.decrypt(row['site_password'].encode()).decode()
            } for row in c.fetchall()]
    conn.close()
    return render_template('dashboard.html', credentials=credentials, username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
