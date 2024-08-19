import logging
import os
import random
import sqlite3
import time
import uuid
import requests
from yt_dlp import YoutubeDL
from datetime import datetime, timedelta
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from captcha_solver import CaptchaSolver
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from werkzeug.security import generate_password_hash, check_password_hash

# Configurable settings
DOWNLOAD_DIR = './downloads'
MAX_THREADS = 4
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    # Add more User-Agents
]
DB_FILE = 'downloads.db'
LOG_FILE = 'scraper.log'
CAPTCHA_API_KEY = '6Le6yykqAAAAAMC4bFpoR_sLS0dHoK1xK3uGfxc4'

# Setting up logging
logging.basicConfig(filename='scraper.log', level=logging.INFO)

# Initialize CAPTCHA solver
solver = CaptchaSolver('2captcha', api_key=CAPTCHA_API_KEY)

# Encryption key
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Initialize Flask app for web interface
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a strong secret key
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_login'


# Initialize the database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Create the downloads table if it doesn't exist
    cursor.execute('''CREATE TABLE IF NOT EXISTS downloads (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT NOT NULL,
                        status TEXT,
                        download_path TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )''')

    # Check if the users table exists
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    # If the 'users' table exists but doesn't have the 'email' column, add it
    if 'users' in columns:
        if 'email' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE NOT NULL")
        if 'reset_token' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        if 'reset_expires_at' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN reset_expires_at DATETIME")
    else:
        # Create the users table with the necessary columns
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            reset_token TEXT,
                            reset_expires_at DATETIME
                        )''')

    conn.commit()
    conn.close()

def download_file(url, download_dir):
    local_filename = os.path.join(download_dir, url.split('/')[-1])
    with requests.get(url, stream=True) as r:
        r.raise_for_status()
        with open(local_filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
    return local_filename


@app.route('/download', methods=['POST'])
@login_required
def download():
    download_url = request.form.get('download_url')
    if not download_url:
        flash("No download URL provided.", "error")
        return redirect(url_for('index'))

    try:
        file_path = download_file(download_url, DOWNLOAD_DIR)
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        flash(f"Failed to download file: {str(e)}", "error")
        return redirect(url_for('index'))

# Insert download record into database
def insert_download_record(url, status, download_path):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO downloads (url, status, download_path) VALUES (?, ?, ?)",
                   (url, status, download_path))
    conn.commit()
    conn.close()


# Step 1: Start a session and login with custom User-Agent
session = requests.Session()


def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

def fetch_information(url, search_query):
    if not is_valid_url(url):
        raise ValueError(f"Invalid URL: {url}")

    chrome_options = Options()
    # chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")
    # chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--no-sandbox")

    user_agent = random.choice(USER_AGENTS)
    chrome_options.add_argument(f'user-agent={user_agent}')

    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        time.sleep(random.uniform(3, 6))  # Random delay for page load

        soup = BeautifulSoup(driver.page_source, 'html.parser')
        driver.quit()

        results = []
        for element in soup.find_all(search_query):
            results.append(element.get_text(strip=True))

        logging.info(f'Found {len(results)} elements for query {search_query} on {url}.')
        return results

    except Exception as e:
        logging.error(f"Error fetching information from {url}: {str(e)}")
        return None


# Step 3: Handle user input for scraping via the web interface
@app.route('/scrape', methods=['GET', 'POST'])
@login_required
def scrape():
    if request.method == 'POST':
        url = request.form['url']
        search_query = request.form['search_query']
        results = fetch_information(url, search_query)
        return render_template('scrape_results.html', url=url, search_query=search_query, results=results)
    return render_template('scrape.html')


# Step 4: Flask web interface for managing downloads
class User(UserMixin):
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route('/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            user_obj = User(id=user[0])
            login_user(user_obj)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                           (username, email, hashed_password))
            conn.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('user_login'))
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                flash('Username already exists. Please choose a different username.')
            elif 'email' in str(e):
                flash('Email already exists. Please choose a different email.')
            else:
                flash('An error occurred during registration.')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if request.method == 'POST':
        email = request.form['email']

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            # Generate reset token
            reset_token = str(uuid.uuid4())
            reset_expires_at = datetime.utcnow() + timedelta(hours=1)  # Token valid for 1 hour

            cursor.execute(
                "UPDATE users SET reset_token = ?, reset_expires_at = ? WHERE id = ?",
                (reset_token, reset_expires_at, user[0])
            )
            conn.commit()

            # Send email with reset link
            reset_link = url_for('reset_token', token=reset_token, _external=True)
            # Here you would send the reset_link via email
            flash(f'Password reset link has been sent to {email}.')
        else:
            flash('Email address not found.')

        conn.close()

    return render_template('reset_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, reset_expires_at FROM users WHERE reset_token = ?",
        (token,)
    )
    user = cursor.fetchone()

    if not user or datetime.utcnow() > datetime.strptime(user[1], "%Y-%m-%d %H:%M:%S.%f"):
        flash('The reset link is invalid or has expired.')
        return redirect(url_for('reset_request'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=16)

        cursor.execute(
            "UPDATE users SET password = ?, reset_token = NULL, reset_expires_at = NULL WHERE id = ?",
            (hashed_password, user[0])
        )
        conn.commit()
        conn.close()

        flash('Your password has been updated.')
        return redirect(url_for('user_login'))

    conn.close()
    return render_template('reset_token.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('user_login'))

# Updated index route remains the same...
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    results = None
    url = None
    search_query = None

    if request.method == 'POST':
        url = request.form['url']
        search_query = request.form['search_query']

        try:
            results = fetch_information(url, search_query)
            if results is None:
                flash(f"Failed to scrape data from {url}. Please check the URL and try again.", "error")
        except ValueError as ve:
            flash(str(ve), "error")

    return render_template('index.html', url=url, search_query=search_query, results=results)

@app.route('/logs')
@login_required
def view_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            logs = f.read()
    else:
        logs = "No logs available."

    return render_template('logs.html', logs=logs)


# Main function to orchestrate the process
def main():
    init_db()
    # start_scheduler()  # Start the scheduled job for downloading videos
    app.run(use_reloader=False)  # Start Flask app


if __name__ == "__main__":
    main()
