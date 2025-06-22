from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import json
import time
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

DATA_FILE = 'users_data.json'
LOG_FILE = 'activity.log'

# Load or create user data storage
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        json.dump({"users": {}}, f)

def log_activity(activity):
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {activity}\n")

def contains_attack_payload(data):
    sqli = ["' OR", "--", "'#", "' OR '1'='1", '" OR "1"="1', "' OR 1=1", "\" OR 1=1"]
    xss = ["<script>", "</script>", "<img", "onerror=", "alert("]
    traversal = ["../", "..\\", "/etc/passwd", "system.ini", "WEB-INF"]
    injection = ["<!--#EXEC", "cmd=", "dir", "ls"]

    attack_patterns = sqli + xss + traversal + injection
    return any(p.lower() in data.lower() for p in attack_patterns)

def load_users():
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def save_users(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

# Create default admin user if not exists
users = load_users()
if "admin" not in users["users"]:
    users["users"]["admin"] = {
        "password_hash": generate_password_hash("admin123"),
        "details": {
            "name": "Admin User",
            "age": "30",
            "disease": "None",
            "blood_group": "O+",
            "contact": "1234567890",
            "address": "123 Admin Street"
        }
    }
    save_users(users)
    print("Default admin user created: username=admin, password=admin123")

# Brute-force protection
login_attempts = {}

def can_attempt_login(username):
    now = time.time()
    attempts = login_attempts.get(username, [])
    attempts = [t for t in attempts if now - t < 60]
    login_attempts[username] = attempts
    return len(attempts) < 3

def record_login_attempt(username):
    now = time.time()
    attempts = login_attempts.get(username, [])
    attempts.append(now)
    login_attempts[username] = attempts

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if contains_attack_payload(username) or contains_attack_payload(password):
            log_activity(f"🚨 Attack pattern detected in login - Username: {username}, Password: {password}")
            error = "Suspicious input detected!"
            return render_template('login.html', error=error)

        if not can_attempt_login(username):
            error = "Too many login attempts. Please wait a minute and try again."
            log_activity(f"Login blocked for {username} due to brute-force protection")
            return render_template('login.html', error=error)

        users = load_users()
        user = users['users'].get(username)

        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            log_activity(f"✅ User '{username}' logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(username)
            error = "Invalid password"
            log_activity(f"❌ Failed login attempt for '{username}'")

    return render_template('login.html', error=error)

@app.route('/signup1', methods=['GET', 'POST'])
def signup1():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if contains_attack_payload(username):
            log_activity(f"🚨 Attack pattern detected in signup - Username: {username}")
            error = "Suspicious username detected!"
            return render_template('signup1.html', error=error)

        users = load_users()
        if username in users['users']:
            error = "User already exists. Please login."
            log_activity(f"Signup attempt failed - username '{username}' exists")
            return render_template('signup1.html', error=error)

        session['signup_username'] = username
        session['signup_password'] = generate_password_hash(password)
        log_activity(f"Signup step 1 completed for '{username}'")
        return redirect(url_for('signup2'))

    return render_template('signup1.html', error=error)

@app.route('/signup2', methods=['GET', 'POST'])
def signup2():
    if 'signup_username' not in session or 'signup_password' not in session:
        return redirect(url_for('signup1'))

    error = None
    if request.method == 'POST':
        name = request.form['name'].strip()
        age = request.form['age'].strip()
        disease = request.form['disease'].strip()
        blood_group = request.form['blood_group'].strip()
        contact = request.form['contact'].strip()
        address = request.form['address'].strip()

        users = load_users()
        username = session['signup_username']
        password_hash = session['signup_password']

        users['users'][username] = {
            "password_hash": password_hash,
            "details": {
                "name": name,
                "age": age,
                "disease": disease,
                "blood_group": blood_group,
                "contact": contact,
                "address": address
            }
        }
        save_users(users)
        log_activity(f"New user '{username}' signed up with medical details")

        session.pop('signup_username', None)
        session.pop('signup_password', None)
        return redirect(url_for('welcome'))

    return render_template('signup2.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    users = load_users()
    user = users['users'].get(username)
    if not user:
        return redirect(url_for('login'))

    details = user['details']

    return render_template(
        'dashboard.html',
        patient_name=details.get('name', 'N/A'),
        patient_age=details.get('age', 'N/A'),
        patient_blood_group=details.get('blood_group', 'N/A'),
        patient_allergies=details.get('disease', 'N/A'),
        patient_medications='None',
        activity_log=[],
    )

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        log_activity(f"User '{username}' logged out")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
