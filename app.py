import os
import logging
import secrets
import time
from flask import Flask, render_template, request, redirect, session, abort
from html import escape
from dotenv import load_dotenv

# --- Load environment ---
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(16))

# --- Logging ---
logging.basicConfig(filename='log.txt', level=logging.INFO, format='%(asctime)s %(message)s')

# --- Simple rate limiting store ---
rate_limit_store = {}

def is_rate_limited(ip):
    current_time = time.time()
    if ip not in rate_limit_store:
        rate_limit_store[ip] = current_time
        return False
    elif current_time - rate_limit_store[ip] < 20:  # 20 seconds cooldown
        return True
    else:
        rate_limit_store[ip] = current_time
        return False

# --- CSRF token logic ---
def generate_csrf_token():
    token = secrets.token_urlsafe(16)
    session['csrf_token'] = token
    return token

def verify_csrf(token):
    return token == session.get('csrf_token')

# --- Routes ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/joinus')
def joinus():
    csrf_token = generate_csrf_token()
    return render_template('joinus.html', csrf_token=csrf_token)

@app.route('/contact')
def contact():
    csrf_token = generate_csrf_token()
    return render_template('contact.html', csrf_token=csrf_token)

@app.route('/submit-join', methods=['POST'])
def submit_join():
    if not verify_csrf(request.form.get('csrf_token')):
        abort(403)

    ip = request.remote_addr
    if is_rate_limited(ip):
        return "Too many requests. Try again later.", 429

    name = escape(request.form.get('name', '').strip())
    email = escape(request.form.get('email', '').strip())
    role = escape(request.form.get('role', '').strip())
    message = escape(request.form.get('message', '').strip())

    with open("submissions.txt", "a") as f:
        f.write(f"[JOIN] {name} | {email} | {role} | {message}\n")

    logging.info(f"[JOIN] {name} | {email} | {role}")
    return redirect('/joinus')

@app.route('/submit-contact', methods=['POST'])
def submit_contact():
    if not verify_csrf(request.form.get('csrf_token')):
        abort(403)

    ip = request.remote_addr
    if is_rate_limited(ip):
        return "Too many requests. Try again later.", 429

    name = escape(request.form.get('name', '').strip())
    email = escape(request.form.get('email', '').strip())
    message = escape(request.form.get('message', '').strip())

    with open("submissions.txt", "a") as f:
        f.write(f"[CONTACT] {name} | {email} | {message}\n")

    logging.info(f"[CONTACT] {name} | {email}")
    return redirect('/contact')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

