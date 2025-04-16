#Vulnerable Flask Application 
from flask import Flask, request, render_template_string, redirect, url_for
import sqlite3
import pickle
import subprocess
import os

app = Flask(__name__)

# **VULNERABILITY 1: Hardcoded Secret Key**
app.secret_key = "supersecretkey123"  # Hardcoded secret (should use env vars)

# **VULNERABILITY 2: SQL Injection (No Parameterized Queries)**
@app.route('/search')
def search():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Direct string concatenation (SQL Injection risk)
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)  # Executes raw SQL without sanitization
    results = cursor.fetchall()
    conn.close()
    return str(results)

# **VULNERABILITY 3: Cross-Site Scripting (XSS)**
@app.route('/xss')
def xss_vulnerable():
    user_input = request.args.get('input', '')
    
    # Renders untrusted input directly (XSS risk)
    return render_template_string(f"<h1>Your input: {user_input}</h1>")

# **VULNERABILITY 4: Insecure Deserialization**
@app.route('/deserialize')
def insecure_deserialization():
    data = request.cookies.get('session_data')
    
    # Unpickles untrusted data (RCE risk)
    deserialized = pickle.loads(data.encode('latin1'))  # Dangerous!
    return f"Deserialized: {deserialized}"

# **VULNERABILITY 5: Command Injection**
@app.route('/ping')
def command_injection():
    host = request.args.get('host', '8.8.8.8')
    
    # Executes shell command unsafely (Command Injection risk)
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)  # Shell=True is dangerous
    return result.decode('utf-8')

# **VULNERABILITY 6: Insecure File Handling**
@app.route('/readfile')
def read_file():
    filename = request.args.get('file', 'example.txt')
    
    # Reads arbitrary files (Path Traversal risk)
    with open(filename, 'r') as f:  # No input validation
        content = f.read()
    return content

# **VULNERABILITY 7: Weak Password Hashing**
users = {
    "admin": "password123"  # Plaintext password (should be hashed)
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # No password hashing (Stored in plaintext)
        if users.get(username) == password:  #  Unsafe comparison
            return "Logged in!"
        else:
            return "Invalid credentials"
    return '''
        <form method="POST">
            <input type="text" name="username">
            <input type="password" name="password">
            <button type="submit">Login</button>
        </form>
    '''

#  **VULNERABILITY 8: Missing CSRF Protection**
@app.route('/transfer_money', methods=['POST'])
def transfer_money():
    amount = request.form['amount']
    to_account = request.form['to_account']
    
    #  No CSRF token (Prone to CSRF attacks)
    return f"Transferred ${amount} to {to_account}"

if __name__ == '__main__':
    app.run(debug=True)  #  Debug mode in production is dangerous



########################################################################################
#   Breakdown of Each Vulnerability

# 1. Hardcoded Secret Key
# app.secret_key = "supersecretkey123"
#  Solution: Generate a random secret key using a secure method (e.g., os.urandom

# 2. SQL Injection
# query = f"SELECT * FROM users WHERE username = '{username}'"
# Solution: Use parameterized SQL queries or an ORM (e.g., SQLAlchemy)

# 3.  Cross-Site Scripting (XSS)
# render_template_string(f"<h1>Your input: {user_input}</h1>")
# Use escape() from markupsafe or Jinja2 autoescaping.

# 4. Insecure Deserialization
# pickle.loads(data.encode('latin1'))
# Use JSON (json.loads) instead of pickle.

# 5. Command Injection
# subprocess.check_output(f"ping -c 1 {host}", shell=True)
# Use the subprocess module with the check_output function and avoid shell=True.
# Avoid shell=True and use subprocess.run(['ping', '-c', '1', host]).

# 6. Weak Password Hashing
# users = {"admin": "password123"}
# Use a secure password hashing library (e.g., bcrypt, Argon2, PBKDF
# Use bcrypt.hashpw(password, bcrypt.gensalt()).

