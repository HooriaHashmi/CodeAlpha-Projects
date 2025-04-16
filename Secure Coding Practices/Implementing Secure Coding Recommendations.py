# Implementing Secure Coding Recommendations in Python
# 1. Preventing Injection Attacks

# Before (Vulnerable):
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# After (Secure):
# Using DB-API parameterization
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# For SQLAlchemy
from sqlalchemy import text
db.session.execute(text("SELECT * FROM users WHERE username = :username"), 
                  {"username": username})

# Command Injection Protection
import subprocess

# Vulnerable
subprocess.call(f"ping {user_input}", shell=True)

# Secure
subprocess.call(["ping", user_input])  # No shell=True

#Cross-Site Scripting (XSS) Protection
from flask import escape
from markupsafe import Markup

# Vulnerable
return f"<div>{user_content}</div>"

# Secure
return f"<div>{escape(user_content)}</div>"

# When you need to render safe HTML
safe_content = Markup("<strong>Trusted content</strong>")

#Secure Authentication Implementation
# Install: pip install bcrypt
import bcrypt

# Hashing
password = b"super secret password"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

# Verifying
if bcrypt.checkpw(password, hashed):
    print("Password match")

# Secure File Handling
from werkzeug.utils import secure_filename
import os

UPLOAD_FOLDER = '/path/to/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return "File uploaded successfully"
    
    return "Invalid file type", 400

# Dependency Security
# Install safety
pip install safety

# Scan your environment
safety check

# Scan requirements file
safety check -r requirements.txt

# For continuous monitoring
pip install pip-audit
pip-audit

