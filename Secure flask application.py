from flask import Flask, request, redirect, url_for, render_template
from flask_login import LoginManager, UserMixin, login_user
from flask_talisman import Talisman
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os
import bcrypt

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    UPLOAD_FOLDER='/secure/uploads',
    ALLOWED_EXTENSIONS={'txt', 'pdf', 'png'},
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Security headers
Talisman(
    app,
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", 'https://cdn.example.com'],
        'style-src': ["'self'", "'unsafe-inline'"]
    }
)

# Authentication setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user = User()
    user.id = user_id
    return user

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password').encode('utf-8')
        
        # Authenticate user (example - replace with real DB lookup)
        stored_hash = get_user_password_hash(username)  # Implement this
        if stored_hash and bcrypt.checkpw(password, stored_hash):
            user = User()
            user.id = username
            login_user(user)
            return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return "File uploaded successfully"
    
    return "Invalid file type", 400

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # For development only