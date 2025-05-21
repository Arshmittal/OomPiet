import re
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory
from authlib.integrations.flask_client import OAuth
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timedelta
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId
import json
from flask_cors import CORS

# Load environment variables
load_dotenv()

# Configuration
API_URL = os.getenv('API_URL')
API_KEY = os.getenv('API_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Default for development
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
MODE = os.getenv('MODE', 'development')

app = Flask(__name__, static_folder='static')
CORS(app)
app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = MODE == 'production'  # True in production

app.logger.setLevel(logging.INFO)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# MongoDB Setup
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client["geotech_db"]
users_collection = db["users"]
dashboard_stats_collection = db["dashboard_stats"]

# Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }
)

# JSON Encoder for ObjectId
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

app.json_encoder = JSONEncoder

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize user dashboard stats
def initialize_new_user_dashboard_stats(email):
    stats = {
        "user_email": email,
        "total_chats": 0,
        "total_messages": 0,
        "last_active": datetime.utcnow(),
        "created_at": datetime.utcnow()
    }
    dashboard_stats_collection.insert_one(stats)
    return stats

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        if not is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'}), 400

        # Check if user already exists
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return jsonify({'success': False, 'error': 'An account with this email already exists'}), 400

        # Hash password and create user
        hashed_password = generate_password_hash(password)
        
        user_data = {
            'email': email,
            'password': hashed_password,
            'name': email.split('@')[0].title(),  # Use email prefix as name
            'picture': '/static/default-profile.png',
            'auth_method': 'email',
            'created_at': datetime.utcnow(),
            'last_login': datetime.utcnow()
        }

        result = users_collection.insert_one(user_data)
        
        # Initialize dashboard stats for new user
        initialize_new_user_dashboard_stats(email)

        app.logger.info(f"New user registered: {email}")
        return jsonify({'success': True, 'message': 'Account created successfully'})

    except Exception as e:
        app.logger.error(f"Error in signup: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during registration'}), 500

@app.route('/api/signin', methods=['POST'])
def signin():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # Find user
        user = users_collection.find_one({'email': email})
        if not user:
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Check if user signed up with email/password (not Google)
        if user.get('auth_method') != 'email':
            return jsonify({'success': False, 'error': 'Please sign in with Google'}), 401

        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'success': False, 'error': 'Invalid email or password'}), 401

        # Update last login
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'last_login': datetime.utcnow()}}
        )

        # Set session
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user['name'],
            'picture': user['picture'],
            'auth_method': user['auth_method']
        }

        app.logger.info(f"User signed in: {email}")
        return jsonify({
            'success': True,
            'user': session['user']
        })

    except Exception as e:
        app.logger.error(f"Error in signin: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during sign in'}), 500



@app.route('/login')
def login():
    session.clear()
    session['oauth_state'] = os.urandom(16).hex()
    session.modified = True
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(
        redirect_uri=redirect_uri,
        state=session['oauth_state']
    )

@app.route('/google/callback')
def google_callback():
    try:
        state = request.args.get('state')
        stored_state = session.get('oauth_state')

        if not state or not stored_state or state != stored_state:
            raise ValueError("State verification failed")
        
        session.pop('oauth_state', None)

        token = google.authorize_access_token()
        if not token:
            raise ValueError("Failed to get access token")

        # Get user info from Google
        resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo', token=token)
        user_info = resp.json()
        
        if not user_info or 'email' not in user_info:
            raise ValueError("Failed to get user info")

        # Store user data in MongoDB
        user_data = {
            "name": user_info.get("name", "User"),
            "email": user_info["email"],
            "picture": user_info.get("picture", "/static/default-profile.png"),
            "last_login": datetime.utcnow()
        }

        # Update user or create if doesn't exist
        result = users_collection.update_one(
            {"email": user_data["email"]},
            {"$set": user_data},
            upsert=True
        )

        # Initialize dashboard stats for new users
        if result.upserted_id:
            initialize_new_user_dashboard_stats(user_data["email"])

        # Set session
        session.permanent = True
        session['user'] = user_data

        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error in Google callback: {str(e)}")
        session.clear()
        return render_template('error.html', error="Authentication failed. Please try again.")

@app.route('/check-login-status')
def check_login_status():
    user = session.get('user')
    if user:
        return jsonify({'loggedIn': True})
    return jsonify({'loggedIn': False})

@app.route('/api/user-profile')
def user_profile():
    user = session.get('user')
    if user:
        return jsonify(user)
    return jsonify({"error": "Not logged in"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Serve the home page HTML file
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# For development - serve our single HTML file
@app.route('/index.html')
def serve_html():
    return render_template('index.html')

if __name__ == '__main__':
    # Create static folder if it doesn't exist
    if not os.path.exists('static'):
        os.makedirs('static')
    
  
    
    # Development server
    debug_mode = MODE == 'development'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)