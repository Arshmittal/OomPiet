from datetime import timezone,timedelta,datetime
from bson import ObjectId
from flask import Flask, render_template, jsonify, redirect, request, url_for, session, send_from_directory, flash
from authlib.integrations.flask_client import OAuth
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash
import json
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Load environment variables
load_dotenv()
#Auth Utils
from Services.auth import utils as AuthUtils
from Services.auth.utils import login_required
from Services.auth import user_auth as UserAuth
from Services.payments import payment_auth as PayAuth

# Configuration
API_URL = os.getenv('API_URL')
API_KEY = os.getenv('API_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY')  # Default for development
MONGO_URI = os.getenv('MONGO_URI')
MODE = os.getenv('MODE', 'development')

# PayFast Configuration
PAYFAST_MERCHANT_ID = os.getenv('PAYFAST_MERCHANT_ID')
PAYFAST_MERCHANT_KEY = os.getenv('PAYFAST_MERCHANT_KEY')
PAYFAST_PASSPHRASE = os.getenv('PAYFAST_PASSPHRASE', '')
PAYFAST_SANDBOX = os.getenv('PAYFAST_SANDBOX', 'true').lower() == 'true'

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
feedback_collection = db["feedback"]  # Add new collection for feedback
sessions_collection = db["sessions"]  # New collection for session management
password_reset_collection = db["password_reset_tokens"]  # New collection for password reset tokens

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

SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SMTP_USERNAME = os.getenv('SMTP_USERNAME')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USERNAME)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)

app.json_encoder = JSONEncoder

# Start cleanup scheduler
# schedule_cleanup()
AuthUtils.schedule_cleanup() 


def _content_security_policy():

    return (
        "default-src 'self'; "
        "script-src 'self' https://accounts.google.com https://www.gstatic.com https://www.googleapis.com 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://accounts.google.com https://www.googleapis.com https://oompiet.space/rag; "
        "frame-src https://accounts.google.com;"
    )

@app.after_request
def add_security_headers(response):
    # Prevent MIME type sniffing
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    # Prevent clickjacking
    response.headers.setdefault('X-Frame-Options', 'DENY')
    # Referrer policy
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    # XSS protection (legacy, still useful for some older user agents)
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')
    # Permissions policy — disable sensitive features by default
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    # Content Security Policy
    response.headers.setdefault('Content-Security-Policy', _content_security_policy())

    # HSTS only in production (requires HTTPS)
    if MODE == 'production':
        response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
        # Ensure cookies marked secure in production
        app.config['SESSION_COOKIE_SECURE'] = True

    return response 

# --- Hardcoded upload page users ---
UPLOAD_USERS = [
    {
        'email': 'david@intailings.com',
        'password_hash': generate_password_hash('1234david'),
        'name': 'User One',
    },
    {
        'email': 'finely@intailings.com',
        'password_hash': generate_password_hash('1234david'),
        'name': 'User Two',
    },
]


limiter = Limiter(
    app=app,
    key_func = get_remote_address,
)

@app.route('/upload-login', methods=['POST'])
def upload_login():
    return UserAuth.upload_user(UPLOAD_USERS)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detail')
def detail():
    return render_template('detail.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')



def initialize_new_user_dashboard_stats(email):
    stats = {
        "user_email": email,
        "total_chats": 0,
        "total_messages": 0,
        "last_active": datetime.now(timezone.utc),
        "created_at": datetime.now(timezone.utc)
    }
    dashboard_stats_collection.insert_one(stats)
    return stats

"""I will remove this function once we have a dedicated Util func"""
def get_login_identifier():
    ip = get_remote_address()
    if request.method == "POST":
        username = request.form.get("username", "no-username")
        return f"{ip}:{username}"
    return ip

# --- Modified Signup Endpoint ---
@app.route('/api/signup', methods=['POST'])
@limiter.limit("3 per minute",  key_func= get_login_identifier,error_message="Too many signup's. Please wait a moment and try again.")
@limiter.limit("3 per minute",  key_func= get_remote_address)
def signup():
    return UserAuth.handle_signup(users_collection, initialize_new_user_dashboard_stats)



@app.route('/api/signin', methods=['POST'])
@limiter.limit("5 per minute",  key_func= get_login_identifier, error_message="Too many login attempts. Please wait a moment and try again.")
@limiter.limit("10 per minute",  key_func= get_remote_address, error_message="Too many login attempts. Please wait a moment and try again.")
def signin():
    return UserAuth.handle_signin(users_collection)




# Password Reset Endpoints
@app.route('/api/forgot-password', methods=['POST'])
@limiter.limit("5 per hour", key_func=get_login_identifier, error_message="Too many attempts. Please wait a moment and try again.")
@limiter.limit("5 per hour", key_func=get_remote_address)
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    return UserAuth.handle_recover_password(users_collection,email)


@app.route('/reset-password/<token>')
def reset_password_page(token):
    """Display password reset form"""
    # Validate token
    token_data = AuthUtils.validate_reset_token(token) #validate_reset_token(token)
    if not token_data:
        return render_template('reset_password.html', error="Invalid or expired reset link")
    
    return render_template('reset_password.html', token=token, email=token_data['email'])


@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("5 per hour", key_func=get_remote_address, error_message="Changed password too many times. Please wait a moment and try again.")
def reset_password():
    return UserAuth.handle_reset_password(users_collection)


@app.route('/login')
# @limiter.limit("5 per minute")
def login():
    session.clear()

    # Fetching the stored redirect_url in the session
    session['redirect_url'] = url_for("index")

    session['oauth_state'] = os.urandom(16).hex()
    session.modified = True
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(
        redirect_uri=redirect_uri,
        state=session['oauth_state']
    )

@app.route('/google/callback')
def google_callback():
    return UserAuth.handle_google_callback(google,users_collection,initialize_new_user_dashboard_stats)

@app.route('/check-login-status')
def check_login_status():
    user = session.get('user')
    if user:
        return jsonify({'loggedIn': True})
    return jsonify({'loggedIn': False})

@app.route('/api/user-profile')
def user_profile():
    return UserAuth.handle_user_profile(users_collection, db)

@app.route('/check-upload-access')
def check_upload_access():
    if session.get('upload_access'):
        return jsonify({'uploadAccess': True})
    return jsonify({'uploadAccess': False})

@app.route('/logout', methods=['POST'])
def logout():
    user_email = session.get('user', {}).get('email')
    if user_email:
        #remove_user_session(user_email)
        AuthUtils.remove_user_session(user_email)
    session.pop('upload_access', None)
    session.clear()
    return jsonify({"success": True})

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/chat_water')
@login_required
def chat_water():
    return render_template('chat_water.html')

@app.route('/chat_concrete')
@login_required
def chat_concrete():
    return render_template('chat_concrete.html')

@app.route('/chat_electrical')
@login_required
def chat_electrical():
    return render_template('chat_electrical.html')

@app.route('/chat_mining')
@login_required
def chat_mining():
    return render_template('chat_mining.html')

@app.route('/upload')
@login_required
def upload():
    return render_template('upload.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/feedback', methods=['POST', 'OPTIONS'])
@login_required
def submit_feedback():
    return UserAuth.handle_feed_back(feedback_collection, dashboard_stats_collection)

@app.route('/api/invalidate-session', methods=['POST'])
def invalidate_session():
    """Invalidate current session (called when user logs in from another device)"""
    return UserAuth.handle_invalidate_session()

@app.route('/session-conflict')
def session_conflict():
    """Handle session conflicts by showing a page to the user"""
    conflict_info = session.get('session_conflict')
    if not conflict_info:
        return redirect(url_for('index'))
    
    return render_template('session_conflict.html', conflict_info=conflict_info)

@app.route('/api/force-login', methods=['POST'])
def force_login():
    """Force login by logging out the previous session"""
    return UserAuth.handle_login(users_collection)

# Serve the home page HTML file
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# For development - serve our single HTML file
@app.route('/index.html')
def serve_html():
    return render_template('index.html')

@app.route('/pay')
@login_required
@limiter.limit("5 per hour", key_func=get_remote_address)
def pay():
    return PayAuth.payment_op()

@app.route('/pay/success')
@login_required
def pay_success():
    return PayAuth.payment_successful(users_collection)

@app.route('/pay/cancel')
@login_required
def pay_cancel():
    flash('Payment cancelled.', 'warning')
    return redirect(url_for('chat'))

@app.route('/pay/notify', methods=['POST'])
def pay_notify():
    return PayAuth.payment_notification(users_collection, PAYFAST_SANDBOX, PAYFAST_PASSPHRASE)

@app.route('/unsubscribe', methods=['POST'])
@login_required
def unsubscribe():
    return UserAuth.handle_unsubscription(users_collection, PAYFAST_SANDBOX)


if __name__ == '__main__':
    # Create static folder if it doesn't exist
    
    app.run(host='0.0.0.0', port=5000)