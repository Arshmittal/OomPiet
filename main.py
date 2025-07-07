import re
from bson import ObjectId
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, make_response, flash
from authlib.integrations.flask_client import OAuth
import os
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timedelta
from werkzeug.middleware.proxy_fix import ProxyFix
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import json
from flask_cors import CORS
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlencode
import requests

# Load environment variables
load_dotenv()

# Configuration
API_URL = os.getenv('API_URL')
API_KEY = os.getenv('API_KEY')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')  # Default for development
MONGO_URI = os.getenv('MONGO_URI')
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
feedback_collection = db["feedback"]  # Add new collection for feedback

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

# Helper: Verify PayFast ITN signature

def verify_payfast_itn(data):
    # Remove signature field
    data_for_sig = {k: v for k, v in data.items() if k != 'signature'}
    # Sort by key, urlencode
    pf_data = urlencode(sorted(data_for_sig.items()))
    # Post back to PayFast for validation
    response = requests.post('https://sandbox.payfast.co.za/eng/query/validate', data=pf_data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
    if response.text.strip() == 'VALID':
        return True
    return False

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

        # Set session, include premium status if present
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user['name'],
            'picture': user['picture'],
            'auth_method': user['auth_method'],
            'premium': user.get('premium', False)
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
            "last_login": datetime.utcnow(),
            "auth_method": "google"  # Add auth method
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

        # Fetch the full user record (including premium status)
        db_user = users_collection.find_one({"email": user_data["email"]})

        # Set session, include premium status if present
        session.permanent = True
        session['user'] = {
            'email': db_user['email'],
            'name': db_user['name'],
            'picture': db_user['picture'],
            'auth_method': db_user['auth_method'],
            'premium': db_user.get('premium', False)
        }
        session.modified = True  # Ensure session is saved

        app.logger.info(f"Google login successful for user: {user_data['email']}")
        return redirect(url_for('index'))

    except Exception as e:
        app.logger.error(f"Error in Google callback: {str(e)}")
        session.clear()
        return redirect(url_for('index'))

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

@app.route('/chat_water')
@login_required
def chat_water():
    return render_template('chat_water.html')

@app.route('/chat_concrete')
@login_required
def chat_concrete():
    return render_template('chat_concrete.html')

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
    # Handle preflight request
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response

    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        user = session.get('user')
        if not user:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        feedback_data = {
            "message_id": data.get('message_id'),
            "content": data.get('content'),
            "query" :data.get('query', '').strip(),  # Add query field with empty string as default
            "is_positive": data.get('is_positive'),
            "user_email": user.get('email'),
            "timestamp": datetime.utcnow(),
            "user_agent": request.headers.get('User-Agent')
        }
        
        # Validate required fields
        if not all(key in feedback_data for key in ['message_id', 'content', 'is_positive', 'query']):
            return jsonify({"success": False, "error": "Missing required fields"}), 400
        
        # Insert feedback into MongoDB
        feedback_collection.insert_one(feedback_data)
        
        # Update dashboard stats
        dashboard_stats_collection.update_one(
            {"user_email": user.get('email')},
            {
                "$inc": {"total_feedback": 1},
                "$set": {"last_active": datetime.utcnow()}
            }
        )
        
        return jsonify({"success": True, "message": "Feedback submitted successfully"})
        
    except Exception as e:
        app.logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

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
def pay():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    
    # Get plan and amount from query parameters
    plan = request.args.get('plan', 'monthly')
    amount = request.args.get('amount', '149.00')
    
    # Set item name based on plan
    if plan == 'annual':
        item_name = 'Premium Plan - Annual Subscription'
    else:
        item_name = 'Premium Plan - Monthly Subscription'
    
    # Create PayFast data
    payfast_data = {
        'merchant_id': '25296103',
        'merchant_key': 'rbn0vhdzshrbi',
        'amount': amount,
        'item_name': item_name,
        'name_first': user.get('name', ''),
        'email_address': user.get('email', ''),
        'return_url': url_for('pay_success', _external=True),
        'cancel_url': url_for('pay_cancel', _external=True),
        'notify_url': url_for('pay_notify', _external=True),
        'custom_str1': user.get('email', ''),
        'custom_str2': plan  # Store the plan type for reference
    }
    return render_template('payfast_form.html', payfast=payfast_data)

@app.route('/pay/success')
@login_required
def pay_success():
    user = session.get('user')
    if not user:
        return redirect(url_for('login'))
    
    # Get plan from query parameters (in case it was passed back from PayFast)
    plan = request.args.get('plan', 'monthly')
    
    # Calculate subscription end date
    if plan == 'annual':
        subscription_end = datetime.utcnow() + timedelta(days=365)
        plan_display = "annual"
    else:
        subscription_end = datetime.utcnow() + timedelta(days=30)
        plan_display = "monthly"
    
    # Mark user as premium in DB with subscription details
    users_collection.update_one(
        {'email': user['email']}, 
        {'$set': {
            'premium': True,
            'subscription_plan': plan,
            'subscription_start': datetime.utcnow(),
            'subscription_end': subscription_end
        }}
    )
    
    # Update session
    session['user']['premium'] = True
    session['user']['subscription_plan'] = plan
    
    # Show appropriate success message
    if plan == 'annual':
        flash('Payment successful! You are now a premium user with an annual subscription.', 'success')
    else:
        flash('Payment successful! You are now a premium user with a monthly subscription.', 'success')
    
    return redirect(url_for('chat'))

@app.route('/pay/cancel')
@login_required
def pay_cancel():
    flash('Payment cancelled.', 'warning')
    return redirect(url_for('chat'))

@app.route('/pay/notify', methods=['POST'])
def pay_notify():
    data = request.form.to_dict()
    app.logger.info(f"PayFast ITN received: {data}")
    # Verify signature
    if not verify_payfast_itn(data):
        app.logger.warning("Invalid PayFast ITN signature!")
        return 'Invalid signature', 400
    
    if data.get('payment_status') == 'COMPLETE' and data.get('custom_str1'):
        email = data.get('custom_str1')
        plan = data.get('custom_str2', 'monthly')
        
        # Calculate subscription end date
        if plan == 'annual':
            # Annual subscription - 1 year from now
            subscription_end = datetime.utcnow() + timedelta(days=365)
        else:
            # Monthly subscription - 1 month from now
            subscription_end = datetime.utcnow() + timedelta(days=30)
        
        # Update user record with premium status, plan type, and subscription end date
        users_collection.update_one(
            {'email': email}, 
            {'$set': {
                'premium': True,
                'subscription_plan': plan,
                'subscription_start': datetime.utcnow(),
                'subscription_end': subscription_end,
                'payment_amount': data.get('amount', '0.00')
            }}
        )
        
        app.logger.info(f"User {email} upgraded to premium with {plan} plan")
    
    return 'OK', 200

if __name__ == '__main__':
    # Create static folder if it doesn't exist
    
    app.run(host='0.0.0.0', port=5000)