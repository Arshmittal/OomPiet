import re
from bson import ObjectId
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_from_directory, make_response
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
from werkzeug.utils import secure_filename
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.embeddings import HuggingFaceEmbeddings
from qdrant_client import QdrantClient
from qdrant_client.http.models import Distance, VectorParams
from langchain_community.vectorstores import Qdrant

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

# Qdrant Configuration
QDRANT_URL = os.getenv('QDRANT_URL', 'https://53d84a77-d8a0-4d6f-8439-512188cbe4d7.eu-west-1-0.aws.cloud.qdrant.io')
QDRANT_API_KEY = os.getenv('QDRANT_API_KEY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3MiOiJtIn0.hc1_ug3Px_WZH1tmNrd1K4MBUmjMuIybVIVolQBHy9U')
COLLECTION_NAME = os.getenv('COLLECTION_NAME', 'dify_docs')

# File Upload Configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size

app = Flask(__name__, static_folder='static')
CORS(app)
app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = MODE == 'production'  # True in production
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

app.logger.setLevel(logging.INFO)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# MongoDB Setup
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client["geotech_db"]
users_collection = db["users"]
dashboard_stats_collection = db["dashboard_stats"]
feedback_collection = db["feedback"]
documents_collection = db["documents"]  # Collection for uploaded documents

# Qdrant Setup
qdrant_client = QdrantClient(
    url=QDRANT_URL,
    api_key=QDRANT_API_KEY,
    timeout=60.0
)

# Create uploads directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_pdf_for_qdrant(file_path, user_email):
    """Process a PDF file and upload its content to Qdrant"""
    try:
        # Load and split the PDF
        loader = PyPDFLoader(file_path)
        pages = loader.load_and_split()
        
        # Add user metadata to each page
        for page in pages:
            page.metadata['uploaded_by'] = user_email
            page.metadata['upload_date'] = datetime.utcnow().isoformat()
            page.metadata['source_file'] = os.path.basename(file_path)
        
        # Initialize embedding model
        embedding_model = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        
        # Upload to Qdrant
        Qdrant.from_documents(
            documents=pages,
            embedding=embedding_model,
            url=QDRANT_URL,
            api_key=QDRANT_API_KEY,
            collection_name=COLLECTION_NAME
        )
        
        return True, len(pages)
    except Exception as e:
        app.logger.error(f"Error processing PDF for Qdrant: {str(e)}")
        return False, str(e)

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

        # Set session
        session.permanent = True
        session['user'] = user_data
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

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/upload')
@login_required
def upload_page():
    return render_template('upload.html')

@app.route('/upload-documents', methods=['POST'])
@login_required
def upload_documents():
    try:
        user = session.get('user')
        if not user:
            return jsonify({"success": False, "error": "User not authenticated"}), 401
        
        # Check if files were uploaded
        if 'files[]' not in request.files and 'files' not in request.files:
            return jsonify({"success": False, "error": "No files uploaded"}), 400
        
        # Get files from request
        files = request.files.getlist('files[]') if 'files[]' in request.files else request.files.getlist('files')
        
        if not files or len(files) == 0 or files[0].filename == '':
            return jsonify({"success": False, "error": "No files selected"}), 400
        
        uploaded_files = []
        
        for file in files:
            if file and allowed_file(file.filename):
                # Secure the filename
                filename = secure_filename(file.filename)
                
                # Create a unique filename with timestamp
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                unique_filename = f"{timestamp}_{filename}"
                
                # Save file to upload folder
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                # Process file for Qdrant
                success, result = process_pdf_for_qdrant(file_path, user.get('email'))
                
                # Store document info in MongoDB
                doc_info = {
                    "original_filename": filename,
                    "stored_filename": unique_filename,
                    "file_path": file_path,
                    "file_size": os.path.getsize(file_path),
                    "upload_date": datetime.utcnow(),
                    "uploaded_by": user.get('email'),
                    "processed_status": "success" if success else "failed",
                    "pages_processed": result if success else 0,
                    "error_message": "" if success else result
                }
                
                documents_collection.insert_one(doc_info)
                
                uploaded_files.append({
                    "filename": filename,
                    "status": "success" if success else "failed",
                    "message": f"Processed {result} pages" if success else f"Error: {result}"
                })
            else:
                uploaded_files.append({
                    "filename": file.filename if file else "Unknown",
                    "status": "failed",
                    "message": "Invalid file type. Only PDF files are allowed."
                })
        
        # Update dashboard stats
        dashboard_stats_collection.update_one(
            {"user_email": user.get('email')},
            {
                "$inc": {"total_documents": len([f for f in uploaded_files if f["status"] == "success"])},
                "$set": {"last_active": datetime.utcnow()}
            }
        )
        
        return jsonify({
            "success": True,
            "message": f"Successfully processed {len([f for f in uploaded_files if f['status'] == 'success'])} out of {len(files)} files",
            "files": uploaded_files
        })
        
    except Exception as e:
        app.logger.error(f"Error uploading documents: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500

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

if __name__ == '__main__':
    # Create static folder if it doesn't exist
    
    app.run(host='0.0.0.0', port=5000)