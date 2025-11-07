from datetime import timedelta, datetime, timezone
from functools import wraps
import hashlib
import os
import re
import secrets
import uuid
from pymongo import MongoClient
from flask import current_app, redirect, request, session, url_for
from flask_limiter.util import get_remote_address

GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY')  # Default for development
MONGO_URI = os.getenv('MONGO_URI')
PAYFAST_PASSPHRASE = os.getenv('PAYFAST_PASSPHRASE')
IS_SANDBOX = True

client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
db = client["geotech_db"]
users_collection = db["users"]
dashboard_stats_collection = db["dashboard_stats"]
feedback_collection = db["feedback"]  # Add new collection for feedback
sessions_collection = db["sessions"]  # New collection for session management
password_reset_collection = db["password_reset_tokens"]  # New collection for password reset tokens





def generate_session_token():
    """Generate a unique session token"""
    return str(uuid.uuid4())

def create_user_session(user_email, session_id=None):
    """Create a new session for a user"""
    if session_id is None:
        session_id = generate_session_token()
    
    #Remove any existing sessions for this user
    sessions_collection.delete_many({"user_email": user_email})
    
    # Create new session
    session_data = {
        "session_id": session_id,
        "user_email": user_email,
        "created_at": datetime.now(timezone.utc),
        "last_activity": datetime.now(timezone.utc),
        "user_agent": request.headers.get('User-Agent', ''),
        "ip_address": request.remote_addr
    }
    
    sessions_collection.insert_one(session_data)
    return session_id


def remove_user_session(user_email):
    """Remove all sessions for a user"""
    sessions_collection.delete_many({"user_email": user_email})

def get_active_session_info(user_email):
    """Get information about the active session for a user"""
    current_app.logger.info(f"Getting active session info for user: {user_email}")
    session_data = sessions_collection.find_one({"user_email": user_email})
    current_app.logger.info(f"Session data found: {session_data is not None}")
    
    if session_data:
        # Check if session is expired
        created_at = session_data["created_at"]
        if hasattr(created_at, 'tzinfo') and created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo = timezone.utc)

        if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
            current_app.logger.info(f"Session expired for user: {user_email}")
            sessions_collection.delete_one({"_id": session_data["_id"]})
            return None
            
        current_app.logger.info(f"Active session found for user: {user_email}")
        return {
            "session_id": session_data["session_id"],
            "created_at": session_data["created_at"],
            "last_activity": session_data["last_activity"],
            "user_agent": session_data["user_agent"],
            "ip_address": session_data["ip_address"]
        }
    
    current_app.logger.info(f"No active session found for user: {user_email}")
    return None


def validate_session(session_id, user_email):
    """Validate if a session is still active"""
    session_data = sessions_collection.find_one({
        "session_id": session_id,
        "user_email": user_email
    })
    
    if not session_data:
        return False
    
    # Check if session is expired (24 hours)
    created_at = session_data.get("created_at")
    if not created_at:
        return False

    # Debug: print what we got
    print(f"DEBUG: created_at type: {type(created_at)}, value: {created_at}")
    if isinstance(created_at, datetime):
        print(f"DEBUG: created_at.tzinfo: {created_at.tzinfo}")

    try:
        # If created_at is a string, parse it
        if isinstance(created_at, str):
            try:
                # Try ISO format first
                created_at = datetime.fromisoformat(created_at)
            except ValueError:
                # Fallback: try parsing with strptime
                for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"]:
                    try:
                        created_at = datetime.strptime(created_at, fmt)
                        break
                    except ValueError:
                        continue
    except (ValueError, AttributeError):
        return False
    
    # ALWAYS make timezone-aware if it's naive (no matter what happened above)
    if hasattr(created_at, 'tzinfo') and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
        print(f"DEBUG: Made timezone-aware: {created_at}")

    # Check last activity
    if datetime.now(timezone.utc) - created_at > timedelta(hours=24):
        sessions_collection.delete_one({"_id": session_data["_id"]})
        return False
    
    # Update last activity
    sessions_collection.update_one(
        {"_id": session_data["_id"]},
        {"$set": {"last_activity": datetime.now(timezone.utc)}}
    )
    
    return True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        
        # Validate session
        user_email = session['user'].get('email')
        session_id = session.get('session_id')
        
        if not user_email or not session_id:
            session.clear()
            return redirect(url_for('login'))
        
        if not validate_session(session_id, user_email):
            session.clear()
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function


def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Password Reset Token Management
def generate_reset_token():
    """Generate a secure random token for password reset"""
    return secrets.token_urlsafe(32)

def create_password_reset_token(email):
    """Create a password reset token for a user"""
    try:
        # Remove any existing tokens for this email
        password_reset_collection.delete_many({"email": email})
        
        # Generate new token
        token = generate_reset_token()
        
        # Create token record (expires in 1 hour)
        token_data = {
            "email": email,
            "token": token,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
            "used": False
        }
        
        password_reset_collection.insert_one(token_data)
        return token
        
    except Exception as e:
        current_app.logger.error(f"Error creating password reset token: {str(e)}")
        return None
    

def validate_reset_token(token):
    """Validate a password reset token"""
    try:
        token_data = password_reset_collection.find_one({
            "token": token,
            "used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)}
        })
        
        return token_data
        
    except Exception as e:
        current_app.logger.error(f"Error validating reset token: {str(e)}")
        return None
    


def mark_token_as_used(token):
    """Mark a password reset token as used"""
    try:
        password_reset_collection.update_one(
            {"token": token},
            {"$set": {"used": True, "used_at": datetime.now(timezone.utc)}}
        )
        return True
    except Exception as e:
        current_app.logger.error(f"Error marking token as used: {str(e)}")
        return False
    

def cleanup_expired_reset_tokens():
    """Clean up expired password reset tokens"""
    try:
        result = password_reset_collection.delete_many({
            "expires_at": {"$lt": datetime.now(timezone.utc)}
        })
        current_app.logger.info(f"Cleaned up {result.deleted_count} expired reset tokens")
    except Exception as e:
        current_app.logger.error(f"Error cleaning up expired reset tokens: {str(e)}")


def generate_payfast_signature(data, passphrase=''):
    # Step 1: Remove 'signature' and empty or 'no value' fields
    filtered_data = {
        k: v for k, v in data.items()
        if k != 'signature' and str(v).strip().lower() != 'no value' and str(v).strip() != ''
    }

    # Step 2: Sort alphabetically by keys
    sorted_items = sorted(filtered_data.items())

    # Step 3: Concatenate with raw values (no quote_plus)
    payload = "&".join([f"{k}={str(v)}" for k, v in sorted_items])

    # Step 4: Add passphrase if present
    if passphrase:
        payload += f"&passphrase={passphrase}"

    # Step 5: Return MD5 hash
    return hashlib.md5(payload.encode('utf-8')).hexdigest()


def verify_payfast_itn(data):
    try:
        received_signature = data.get('signature')
        passphrase = PAYFAST_PASSPHRASE if IS_SANDBOX else ''


        calculated_signature = generate_payfast_signature(data, passphrase)

        if received_signature != calculated_signature:
            current_app.logger.warning(f"Signature mismatch:\nReceived: {received_signature}\nExpected: {calculated_signature}")
            return False

        return True
    except Exception as e:
        current_app.logger.error(f"Error verifying PayFast ITN: {str(e)}")
        return False
    

def cleanup_expired_sessions():
    """Clean up expired sessions (older than 24 hours)"""
    try:
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
        result = sessions_collection.delete_many({
            "created_at": {"$lt": cutoff_time}
        })
        current_app.logger.info(f"Cleaned up {result.deleted_count} expired sessions")
        
        # Also cleanup expired reset tokens
        cleanup_expired_reset_tokens()

    except Exception as e:
        current_app.logger.error(f"Error cleaning up expired sessions: {str(e)}")


# Schedule cleanup task (run every hour)
def schedule_cleanup():
    """Schedule the cleanup task to run periodically"""
    import threading
    import time
    
    def cleanup_worker():
        while True:
            try:
                cleanup_expired_sessions()
                time.sleep(3600)  # Run every hour
            except Exception as e:
                # current_app.logger.error(f"Error in cleanup worker: {str(e)}")
                time.sleep(3600)  # Continue trying every hour
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()