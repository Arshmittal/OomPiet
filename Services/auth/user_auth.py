import os
from urllib.parse import urlencode
from flask import current_app, make_response, redirect, request, jsonify , session, url_for
from datetime import datetime, timedelta, timezone
import requests
from werkzeug.security import check_password_hash,generate_password_hash
from Utils.EmailSender import send_password_reset_email
from . import utils as AuthUtils

# These variables will be initialized from environment variables loaded in main.py
TENANT_ID = os.getenv("TID")  # Your Azure AD tenant ID
CLIENT_ID = os.getenv("CID")  # Your Azure AD client ID
CLIENT_SECRET = os.getenv("SID")  # Your Azure AD client secret

def handle_signup(users_collection , initialize_new_user_dashboard_stats_func):
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        first_name = data.get('firstName', '').strip()
        last_name = data.get('lastName', '').strip()
        birthdate = data.get('birthdate', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')

        # Validation
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required'}), 400

        # if not is_valid_email(email): 
        if not AuthUtils.is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'}),400

        # Check if user already exists
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return jsonify({'success': False, 'error': 'An account with this email already exists'}), 400

        # Hash password and create user (verified immediately since no OTP flow)
        hashed_password = generate_password_hash(password)
        user_data = {
            'email': email,
            'password': hashed_password,
            'name': f"{first_name} {last_name}",
            'surname': last_name,
            'birthdate': birthdate,
            'phone': phone,
            'picture': '/static/avatardefault.png',
            'auth_method': 'email',
            'created_at': datetime.now(timezone.utc),
            'last_login': datetime.now(timezone.utc),
            'verified': True
        }
        users_collection.insert_one(user_data)
        initialize_new_user_dashboard_stats_func(email)

        return jsonify({'success': True, 'message': 'Account created successfully! You can now sign in.'}), 200

    except Exception as e:
        current_app.logger.error(f"Error in signup: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during registration'}), 500
    




def handle_signin(users_collection):

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

        # Check if user already has an active session
        current_app.logger.info(f"Checking for active session for user: {email}")
        active_session = AuthUtils.get_active_session_info(email)
        current_app.logger.info(f"Active session found: {active_session is not None}")

        if active_session:
            current_app.logger.info(f"Session conflict detected for user: {email}")
            # Return session conflict information
            return jsonify({
                'success': False,
                'error': 'session_conflict',
                'message': 'This account is already active on another device. Do you want to continue and log out the other session?',
                'session_info': {
                    'user_agent': active_session['user_agent'],
                    'ip_address': active_session['ip_address'],
                    'last_activity': active_session['last_activity'].isoformat()
                }
            }), 409

        # If no session conflict, continue with successful login
        # Set session data
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user.get('name', ''),
            'picture': user.get('picture', '/static/default-profile.png'),
            'auth_method': user.get('auth_method', 'email'),
            'premium': user.get('premium', False)
        }
        session['session_id'] = AuthUtils.create_user_session(email)

        current_app.logger.info(f"Login successful for user: {email}")
        return jsonify({'success': True, 'message': 'Login successful', 'user': session['user']}), 200

    except Exception as e:
        current_app.logger.error(f"Signin error: {str(e)}")
        return jsonify({'success': False, 'error': f'An internal server error occurred: {str(e)}'}), 500
    

def handle_recover_password(users_collection,email):
    try:
        # Validation
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # if not is_valid_email(email):
        if not AuthUtils.is_valid_email(email):
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        

        print("Checking if user exists...")
        
        # Check if user exists and uses email authentication
        user = users_collection.find_one({'email': email})

        if not user:
            # Don't reveal if user exists or not for security
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        
        # Only allow password reset for email-authenticated users
        if user.get('auth_method') != 'email':
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        
        # Generate reset token
        reset_token = AuthUtils.create_password_reset_token(email) #create_password_reset_token(email)

        if not reset_token:
            return jsonify({'success': False, 'error': 'Failed to generate reset token'}), 500
        
        # Create reset link
        reset_link = url_for('reset_password_page', token=reset_token, _external=True)

        # Log the reset link being generated
        current_app.logger.info(f"Generated reset link: {reset_link}")
        
        # Send email using the new EmailSender package
        error_message = send_password_reset_email(email, reset_link)

        # Log what the email sender returned
        current_app.logger.info(f"Email sender returned: {error_message if error_message else 'SUCCESS'}")
        
        if error_message is None:
            current_app.logger.info(f"Password reset email sent to: {email}")
            return jsonify({'success': True, 'message': 'If an account with this email exists, you will receive a password reset link.'})
        else:
            current_app.logger.error(f"Failed to send password reset email: {error_message}")
            return jsonify({'success': False, 'error': 'Failed to send password reset email. Please try again later.'}), 500
          
        
    except Exception as e:
        current_app.logger.error(f"Error in forgot_password: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while processing your request'}), 500
    

def handle_upload_user(UPLOAD_USERS):
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    
    # Only allow the two hardcoded users
    user = next((u for u in UPLOAD_USERS if u['email'] == email), None)
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'success': False, 'error': 'Invalid email or password'}), 401
    
    # Set session for upload page
    session.permanent = True
    session['user'] = {
        'email': user['email'],
        'name': user['name'],
        'auth_method': 'upload_modal',
    }
    session['upload_access'] = True
    return jsonify({'success': True, 'user': session['user']})


def handle_login(users_collection):
    try:
        current_app.logger.info("Force login endpoint called")
        data = request.get_json()
        user_email = data.get('email')
        
        current_app.logger.info(f"Force login request for email: {user_email}")
        
        if not user_email:
            current_app.logger.error("Force login failed: Email is required")
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        # Remove existing session
        current_app.logger.info(f"Removing existing sessions for user: {user_email}")
        # remove_user_session(user_email)
        AuthUtils.remove_user_session(user_email)
        
        # Get user data
        user = users_collection.find_one({'email': user_email})
        if not user:
            current_app.logger.error(f"Force login failed: User not found for email: {user_email}")
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        current_app.logger.info(f"User found: {user.get('name', 'Unknown')}")
        
        # Create new session
        current_app.logger.info("Creating new session")
        session_id = AuthUtils.create_user_session(user_email) #create_user_session(user_email)
        
        # Set session
        session.permanent = True
        session['user'] = {
            'email': user['email'],
            'name': user['name'],
            'picture': user['picture'],
            'auth_method': user['auth_method'],
            'premium': user.get('premium', False)
        }
        session['session_id'] = session_id
        
        # Clear session conflict info
        session.pop('session_conflict', None)
        
        current_app.logger.info(f"Force login successful for user: {user_email}")
        return jsonify({
            'success': True,
            'user': session['user']
        })
        
    except Exception as e:
        current_app.logger.error(f"Error in force login: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred during force login'}), 500
    

def handle_feed_back(feedback_collection, dashboard_stats_collection):
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
            "timestamp": datetime.now(timezone.utc),
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
                "$set": {"last_active": datetime.now(timezone.utc)}
            }
        )
        
        return jsonify({"success": True, "message": "Feedback submitted successfully"})
        
    except Exception as e:
        current_app.logger.error(f"Error submitting feedback: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    

def handle_reset_password(users_collection):
    try:
        data = request.get_json()
        token = data.get('token', '')
        new_password = data.get('password', '')
        
        # Validation
        if not token or not new_password:
            return jsonify({'success': False, 'error': 'Token and password are required'}), 400
        
        if len(new_password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters long'}), 400
        
        # Validate token
        token_data = AuthUtils.validate_reset_token(token) #validate_reset_token(token)
        if not token_data:
            return jsonify({'success': False, 'error': 'Invalid or expired reset token'}), 400
        
        # Get user
        user = users_collection.find_one({'email': token_data['email']})
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Update password
        hashed_password = generate_password_hash(new_password)
        users_collection.update_one(
            {'_id': user['_id']},
            {'$set': {'password': hashed_password, 'last_login': datetime.now(timezone.utc)}}
        )
        
        # Mark token as used
        # mark_token_as_used(token)
        AuthUtils.mark_token_as_used(token)
        
        # Remove all active sessions for this user (force re-login)
        # remove_user_session(token_data['email'])
        AuthUtils.remove_user_session(token_data['email'])
        
        current_app.logger.info(f"Password reset successful for: {token_data['email']}")
        return jsonify({'success': True, 'message': 'Password reset successful! You can now sign in with your new password.'})
        
    except Exception as e:
        current_app.logger.error(f"Error in reset_password: {str(e)}")
        return jsonify({'success': False, 'error': 'An error occurred while resetting your password'}), 500
    


def handle_google_callback(google, users_collection, initialize_new_user_dashboard_stats):

    # Get redirect URL from query parameters
    redirect_url = session.get("redirect_url", "url_for('index')")
    
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

        # Check if user already has an active session
        active_session = AuthUtils.get_active_session_info(user_info["email"]) #get_active_session_info(user_info["email"])
        if active_session:
            # Store session conflict info in session for later handling
            session['session_conflict'] = {
                'user_email': user_info["email"],
                'session_info': {
                    'user_agent': active_session['user_agent'],
                    'ip_address': active_session['ip_address'],
                    'last_activity': active_session['last_activity'].isoformat()
                }
            }
            return redirect(url_for('session_conflict'))

        # Store user data in MongoDB
        user_data = {
            "name": user_info.get("name", "User"),
            "email": user_info["email"],
            "picture": user_info.get("picture", "/static/default-profile.png"),
            "last_login": datetime.now(timezone.utc),
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

        # Create new session
        session_id = AuthUtils.create_user_session(user_data["email"]) #create_user_session(user_data["email"])

        # Set session, include premium status if present
        session.permanent = True
        session['user'] = {
            'email': db_user['email'],
            'name': db_user['name'],
            'picture': db_user['picture'],
            'auth_method': db_user['auth_method'],
            'premium': db_user.get('premium', False)
        }
        session['session_id'] = session_id
        session.modified = True

        current_app.logger.info(f"Google login successful for user: {user_data['email']}")

        params = {
            "success" : "true",
            "email" : db_user["email"],
            "name" : db_user["name"]
        }

        # Redirect to frontend with success and user info
        return redirect(f"{redirect_url}?{urlencode(params)}")

    except Exception as e:
        current_app.logger.error(f"Error in Google callback: {str(e)}")
        session.clear()

        return redirect(f"{redirect_url}?error=auth_failed&message={str(e)}")
    
def handle_user_profile(users_collection, db):
    user = session.get('user')
    if not user:
        return jsonify({"error": "Not logged in"}), 401

    # Fetch the full user document from MongoDB
    db_user = users_collection.find_one({'email': user['email']})
    if not db_user:
        return jsonify({"error": "User not found"}), 404

    # Remove sensitive fields if needed
    db_user.pop('password', None)
    db_user['_id'] = str(db_user['_id'])

    # Add the real usage count to the user dict (if you use this)
    user_limits = db.user_limits.find_one({"user_id": user["email"]})
    usage_count = user_limits["sonnet_usage_count"] if user_limits and "sonnet_usage_count" in user_limits else 0
    db_user["sonnet_usage_count"] = usage_count

    # Always include subscription info for frontend
    db_user["payfast_subscription_id"] = db_user.get("payfast_subscription_id", None)
    db_user["subscription_status"] = "active" if db_user.get("payfast_subscription_id") else "none"
    db_user["subscription_plan"] = db_user.get("subscription_plan", None)
    db_user["premium"] = db_user.get("premium", False)

    return jsonify(db_user)


def handle_invalidate_session():
    try:
        user_email = session.get('user', {}).get('email')
        if user_email:
            # Remove the current session
            #remove_user_session(user_email)
            AuthUtils.remove_user_session(user_email)
        # Clear the session
        session.clear()
        return jsonify({'success': True, 'message': 'Session invalidated'})
        
    except Exception as e:
        current_app.logger.error(f"Error invalidating session: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to invalidate session'}), 500
    

def handle_unsubscription(users_collection, PAYFAST_SANDBOX):
    user = session.get('user')
    if not user:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401

    db_user = users_collection.find_one({'email': user['email']})
    pf_subscription_id = db_user.get('payfast_subscription_id')
    if not pf_subscription_id:
        return jsonify({'success': False, 'error': 'No active subscription'}), 400

    # Use sandbox or production URL based on environment
    if PAYFAST_SANDBOX:
        cancel_url = 'https://sandbox.payfast.co.za/eng/query/subscription/cancel'
    else:
        cancel_url = 'https://www.payfast.co.za/eng/query/subscription/cancel'
    
    payload = {
          'merchant_id': '25296103',
        'merchant_key': 'rbn0vhdzshrbi',
        'subscription_id': pf_subscription_id
    }
    response = requests.post(cancel_url, data=payload)
    if response.status_code == 200 and 'true' in response.text.lower():
        users_collection.update_one({'email': user['email']}, {'$unset': {'payfast_subscription_id': ""}})
        users_collection.update_one({'email': user['email']}, {'$set': {'premium': False}})
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to cancel subscription'}), 500
    