# Mentormate — README

Short guide to run and understand the project. See the main app in [main.py](main.py).

## Quick start

1. Create a `.env` with required variables (see list below) or copy from `.env` if present.
2. Install dependencies:

```sh
pip install -r requirements.txt
python main.py
```

### Required environment variables
(Referenced in main.py)

- API_URL, API_KEY
- GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
- SECRET_KEY
- MONGO_URI
- PAYFAST_MERCHANT_ID, PAYFAST_MERCHANT_KEY, PAYFAST_PASSPHRASE, PAYFAST_SANDBOX
- SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM
- MODE (optional, defaults to development)

### Key files
- main.py — Flask app and routes.
- Services/auth/utils.py — auth helpers, decorators, schedule cleanup.
- Services/auth/user_auth.py — sign-up / sign-in / password reset / session handling.
- Services/payments/payment_auth.py — PayFast integration.
- templates/ — HTML templates used by routes.
- static/ — static assets.

### API: endpoints, expected input and typical responses

Notes:

All JSON responses follow { "success": bool, ... } when implemented.

Protected endpoints require a valid session (login_required).

`GET /`
```
Purpose: render index page
Input: none
Response: HTML page (200)
```

`GET /detail`
```
Input: none
Response: HTML page (200)
```

`GET /terms`
```

Input: none
Response: HTML page (200)
```
`POST /upload-login`
```json
Input (JSON): { "email": string, "password": string }
Behavior: checks against hardcoded UPLOAD_USERS
Success (200): { "success": true, "user": { "email": "...", "name": "..." } }
Failure (401): { "success": false, "error": "Invalid email or password" }
```
`POST /api/signup`

```json
Input (JSON): { "email": string, "password": string, ...optional fields }
Behavior: create user in users collection, initialize dashboard stats
Success (200): { "success": true, "message": "Account created successfully!" }
Failure (400/409): { "success": false, "error": "..." }
```

`POST /api/signin`
```json
Input (JSON): { "email": string, "password": string }
Behavior: authenticate, set session
Success (200): { "success": true, "user": { "email": "...", "name": "...", ... } }
Failure (401): { "success": false, "error": "Invalid email or password" }
```

`POST /api/forgot-password`
```json
Input (JSON): { "email": string }
Behavior: create reset token, send email (if configured)
Success (200): { "success": true, "message": "If account exists, reset link sent" }
Failure (400/500): { "success": false, "error": "..." }
```

`GET /reset-password/<token>`
```
Input: URL param token
Behavior: validate token
Success (200): renders reset_password.html with token and email
Failure: renders reset_password.html with error message
```
`POST /api/reset-password`
```json
Input (JSON): { "token": string, "password": string }
Behavior: validate token and update password
Success (200): { "success": true, "message": "Password updated" }
Failure (400/401): { "success": false, "error": "Invalid or expired token" }
```
`GET /login`

```json
Purpose: start Google OAuth flow
Input: none
Response: redirect to Google OAuth endpoint
```
`GET /google/callback`
```

Input: OAuth callback query params (code, state)
Behavior: complete OAuth, create or fetch user, set session
Response: redirect to app page or session conflict flow
```

`GET /check-login-status`
```

Input: none (uses session)
Response: { "loggedIn": true } or { "loggedIn": false }
```
`GET /api/user-profile`
```json
Input: none (requires session)
Response (200): JSON user profile (no password), example: { "success": true, "user": { "email": "...", "name": "...", "premium": bool, ... } }
Failure (401): { "success": false, "error": "Not authenticated" }
```

`GET /check-upload-access`
```
Input: none
Response: { "uploadAccess": true } or { "uploadAccess": false }
```

`POST /logout`
```
Input: none (uses session)
Behavior: remove user session, clear session
Response (200): { "success": true }
```
# Protected pages (require login_required)

`GET /chat`, `/chat_water`, `/chat_concrete`, `/chat_electrical`, `/chat_mining`, `/upload`, `/dashboard`
```
Input: none
Response: HTML page (200) or redirect to login when unauthorized
```
`POST /api/feedback (POST, OPTIONS)`
```json
Input (JSON): { "message_id": string, "content": string, "is_positive": bool, "query": string }
Behavior: save feedback, update dashboard stats
Success (200): { "success": true, "feedback_id": "<id>" }
Failure (400/500): { "success": false, "error": "..." }
```

`POST /api/invalidate-session`

```json
Input: (implementation-specific; likely uses session or JSON with session id)
Behavior: invalidate current or specified session
Response: { "success": true } or { "success": false, "error": "..." }
```

`GET /session-conflict`
```
Input: none (reads session['session_conflict'])
Behavior: shows conflict page if a conflict exists
Response: HTML or redirect to /
```

`POST /api/force-login`
```json
Input (JSON): { "email": string } or relies on session state
Behavior: force-login (invalidate other sessions, keep this one)
Success (200): { "success": true }
Failure (400/404): { "success": false, "error": "..." }
```

`GET /static/path:path`

- Serves static files from static/ folder

## Payments

`GET /pay (protected)`
```
Behavior: start payment flow or render payment page
Response: HTML or redirect
```

`GET /pay/success (protected)`
```
Behavior: mark subscription/premium, redirect to chat
Response: redirect/HTML
```

`GET /pay/cancel (protected)`
```
Behavior: flash cancellation, redirect to chat
Response: redirect
```

`POST /pay/notify`
```
Input: PayFast ITN POST form data (signature + payment fields)
Behavior: verify payload, record payment, update subscription
Success (200): plain 200 OK
Failure (400): invalid signature or invalid payload
```

`POST /unsubscribe (protected)`
```json
Input: none or JSON depending on implementation
Behavior: cancel subscription via PayFast, update user record
Response: { "success": true } or error JSON
```
# Data & serialization
MongoDB collections used: users, dashboard_stats, feedback, sessions, password_reset_tokens.
main.py sets a custom JSON encoder to serialize ObjectId (to string) and datetimes (ISO).

Notes and troubleshooting

If you see ImportError related to bson: ensure you have pymongo installed and remove the standalone bson package. Install with:

```sh
pip uninstall bson
pip install pymongo
```

Configure SMTP and PayFast credentials in .env for email and payment flows.
For production, set MODE=production and provide a secure SECRET_KEY.

