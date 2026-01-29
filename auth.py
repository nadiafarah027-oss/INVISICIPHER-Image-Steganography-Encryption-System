"""
InvisiCipher Authentication System
Handles user registration, login, and session management
"""

from flask import Blueprint, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import os
import json
from functools import wraps

# Create auth blueprint
auth_bp = Blueprint('auth', __name__)

# Configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'invisichipher-secret-key-change-in-production')
TOKEN_EXPIRATION_HOURS = 24

# Simple file-based user storage (in production, use a real database)
USERS_FILE = 'users.json'

def init_users_file():
    """Initialize users file if it doesn't exist"""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)

def load_users():
    """Load users from file"""
    init_users_file()
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    """Save users to file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def generate_token(user_id, email):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorator to require valid token for routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Get token from header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        # Verify token
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        # Add user info to request
        request.user = payload
        
        return f(*args, **kwargs)
    
    return decorated


@auth_bp.route('/signup', methods=['POST'])
def signup():
    """
    Register a new user
    Expects: username, email, password
    Returns: success message or error
    """
    try:
        data = request.get_json()
        
        # Validate input
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        
        # Validate email format (basic)
        if '@' not in email or '.' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Load existing users
        users = load_users()
        
        # Check if user already exists
        if email in users:
            return jsonify({'error': 'Email already registered'}), 400
        
        for user in users.values():
            if user['username'].lower() == username.lower():
                return jsonify({'error': 'Username already taken'}), 400
        
        # Create new user
        user_id = str(len(users) + 1)
        users[email] = {
            'id': user_id,
            'username': username,
            'email': email,
            'password': generate_password_hash(password),
            'created_at': datetime.datetime.utcnow().isoformat(),
            'last_login': None
        }
        
        # Save users
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': 'Account created successfully',
            'user': {
                'id': user_id,
                'username': username,
                'email': email
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': f'Signup failed: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login user
    Expects: email (or username), password, remember (optional)
    Returns: JWT token and user info
    """
    try:
        data = request.get_json()
        
        # Get credentials
        identifier = data.get('email', '').strip().lower()  # Can be email or username
        password = data.get('password', '')
        remember = data.get('remember', False)
        
        if not identifier or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Load users
        users = load_users()
        
        # Find user by email or username
        user = None
        user_email = None
        
        # Check if identifier is email
        if identifier in users:
            user = users[identifier]
            user_email = identifier
        else:
            # Check if identifier is username
            for email, u in users.items():
                if u['username'].lower() == identifier:
                    user = u
                    user_email = email
                    break
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Verify password
        if not check_password_hash(user['password'], password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Update last login
        user['last_login'] = datetime.datetime.utcnow().isoformat()
        users[user_email] = user
        save_users(users)
        
        # Generate token
        token = generate_token(user['id'], user_email)
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user_email
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500


@auth_bp.route('/verify', methods=['GET'])
@token_required
def verify():
    """
    Verify if token is valid
    Returns: user info
    """
    try:
        user_id = request.user['user_id']
        email = request.user['email']
        
        # Load users
        users = load_users()
        
        if email not in users:
            return jsonify({'error': 'User not found'}), 404
        
        user = users[email]
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': email
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Verification failed: {str(e)}'}), 500


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout():
    """
    Logout user (client should delete token)
    """
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    }), 200


@auth_bp.route('/change-password', methods=['POST'])
@token_required
def change_password():
    """
    Change user password
    Expects: old_password, new_password
    """
    try:
        data = request.get_json()
        
        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')
        
        if not old_password or not new_password:
            return jsonify({'error': 'Old and new passwords are required'}), 400
        
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters'}), 400
        
        # Get user
        email = request.user['email']
        users = load_users()
        
        if email not in users:
            return jsonify({'error': 'User not found'}), 404
        
        user = users[email]
        
        # Verify old password
        if not check_password_hash(user['password'], old_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Update password
        user['password'] = generate_password_hash(new_password)
        users[email] = user
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': 'Password changed successfully'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Password change failed: {str(e)}'}), 500


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """
    Request password reset
    Expects: email
    """
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Load users
        users = load_users()
        
        if email not in users:
            # Don't reveal if email exists or not
            return jsonify({
                'success': True,
                'message': 'If the email exists, a reset link has been sent'
            }), 200
        
        # In production, send actual email with reset token
        # For now, just return success
        
        return jsonify({
            'success': True,
            'message': 'Password reset link sent to your email'
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Reset failed: {str(e)}'}), 500


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """
    Get user profile
    Returns: user info
    """
    try:
        email = request.user['email']
        users = load_users()
        
        if email not in users:
            return jsonify({'error': 'User not found'}), 404
        
        user = users[email]
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': email,
                'created_at': user['created_at'],
                'last_login': user['last_login']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Failed to get profile: {str(e)}'}), 500


@auth_bp.route('/update-profile', methods=['PUT'])
@token_required
def update_profile():
    """
    Update user profile
    Expects: username (optional)
    """
    try:
        data = request.get_json()
        new_username = data.get('username', '').strip()
        
        if not new_username:
            return jsonify({'error': 'Username is required'}), 400
        
        if len(new_username) < 3:
            return jsonify({'error': 'Username must be at least 3 characters'}), 400
        
        email = request.user['email']
        users = load_users()
        
        if email not in users:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if username is taken
        for user_email, user in users.items():
            if user_email != email and user['username'].lower() == new_username.lower():
                return jsonify({'error': 'Username already taken'}), 400
        
        # Update username
        users[email]['username'] = new_username
        save_users(users)
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': {
                'id': users[email]['id'],
                'username': new_username,
                'email': email
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': f'Profile update failed: {str(e)}'}), 500