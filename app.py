from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Allow frontend to call this API

# Database connection configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'postgres-service'),
    'port': os.environ.get('DB_PORT', '5432'),
    'database': os.environ.get('DB_NAME', 'userdb'),
    'user': os.environ.get('DB_USER', 'dbuser'),
    'password': os.environ.get('DB_PASSWORD', 'dbpass123')
}

def get_db_connection():
    """Create database connection"""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        return None

def hash_password(password):
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'service': 'user-management-backend'
    }), 200

@app.route('/api/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        # Validate input
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({'error': 'All fields are required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        # Hash password
        password_hash = hash_password(password)
        
        # Insert into database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        
        try:
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s) RETURNING id",
                (username, email, password_hash)
            )
            user_id = cur.fetchone()[0]
            conn.commit()
            
            return jsonify({
                'message': 'User registered successfully!',
                'user_id': user_id,
                'username': username
            }), 201
            
        except psycopg2.IntegrityError as e:
            conn.rollback()
            if 'username' in str(e):
                return jsonify({'error': 'Username already exists'}), 409
            elif 'email' in str(e):
                return jsonify({'error': 'Email already exists'}), 409
            else:
                return jsonify({'error': 'Registration failed'}), 400
        finally:
            cur.close()
            conn.close()
            
    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Login user"""
    try:
        data = request.get_json()
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        # Hash password to compare
        password_hash = hash_password(password)
        
        # Query database
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, email, created_at FROM users WHERE username = %s AND password_hash = %s",
            (username, password_hash)
        )
        
        user = cur.fetchone()
        cur.close()
        conn.close()
        
        if user:
            return jsonify({
                'message': 'Login successful!',
                'user': {
                    'id': user[0],
                    'username': user[1],
                    'email': user[2],
                    'created_at': user[3].isoformat() if user[3] else None
                }
            }), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
            
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users (for testing - remove in production!)"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500
        
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, created_at FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
        cur.close()
        conn.close()
        
        users_list = [
            {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'created_at': user[3].isoformat() if user[3] else None
            }
            for user in users
        ]
        
        return jsonify({'users': users_list}), 200
        
    except Exception as e:
        print(f"Get users error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Run on port 5000, accessible from any network interface
    app.run(host='0.0.0.0', port=5000, debug=True)