from flask import Flask, jsonify, request, render_template, send_file, session, redirect, url_for
import qrcode
import sqlite3
from PIL import Image, ImageDraw, ImageFont
import os
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from io import BytesIO
import base64
import zipfile
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend to prevent GUI crashes
import matplotlib.pyplot as plt
import hashlib
import datetime
import pytz
import jwt
import secrets
import bcrypt
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# SQLite database configuration
DATABASE = 'funfair.db'

# Set up logging
logging.basicConfig(level=logging.INFO)

# Security configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    # Generate a secure key if not provided
    SECRET_KEY = secrets.token_hex(32)
    logging.warning("SECRET_KEY not set in environment. Generated temporary key. Set SECRET_KEY in .env for production!")

app.secret_key = SECRET_KEY

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Secure session configuration
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
if os.environ.get('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True

def get_db_connection():
    """Get SQLite database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_table_if_not_exists():
    """Create all necessary database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create visitors table
    create_visitors_table_query = '''
    CREATE TABLE IF NOT EXISTS visitors (
        ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        amount REAL,
        balance REAL,
        qr_code TEXT,
        issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        pin TEXT
    );
    '''

    # Create topup_transactions table
    create_topup_transactions_table_query = '''
    CREATE TABLE IF NOT EXISTS topup_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        amount REAL NOT NULL,
        pin TEXT,
        type TEXT CHECK(type IN ('Issue', 'Top up')) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''

    # Create payments table
    create_payments_table_query = '''
    CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        staff TEXT,
        customer TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''

    # Create access_keys table
    create_access_keys_table_query = '''
    CREATE TABLE IF NOT EXISTS access_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        counter TEXT,
        pass_key TEXT NOT NULL,
        passkey_display TEXT
    );
    '''

    # Create admins table with enhanced security fields
    create_admins_table_query = '''
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,
        last_login TIMESTAMP,
        created_by TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''


    # Create audit_logs table
    create_audit_logs_table_query = '''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_type TEXT NOT NULL,
        user_id TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''

    try:
        cursor.execute(create_visitors_table_query)
        cursor.execute(create_topup_transactions_table_query)
        cursor.execute(create_payments_table_query)
        cursor.execute(create_access_keys_table_query)
        cursor.execute(create_admins_table_query)
        cursor.execute(create_audit_logs_table_query)
        conn.commit()
        logging.info("Database tables created successfully")
        
        # Migrate access_keys table to add passkey_display column if needed
        try:
            cursor.execute("ALTER TABLE access_keys ADD COLUMN passkey_display TEXT")
            conn.commit()
            logging.info("Added passkey_display column to access_keys table")
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass
        
        # Migrate existing admins table if needed
        try:
            cursor.execute("PRAGMA table_info(admins)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'failed_login_attempts' not in columns:
                cursor.execute("ALTER TABLE admins ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
            if 'locked_until' not in columns:
                cursor.execute("ALTER TABLE admins ADD COLUMN locked_until TIMESTAMP")
            if 'last_login' not in columns:
                cursor.execute("ALTER TABLE admins ADD COLUMN last_login TIMESTAMP")
            if 'created_by' not in columns:
                cursor.execute("ALTER TABLE admins ADD COLUMN created_by TEXT")
            if 'is_active' not in columns:
                cursor.execute("ALTER TABLE admins ADD COLUMN is_active INTEGER DEFAULT 1")
            conn.commit()
        except sqlite3.Error:
            pass  # Table might not exist yet
        
        # Drop Generate_qr table if it exists (no longer needed)
        try:
            cursor.execute("DROP TABLE IF EXISTS Generate_qr")
            conn.commit()
        except sqlite3.Error:
            pass
            
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
    finally:
        cursor.close()
        conn.close()

def apply_schema_upgrades():
    """Apply lightweight schema upgrades for existing SQLite DBs."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        conn.commit()
    except sqlite3.Error as err:
        logging.error(f"Schema upgrade error: {err}")
    finally:
        cursor.close()
        conn.close()

# Password security functions
def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12)).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against a hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False

def validate_password_strength(password, is_super_admin=False):
    """Validate password strength requirements"""
    min_length = 12 if is_super_admin else 8
    
    if len(password) < min_length:
        return False, f"Password must be at least {min_length} characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    # Additional requirements for super admin
    if is_super_admin:
        if len(password) < 12:
            return False, "Super admin password must be at least 12 characters long"
        # Require at least 2 special characters for super admin
        special_chars = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password))
        if special_chars < 2:
            return False, "Super admin password must contain at least 2 special characters"
        # Require at least 2 numbers for super admin
        numbers = len(re.findall(r'[0-9]', password))
        if numbers < 2:
            return False, "Super admin password must contain at least 2 numbers"
    
    return True, "Password is valid"

def generate_secure_password(length=16):
    """Generate a secure random password"""
    import string
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(length))
    return password

def issue_coupon(full_name, amount, admin_username):
    """Issue a new QR code coupon for a visitor"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the user already exists
    cursor.execute("SELECT * FROM visitors WHERE full_name = ?", (full_name,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        raise ValueError("User already exists. Coupon not issued. Please try a different name.")

    # Insert coupon details into the database (store admin_username in pin field for tracking)
    cursor.execute(
        "INSERT INTO visitors (full_name, amount, balance, qr_code, pin) VALUES (?, ?, ?, ?, ?)",
        (full_name, amount, amount, "", admin_username)
    )
    ticket_id = cursor.lastrowid

    # Generate QR code URL for authenticator
    qr_code_url = f"http://localhost:5001/authenticator?ticket_id={ticket_id}"

    # Generate QR code for the coupon with the URL
    qr = qrcode.make(qr_code_url)
    qr_img = qr.convert("RGB")
    qr_width, qr_height = qr_img.size

    # Create a new image with extra space for text
    new_img_height = qr_height + 140
    new_img = Image.new('RGB', (qr_width, new_img_height), (255, 255, 255))

    # Paste the QR code onto the new image
    new_img.paste(qr_img, (0, 110))

    # Create a drawing object to add text to the new image
    draw = ImageDraw.Draw(new_img)

    # Draw "Funfair 2025" at the top
    funfair_text = "Funfair 2025"
    funfair_position = ((qr_width - draw.textbbox((0, 0), funfair_text, font=ImageFont.load_default())[2]) // 2, 5)
    draw.text(funfair_position, funfair_text, font=ImageFont.load_default(), fill=(0, 0, 0))

    # Draw "Coupon" below "Funfair 2025"
    coupon_text = "Coupon"
    coupon_position = ((qr_width - draw.textbbox((0, 0), coupon_text, font=ImageFont.load_default())[2]) // 2, 30)
    draw.text(coupon_position, coupon_text, font=ImageFont.load_default(), fill=(0, 0, 0))

    # Draw the full name below "Coupon"
    name_bbox = draw.textbbox((0, 0), full_name, font=ImageFont.load_default())
    name_position = ((qr_width - (name_bbox[2] - name_bbox[0])) // 2, 50)
    draw.text(name_position, full_name, font=ImageFont.load_default(), fill=(0, 0, 0))

    # Draw the ticket ID below the name
    ticket_id_text = f"Ticket ID: {ticket_id}"
    ticket_bbox = draw.textbbox((0, 0), ticket_id_text, font=ImageFont.load_default())
    ticket_position = ((qr_width - (ticket_bbox[2] - ticket_bbox[0])) // 2, 70)
    draw.text(ticket_position, ticket_id_text, font=ImageFont.load_default(), fill=(0, 0, 0))

    # Save QR code image to a BytesIO buffer
    buffered = BytesIO()
    new_img.save(buffered, format="PNG")
    qr_img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    # Update the database with the generated QR code image string
    cursor.execute("UPDATE visitors SET qr_code = ? WHERE ticket_id = ?", (qr_img_str, ticket_id))

    # Insert into topup_transactions table for issued coupon (store admin_username in pin field for tracking)
    cursor.execute("INSERT INTO topup_transactions (full_name, amount, type, pin) VALUES (?, ?, 'Issue', ?)", (full_name, amount, admin_username))
    conn.commit()

    cursor.close()
    conn.close()

    return qr_img_str, ticket_id

# Helper functions
def log_activity(user_type, user_id, action, details="", ip_address=None):
    """Log system activity with enhanced details for super admin actions"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Enhanced logging for super admin actions
    if user_type == 'super_admin':
        # Add timestamp and additional context
        timestamp = datetime.datetime.utcnow().isoformat()
        enhanced_details = f"[{timestamp}] {details}"
        if not ip_address:
            ip_address = request.remote_addr
    else:
        enhanced_details = details
        if not ip_address:
            ip_address = request.remote_addr
    
    cursor.execute(
        "INSERT INTO audit_logs (user_type, user_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_type, user_id, action, enhanced_details, ip_address)
    )
    conn.commit()
    cursor.close()
    conn.close()

def require_admin_auth(f):
    """Decorator to require admin authentication - Session-less security"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Only check Authorization header, ignore session for maximum security
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({"error": "Admin authentication required"}), 401
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            username = payload.get('username')
            role = payload.get('role')
            
            # Verify role is admin or super_admin
            if role not in ['admin', 'super_admin']:
                return jsonify({"error": "Admin access required"}), 403
            
            # Verify user exists in database and is active
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id, is_active, locked_until FROM admins WHERE username = ?", (username,))
                user = cursor.fetchone()
                
                if not user:
                    return jsonify({"error": "User not found"}), 403
                
                if user['is_active'] != 1:
                    return jsonify({"error": "Account is disabled"}), 403
                
                # Check if account is locked
                if user['locked_until']:
                    locked_until = datetime.datetime.fromisoformat(user['locked_until'])
                    if datetime.datetime.utcnow() < locked_until:
                        return jsonify({"error": "Account is locked"}), 403
                
            finally:
                cursor.close()
                conn.close()
                
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            logging.error(f"Auth error: {e}")
            return jsonify({"error": "Authentication error"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def require_super_admin_auth(f):
    """Decorator to require super admin authentication"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({"error": "Super admin authentication required"}), 401
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            if payload.get('role') != 'super_admin':
                return jsonify({"error": "Super admin access required"}), 403
            
            username = payload.get('username')
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT id, is_active, locked_until FROM admins WHERE username = ? AND role = 'super_admin'", (username,))
                user = cursor.fetchone()
                
                if not user:
                    return jsonify({"error": "Super admin not found"}), 403
                
                if user['is_active'] != 1:
                    return jsonify({"error": "Account is disabled"}), 403
                
                if user['locked_until']:
                    locked_until = datetime.datetime.fromisoformat(user['locked_until'])
                    if datetime.datetime.utcnow() < locked_until:
                        return jsonify({"error": "Account is locked"}), 403
                        
            finally:
                cursor.close()
                conn.close()
                
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception as e:
            logging.error(f"Super admin auth error: {e}")
            return jsonify({"error": "Authentication error"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def require_admin_page_auth(f):
    """Decorator to require admin authentication for page routes (redirects to login) - Session-less security"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # For page routes, we'll let the frontend handle token validation
        # This allows the page to load and then redirect via JavaScript if no token
        return f(*args, **kwargs)
    return decorated_function

# Admin login route
@app.route('/admin_login', methods=['POST'])
@limiter.limit("10 per 15 minutes")
def admin_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Check if user exists
            cursor.execute("SELECT id, password_hash, role, is_active, failed_login_attempts, locked_until FROM admins WHERE username = ?", (username,))
            user = cursor.fetchone()
            
            if not user:
                # Don't reveal if username exists
                log_activity('admin', username, 'login_failed', 'Failed login attempt - user not found')
                return jsonify({"error": "Invalid credentials"}), 401
            
            # Check if account is active
            if user['is_active'] != 1:
                log_activity('admin', username, 'login_failed', 'Failed login attempt - account disabled')
                return jsonify({"error": "Account is disabled"}), 403
            
            # Check if account is locked
            if user['locked_until']:
                locked_until = datetime.datetime.fromisoformat(user['locked_until'])
                if datetime.datetime.utcnow() < locked_until:
                    remaining = (locked_until - datetime.datetime.utcnow()).total_seconds() / 60
                    log_activity('admin', username, 'login_failed', f'Failed login attempt - account locked for {remaining:.0f} more minutes')
                    return jsonify({"error": f"Account is locked. Try again in {int(remaining)} minutes."}), 403
                else:
                    # Lock expired, reset it
                    cursor.execute("UPDATE admins SET locked_until = NULL, failed_login_attempts = 0 WHERE username = ?", (username,))
                    conn.commit()
            
            # Verify password
            if not verify_password(password, user['password_hash']):
                # Increment failed attempts
                failed_attempts = (user['failed_login_attempts'] or 0) + 1
                locked_until = None
                
                # Lock account after 5 failed attempts
                # Longer lockout for super admin (60 minutes) vs regular admin (30 minutes)
                lockout_minutes = 60 if user['role'] == 'super_admin' else 30
                if failed_attempts >= 5:
                    locked_until = (datetime.datetime.utcnow() + datetime.timedelta(minutes=lockout_minutes)).isoformat()
                    cursor.execute("UPDATE admins SET failed_login_attempts = ?, locked_until = ? WHERE username = ?", 
                                 (failed_attempts, locked_until, username))
                    if user['role'] == 'super_admin':
                        log_activity('super_admin', username, 'account_locked', 
                                   f'Super admin account locked after {failed_attempts} failed attempts from IP: {request.remote_addr}')
                    else:
                        log_activity('admin', username, 'account_locked', f'Account locked after {failed_attempts} failed attempts')
                    conn.commit()
                    return jsonify({"error": f"Account locked due to too many failed attempts. Try again in {lockout_minutes} minutes."}), 403
                else:
                    cursor.execute("UPDATE admins SET failed_login_attempts = ? WHERE username = ?", (failed_attempts, username))
                
                conn.commit()
                log_activity('admin', username, 'login_failed', f'Failed login attempt ({failed_attempts}/5)')
                return jsonify({"error": "Invalid credentials"}), 401
            
            # Successful login - reset failed attempts and update last_login
            cursor.execute("UPDATE admins SET failed_login_attempts = 0, locked_until = NULL, last_login = ? WHERE username = ?", 
                         (datetime.datetime.utcnow().isoformat(), username))
            conn.commit()
            
            # Create JWT token with role from database
            # Shorter expiration for super admin (30 minutes) vs regular admin (1 hour)
            expiration_hours = 0.5 if user['role'] == 'super_admin' else 1.0
            token = jwt.encode({
                'username': username,
                'user_id': user['id'],
                'role': user['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=expiration_hours)
            }, SECRET_KEY, algorithm='HS256')
            
            session['admin_token'] = token
            
            # Enhanced logging for super admin logins
            if user['role'] == 'super_admin':
                log_activity('super_admin', username, 'login', 
                           f'Successful super admin login from IP: {request.remote_addr}')
            else:
                log_activity('admin', username, 'login', 'Successful admin login')
            
            return jsonify({
                "success": True,
                "token": token,
                "role": user['role'],
                "message": "Login successful"
            })
            
        finally:
            cursor.close()
            conn.close()
            
    except Exception as e:
        # Handle rate limit errors
        if hasattr(e, 'status_code') and e.status_code == 429:
            return jsonify({"error": "Too many login attempts. Please wait a few minutes and try again."}), 429
        logging.error(f"Login error: {e}")
        return jsonify({"error": "Server error. Please try again."}), 500

# Admin sign out route
@app.route('/api/admin/signout', methods=['POST'])
def admin_signout():
    """Sign out admin user and log the action"""
    try:
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if token:
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                username = payload.get('username')
                role = payload.get('role', 'admin')
                
                # Log sign out action
                log_activity(role, username, 'logout', 'Admin signed out', request.remote_addr)
            except jwt.ExpiredSignatureError:
                # Token expired, but still allow sign out
                pass
            except jwt.InvalidTokenError:
                # Invalid token, but still allow sign out
                pass
        
        # Clear session
        session.pop('admin_token', None)
        
        return jsonify({"success": True, "message": "Signed out successfully"})
        
    except Exception as e:
        logging.error(f"Sign out error: {e}")
        # Still return success to allow client-side cleanup
        return jsonify({"success": True, "message": "Signed out successfully"})

# QR Scanner route
@app.route('/qr_scanner')
def qr_scanner():
    return render_template('qr_scanner.html')

# Corporate QR Scanner for payments
@app.route('/corporate_scanner')
def corporate_scanner():
    return render_template('corporate_scanner.html')

# Check balance by ticket ID
@app.route('/check_balance_by_ticket')
def check_balance_by_ticket():
    ticket_id = request.args.get('ticket_id')
    
    if not ticket_id:
        return jsonify({"error": "Ticket ID required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT full_name, balance FROM visitors WHERE ticket_id = ?", (ticket_id,))
        result = cursor.fetchone()
        
        if result:
            log_activity('visitor', result[0], 'balance_check', f'Ticket ID: {ticket_id}')
            return jsonify({
                "success": True,
                "visitor_name": result[0],
                "balance": result[1]
            })
        else:
            return jsonify({"error": "Ticket not found"}), 404
            
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# API endpoint for stall staff to scan QR code and start transaction
@app.route('/scan_for_payment', methods=['POST'])
def scan_for_payment():
    data = request.get_json()
    qr_data = data.get('qr_data', '')
    
    # Extract ticket ID from QR code URL
    if 'ticket_id=' in qr_data:
        ticket_id = qr_data.split('ticket_id=')[1].split('&')[0]
    else:
        return jsonify({"error": "Invalid QR code format"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if ticket exists and get details
        cursor.execute("SELECT ticket_id, full_name, balance, issue_date FROM visitors WHERE ticket_id = ?", (ticket_id,))
        result = cursor.fetchone()
        
        if result:
            ticket_id, visitor_name, balance, issue_date = result
            
            # Get list of stalls for authentication
            cursor.execute("SELECT user, pass_key FROM access_keys ORDER BY user")
            stalls = [{"name": row[0], "passkey": row[1]} for row in cursor.fetchall()]
            
            log_activity('corporates', 'system', 'qr_scanned', f'QR scanned for {visitor_name}, balance: {balance}')
            
            return jsonify({
                "success": True,
                "ticket_id": ticket_id,
                "visitor_name": visitor_name,
                "balance": balance,
                "issue_date": issue_date,
                "stalls": stalls,
                "redirect_url": f"/authenticator?ticket_id={ticket_id}"
            })
        else:
            return jsonify({"error": "QR code not found or invalid"}), 404
            
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Print QR route
@app.route('/print_qr')
def print_qr():
    visitor_name = request.args.get('visitor_name')
    balance = request.args.get('balance')
    issue_date = request.args.get('issue_date')
    qr_image = request.args.get('qr_image')
    
    return render_template('print_qr.html', 
                         visitor_name=visitor_name,
                         balance=balance,
                         issue_date=issue_date,
                         qr_image=qr_image)

# Live dashboard data
@app.route('/api/dashboard_data')
@require_admin_auth
def dashboard_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Total revenue (from both issues and top-ups)
        cursor.execute("SELECT SUM(amount) FROM topup_transactions")
        total_revenue = cursor.fetchone()[0] or 0
        
        # QR codes issued today
        cursor.execute("SELECT COUNT(*) FROM visitors WHERE date(issue_date) = date('now')")
        qr_codes_today = cursor.fetchone()[0]
        
        # Top-ups today
        cursor.execute("SELECT COUNT(*) FROM topup_transactions WHERE type = 'Top up' AND date(created_at) = date('now')")
        topups_today = cursor.fetchone()[0]
        
        # Recent transactions
        cursor.execute("""
            SELECT c.name, c.amount, c.customer, c.time 
            FROM payments c 
            ORDER BY c.time DESC 
            LIMIT 10
        """)
        recent_transactions = cursor.fetchall()
        
        # Recent activity (QR issuance, recharges, payments)
        cursor.execute("""
            SELECT 
                sl.user_type,
                sl.user_id,
                sl.action,
                sl.details,
                sl.timestamp,
                sl.ip_address
            FROM audit_logs sl
            WHERE sl.action IN ('issue_coupon', 'topup_coupon', 'process_payment', 'admin_create_visitor')
            ORDER BY sl.timestamp DESC
            LIMIT 15
        """)
        recent_activity = cursor.fetchall()
        
        # Revenue by hour (last 24 hours)
        cursor.execute("""
            SELECT strftime('%H', time) as hour, SUM(amount) as total
            FROM payments 
            WHERE time >= datetime('now', '-24 hours')
            GROUP BY strftime('%H', time)
            ORDER BY hour
        """)
        hourly_revenue = cursor.fetchall()
        
        return jsonify({
            "total_revenue": total_revenue,
            "qr_codes_today": qr_codes_today,
            "topups_today": topups_today,
            "recent_transactions": [dict(row) for row in recent_transactions],
            "recent_activity": [dict(row) for row in recent_activity],
            "hourly_revenue": [{"hour": row[0], "total": row[1]} for row in hourly_revenue]
        })
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# API to issue a coupon
@app.route('/issue_coupon', methods=['POST'])
@require_admin_auth
def issue_coupon_route():
    # Get admin username and role from JWT token
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        admin_username = payload.get('username')
        admin_role = payload.get('role', 'admin')  # Get role from token, default to 'admin'
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json()
    full_name = data.get('full_name', '').strip()
    try:
        amount = float(data.get('amount', 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    # Validate full name (must contain at least two words)
    if len(full_name.split(' ')) < 2:
        return jsonify({"error": "Please enter a full name (at least two words)."}), 400

    try:
        qr_code_img_str, ticket_id = issue_coupon(full_name, amount, admin_username)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Log the activity with correct role
    log_activity(admin_role, admin_username, 'issue_coupon', f'Issued coupon for {full_name}, amount: {amount}')
    
    return jsonify({
        "message": "Coupon issued successfully",
        "qr_code_img_str": qr_code_img_str,
        "print_url": f"/print_qr?visitor_name={full_name}&ticket_id={ticket_id}&balance={amount}&issue_date={datetime.datetime.now().strftime('%Y-%m-%d')}&qr_image={qr_code_img_str}"
    })

@app.route('/topup_coupon', methods=['POST'])
@require_admin_auth
def topup_coupon():
    # Get admin username and role from JWT token
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        admin_username = payload.get('username')
        admin_role = payload.get('role', 'admin')  # Get role from token, default to 'admin'
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json()
    full_name = data.get('full_name', '').strip()
    try:
        amount_to_add = float(data.get('amount', 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    if not full_name:
        return jsonify({"error": "Full name is required"}), 400

    logging.info(f"Received top-up request for {full_name}, amount: {amount_to_add}, admin: {admin_username}")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if the provided name exists in the visitors table
        cursor.execute("SELECT * FROM visitors WHERE full_name = ?", (full_name,))
        visitors_result = cursor.fetchall()
        if not visitors_result:
            return jsonify({"success": False, "message": "Coupon not found for the provided name."}), 404

        # Fetch current balance before update
        cursor.execute("SELECT balance FROM visitors WHERE full_name = ?", (full_name,))
        current_balance_row = cursor.fetchone()
        current_balance = float(current_balance_row[0]) if current_balance_row else 0.0

        # Update the coupon balance
        cursor.execute("UPDATE visitors SET balance = balance + ? WHERE full_name = ?", (amount_to_add, full_name))

        # Insert into topup_transactions table (store admin_username in pin field for tracking)
        cursor.execute("INSERT INTO topup_transactions (full_name, amount, pin, type) VALUES (?, ?, ?, 'Top up')", (full_name, amount_to_add, admin_username))
        conn.commit()

        # Log the activity with correct role
        log_activity(admin_role, admin_username, 'topup_coupon', f'Recharged {full_name} with AED {amount_to_add}')

        new_balance = current_balance + amount_to_add
        return jsonify({
            "success": True,
            "message": "Coupon topped up successfully!",
            "visitor_name": full_name,
            "amount_added": amount_to_add,
            "new_balance": new_balance
        }), 200

    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"success": False, "message": "Database error occurred."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/check-balance', methods=['GET', 'POST'])
def check_balance_page():
    # If JSON request, behave as API and return JSON
    if request.is_json:
        data = request.get_json(silent=True) or {}
        ticket_id_or_name = data.get('ticket_id') or data.get('full_name')
        if not ticket_id_or_name:
            return jsonify({"error": "ticket_id or full_name is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Try by ticket_id first if numeric
            if str(ticket_id_or_name).isdigit():
                cursor.execute("SELECT ticket_id, full_name, balance, issue_date FROM visitors WHERE ticket_id = ?", (ticket_id_or_name,))
            else:
                cursor.execute("SELECT ticket_id, full_name, balance, issue_date FROM visitors WHERE full_name = ?", (ticket_id_or_name,))
            result = cursor.fetchone()
            if not result:
                return jsonify({"error": "Coupon not found."}), 404
            return jsonify({
                "ticket_id": result[0],
                "full_name": result[1],
                "balance": result[2],
                "issue_date": result[3]
            })
        except sqlite3.Error:
            return jsonify({"error": "Database connection error."}), 500
        finally:
            cursor.close()
            conn.close()

    # Default: render HTML form flow
    balance = None
    error_message = None
    if request.method == 'POST':
        full_name = request.form.get('full_name') or request.form.get('ticket_id')
        if not full_name:
            error_message = "Name is required."
        else:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                if str(full_name).isdigit():
                    cursor.execute("SELECT balance FROM visitors WHERE ticket_id = ?", (full_name,))
                else:
                    cursor.execute("SELECT balance FROM visitors WHERE full_name = ?", (full_name,))
                result = cursor.fetchone()
                if result:
                    balance = result[0]
                else:
                    error_message = "Coupon not found."
            except sqlite3.Error:
                error_message = "Database connection error."
            finally:
                cursor.close()
                conn.close()
    return render_template('check_balance.html', balance=balance, error_message=error_message)

@app.route('/deduct_balance', methods=['GET', 'POST'])
def deduct_balance():
    if request.method == 'GET':
        ticket_id = request.args.get('ticket_id')
        user = request.args.get('user')
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("SELECT balance FROM visitors WHERE ticket_id = ?", (ticket_id,))
            result = cursor.fetchone()
            balance = result[0] if result else None

            return render_template('deduct_balance.html', ticket_id=ticket_id, balance=balance, user=user)

        finally:
            cursor.close()
            conn.close()

    # Handling the POST request
    data = request.get_json()
    ticket_id = data['ticket_id']
    amount_to_deduct = float(data['amount'])
    user = data['user']

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch the selected counter based on the user
        cursor.execute("SELECT counter FROM access_keys WHERE user = ?", (user,))
        counter_result = cursor.fetchone()
        selected_counter = counter_result[0] if counter_result else None

        logging.info(f"Received deduct request for ticket_id: {ticket_id}, amount: {amount_to_deduct}, counter: {selected_counter}, user: {user}")

        # Fetch the current balance
        cursor.execute("SELECT balance FROM visitors WHERE ticket_id = ?", (ticket_id,))
        result = cursor.fetchone()

        if result:
            current_balance = result[0]
            logging.info(f"Current balance for ticket_id {ticket_id}: {current_balance}")

            if current_balance >= amount_to_deduct:
                new_balance = current_balance - amount_to_deduct
                cursor.execute("UPDATE visitors SET balance = ? WHERE ticket_id = ?", (new_balance, ticket_id))
                conn.commit()

                # Fetch the customer's name based on ticket_id
                cursor.execute("SELECT full_name FROM visitors WHERE ticket_id = ?", (ticket_id,))
                customer_result = cursor.fetchone()
                customer_name = customer_result[0] if customer_result else None

                if selected_counter:
                    # Insert into payments table with time automatically captured
                    cursor.execute(
                        """
                        INSERT INTO payments (name, amount, staff, customer) 
                        VALUES (?, ?, ?, ?)
                        """,
                        (selected_counter, amount_to_deduct, user, customer_name)
                    )
                    conn.commit()
                else:
                    logging.warning(f"No counter found for user: {user}. Not inserting into payments table.")

                return jsonify({
                    "success": True,
                    "message": "Balance deducted successfully!",
                    "amount": amount_to_deduct,
                    "counter": selected_counter
                }), 200
            else:
                return jsonify({"success": False, "message": "Insufficient balance."}), 400
        else:
            return jsonify({"success": False, "message": "Coupon not found."}), 404

    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"success": False, "message": "Database error occurred."}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/end_transaction')
def end_transaction():
    amount = request.args.get('amount')
    user = request.args.get('user')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch the counter associated with the user
    cursor.execute("SELECT counter FROM access_keys WHERE user = ?", (user,))
    counter = cursor.fetchone()
    
    if counter:
        counter_name = counter[0]
    else:
        counter_name = "Unknown Counter"
    
    cursor.close()
    conn.close()
    
    return render_template('end_transaction.html', amount=amount, counter=counter_name)

@app.route('/aborted_transaction')
def aborted_transaction():
    return render_template('aborted_transaction.html')

@app.route('/authenticator', methods=['GET'])
def authenticator():
    ticket_id = request.args.get('ticket_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch all users from the access_keys table
    cursor.execute("SELECT user FROM access_keys ORDER BY user ASC")
    users = cursor.fetchall()
    
    cursor.close()
    conn.close()

    return render_template('authenticator.html', users=users, ticket_id=ticket_id)

@app.route('/validate_passkey', methods=['POST'])
def validate_passkey():
    data = request.get_json()
    user = data['user']
    pass_key = data['pass_key']
    ticket_id = data.get('ticket_id')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT pass_key FROM access_keys WHERE user = ?", (user,))
    result = cursor.fetchone()

    if result and result[0] == pass_key:
        return jsonify({"success": True, "ticket_id": ticket_id}), 200
    else:
        return jsonify({"success": False, "message": "Invalid pass key."}), 403

@app.route('/process_payment', methods=['POST'])
def process_payment():
    """Unified endpoint for stall staff to process a payment with passkey."""
    data = request.get_json() or {}
    ticket_id = data.get('ticket_id')
    amount_to_deduct = float(data.get('amount') or 0)
    passkey = data.get('passkey')

    if not ticket_id or not passkey or amount_to_deduct <= 0:
        return jsonify({"error": "ticket_id, passkey and positive amount are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Resolve user and counter by passkey (plain text comparison)
        cursor.execute("SELECT user, counter FROM access_keys WHERE pass_key = ?", (passkey,))
        auth_row = cursor.fetchone()
        if not auth_row:
            return jsonify({"error": "Invalid passkey"}), 403
        user, counter = auth_row

        # Fetch current balance and customer name
        cursor.execute("SELECT balance, full_name FROM visitors WHERE ticket_id = ?", (ticket_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Coupon not found."}), 404
        current_balance, customer_name = row

        if float(current_balance) < amount_to_deduct:
            return jsonify({"error": "Insufficient balance."}), 400

        # Deduct and log transaction
        new_balance = float(current_balance) - amount_to_deduct
        cursor.execute("UPDATE visitors SET balance = ? WHERE ticket_id = ?", (new_balance, ticket_id))
        cursor.execute("INSERT INTO payments (name, amount, staff, customer) VALUES (?, ?, ?, ?)", (counter, amount_to_deduct, user, customer_name))
        conn.commit()

        # Log the payment activity
        log_activity('corporates', user, 'process_payment', f'Payment of AED {amount_to_deduct} processed at {counter} for {customer_name}')

        return jsonify({
            "success": True,
            "amount": amount_to_deduct,
            "new_balance": new_balance,
            "transaction_id": cursor.lastrowid,
            "counter": counter,
            "user": user
        })
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error occurred."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/system_logs')
@require_super_admin_auth
def api_system_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT timestamp, user_type, user_id, action, details, ip_address
            FROM audit_logs
            ORDER BY timestamp DESC
            LIMIT 200
        """)
        logs = [
            {
                "timestamp": row[0],
                "user_type": row[1],
                "user_id": row[2],
                "action": row[3],
                "details": row[4],
                "ip_address": row[5]
            }
            for row in cursor.fetchall()
        ]
        return jsonify({"logs": logs})
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/generate_reports')
@require_admin_page_auth
def generate_reports():
    return render_template('generate_reports.html')

@app.route('/generate_comprehensive_report', methods=['GET'])
@require_admin_auth
def generate_comprehensive_report():
    """Generate a comprehensive Excel report with all user data"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create Excel writer object
        excel_filename = "comprehensive_user_report.xlsx"
        with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
            
            # 1. Visitors (Coupons) Sheet - Enhanced with more details
            cursor.execute("""
                SELECT ticket_id, full_name, amount, balance, issue_date, pin as issued_by,
                       CASE 
                           WHEN balance > amount THEN 0
                           ELSE ROUND((amount - balance), 2)
                       END as total_spent,
                       CASE 
                           WHEN balance > amount THEN 0
                           ELSE ROUND(((amount - balance) / amount * 100), 2)
                       END as percentage_used,
                       ROUND(julianday('now') - julianday(issue_date), 1) as days_since_issue
                FROM visitors
                ORDER BY issue_date DESC
            """)
            visitors_data = cursor.fetchall()
            if visitors_data:
                df_visitors = pd.DataFrame(visitors_data, columns=[
                    'Ticket ID', 'Full Name', 'Initial Amount', 'Current Balance', 'Issue Date', 'Issued By',
                    'Total Spent (AED)', 'Percentage Used (%)', 'Days Since Issue'
                ])
                # Convert Issue Date to UAE timezone
                if 'Issue Date' in df_visitors.columns:
                    df_visitors['Issue Date'] = pd.to_datetime(df_visitors['Issue Date'], errors='coerce')
                    uae_tz = pytz.timezone('Asia/Dubai')
                    # Handle timezone conversion - assume UTC if no timezone info
                    if df_visitors['Issue Date'].dt.tz is None:
                        df_visitors['Issue Date'] = df_visitors['Issue Date'].dt.tz_localize('UTC')
                    df_visitors['Issue Date'] = df_visitors['Issue Date'].dt.tz_convert(uae_tz)
                    df_visitors['Issue Date'] = df_visitors['Issue Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_visitors.to_excel(writer, sheet_name='Visitors', index=False)
            else:
                # Create empty sheet with headers
                df_visitors = pd.DataFrame(columns=[
                    'Ticket ID', 'Full Name', 'Initial Amount', 'Current Balance', 'Issue Date', 'Issued By',
                    'Total Spent (AED)', 'Percentage Used (%)', 'Days Since Issue'
                ])
                df_visitors.to_excel(writer, sheet_name='Visitors', index=False)
            
            # 2. Revenue Transactions Sheet - Enhanced with transaction ID and ticket ID
            cursor.execute("""
                SELECT r.id as transaction_id, r.full_name, r.amount, r.type, r.pin as admin, r.created_at,
                       c.ticket_id, c.balance as current_balance
                FROM topup_transactions r
                LEFT JOIN visitors c ON r.full_name = c.full_name
                ORDER BY r.created_at DESC
            """)
            revenue_data = cursor.fetchall()
            if revenue_data:
                df_revenue = pd.DataFrame(revenue_data, columns=[
                    'Transaction ID', 'Visitor Name', 'Ticket ID', 'Amount (AED)', 'Type', 'Admin', 
                    'Current Balance (AED)', 'Date'
                ])
                # Convert Date to UAE timezone
                if 'Date' in df_revenue.columns:
                    df_revenue['Date'] = pd.to_datetime(df_revenue['Date'], errors='coerce')
                    uae_tz = pytz.timezone('Asia/Dubai')
                    if df_revenue['Date'].dt.tz is None:
                        df_revenue['Date'] = df_revenue['Date'].dt.tz_localize('UTC')
                    df_revenue['Date'] = df_revenue['Date'].dt.tz_convert(uae_tz)
                    df_revenue['Date'] = df_revenue['Date'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_revenue.to_excel(writer, sheet_name='Revenue Transactions', index=False)
            else:
                df_revenue = pd.DataFrame(columns=[
                    'Transaction ID', 'Visitor Name', 'Ticket ID', 'Amount (AED)', 'Type', 'Admin', 
                    'Current Balance (AED)', 'Date'
                ])
                df_revenue.to_excel(writer, sheet_name='Revenue Transactions', index=False)
            
            # 3. Counter Transactions (Payments) Sheet - Enhanced with transaction ID and ticket ID
            cursor.execute("""
                SELECT cnt.id as transaction_id, cnt.name as counter_name, cnt.amount, cnt.staff, 
                       cnt.customer, cnt.time, c.ticket_id, c.balance as visitor_balance
                FROM payments cnt
                LEFT JOIN visitors c ON cnt.customer = c.full_name
                ORDER BY cnt.time DESC
            """)
            counters_data = cursor.fetchall()
            if counters_data:
                df_counters = pd.DataFrame(counters_data, columns=[
                    'Transaction ID', 'Counter Name', 'Amount (AED)', 'Staff', 'Customer', 
                    'Ticket ID', 'Visitor Balance (AED)', 'Time'
                ])
                # Convert Time to UAE timezone
                if 'Time' in df_counters.columns:
                    df_counters['Time'] = pd.to_datetime(df_counters['Time'], errors='coerce')
                    uae_tz = pytz.timezone('Asia/Dubai')
                    if df_counters['Time'].dt.tz is None:
                        df_counters['Time'] = df_counters['Time'].dt.tz_localize('UTC')
                    df_counters['Time'] = df_counters['Time'].dt.tz_convert(uae_tz)
                    df_counters['Time'] = df_counters['Time'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_counters.to_excel(writer, sheet_name='Counter Transactions', index=False)
            else:
                df_counters = pd.DataFrame(columns=[
                    'Transaction ID', 'Counter Name', 'Amount (AED)', 'Staff', 'Customer', 
                    'Ticket ID', 'Visitor Balance (AED)', 'Time'
                ])
                df_counters.to_excel(writer, sheet_name='Counter Transactions', index=False)
            
            # 4. Admin Users Sheet - Enhanced with security details
            cursor.execute("""
                SELECT username, role, last_login, created_at, is_active, created_by,
                       failed_login_attempts,
                       CASE WHEN locked_until IS NOT NULL AND datetime(locked_until) > datetime('now') 
                            THEN 'Locked' ELSE 'Active' END as account_status,
                       ROUND(julianday('now') - julianday(created_at), 1) as account_age_days
                FROM admins
                ORDER BY created_at DESC
            """)
            admin_data = cursor.fetchall()
            if admin_data:
                df_admins = pd.DataFrame(admin_data, columns=[
                    'Username', 'Role', 'Last Login', 'Created At', 'Is Active', 'Created By',
                    'Failed Login Attempts', 'Account Status', 'Account Age (Days)'
                ])
                # Convert timestamps to UAE timezone
                uae_tz = pytz.timezone('Asia/Dubai')
                if 'Last Login' in df_admins.columns:
                    df_admins['Last Login'] = pd.to_datetime(df_admins['Last Login'], errors='coerce')
                    if df_admins['Last Login'].dt.tz is None:
                        df_admins['Last Login'] = df_admins['Last Login'].dt.tz_localize('UTC')
                    df_admins['Last Login'] = df_admins['Last Login'].dt.tz_convert(uae_tz)
                    df_admins['Last Login'] = df_admins['Last Login'].dt.strftime('%Y-%m-%d %H:%M:%S')
                if 'Created At' in df_admins.columns:
                    df_admins['Created At'] = pd.to_datetime(df_admins['Created At'], errors='coerce')
                    if df_admins['Created At'].dt.tz is None:
                        df_admins['Created At'] = df_admins['Created At'].dt.tz_localize('UTC')
                    df_admins['Created At'] = df_admins['Created At'].dt.tz_convert(uae_tz)
                    df_admins['Created At'] = df_admins['Created At'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_admins.to_excel(writer, sheet_name='Admin Users', index=False)
            else:
                df_admins = pd.DataFrame(columns=[
                    'Username', 'Role', 'Last Login', 'Created At', 'Is Active', 'Created By',
                    'Failed Login Attempts', 'Account Status', 'Account Age (Days)'
                ])
                df_admins.to_excel(writer, sheet_name='Admin Users', index=False)
            
            # 5. System Logs Sheet
            cursor.execute("""
                SELECT user_type, user_id, action, details, ip_address, timestamp
                FROM audit_logs
                ORDER BY timestamp DESC
            """)
            logs_data = cursor.fetchall()
            if logs_data:
                df_logs = pd.DataFrame(logs_data, columns=[
                    'User Type', 'User ID', 'Action', 'Details', 'IP Address', 'Timestamp'
                ])
                # Convert Timestamp to UAE timezone
                if 'Timestamp' in df_logs.columns:
                    df_logs['Timestamp'] = pd.to_datetime(df_logs['Timestamp'], errors='coerce')
                    uae_tz = pytz.timezone('Asia/Dubai')
                    if df_logs['Timestamp'].dt.tz is None:
                        df_logs['Timestamp'] = df_logs['Timestamp'].dt.tz_localize('UTC')
                    df_logs['Timestamp'] = df_logs['Timestamp'].dt.tz_convert(uae_tz)
                    df_logs['Timestamp'] = df_logs['Timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
                df_logs.to_excel(writer, sheet_name='System Logs', index=False)
            else:
                df_logs = pd.DataFrame(columns=[
                    'User Type', 'User ID', 'Action', 'Details', 'IP Address', 'Timestamp'
                ])
                df_logs.to_excel(writer, sheet_name='System Logs', index=False)
            
            # 6. Summary Sheet - Enhanced with more statistics
            cursor.execute("SELECT COUNT(*) FROM visitors")
            total_visitors = cursor.fetchone()[0]
            
            cursor.execute("SELECT SUM(amount) FROM topup_transactions WHERE type = 'Issue'")
            total_issued = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT SUM(amount) FROM topup_transactions WHERE type = 'Top up'")
            total_topup = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT SUM(amount) FROM payments")
            total_payments = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM admins")
            total_admins = cursor.fetchone()[0]
            
            cursor.execute("SELECT AVG(balance) FROM visitors WHERE balance IS NOT NULL")
            avg_balance = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT SUM(amount - balance) FROM visitors WHERE balance IS NOT NULL")
            total_spent = cursor.fetchone()[0] or 0
            
            cursor.execute("SELECT COUNT(*) FROM topup_transactions")
            total_revenue_transactions = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM payments")
            total_payment_transactions = cursor.fetchone()[0]
            
            cursor.execute("""
                SELECT customer, COUNT(*) as transaction_count 
                FROM payments 
                WHERE customer IS NOT NULL
                GROUP BY customer 
                ORDER BY transaction_count DESC 
                LIMIT 1
            """)
            most_active = cursor.fetchone()
            most_active_visitor = most_active[0] if most_active else 'N/A'
            most_active_count = most_active[1] if most_active else 0
            
            cursor.execute("""
                SELECT customer, SUM(amount) as total_spent 
                FROM payments 
                WHERE customer IS NOT NULL
                GROUP BY customer 
                ORDER BY total_spent DESC 
                LIMIT 1
            """)
            top_spender = cursor.fetchone()
            top_spender_name = top_spender[0] if top_spender else 'N/A'
            top_spender_amount = top_spender[1] if top_spender else 0
            
            cursor.execute("SELECT COUNT(*) FROM visitors WHERE qr_code IS NOT NULL AND qr_code != ''")
            visitors_with_qr = cursor.fetchone()[0]
            
            summary_data = {
                'Metric': [
                    'Total Visitors',
                    'Visitors with QR Codes',
                    'Total Amount Issued (AED)',
                    'Total Amount Top-up (AED)',
                    'Total Payments (AED)',
                    'Total Spent by Visitors (AED)',
                    'Average Visitor Balance (AED)',
                    'Total Revenue Transactions',
                    'Total Payment Transactions',
                    'Most Active Visitor',
                    'Most Active Visitor Transactions',
                    'Top Spender',
                    'Top Spender Amount (AED)',
                    'Total Admin Users',
                    'Report Generated'
                ],
                'Value': [
                    total_visitors,
                    visitors_with_qr,
                    round(total_issued, 2),
                    round(total_topup, 2),
                    round(total_payments, 2),
                    round(total_spent, 2),
                    round(avg_balance, 2),
                    total_revenue_transactions,
                    total_payment_transactions,
                    most_active_visitor,
                    most_active_count,
                    top_spender_name,
                    round(top_spender_amount, 2),
                    total_admins,
                    datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ]
            }
            df_summary = pd.DataFrame(summary_data)
            df_summary.to_excel(writer, sheet_name='Summary', index=False)
        
        return send_file(excel_filename, as_attachment=True, download_name='comprehensive_user_report.xlsx')

    except Exception as err:
        logging.error(f"Error generating report: {err}")
        return jsonify({"error": f"Error generating report: {str(err)}"}), 500
    finally:
        cursor.close()
        conn.close()

# Serve the frontend HTML pages
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/visitor_portal')
def visitor_portal():
    return render_template('visitor_portal.html')

@app.route('/topup-instructions')
def topup_instructions():
    return render_template('topup_instructions.html')

@app.route('/admin/issue-coupon')
@require_admin_page_auth
def issue_coupon_page():
    return render_template('issue_coupon.html')

@app.route('/admin/recharge-coupon')
@require_admin_page_auth
def recharge_coupon_page():
    return render_template('recharge_coupon.html')

@app.route('/admin/view-visitor-qrcodes')
@require_admin_page_auth
def view_visitor_qrcodes_page():
    return render_template('view_visitor_qrcodes.html')

@app.route('/admin_login')
def admin_login_page():
    return render_template('admin_login.html')

@app.route('/admin')
def admin():
    # Check if admin is logged in
    token = session.get('admin_token')
    if not token:
        return redirect('/admin_login')
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        if payload.get('role') not in ['admin', 'super_admin']:
            return redirect('/admin_login')
    except:
        return redirect('/admin_login')
    
    return render_template('admin.html')

@app.route('/live_dashboard')
@require_admin_page_auth
def live_dashboard():
    return render_template('live_dashboard.html')

@app.route('/manage_accounts')
@require_admin_page_auth
def manage_accounts():
    return render_template('manage_accounts.html')

@app.route('/system_logs')
@require_admin_page_auth
def system_logs():
    return render_template('system_logs.html')

# Admin API to create corporate accounts and staff
@app.route('/api/create_corporate_account', methods=['POST'])
@require_admin_auth
def create_corporate_account():
    data = request.get_json()
    corporate_name = data.get('corporate_name', '').strip()
    counter = data.get('counter', '').strip()
    staff_passkey = data.get('staff_passkey', '').strip()
    corporate_account = data.get('corporate_account', '').strip()
    
    if not corporate_name or not counter or not staff_passkey:
        return jsonify({"error": "Corporate name, counter, and passkey are required"}), 400
    
    # Validate passkey length (minimum 4 characters)
    if len(staff_passkey) < 4:
        return jsonify({"error": "Passkey must be at least 4 characters long"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if corporate already exists
        cursor.execute("SELECT id FROM access_keys WHERE user = ?", (corporate_name,))
        if cursor.fetchone():
            return jsonify({"error": "Corporate account already exists"}), 400
        
        # Store passkey as plain text
        cursor.execute("INSERT INTO access_keys (user, counter, pass_key, passkey_display) VALUES (?, ?, ?, ?)", 
                      (corporate_name, counter, staff_passkey, staff_passkey))
        
        
        conn.commit()
        
        log_activity('admin', 'system', 'create_corporate', f'Created corporate account: {corporate_name}')
        
        return jsonify({
            "success": True,
            "message": f"Corporate account '{corporate_name}' created successfully",
            "corporate_name": corporate_name,
            "passkey": staff_passkey
        })
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin API to get all corporate accounts
@app.route('/api/corporate_accounts')
@require_admin_auth
def get_corporate_accounts():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT user, counter, pass_key
            FROM access_keys
            ORDER BY user
        """)
        
        stalls = []
        for row in cursor.fetchall():
            stalls.append({
                "corporate_name": row[0],
                "counter": row[1],
                "staff_passkey": row[2] or 'N/A'  # Return plain text passkey
            })
        
        return jsonify({"corporate_accounts": stalls})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Update Corporate Account API
@app.route('/api/update_corporate_account', methods=['POST'])
@require_admin_auth
def update_corporate_account():
    data = request.get_json() or {}
    corporate_name = (data.get('corporate_name') or '').strip()
    new_passkey = (data.get('passkey') or '').strip()
    new_counter = (data.get('counter') or '').strip()

    if not corporate_name:
        return jsonify({"error": "corporate_name is required"}), 400
    
    # Validate passkey length if provided (minimum 4 characters)
    if new_passkey and len(new_passkey) < 4:
        return jsonify({"error": "Passkey must be at least 4 characters long"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM access_keys WHERE user = ?", (corporate_name,))
        if not cursor.fetchone():
            return jsonify({"error": "Corporate not found"}), 404

        updates = []
        params = []
        if new_passkey:
            # Store passkey as plain text
            updates.append("pass_key = ?")
            updates.append("passkey_display = ?")
            params.append(new_passkey)
            params.append(new_passkey)
        if new_counter:
            updates.append("counter = ?")
            params.append(new_counter)
        if not updates:
            return jsonify({"error": "No fields to update"}), 400

        params.append(corporate_name)
        sql = f"UPDATE access_keys SET {', '.join(updates)} WHERE user = ?"
        cursor.execute(sql, tuple(params))
        conn.commit()
        
        log_activity('admin', 'system', 'update_corporate', f"Updated corporate {corporate_name}")
        return jsonify({"success": True})
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Delete Corporate Account API
@app.route('/api/delete_corporate_account', methods=['POST'])
@require_admin_auth
def delete_corporate_account():
    data = request.get_json() or {}
    corporate_name = (data.get('corporate_name') or '').strip()
    if not corporate_name:
        return jsonify({"error": "corporate_name is required"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM access_keys WHERE user = ?", (corporate_name,))
        if cursor.rowcount == 0:
            return jsonify({"error": "Corporate not found"}), 404
        conn.commit()
        log_activity('admin', 'system', 'delete_corporate', f"Deleted corporate {corporate_name}")
        return jsonify({"success": True})
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Dashboard route
@app.route('/admin_dashboard')
@require_admin_page_auth
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Admin Statistics API
@app.route('/api/admin_stats')
@require_admin_auth
def admin_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get total visitors
        cursor.execute("SELECT COUNT(*) FROM visitors")
        total_visitors = cursor.fetchone()[0]
        
        # Get total revenue (from both issues and top-ups)
        cursor.execute("SELECT SUM(amount) FROM topup_transactions")
        total_revenue = cursor.fetchone()[0] or 0
        
        # Get total transactions (all revenue entries)
        cursor.execute("SELECT COUNT(*) FROM topup_transactions")
        total_transactions = cursor.fetchone()[0]
        
        return jsonify({
            "total_visitors": total_visitors,
            "total_revenue": round(total_revenue, 2),
            "total_transactions": total_transactions
        })
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Visitors API
@app.route('/api/admin_visitors')
@require_admin_auth
def admin_visitors():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT ticket_id, full_name, amount, balance, issue_date, pin
            FROM visitors
            ORDER BY issue_date DESC
        """)
        
        visitors = []
        for row in cursor.fetchall():
            visitors.append({
                "ticket_id": row[0],
                "full_name": row[1],
                "amount": row[2],
                "balance": row[3],
                "issue_date": row[4],
                "pin": row[5]
            })
        
        return jsonify({"visitors": visitors})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Visitor QR Codes API
@app.route('/api/admin_visitor_qrcodes')
@require_admin_auth
def admin_visitor_qrcodes():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT ticket_id, full_name, amount, balance, qr_code, issue_date
            FROM visitors
            WHERE qr_code IS NOT NULL AND qr_code != ''
            ORDER BY issue_date DESC
        """)
        
        visitors = []
        for row in cursor.fetchall():
            visitors.append({
                "ticket_id": row[0],
                "full_name": row[1],
                "amount": row[2],
                "balance": row[3],
                "qr_code": row[4],
                "issue_date": row[5]
            })
        
        return jsonify({"visitors": visitors})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Visitor Transactions API
@app.route('/api/admin_visitor_transactions')
@require_admin_auth
def admin_visitor_transactions():
    """Get all transactions for a specific visitor by ticket_id or full_name"""
    ticket_id = request.args.get('ticket_id')
    full_name = request.args.get('full_name')
    
    if not ticket_id and not full_name:
        return jsonify({"error": "ticket_id or full_name is required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get visitor name if ticket_id is provided
        if ticket_id:
            cursor.execute("SELECT full_name FROM visitors WHERE ticket_id = ?", (ticket_id,))
            result = cursor.fetchone()
            if result:
                full_name = result[0]
            else:
                return jsonify({"error": "Visitor not found"}), 404
        
        transactions = []
        
        # Get revenue transactions (Issue and Top up)
        cursor.execute("""
            SELECT created_at, type, amount, pin
            FROM topup_transactions
            WHERE full_name = ?
            ORDER BY created_at DESC
        """, (full_name,))
        
        for row in cursor.fetchall():
            transactions.append({
                "date": row[0],
                "type": row[1],
                "amount": row[2],
                "admin": row[3] if row[3] else "System",
                "stall_booth": None,
                "details": f"{row[1]} transaction"
            })
        
        # Get payment transactions (from counters table)
        cursor.execute("""
            SELECT time, amount, name, staff
            FROM payments
            WHERE customer = ?
            ORDER BY time DESC
        """, (full_name,))
        
        for row in cursor.fetchall():
            transactions.append({
                "date": row[0],
                "type": "Payment",
                "amount": row[1],  # amount is the payment amount
                "admin": row[3] if row[3] else "Unknown",
                "stall_booth": row[2],  # name is the stall/counter name
                "details": f"Payment at {row[2]}"
            })
        
        # Sort by date (most recent first)
        transactions.sort(key=lambda x: x['date'], reverse=True)
        
        return jsonify({
            "visitor_name": full_name,
            "ticket_id": ticket_id,
            "transactions": transactions
        })
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Delete Visitor API
@app.route('/api/admin_delete_visitor', methods=['POST'])
@require_admin_auth
def admin_delete_visitor():
    data = request.get_json() or {}
    ticket_id = data.get('ticket_id')
    if not ticket_id:
        return jsonify({"error": "ticket_id is required"}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM visitors WHERE ticket_id = ?", (ticket_id,))
        if cursor.rowcount == 0:
            return jsonify({"error": "Visitor not found"}), 404
        conn.commit()
        log_activity('admin', 'system', 'delete_visitor', f"Deleted visitor {ticket_id}")
        return jsonify({"success": True})
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()


# Admin Update Visitor API
@app.route('/api/admin_update_visitor', methods=['POST'])
@require_admin_auth
def admin_update_visitor():
    data = request.get_json() or {}
    ticket_id = data.get('ticket_id')
    new_full_name = (data.get('full_name') or '').strip()

    if not ticket_id:
        return jsonify({"error": "ticket_id is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT full_name FROM visitors WHERE ticket_id = ?", (ticket_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"error": "Visitor not found"}), 404

        if new_full_name:
            cursor.execute("SELECT 1 FROM visitors WHERE full_name = ? AND ticket_id != ?", (new_full_name, ticket_id))
            if cursor.fetchone():
                return jsonify({"error": "Full name already exists"}), 400
            cursor.execute("UPDATE visitors SET full_name = ? WHERE ticket_id = ?", (new_full_name, ticket_id))
            conn.commit()

        log_activity('admin', 'system', 'update_visitor', f"Updated visitor {ticket_id}")
        return jsonify({"success": True})
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin User Management APIs
@app.route('/api/admin/list', methods=['GET'])
@require_super_admin_auth
def list_admin_users():
    """List all admin users (super admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, username, role, is_active, failed_login_attempts, locked_until, 
                   last_login, created_by, created_at
            FROM admins
            ORDER BY created_at DESC
        """)
        
        admins = []
        for row in cursor.fetchall():
            admins.append({
                "id": row[0],
                "username": row[1],
                "role": row[2],
                "is_active": bool(row[3]),
                "failed_login_attempts": row[4] or 0,
                "locked_until": row[5],
                "last_login": row[6],
                "created_by": row[7],
                "created_at": row[8]
            })
        
        return jsonify({"admins": admins})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/create_admin', methods=['POST'])
@require_super_admin_auth
def create_admin():
    """Create new admin account (super admin only)"""
    # Get current admin username from token
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        current_admin = payload.get('username')
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password', '')
    role = (data.get('role') or 'admin').strip()
    password_confirmation = data.get('password_confirmation', '')
    
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    
    if role not in ['admin', 'super_admin']:
        return jsonify({"error": "Role must be 'admin' or 'super_admin'"}), 400
    
    # Require password confirmation for sensitive operations
    if not password_confirmation:
        return jsonify({"error": "Password confirmation is required for creating admin accounts"}), 400
    
    if password != password_confirmation:
        return jsonify({"error": "Password and confirmation do not match"}), 400
    
    # Validate password strength (stricter for super_admin)
    is_super_admin = (role == 'super_admin')
    is_valid, message = validate_password_strength(password, is_super_admin=is_super_admin)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    # Verify current super admin password for creating super admin accounts
    if is_super_admin:
        current_password = data.get('current_password', '')
        if not current_password:
            return jsonify({"error": "Current password is required to create super admin accounts"}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT password_hash FROM admins WHERE username = ? AND role = 'super_admin'", (current_admin,))
            current_user = cursor.fetchone()
            if not current_user or not verify_password(current_password, current_user['password_hash']):
                log_activity('admin', current_admin, 'create_admin_failed', f'Failed to create super admin - invalid password confirmation for {username}', request.remote_addr)
                return jsonify({"error": "Current password is incorrect"}), 401
        finally:
            cursor.close()
            conn.close()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if username already exists
        cursor.execute("SELECT id FROM admins WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({"error": "Username already exists"}), 400
        
        # Hash password
        password_hash = hash_password(password)
        
        # Create admin account
        cursor.execute("""
            INSERT INTO admins (username, password_hash, role, created_by)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, role, current_admin))
        
        conn.commit()
        
        # Enhanced logging for super admin actions
        log_activity('super_admin', current_admin, 'create_admin', 
                    f'Created {role} account: {username} from IP: {request.remote_addr}')
        
        return jsonify({
            "success": True,
            "message": f"Admin account '{username}' created successfully",
            "username": username,
            "role": role
        })
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/update_password', methods=['POST'])
@require_admin_auth
def update_password():
    """Update own password"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload.get('username')
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({"error": "Current password and new password are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get current password hash and role
        cursor.execute("SELECT password_hash, role FROM admins WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Verify current password
        if not verify_password(current_password, user['password_hash']):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Validate new password strength (stricter for super_admin)
        is_super_admin = (user['role'] == 'super_admin')
        is_valid, message = validate_password_strength(new_password, is_super_admin=is_super_admin)
        if not is_valid:
            return jsonify({"error": message}), 400
        
        # Hash new password
        new_password_hash = hash_password(new_password)
        
        # Update password
        cursor.execute("UPDATE admins SET password_hash = ? WHERE username = ?", (new_password_hash, username))
        conn.commit()
        
        # Enhanced logging for super admin password changes
        if is_super_admin:
            log_activity('super_admin', username, 'update_password', 
                        f'Super admin password updated from IP: {request.remote_addr}')
        else:
            log_activity('admin', username, 'update_password', 'Password updated')
        
        return jsonify({"success": True, "message": "Password updated successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/reset_password', methods=['POST'])
@require_super_admin_auth
def reset_password():
    """Reset another admin's password (super admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        current_admin = payload.get('username')
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    new_password = data.get('new_password', '')
    password_confirmation = data.get('password_confirmation', '')
    current_password = data.get('current_password', '')
    
    if not username or not new_password:
        return jsonify({"error": "Username and new password are required"}), 400
    
    # Require password confirmation
    if not password_confirmation:
        return jsonify({"error": "Password confirmation is required"}), 400
    
    if new_password != password_confirmation:
        return jsonify({"error": "Password and confirmation do not match"}), 400
    
    # Require current super admin password for security
    if not current_password:
        return jsonify({"error": "Current password is required to reset passwords"}), 400
    
    # Verify current super admin password
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash FROM admins WHERE username = ? AND role = 'super_admin'", (current_admin,))
        current_user = cursor.fetchone()
        if not current_user or not verify_password(current_password, current_user['password_hash']):
            log_activity('super_admin', current_admin, 'reset_password_failed', 
                        f'Failed to reset password for {username} - invalid password confirmation from IP: {request.remote_addr}')
            return jsonify({"error": "Current password is incorrect"}), 401
    finally:
        cursor.close()
        conn.close()

    # Check if target user is super admin to apply stricter validation
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT role FROM admins WHERE username = ?", (username,))
        target_user = cursor.fetchone()
        is_super_admin = target_user and target_user['role'] == 'super_admin'
    finally:
        cursor.close()
        conn.close()

    # Validate password strength (stricter for super_admin)
    is_valid, message = validate_password_strength(new_password, is_super_admin=is_super_admin)
    if not is_valid:
        return jsonify({"error": message}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if user exists
        cursor.execute("SELECT id FROM admins WHERE username = ?", (username,))
        if not cursor.fetchone():
            return jsonify({"error": "User not found"}), 404
        
        # Hash new password
        new_password_hash = hash_password(new_password)
        
        # Update password and reset failed attempts
        cursor.execute("""
            UPDATE admins 
            SET password_hash = ?, failed_login_attempts = 0, locked_until = NULL
            WHERE username = ?
        """, (new_password_hash, username))
        
        conn.commit()
        
        # Enhanced logging for super admin actions
        log_activity('super_admin', current_admin, 'reset_password', 
                    f'Reset password for {username} from IP: {request.remote_addr}')
        
        return jsonify({"success": True, "message": f"Password reset successfully for {username}"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/delete', methods=['POST'])
@require_super_admin_auth
def delete_admin():
    """Delete admin account (super admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        current_admin = payload.get('username')
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password_confirmation = data.get('password_confirmation', '')
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    if username == current_admin:
        return jsonify({"error": "Cannot delete your own account"}), 400
    
    # Require password confirmation for deletion
    if not password_confirmation:
        return jsonify({"error": "Password confirmation is required to delete accounts"}), 400
    
    # Verify current super admin password
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash FROM admins WHERE username = ? AND role = 'super_admin'", (current_admin,))
        current_user = cursor.fetchone()
        if not current_user or not verify_password(password_confirmation, current_user['password_hash']):
            log_activity('super_admin', current_admin, 'delete_admin_failed', 
                        f'Failed to delete account {username} - invalid password confirmation from IP: {request.remote_addr}')
            return jsonify({"error": "Password confirmation is incorrect"}), 401
    except Exception as e:
        logging.error(f"Password verification error: {e}")
        return jsonify({"error": "Password verification failed"}), 500
    finally:
        cursor.close()
        conn.close()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if user exists
        cursor.execute("SELECT id, role FROM admins WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Super admin account protection: Prevent deletion of any super admin account
        if user['role'] == 'super_admin':
            log_activity('super_admin', current_admin, 'delete_admin_blocked', 
                       f'Blocked deletion of super admin account: {username} from IP: {request.remote_addr}')
            return jsonify({"error": "Super administrator accounts cannot be deleted"}), 403
        
        # Delete user
        cursor.execute("DELETE FROM admins WHERE username = ?", (username,))
        conn.commit()
        
        # Enhanced logging for super admin actions
        log_activity('super_admin', current_admin, 'delete_admin', 
                    f'Deleted {user["role"]} account: {username} from IP: {request.remote_addr}')
        
        return jsonify({"success": True, "message": f"Admin account '{username}' deleted successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/admin/toggle_active', methods=['POST'])
@require_super_admin_auth
def toggle_active():
    """Enable/disable admin account (super admin only)"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        current_admin = payload.get('username')
    except:
        return jsonify({"error": "Invalid token"}), 401
    
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password_confirmation = data.get('password_confirmation', '')
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
    
    if username == current_admin:
        return jsonify({"error": "Cannot disable your own account"}), 400
    
    # Require password confirmation for disabling accounts
    if not password_confirmation:
        return jsonify({"error": "Password confirmation is required to enable/disable accounts"}), 400
    
    # Verify current super admin password
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password_hash FROM admins WHERE username = ? AND role = 'super_admin'", (current_admin,))
        current_user = cursor.fetchone()
        if not current_user or not verify_password(password_confirmation, current_user['password_hash']):
            log_activity('super_admin', current_admin, 'toggle_active_failed', 
                        f'Failed to toggle account {username} - invalid password confirmation from IP: {request.remote_addr}')
            return jsonify({"error": "Password confirmation is incorrect"}), 401
    finally:
        cursor.close()
        conn.close()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get current status and role
        cursor.execute("SELECT is_active, role FROM admins WHERE username = ?", (username,))
        user = cursor.fetchone()
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Super admin account protection: Prevent disabling any super admin account
        if user['role'] == 'super_admin':
            log_activity('super_admin', current_admin, 'toggle_active_blocked', 
                       f'Blocked disabling super admin account: {username} from IP: {request.remote_addr}')
            return jsonify({"error": "Super administrator accounts cannot be disabled"}), 403
        
        # Toggle status
        new_status = 0 if user['is_active'] == 1 else 1
        cursor.execute("UPDATE admins SET is_active = ? WHERE username = ?", (new_status, username))
        conn.commit()
        
        status_text = "enabled" if new_status == 1 else "disabled"
        # Enhanced logging for super admin actions
        log_activity('super_admin', current_admin, 'toggle_active', 
                    f'{status_text.capitalize()} {user["role"]} account: {username} from IP: {request.remote_addr}')
        
        return jsonify({
            "success": True,
            "message": f"Admin account '{username}' {status_text} successfully",
            "is_active": bool(new_status)
        })
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Transactions API
@app.route('/api/admin_transactions')
@require_admin_auth
def admin_transactions():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get revenue transactions
        cursor.execute("""
            SELECT created_at, type, full_name, amount, pin
            FROM topup_transactions
            ORDER BY created_at DESC
            LIMIT 100
        """)
        
        transactions = []
        for row in cursor.fetchall():
            transactions.append({
                "date": row[0],
                "type": row[1],
                "visitor": row[2],
                "amount": row[3],
                "stall_booth": row[4],
                "details": f"{row[1]} transaction"
            })
        
        # Get payment transactions
        cursor.execute("""
            SELECT time, customer, amount, name, staff
            FROM payments
            ORDER BY time DESC
            LIMIT 100
        """)
        
        for row in cursor.fetchall():
            transactions.append({
                "date": row[0],
                "type": "Payment",
                "visitor": row[1],
                "amount": row[2],
                "stall_booth": row[3],
                "details": f"Payment by {row[4] or 'Unknown'}"
            })
        
        # Sort by date (most recent first)
        transactions.sort(key=lambda x: x['date'], reverse=True)
        
        return jsonify({"transactions": transactions[:100]})  # Limit to 100 most recent
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    create_table_if_not_exists()  # Ensure the table is created
    apply_schema_upgrades()
    print("Starting Funfair QR Code Payment System with SQLite...")
    print("Open your browser and go to: http://localhost:5001")
    print("Press Ctrl+C to stop the server")
    app.run(debug=True, port=5001)
