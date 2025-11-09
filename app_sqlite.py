from flask import Flask, jsonify, request, render_template, send_file, session, redirect, url_for
import qrcode
import sqlite3
from PIL import Image, ImageDraw, ImageFont
import os
from flask_cors import CORS
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
import jwt
import secrets

app = Flask(__name__)
CORS(app)

# SQLite database configuration
DATABASE = 'funfair.db'

# Set up logging
logging.basicConfig(level=logging.INFO)

# Admin credentials (in production, use environment variables)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
SECRET_KEY = os.environ.get('SECRET_KEY', 'funfair-secret-key-2025')

app.secret_key = SECRET_KEY

def get_db_connection():
    """Get SQLite database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_table_if_not_exists():
    """Create all necessary database tables"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create coupons table
    create_coupons_table_query = '''
    CREATE TABLE IF NOT EXISTS coupons (
        ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        amount REAL,
        balance REAL,
        qr_code TEXT,
        issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        pin TEXT
    );
    '''

    # Create revenue table
    create_revenue_table_query = '''
    CREATE TABLE IF NOT EXISTS revenue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        amount REAL NOT NULL,
        pin TEXT,
        type TEXT CHECK(type IN ('Issue', 'Top up')) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''

    # Create counters table
    create_counters_table_query = '''
    CREATE TABLE IF NOT EXISTS counters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        staff TEXT,
        customer TEXT,
        time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''

    # Create authenticator table
    create_authenticator_table_query = '''
    CREATE TABLE IF NOT EXISTS authenticator (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT NOT NULL,
        counter TEXT,
        pass_key TEXT NOT NULL
    );
    '''

    # Create Generate_qr table
    create_generate_qr_table_query = '''
    CREATE TABLE IF NOT EXISTS Generate_qr (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Name TEXT NOT NULL,
        Pin TEXT NOT NULL
    );
    '''

    # Create admin table
    create_admin_table_query = '''
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    '''


    # Create system_logs table
    create_system_logs_table_query = '''
    CREATE TABLE IF NOT EXISTS system_logs (
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
        cursor.execute(create_coupons_table_query)
        cursor.execute(create_revenue_table_query)
        cursor.execute(create_counters_table_query)
        cursor.execute(create_authenticator_table_query)
        cursor.execute(create_generate_qr_table_query)
        cursor.execute(create_admin_table_query)
        cursor.execute(create_system_logs_table_query)
        conn.commit()
        logging.info("Database tables created successfully")
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

def issue_coupon(full_name, amount, pin):
    """Issue a new QR code coupon for a visitor"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the provided PIN is valid
    cursor.execute("SELECT pin FROM Generate_qr WHERE pin = ?", (pin,))
    pin_result = cursor.fetchone()
    
    if not pin_result:
        cursor.close()
        conn.close()
        raise ValueError("Incorrect PIN. Coupon not issued.")

    # Check if the user already exists
    cursor.execute("SELECT * FROM coupons WHERE full_name = ?", (full_name,))
    existing_user = cursor.fetchone()

    if existing_user:
        cursor.close()
        conn.close()
        raise ValueError("User already exists. Coupon not issued. Please try a different name.")

    # Insert coupon details into the database
    cursor.execute(
        "INSERT INTO coupons (full_name, amount, balance, qr_code, pin) VALUES (?, ?, ?, ?, ?)",
        (full_name, amount, amount, "", pin)
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
    cursor.execute("UPDATE coupons SET qr_code = ? WHERE ticket_id = ?", (qr_img_str, ticket_id))

    # Insert into revenue table for issued coupon with PIN
    cursor.execute("INSERT INTO revenue (full_name, amount, type, pin) VALUES (?, ?, 'Issue', ?)", (full_name, amount, pin))
    conn.commit()

    cursor.close()
    conn.close()

    return qr_img_str, ticket_id

# Helper functions
def log_activity(user_type, user_id, action, details="", ip_address=None):
    """Log system activity"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO system_logs (user_type, user_id, action, details, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_type, user_id, action, details, ip_address or request.remote_addr)
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
            if payload['role'] != 'admin':
                return jsonify({"error": "Admin access required"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
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
def admin_login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            # Create JWT token with shorter expiration for security
            token = jwt.encode({
                'username': username,
                'role': 'admin',
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # 1 hour instead of 24
            }, SECRET_KEY, algorithm='HS256')
            
            session['admin_token'] = token
            log_activity('admin', username, 'login', 'Successful admin login')
            
            return jsonify({
                "success": True,
                "token": token,
                "message": "Login successful"
            })
        else:
            log_activity('admin', username, 'login_failed', 'Failed login attempt')
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": "Server error"}), 500

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
        cursor.execute("SELECT full_name, balance FROM coupons WHERE ticket_id = ?", (ticket_id,))
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
        cursor.execute("SELECT ticket_id, full_name, balance, issue_date FROM coupons WHERE ticket_id = ?", (ticket_id,))
        result = cursor.fetchone()
        
        if result:
            ticket_id, visitor_name, balance, issue_date = result
            
            # Get list of stalls for authentication
            cursor.execute("SELECT user, pass_key FROM authenticator ORDER BY user")
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
        cursor.execute("SELECT SUM(amount) FROM revenue")
        total_revenue = cursor.fetchone()[0] or 0
        
        # QR codes issued today
        cursor.execute("SELECT COUNT(*) FROM coupons WHERE date(issue_date) = date('now')")
        qr_codes_today = cursor.fetchone()[0]
        
        # Top-ups today
        cursor.execute("SELECT COUNT(*) FROM revenue WHERE type = 'Top up' AND date(created_at) = date('now')")
        topups_today = cursor.fetchone()[0]
        
        # Recent transactions
        cursor.execute("""
            SELECT c.name, c.amount, c.customer, c.time 
            FROM counters c 
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
            FROM system_logs sl
            WHERE sl.action IN ('issue_coupon', 'topup_coupon', 'process_payment', 'admin_create_visitor')
            ORDER BY sl.timestamp DESC
            LIMIT 15
        """)
        recent_activity = cursor.fetchall()
        
        # Revenue by hour (last 24 hours)
        cursor.execute("""
            SELECT strftime('%H', time) as hour, SUM(amount) as total
            FROM counters 
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
def issue_coupon_route():
    data = request.get_json()
    full_name = data.get('full_name', '').strip()
    pin = (data.get('pin') or '').strip()
    try:
        amount = float(data.get('amount', 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    # Validate full name (must contain at least two words)
    if len(full_name.split(' ')) < 2:
        return jsonify({"error": "Please enter a full name (at least two words)."}), 400

    try:
        qr_code_img_str, ticket_id = issue_coupon(full_name, amount, pin)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    # Log the activity
    log_activity('alnoor_staff', pin, 'issue_coupon', f'Issued coupon for {full_name}, amount: {amount}')
    
    return jsonify({
        "message": "Coupon issued successfully",
        "qr_code_img_str": qr_code_img_str,
        "print_url": f"/print_qr?visitor_name={full_name}&ticket_id={ticket_id}&balance={amount}&issue_date={datetime.datetime.now().strftime('%Y-%m-%d')}&qr_image={qr_code_img_str}"
    })

@app.route('/topup_coupon', methods=['POST'])
def topup_coupon():
    data = request.get_json()
    full_name = data['full_name']
    amount_to_add = float(data['amount'])
    pin = data['pin']

    logging.info(f"Received top-up request for {full_name}, amount: {amount_to_add}, pin: {pin}")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if the provided name exists in the coupons table
        cursor.execute("SELECT * FROM coupons WHERE full_name = ?", (full_name,))
        coupons_result = cursor.fetchall()
        if not coupons_result:
            return jsonify({"success": False, "message": "Coupon not found for the provided name."}), 404
        
        # Validate the PIN by checking if it exists in the Generate_qr table
        cursor.execute("SELECT * FROM Generate_qr WHERE Pin = ?", (pin,))
        pin_result = cursor.fetchall()
        if not pin_result:
            return jsonify({"success": False, "message": "Invalid PIN provided."}), 403

        # Fetch current balance before update
        cursor.execute("SELECT balance FROM coupons WHERE full_name = ?", (full_name,))
        current_balance_row = cursor.fetchone()
        current_balance = float(current_balance_row[0]) if current_balance_row else 0.0

        # Update the coupon balance
        cursor.execute("UPDATE coupons SET balance = balance + ? WHERE full_name = ?", (amount_to_add, full_name))

        # Insert into revenue table including the PIN
        cursor.execute("INSERT INTO revenue (full_name, amount, pin, type) VALUES (?, ?, ?, 'Top up')", (full_name, amount_to_add, pin))
        conn.commit()

        # Get booth name for logging
        booth_name = pin_result[0][1] if pin_result else "Unknown Booth"
        
        # Log the activity
        log_activity('alnoor_staff', pin, 'topup_coupon', f'Recharged {full_name} with AED {amount_to_add} at booth {booth_name}')

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
                cursor.execute("SELECT ticket_id, full_name, balance, issue_date FROM coupons WHERE ticket_id = ?", (ticket_id_or_name,))
            else:
                cursor.execute("SELECT ticket_id, full_name, balance, issue_date FROM coupons WHERE full_name = ?", (ticket_id_or_name,))
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
                    cursor.execute("SELECT balance FROM coupons WHERE ticket_id = ?", (full_name,))
                else:
                    cursor.execute("SELECT balance FROM coupons WHERE full_name = ?", (full_name,))
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
            cursor.execute("SELECT balance FROM coupons WHERE ticket_id = ?", (ticket_id,))
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
        cursor.execute("SELECT counter FROM authenticator WHERE user = ?", (user,))
        counter_result = cursor.fetchone()
        selected_counter = counter_result[0] if counter_result else None

        logging.info(f"Received deduct request for ticket_id: {ticket_id}, amount: {amount_to_deduct}, counter: {selected_counter}, user: {user}")

        # Fetch the current balance
        cursor.execute("SELECT balance FROM coupons WHERE ticket_id = ?", (ticket_id,))
        result = cursor.fetchone()

        if result:
            current_balance = result[0]
            logging.info(f"Current balance for ticket_id {ticket_id}: {current_balance}")

            if current_balance >= amount_to_deduct:
                new_balance = current_balance - amount_to_deduct
                cursor.execute("UPDATE coupons SET balance = ? WHERE ticket_id = ?", (new_balance, ticket_id))
                conn.commit()

                # Fetch the customer's name based on ticket_id
                cursor.execute("SELECT full_name FROM coupons WHERE ticket_id = ?", (ticket_id,))
                customer_result = cursor.fetchone()
                customer_name = customer_result[0] if customer_result else None

                if selected_counter:
                    # Insert into counters table with time automatically captured
                    cursor.execute(
                        """
                        INSERT INTO counters (name, amount, staff, customer) 
                        VALUES (?, ?, ?, ?)
                        """,
                        (selected_counter, amount_to_deduct, user, customer_name)
                    )
                    conn.commit()
                else:
                    logging.warning(f"No counter found for user: {user}. Not inserting into counters table.")

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
    cursor.execute("SELECT counter FROM authenticator WHERE user = ?", (user,))
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
    
    # Fetch all users from the authenticator table
    cursor.execute("SELECT user FROM authenticator ORDER BY user ASC")
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

    cursor.execute("SELECT pass_key FROM authenticator WHERE user = ?", (user,))
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
        # Resolve user and counter by passkey
        cursor.execute("SELECT user, counter FROM authenticator WHERE pass_key = ?", (passkey,))
        auth_row = cursor.fetchone()
        if not auth_row:
            return jsonify({"error": "Invalid passkey"}), 403
        user, counter = auth_row

        # Fetch current balance and customer name
        cursor.execute("SELECT balance, full_name FROM coupons WHERE ticket_id = ?", (ticket_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "Coupon not found."}), 404
        current_balance, customer_name = row

        if float(current_balance) < amount_to_deduct:
            return jsonify({"error": "Insufficient balance."}), 400

        # Deduct and log transaction
        new_balance = float(current_balance) - amount_to_deduct
        cursor.execute("UPDATE coupons SET balance = ? WHERE ticket_id = ?", (new_balance, ticket_id))
        cursor.execute("INSERT INTO counters (name, amount, staff, customer) VALUES (?, ?, ?, ?)", (counter, amount_to_deduct, user, customer_name))
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
@require_admin_auth
def api_system_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT timestamp, user_type, user_id, action, details, ip_address
            FROM system_logs
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

@app.route('/generate_counters_report', methods=['GET'])
@require_admin_auth
def generate_counters_report():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT name, amount FROM counters")
        data = cursor.fetchall()

        if not data:
            return jsonify({"error": "No data available for counters."}), 404

        df = pd.DataFrame(data, columns=['Name', 'Amount'])
        excel_filename = "counters_report.xlsx"
        df.to_excel(excel_filename, index=False)

        plt.figure(figsize=(10, 6))
        plt.bar(df['Name'], df['Amount'], color='blue')
        plt.title('Counters Revenue Report')
        plt.xlabel('Name')
        plt.ylabel('Amount')
        plt.xticks(rotation=45)
        chart_filename = "counters_chart.png"
        plt.savefig(chart_filename)
        plt.close()

        zip_filename = "counters_report.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            zipf.write(excel_filename)
            zipf.write(chart_filename)

        return send_file(zip_filename, as_attachment=True)

    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error occurred."}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/generate_total_revenue_report', methods=['GET'])
@require_admin_auth
def generate_total_revenue_report():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT amount, type FROM revenue")
        revenue_data = cursor.fetchall()

        if not revenue_data:
            return jsonify({"error": "No data available for revenue."}), 404

        # Create a DataFrame
        df_revenue = pd.DataFrame(revenue_data, columns=['Amount', 'Type'])

        # Convert 'Amount' column to numeric, forcing errors to NaN
        df_revenue['Amount'] = pd.to_numeric(df_revenue['Amount'], errors='coerce')

        # Check for NaN values
        if df_revenue['Amount'].isnull().all():
            return jsonify({"error": "No valid numeric data to plot."}), 400

        # Generate Excel file
        revenue_excel_path = 'total_revenue_report.xlsx'
        df_revenue.to_excel(revenue_excel_path, index=False)

        # Create a bar chart
        plt.figure(figsize=(10, 6))
        df_revenue.groupby('Type')['Amount'].sum().plot(kind='bar', color='orange')
        plt.xlabel('Revenue Type')
        plt.ylabel('Total Amount')
        plt.title('Total Revenue by Type')
        plt.tight_layout()
        chart_path = 'total_revenue_chart.png'
        plt.savefig(chart_path)
        plt.close()

        # Create a zip file
        zip_filename = 'total_revenue_report.zip'
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            zipf.write(revenue_excel_path)
            zipf.write(chart_path)

        return send_file(zip_filename, as_attachment=True)

    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error occurred."}), 500
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

@app.route('/alnoor-staff')
def alnoor_staff():
    return render_template('alnoor_staff.html')

@app.route('/issue-coupon')
def issue_coupon_page():
    return render_template('issue_coupon.html')

@app.route('/recharge-coupon')
def recharge_coupon_page():
    return render_template('recharge_coupon.html')

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
        if payload['role'] != 'admin':
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
    staff_passkey = data.get('staff_passkey', '').strip()
    corporate_account = data.get('corporate_account', '').strip()
    
    if not corporate_name or not staff_passkey:
        return jsonify({"error": "Corporate name and passkey are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if corporate already exists
        cursor.execute("SELECT id FROM authenticator WHERE user = ?", (corporate_name,))
        if cursor.fetchone():
            return jsonify({"error": "Corporate account already exists"}), 400
        
        # Create corporate account
        cursor.execute("INSERT INTO authenticator (user, counter, pass_key) VALUES (?, ?, ?)", 
                      (corporate_name, corporate_name, staff_passkey))
        
        
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
            SELECT user, pass_key, counter
            FROM authenticator
            ORDER BY user
        """)
        
        stalls = []
        for row in cursor.fetchall():
            stalls.append({
                "corporate_name": row[0],
                "staff_passkey": row[1],
                "counter": row[2]
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

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM authenticator WHERE user = ?", (corporate_name,))
        if not cursor.fetchone():
            return jsonify({"error": "Corporate not found"}), 404

        updates = []
        params = []
        if new_passkey:
            updates.append("pass_key = ?")
            params.append(new_passkey)
        if new_counter:
            updates.append("counter = ?")
            params.append(new_counter)
        if not updates:
            return jsonify({"error": "No fields to update"}), 400

        params.append(corporate_name)
        sql = f"UPDATE authenticator SET {', '.join(updates)} WHERE user = ?"
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
        cursor.execute("DELETE FROM authenticator WHERE user = ?", (corporate_name,))
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
        cursor.execute("SELECT COUNT(*) FROM coupons")
        total_visitors = cursor.fetchone()[0]
        
        # Get total revenue (from both issues and top-ups)
        cursor.execute("SELECT SUM(amount) FROM revenue")
        total_revenue = cursor.fetchone()[0] or 0
        
        # Get total transactions (all revenue entries)
        cursor.execute("SELECT COUNT(*) FROM revenue")
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
            FROM coupons
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
        cursor.execute("DELETE FROM coupons WHERE ticket_id = ?", (ticket_id,))
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
        cursor.execute("SELECT full_name FROM coupons WHERE ticket_id = ?", (ticket_id,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"error": "Visitor not found"}), 404

        if new_full_name:
            cursor.execute("SELECT 1 FROM coupons WHERE full_name = ? AND ticket_id != ?", (new_full_name, ticket_id))
            if cursor.fetchone():
                return jsonify({"error": "Full name already exists"}), 400
            cursor.execute("UPDATE coupons SET full_name = ? WHERE ticket_id = ?", (new_full_name, ticket_id))
            conn.commit()

        log_activity('admin', 'system', 'update_visitor', f"Updated visitor {ticket_id}")
        return jsonify({"success": True})
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Booth Staff API
@app.route('/api/admin_alnoor_staff')
@require_admin_auth
def admin_alnoor_staff():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT Name, Pin FROM Generate_qr ORDER BY Name")
        
        booths = []
        for row in cursor.fetchall():
            booths.append({
                "alnoor_name": row[0],
                "alnoor_pin": row[1],
                "location": "Not specified"  # Can be enhanced later
            })
        
        return jsonify({"alnoor_pins": booths})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()


# Admin Create Booth API
@app.route('/api/admin_create_booth', methods=['POST'])
@require_admin_auth
def admin_create_booth():
    data = request.get_json() or {}
    booth_name = (data.get('booth_name') or '').strip()
    booth_pin = (data.get('booth_pin') or '').strip()
    
    if not booth_name or not booth_pin:
        return jsonify({"error": "booth_name and booth_pin are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if booth name already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (booth_name,))
        if cursor.fetchone():
            return jsonify({"error": "Booth name already exists"}), 400
        
        # Check if PIN already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Pin = ?", (booth_pin,))
        if cursor.fetchone():
            return jsonify({"error": "PIN already exists"}), 400
        
        # Create booth in Generate_qr table
        cursor.execute("INSERT INTO Generate_qr (Name, Pin) VALUES (?, ?)", (booth_name, booth_pin))
        
        # Create corresponding stall account in authenticator table
        cursor.execute("INSERT INTO authenticator (user, counter, pass_key) VALUES (?, ?, ?)", 
                      (booth_name, booth_name, booth_pin))
        
        conn.commit()
        
        log_activity('admin', 'system', 'create_booth', f"Created booth: {booth_name}")
        return jsonify({"success": True, "message": f"Booth '{booth_name}' created successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Update Booth Name API
@app.route('/api/admin_update_booth_name', methods=['POST'])
@require_admin_auth
def admin_update_booth_name():
    data = request.get_json() or {}
    old_booth_name = (data.get('old_booth_name') or '').strip()
    new_booth_name = (data.get('new_booth_name') or '').strip()
    
    if not old_booth_name or not new_booth_name:
        return jsonify({"error": "old_booth_name and new_booth_name are required"}), 400
    
    if old_booth_name == new_booth_name:
        return jsonify({"error": "New name must be different from current name"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if old booth exists
        cursor.execute("SELECT Pin FROM Generate_qr WHERE Name = ?", (old_booth_name,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"error": "Booth not found"}), 404
        
        # Check if new booth name already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (new_booth_name,))
        if cursor.fetchone():
            return jsonify({"error": "Booth name already exists"}), 400
        
        # Update booth name in Generate_qr table
        cursor.execute("UPDATE Generate_qr SET Name = ? WHERE Name = ?", (new_booth_name, old_booth_name))
        
        # Update booth name in authenticator table
        cursor.execute("UPDATE authenticator SET user = ?, counter = ? WHERE user = ?", 
                      (new_booth_name, new_booth_name, old_booth_name))
        
        conn.commit()
        
        log_activity('admin', 'system', 'update_booth_name', f"Updated booth name from {old_booth_name} to {new_booth_name}")
        return jsonify({"success": True, "message": f"Booth name updated from '{old_booth_name}' to '{new_booth_name}'"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Update Booth PIN API
@app.route('/api/admin_update_booth_pin', methods=['POST'])
@require_admin_auth
def admin_update_booth_pin():
    data = request.get_json() or {}
    booth_name = (data.get('booth_name') or '').strip()
    new_pin = (data.get('new_pin') or '').strip()
    
    if not booth_name or not new_pin:
        return jsonify({"error": "booth_name and new_pin are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if booth exists
        cursor.execute("SELECT Pin FROM Generate_qr WHERE Name = ?", (booth_name,))
        existing = cursor.fetchone()
        if not existing:
            return jsonify({"error": "Booth not found"}), 404
        
        # Check if new PIN already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Pin = ? AND Name != ?", (new_pin, booth_name))
        if cursor.fetchone():
            return jsonify({"error": "PIN already exists for another booth"}), 400
        
        # Update the PIN in Generate_qr table
        cursor.execute("UPDATE Generate_qr SET Pin = ? WHERE Name = ?", (new_pin, booth_name))
        
        # Update the PIN in authenticator table
        cursor.execute("UPDATE authenticator SET pass_key = ? WHERE user = ?", (new_pin, booth_name))
        
        conn.commit()
        
        log_activity('admin', 'system', 'update_booth_pin', f"Updated booth {booth_name} PIN")
        return jsonify({"success": True, "message": f"Booth {booth_name} PIN updated successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Delete Booth API
@app.route('/api/admin_delete_booth', methods=['POST'])
@require_admin_auth
def admin_delete_booth():
    data = request.get_json() or {}
    booth_name = (data.get('booth_name') or '').strip()
    
    if not booth_name:
        return jsonify({"error": "booth_name is required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if booth exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (booth_name,))
        if not cursor.fetchone():
            return jsonify({"error": "Booth not found"}), 404
        
        # Delete from Generate_qr table
        cursor.execute("DELETE FROM Generate_qr WHERE Name = ?", (booth_name,))
        
        # Delete from authenticator table
        cursor.execute("DELETE FROM authenticator WHERE user = ?", (booth_name,))
        
        conn.commit()
        
        log_activity('admin', 'system', 'delete_booth', f"Deleted booth: {booth_name}")
        return jsonify({"success": True, "message": f"Booth '{booth_name}' deleted successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Create Alnoor API (alias for booth)
@app.route('/api/admin_create_alnoor', methods=['POST'])
@require_admin_auth
def admin_create_alnoor():
    data = request.get_json() or {}
    alnoor_name = (data.get('alnoor_name') or '').strip()
    alnoor_pin = (data.get('alnoor_pin') or '').strip()
    
    if not alnoor_name or not alnoor_pin:
        return jsonify({"error": "alnoor_name and alnoor_pin are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if alnoor name already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (alnoor_name,))
        if cursor.fetchone():
            return jsonify({"error": "Alnoor name already exists"}), 400
        
        # Check if PIN already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Pin = ?", (alnoor_pin,))
        if cursor.fetchone():
            return jsonify({"error": "PIN already exists"}), 400
        
        # Create alnoor in Generate_qr table
        cursor.execute("INSERT INTO Generate_qr (Name, Pin) VALUES (?, ?)", (alnoor_name, alnoor_pin))
        
        # Create corresponding stall account in authenticator table
        cursor.execute("INSERT INTO authenticator (user, counter, pass_key) VALUES (?, ?, ?)", 
                      ('alnoor_staff', alnoor_name, alnoor_pin))
        
        conn.commit()
        
        log_activity('admin', 'system', 'create_alnoor', f"Created alnoor: {alnoor_name}")
        return jsonify({"success": True, "message": f"Alnoor '{alnoor_name}' created successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Update Alnoor Name API
@app.route('/api/admin_update_alnoor_name', methods=['POST'])
@require_admin_auth
def admin_update_alnoor_name():
    data = request.get_json() or {}
    old_alnoor_name = (data.get('old_alnoor_name') or '').strip()
    new_alnoor_name = (data.get('new_alnoor_name') or '').strip()
    
    if not old_alnoor_name or not new_alnoor_name:
        return jsonify({"error": "old_alnoor_name and new_alnoor_name are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if old alnoor exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (old_alnoor_name,))
        if not cursor.fetchone():
            return jsonify({"error": "Alnoor not found"}), 404
        
        # Check if new name already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (new_alnoor_name,))
        if cursor.fetchone():
            return jsonify({"error": "New alnoor name already exists"}), 400
        
        # Update alnoor name in Generate_qr table
        cursor.execute("UPDATE Generate_qr SET Name = ? WHERE Name = ?", (new_alnoor_name, old_alnoor_name))
        
        # Update corresponding counter in authenticator table
        cursor.execute("UPDATE authenticator SET counter = ? WHERE counter = ?", (new_alnoor_name, old_alnoor_name))
        
        conn.commit()
        
        log_activity('admin', 'system', 'update_alnoor_name', f"Updated alnoor name from {old_alnoor_name} to {new_alnoor_name}")
        return jsonify({"success": True, "message": f"Alnoor name updated from '{old_alnoor_name}' to '{new_alnoor_name}'"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Update Alnoor PIN API
@app.route('/api/admin_update_alnoor_pin', methods=['POST'])
@require_admin_auth
def admin_update_alnoor_pin():
    data = request.get_json() or {}
    alnoor_name = (data.get('alnoor_name') or '').strip()
    new_pin = (data.get('new_pin') or '').strip()
    
    if not alnoor_name or not new_pin:
        return jsonify({"error": "alnoor_name and new_pin are required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if alnoor exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (alnoor_name,))
        if not cursor.fetchone():
            return jsonify({"error": "Alnoor not found"}), 404
        
        # Check if new PIN already exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Pin = ?", (new_pin,))
        if cursor.fetchone():
            return jsonify({"error": "PIN already exists"}), 400
        
        # Update PIN in Generate_qr table
        cursor.execute("UPDATE Generate_qr SET Pin = ? WHERE Name = ?", (new_pin, alnoor_name))
        
        # Update corresponding pass_key in authenticator table
        cursor.execute("UPDATE authenticator SET pass_key = ? WHERE counter = ?", (new_pin, alnoor_name))
        
        conn.commit()
        
        log_activity('admin', 'system', 'update_alnoor_pin', f"Updated alnoor {alnoor_name} PIN")
        return jsonify({"success": True, "message": f"Alnoor '{alnoor_name}' PIN updated successfully"})
        
    except sqlite3.Error as err:
        logging.error(f"Database error: {err}")
        return jsonify({"error": "Database error"}), 500
    finally:
        cursor.close()
        conn.close()

# Admin Delete Alnoor API
@app.route('/api/admin_delete_alnoor', methods=['POST'])
@require_admin_auth
def admin_delete_alnoor():
    data = request.get_json() or {}
    alnoor_name = (data.get('alnoor_name') or '').strip()
    
    if not alnoor_name:
        return jsonify({"error": "alnoor_name is required"}), 400
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if alnoor exists
        cursor.execute("SELECT Name FROM Generate_qr WHERE Name = ?", (alnoor_name,))
        if not cursor.fetchone():
            return jsonify({"error": "Alnoor not found"}), 404
        
        # Delete alnoor from Generate_qr table
        cursor.execute("DELETE FROM Generate_qr WHERE Name = ?", (alnoor_name,))
        
        # Delete corresponding entry from authenticator table
        cursor.execute("DELETE FROM authenticator WHERE counter = ?", (alnoor_name,))
        
        conn.commit()
        
        log_activity('admin', 'system', 'delete_alnoor', f"Deleted alnoor: {alnoor_name}")
        return jsonify({"success": True, "message": f"Alnoor '{alnoor_name}' deleted successfully"})
        
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
            FROM revenue
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
            FROM counters
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
    print("🚀 Starting Funfair QR Code Payment System with SQLite...")
    print("📱 Open your browser and go to: http://localhost:5001")
    print("🛑 Press Ctrl+C to stop the server")
    app.run(debug=True, port=5001)
