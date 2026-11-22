from flask import Flask, request, jsonify, session
import sqlite3
from argon2 import PasswordHasher
import pyotp
import secrets
import re
import time
import math
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

# Server-side Pepper (Defense in Depth for Password Hashing)
SERVER_PEPPER = os.environ.get('SECURESHOP_PEPPER', 'SUT_CET431_PEPPER_2026_SECRET_KEY')
ph = PasswordHasher()

DB_NAME = 'secureshop.db'

BREACHED_PASSWORDS = {
    '123456', '12345678', '123456789', 'password', 'password123',
    'admin123', 'qwerty123', 'welcome123', 'letmein', 'iloveyou', '11111111'
}

# In-memory rate limiter for non-login sensitive endpoints (e.g., /confirm)
FAILED_ATTEMPTS_TRACKER = {}

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def log_audit(conn, user_id, username, action, details, status='INFO'):
    ip = request.remote_addr or '127.0.0.1'
    conn.execute(
        """INSERT INTO audit_logs (user_id, username, action, details, ip_address, status)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, username or 'Anonymous', action, details, ip, status)
    )

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            last_totp_step INTEGER DEFAULT 0,
            confirmation_code TEXT NOT NULL,
            is_confirmed INTEGER DEFAULT 0,
            store_credit REAL DEFAULT 1000.00,
            role TEXT DEFAULT 'user',
            failed_attempts INTEGER DEFAULT 0,
            locked_until REAL DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT DEFAULT 'General',
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 10
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS coupons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            discount_percent REAL NOT NULL,
            active INTEGER DEFAULT 1
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            items_summary TEXT NOT NULL,
            total_paid REAL NOT NULL,
            coupon_used TEXT,
            status TEXT DEFAULT 'Confirmed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS newsletter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            issued_coupon TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT DEFAULT 'INFO',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed Admin Account
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """INSERT INTO users (username, email, password_hash, totp_secret, confirmation_code, is_confirmed, store_credit, role)
               VALUES (?, ?, ?, ?, ?, 1, 5000.00, 'admin')""",
            ("admin", "admin@secureshop.local", ph.hash("AdminSecret2026!" + SERVER_PEPPER), "JBSWY3DPEHPK3PXP", "CONF00")
        )

    # Seed Normal Test User
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'omar'")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """INSERT INTO users (username, email, password_hash, totp_secret, confirmation_code, is_confirmed, store_credit, role)
               VALUES (?, ?, ?, ?, ?, 1, 1000.00, 'user')""",
            ("omar", "omar@secureshop.local", ph.hash("UserSecret2026!" + SERVER_PEPPER), "JBSWY3DPEHPK3PXP", "CONF01")
        )

    # Seed Products
    cursor.execute("SELECT COUNT(*) FROM products")
    if cursor.fetchone()[0] == 0:
        products = [
            ('Gaming Laptop', 'Computers', 'High-performance laptop with 16GB RAM and dedicated GPU.', 1500.00, 5),
            ('Noise-Cancelling Headphones', 'Audio', 'Wireless over-ear headphones with 30h battery life.', 200.00, 15),
            ('Mechanical Keyboard', 'Accessories', 'Tactile RGB mechanical keyboard with aluminum frame.', 100.00, 20),
            ('4K USB-C Monitor', 'Computers', '27-inch IPS UHD monitor for creators and developers.', 450.00, 8),
            ('Hardware Security Key', 'Security', 'FIDO2 / TOTP hardware authentication security token.', 50.00, 30)
        ]
        cursor.executemany(
            "INSERT INTO products (name, category, description, price, stock) VALUES (?, ?, ?, ?, ?)",
            products
        )

    # Seed Coupons
    cursor.execute("SELECT COUNT(*) FROM coupons")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO coupons (code, discount_percent, active) VALUES (?, ?, 1)",
            [('WELCOME20', 0.20), ('NEWSLETTER10', 0.10)]
        )

    conn.commit()
    conn.close()

init_db()

# --- Security Headers & Global Fail-Secure Error Handlers ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    return response

@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "Requested resource was not found."}), 404

@app.errorhandler(405)
def handle_405(e):
    return jsonify({"error": "HTTP method not allowed on this endpoint."}), 405

@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify({"error": "An unexpected server error occurred."}), 500

@app.before_request
def csrf_protect():
    if request.method in ('POST', 'PUT', 'DELETE'):
        token = request.headers.get('X-CSRF-Token')
        if not token or not session.get('csrf_token') or not secrets.compare_digest(token, session.get('csrf_token')):
            return jsonify({"error": "CSRF validation failed. Please refresh the page."}), 403

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required."}), 401
        # Re-verify user existence & active state in DB against mid-session deletion/deactivation
        conn = get_db()
        user = conn.execute("SELECT id, role, is_confirmed FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        conn.close()
        if not user or user['is_confirmed'] == 0:
            session.clear()
            return jsonify({"error": "Session invalidated. Please log in again."}), 401
        session['role'] = user['role']
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Authentication required."}), 401
        # Always verify live admin role in DB (handles mid-session demotion)
        conn = get_db()
        user = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user or user['role'] != 'admin':
            log_audit(conn, session.get('user_id'), session.get('username'), 'UNAUTHORIZED_ADMIN_ACCESS', f'Attempted access to {request.path}', 'ALERT')
            conn.commit()
            conn.close()
            return jsonify({"error": "Forbidden: Admin privileges required."}), 403
        conn.close()
        return f(*args, **kwargs)
    return decorated

def is_strong_password(password):
    if len(password) < 8 or password.lower() in BREACHED_PASSWORDS:
        return False
    if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'\d', password):
        return False
    return True

def is_valid_email(email):
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))

def contains_html_tags(text):
    return bool(re.search(r'[<>]', str(text)))

# --- Session & CSRF Bootstrap ---
@app.route('/session', methods=['GET'])
def get_session_state():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute(
            "SELECT id, username, email, store_credit, role FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        conn.close()
        if user:
            return jsonify({
                "logged_in": True,
                "csrf_token": session['csrf_token'],
                "user": dict(user)
            }), 200
    return jsonify({"logged_in": False, "csrf_token": session['csrf_token']}), 200

# --- 1. Registration, Confirmation, Login & Logout ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = str(data.get('password', ''))

    if not re.match(r'^[a-zA-Z0-9_]{3,25}$', username):
        return jsonify({"error": "Username must be 3-25 alphanumeric characters."}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Password must be 8+ chars with uppercase, lowercase, a digit, and not be a common breached password."}), 400

    conn = get_db()
    try:
        hashed_pw = ph.hash(password + SERVER_PEPPER)
        totp_secret = pyotp.random_base32()
        confirm_code = secrets.token_hex(3).upper()

        cursor = conn.execute(
            """INSERT INTO users (username, email, password_hash, totp_secret, confirmation_code, is_confirmed)
               VALUES (?, ?, ?, ?, ?, 0)""",
            (username, email, hashed_pw, totp_secret, confirm_code)
        )
        log_audit(conn, cursor.lastrowid, username, 'REGISTER', 'New account registered (pending confirmation)', 'INFO')
        conn.commit()
        conn.close()

        return jsonify({
            "message": "Account created! Confirm it with the code below before logging in.",
            "confirmation_code": confirm_code,
            "totp_secret": totp_secret
        }), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username or email already exists."}), 409

@app.route('/confirm', methods=['POST'])
def confirm_account():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    code = str(data.get('confirmation_code', '')).strip().upper()

    if not username or not code:
        return jsonify({"error": "Username and confirmation code are required."}), 400

    # Rate-limit confirmation brute-force attempts
    key = f"confirm:{request.remote_addr}:{username}"
    now = time.time()
    record = FAILED_ATTEMPTS_TRACKER.get(key, {"count": 0, "locked_until": 0})
    if record["locked_until"] > now:
        return jsonify({"error": "Too many confirmation attempts. Try again later."}), 429

    conn = get_db()
    user = conn.execute(
        "SELECT id, confirmation_code, is_confirmed FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user or not secrets.compare_digest(user['confirmation_code'], code):
        record["count"] += 1
        if record["count"] >= 5:
            record["locked_until"] = now + 60
            record["count"] = 0
        FAILED_ATTEMPTS_TRACKER[key] = record
        log_audit(conn, None, username, 'ACCOUNT_CONFIRM_FAILED', 'Invalid confirmation attempt', 'WARN')
        conn.commit()
        conn.close()
        return jsonify({"error": "Invalid confirmation details."}), 400

    FAILED_ATTEMPTS_TRACKER.pop(key, None)
    if user['is_confirmed'] == 1:
        conn.close()
        return jsonify({"message": "Account is already confirmed."}), 200

    conn.execute("UPDATE users SET is_confirmed = 1 WHERE id = ?", (user['id'],))
    log_audit(conn, user['id'], username, 'ACCOUNT_CONFIRMED', 'Account verified and activated', 'INFO')
    conn.commit()
    conn.close()
    return jsonify({"message": "Account confirmed! You can now log in."}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))
    otp_code = str(data.get('otp', '')).strip()

    if not username or not password or not otp_code:
        return jsonify({"error": "Username, password, and 6-digit MFA code are required."}), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not user:
        log_audit(conn, None, username, 'LOGIN_FAILED', 'Unknown username', 'WARN')
        conn.commit()
        conn.close()
        return jsonify({"error": "Invalid credentials or MFA code."}), 401

    now = time.time()
    if user['locked_until'] and user['locked_until'] > now:
        remaining = int(user['locked_until'] - now)
        log_audit(conn, user['id'], username, 'LOGIN_BLOCKED_LOCKOUT', f'Locked account login attempt ({remaining}s left)', 'ALERT')
        conn.commit()
        conn.close()
        return jsonify({"error": f"Account temporarily locked. Try again in {remaining}s."}), 429

    if user['is_confirmed'] == 0:
        conn.close()
        return jsonify({"error": "Account not confirmed yet. Please confirm your account first."}), 403

    try:
        ph.verify(user['password_hash'], password + SERVER_PEPPER)
        totp = pyotp.TOTP(user['totp_secret'])
        if not totp.verify(otp_code, valid_window=1):
            raise ValueError("Invalid OTP")

        # Anti-Replay Check for TOTP
        current_step = int(now // 30)
        if current_step <= (user['last_totp_step'] or 0):
            log_audit(conn, user['id'], username, 'TOTP_REPLAY_BLOCKED', 'Attempted reuse of already-consumed TOTP step', 'ALERT')
            conn.commit()
            conn.close()
            return jsonify({"error": "This MFA code has already been used. Wait for the next 30-second code."}), 401

    except Exception:
        attempts = user['failed_attempts'] + 1
        lock_time = now + 60 if attempts >= 5 else 0
        conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (0 if attempts >= 5 else attempts, lock_time, user['id'])
        )
        status = 'ALERT' if attempts >= 5 else 'WARN'
        detail = 'Account locked for 60s after 5 failed attempts' if attempts >= 5 else f'Failed attempt {attempts}/5'
        log_audit(conn, user['id'], username, 'LOGIN_FAILED', detail, status)
        conn.commit()
        conn.close()
        return jsonify({"error": "Invalid credentials or MFA code."}), 401

    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = 0, last_totp_step = ? WHERE id = ?",
        (current_step, user['id'])
    )
    log_audit(conn, user['id'], username, 'LOGIN_SUCCESS', f'Authenticated with Argon2id + TOTP (Role: {user["role"]})', 'INFO')
    conn.commit()
    conn.close()

    # Session regeneration (Anti-Session Fixation)
    session.clear()
    session['csrf_token'] = secrets.token_hex(32)
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']

    return jsonify({
        "message": f"Welcome back, {user['username']}!",
        "csrf_token": session['csrf_token'],
        "user": {
            "id": user['id'],
            "username": user['username'],
            "email": user['email'],
            "store_credit": user['store_credit'],
            "role": user['role']
        }
    }), 200

@app.route('/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    uname = session.get('username')
    if uid:
        conn = get_db()
        log_audit(conn, uid, uname, 'LOGOUT', 'User logged out', 'INFO')
        conn.commit()
        conn.close()
    session.clear()
    session['csrf_token'] = secrets.token_hex(32)
    return jsonify({"message": "Logged out safely.", "csrf_token": session['csrf_token']}), 200

# --- 2. Product Catalogue, Detail & Search/Filtering ---
@app.route('/products', methods=['GET'])
def get_products():
    search = request.args.get('search', '').strip()
    category = request.args.get('category', '').strip()

    query = "SELECT id, name, category, description, price, stock FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND (name LIKE ? OR description LIKE ?)"
        params.extend([f'%{search}%', f'%{search}%'])
    if category and category.lower() != 'all':
        query += " AND category = ?"
        params.append(category)

    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product_detail(product_id):
    conn = get_db()
    row = conn.execute(
        "SELECT id, name, category, description, price, stock FROM products WHERE id = ?",
        (product_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Product not found."}), 404
    return jsonify(dict(row)), 200

# --- 3. Shopping Cart (Add, Update Quantity, Remove) ---
@app.route('/cart', methods=['GET'])
@login_required
def view_cart():
    return jsonify(session.get('cart', {})), 200

@app.route('/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    data = request.get_json(silent=True) or {}
    if 'price' in data or 'total' in data:
        conn = get_db()
        log_audit(conn, session['user_id'], session['username'], 'PRICE_TAMPERING_ATTEMPT', 'Client sent unauthorized price field to /cart/add', 'ALERT')
        conn.commit()
        conn.close()
        return jsonify({"error": "Security alert: Client-side price parameters are rejected."}), 400

    try:
        product_id = int(data.get('product_id'))
        quantity = int(data.get('quantity', 1))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid product ID or quantity."}), 400

    if quantity <= 0 or quantity > 50:
        return jsonify({"error": "Quantity must be between 1 and 50."}), 400

    conn = get_db()
    product = conn.execute("SELECT id, name, price, stock FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()

    if not product:
        return jsonify({"error": "Product not found."}), 404

    cart = session.get('cart', {})
    pid = str(product_id)
    current_qty = cart[pid]['quantity'] if pid in cart else 0

    if current_qty + quantity > product['stock']:
        return jsonify({"error": f"Only {product['stock']} units available in stock."}), 400

    if pid in cart:
        cart[pid]['quantity'] += quantity
    else:
        cart[pid] = {
            "product_id": product['id'],
            "name": product['name'],
            "price": product['price'],
            "quantity": quantity
        }

    session['cart'] = cart
    session.modified = True
    return jsonify({"message": "Added to cart.", "cart": cart}), 200

@app.route('/cart/update', methods=['POST'])
@login_required
def update_cart_quantity():
    data = request.get_json(silent=True) or {}
    try:
        product_id = int(data.get('product_id'))
        quantity = int(data.get('quantity'))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid input."}), 400

    cart = session.get('cart', {})
    pid = str(product_id)
    if pid not in cart:
        return jsonify({"error": "Item not in cart."}), 404

    if quantity <= 0:
        del cart[pid]
        session['cart'] = cart
        session.modified = True
        return jsonify({"message": "Item removed from cart.", "cart": cart}), 200

    conn = get_db()
    product = conn.execute("SELECT stock FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()

    if not product or quantity > product['stock']:
        return jsonify({"error": "Requested quantity exceeds available stock."}), 400

    cart[pid]['quantity'] = quantity
    session['cart'] = cart
    session.modified = True
    return jsonify({"message": "Quantity updated.", "cart": cart}), 200

@app.route('/cart/remove', methods=['POST'])
@login_required
def remove_from_cart():
    data = request.get_json(silent=True) or {}
    pid = str(data.get('product_id', ''))
    cart = session.get('cart', {})
    if pid in cart:
        del cart[pid]
        session['cart'] = cart
        session.modified = True
        return jsonify({"message": "Item removed.", "cart": cart}), 200
    return jsonify({"error": "Item not found in cart."}), 404

# --- 4. Coupons & Newsletter ---
@app.route('/newsletter', methods=['POST'])
def newsletter_signup():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip().lower()
    if not is_valid_email(email):
        return jsonify({"error": "Please enter a valid email address."}), 400

    conn = get_db()
    existing = conn.execute("SELECT issued_coupon FROM newsletter WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({
            "message": f"Already subscribed! Use coupon code: {existing['issued_coupon']}",
            "coupon_code": existing['issued_coupon']
        }), 200

    conn.execute("INSERT INTO newsletter (email, issued_coupon) VALUES (?, 'NEWSLETTER10')", (email,))
    conn.commit()
    conn.close()
    return jsonify({
        "message": "Subscribed! Your 10% coupon code is: NEWSLETTER10",
        "coupon_code": "NEWSLETTER10"
    }), 201

# --- 5. Checkout & Orders ---
@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    data = request.get_json(silent=True) or {}
    if any(k in data for k in ('price', 'total', 'total_paid', 'discount')):
        conn = get_db()
        log_audit(conn, session['user_id'], session['username'], 'CHECKOUT_TAMPERING_ATTEMPT', 'Client submitted forged price/discount fields', 'ALERT')
        conn.commit()
        conn.close()
        return jsonify({"error": "Security alert: Price/discount tampering rejected."}), 400

    cart = session.get('cart', {})
    if not cart:
        return jsonify({"error": "Your cart is empty."}), 400

    coupon_code = str(data.get('coupon_code', '')).strip().upper()
    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        discount = 0.0
        if coupon_code:
            coupon = conn.execute(
                "SELECT discount_percent FROM coupons WHERE code = ? AND active = 1",
                (coupon_code,)
            ).fetchone()
            if not coupon:
                conn.rollback()
                conn.close()
                return jsonify({"error": "Invalid or inactive coupon code."}), 400
            discount = coupon['discount_percent']

        total_amount = 0.0
        summary_parts = []
        for pid, item in cart.items():
            db_prod = conn.execute(
                "SELECT id, name, price, stock FROM products WHERE id = ?",
                (int(pid),)
            ).fetchone()
            qty = int(item['quantity'])
            if not db_prod or qty <= 0 or db_prod['stock'] < qty:
                conn.rollback()
                conn.close()
                return jsonify({"error": f"Insufficient stock for {item.get('name', 'item')}."}), 400
            total_amount += db_prod['price'] * qty
            summary_parts.append(f"{db_prod['name']} (x{qty})")

        final_total = round(total_amount * (1.0 - discount), 2)
        user_id = session['user_id']
        user = conn.execute("SELECT store_credit FROM users WHERE id = ?", (user_id,)).fetchone()

        if user['store_credit'] < final_total:
            conn.rollback()
            conn.close()
            return jsonify({"error": "Insufficient store credit for this order."}), 402

        new_credit = round(user['store_credit'] - final_total, 2)
        conn.execute("UPDATE users SET store_credit = ? WHERE id = ?", (new_credit, user_id))

        for pid, item in cart.items():
            conn.execute(
                "UPDATE products SET stock = stock - ? WHERE id = ?",
                (int(item['quantity']), int(pid))
            )

        items_summary = ", ".join(summary_parts)
        cursor = conn.execute(
            """INSERT INTO orders (user_id, items_summary, total_paid, coupon_used, status)
               VALUES (?, ?, ?, ?, 'Confirmed')""",
            (user_id, items_summary, final_total, coupon_code or None)
        )
        order_id = cursor.lastrowid
        log_audit(conn, user_id, session['username'], 'ORDER_CONFIRMED', f'Order #{order_id} paid ${final_total:.2f}', 'INFO')
        conn.commit()
        conn.close()

        session.pop('cart', None)
        session.modified = True

        return jsonify({
            "message": "Order confirmed!",
            "order": {
                "order_id": order_id,
                "items_summary": items_summary,
                "total_paid": final_total,
                "coupon_used": coupon_code or "None",
                "status": "Confirmed"
            },
            "remaining_credit": new_credit
        }), 200
    except Exception:
        conn.rollback()
        conn.close()
        return jsonify({"error": "Checkout failed. Please try again."}), 500

@app.route('/orders', methods=['GET'])
@login_required
def get_user_orders():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, items_summary, total_paid, coupon_used, status, created_at FROM orders WHERE user_id = ? ORDER BY id DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

# --- 6. User Account Page (View & Update Profile) ---
@app.route('/account', methods=['GET', 'PUT'])
@login_required
def user_account():
    user_id = session['user_id']
    conn = get_db()

    if request.method == 'GET':
        user = conn.execute(
            "SELECT id, username, email, store_credit, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        conn.close()
        return jsonify(dict(user)), 200

    data = request.get_json(silent=True) or {}
    new_email = str(data.get('email', '')).strip().lower()
    current_password = str(data.get('current_password', ''))
    new_password = str(data.get('new_password', ''))

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    try:
        if new_email and new_email != user['email']:
            if not is_valid_email(new_email):
                conn.close()
                return jsonify({"error": "Invalid email format."}), 400
            conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
            log_audit(conn, user_id, session['username'], 'PROFILE_UPDATED', f'Updated email to {new_email}', 'INFO')

        if new_password:
            if not current_password:
                conn.close()
                return jsonify({"error": "Current password is required to change password."}), 400
            try:
                ph.verify(user['password_hash'], current_password + SERVER_PEPPER)
            except Exception:
                log_audit(conn, user_id, session['username'], 'PASSWORD_CHANGE_FAILED', 'Wrong current password provided', 'WARN')
                conn.commit()
                conn.close()
                return jsonify({"error": "Current password is incorrect."}), 401
            if not is_strong_password(new_password):
                conn.close()
                return jsonify({"error": "New password must be 8+ chars with uppercase, lowercase, digit, and not breached."}), 400
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (ph.hash(new_password + SERVER_PEPPER), user_id))
            log_audit(conn, user_id, session['username'], 'PASSWORD_CHANGED', 'User updated password', 'INFO')
            session['csrf_token'] = secrets.token_hex(32)

        conn.commit()
        updated = conn.execute(
            "SELECT id, username, email, store_credit, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        conn.close()
        return jsonify({"message": "Profile updated successfully.", "csrf_token": session['csrf_token'], "user": dict(updated)}), 200
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Email is already in use by another account."}), 409

# --- 7. Admin Panel (Users, Products, Coupons & Security Audit Logs) ---
@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, email, is_confirmed, store_credit, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/admin/users/<int:target_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_manage_user(target_id):
    conn = get_db()
    if request.method == 'DELETE':
        if target_id == session['user_id']:
            conn.close()
            return jsonify({"error": "Admin cannot delete their own active account."}), 400
        conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
        log_audit(conn, session['user_id'], session['username'], 'ADMIN_DELETE_USER', f'Deleted user ID {target_id}', 'WARN')
        conn.commit()
        conn.close()
        return jsonify({"message": "User deleted."}), 200

    data = request.get_json(silent=True) or {}
    if 'store_credit' in data:
        try:
            credit = float(data['store_credit'])
            if not math.isfinite(credit) or credit < 0:
                raise ValueError()
        except (TypeError, ValueError):
            conn.close()
            return jsonify({"error": "Invalid store credit value."}), 400
        conn.execute("UPDATE users SET store_credit = ? WHERE id = ?", (credit, target_id))
    if 'role' in data and data['role'] in ('user', 'admin'):
        if target_id == session['user_id'] and data['role'] != 'admin':
            conn.close()
            return jsonify({"error": "Cannot demote yourself."}), 400
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (data['role'], target_id))

    log_audit(conn, session['user_id'], session['username'], 'ADMIN_UPDATE_USER', f'Updated user ID {target_id}', 'INFO')
    conn.commit()
    conn.close()
    return jsonify({"message": "User updated successfully."}), 200

@app.route('/admin/products', methods=['POST'])
@admin_required
def admin_add_product():
    data = request.get_json(silent=True) or {}
    name = str(data.get('name', '')).strip()
    category = str(data.get('category', 'General')).strip() or 'General'
    description = str(data.get('description', '')).strip()
    try:
        price = float(data.get('price'))
        stock = int(data.get('stock', 10))
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid price or stock."}), 400

    if not name or contains_html_tags(name) or contains_html_tags(category) or contains_html_tags(description):
        return jsonify({"error": "Invalid characters in product fields."}), 400
    if not math.isfinite(price) or price < 0 or stock < 0:
        return jsonify({"error": "Invalid product price or stock."}), 400

    conn = get_db()
    conn.execute(
        "INSERT INTO products (name, category, description, price, stock) VALUES (?, ?, ?, ?, ?)",
        (name, category, description, price, stock)
    )
    log_audit(conn, session['user_id'], session['username'], 'ADMIN_ADD_PRODUCT', f'Added product: {name}', 'INFO')
    conn.commit()
    conn.close()
    return jsonify({"message": "Product added successfully."}), 201

@app.route('/admin/products/<int:prod_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_edit_delete_product(prod_id):
    conn = get_db()
    if request.method == 'DELETE':
        conn.execute("DELETE FROM products WHERE id = ?", (prod_id,))
        log_audit(conn, session['user_id'], session['username'], 'ADMIN_DELETE_PRODUCT', f'Deleted product ID {prod_id}', 'WARN')
        conn.commit()
        conn.close()
        return jsonify({"message": "Product deleted."}), 200

    data = request.get_json(silent=True) or {}
    try:
        price = float(data.get('price'))
        stock = int(data.get('stock'))
        if not math.isfinite(price) or price < 0 or stock < 0:
            raise ValueError()
    except (TypeError, ValueError):
        conn.close()
        return jsonify({"error": "Invalid price or stock."}), 400

    conn.execute("UPDATE products SET price = ?, stock = ? WHERE id = ?", (price, stock, prod_id))
    log_audit(conn, session['user_id'], session['username'], 'ADMIN_UPDATE_PRODUCT', f'Updated product ID {prod_id}', 'INFO')
    conn.commit()
    conn.close()
    return jsonify({"message": "Product updated."}), 200

@app.route('/admin/coupons', methods=['GET', 'POST'])
@admin_required
def admin_coupons():
    conn = get_db()
    if request.method == 'GET':
        rows = conn.execute("SELECT id, code, discount_percent, active FROM coupons").fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows]), 200

    data = request.get_json(silent=True) or {}
    code = str(data.get('code', '')).strip().upper()
    try:
        discount = float(data.get('discount_percent'))
    except (TypeError, ValueError):
        conn.close()
        return jsonify({"error": "Invalid discount."}), 400

    if not re.match(r'^[A-Z0-9]{3,20}$', code) or not math.isfinite(discount) or not (0 < discount < 1):
        conn.close()
        return jsonify({"error": "Code must be 3-20 alphanumeric chars and discount between 0.01 and 0.99."}), 400

    try:
        conn.execute("INSERT INTO coupons (code, discount_percent, active) VALUES (?, ?, 1)", (code, discount))
        log_audit(conn, session['user_id'], session['username'], 'ADMIN_ADD_COUPON', f'Created coupon: {code}', 'INFO')
        conn.commit()
        conn.close()
        return jsonify({"message": "Coupon created."}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Coupon already exists."}), 409

@app.route('/admin/coupons/<int:coupon_id>', methods=['DELETE'])
@admin_required
def admin_delete_coupon(coupon_id):
    conn = get_db()
    conn.execute("DELETE FROM coupons WHERE id = ?", (coupon_id,))
    log_audit(conn, session['user_id'], session['username'], 'ADMIN_DELETE_COUPON', f'Deleted coupon ID {coupon_id}', 'WARN')
    conn.commit()
    conn.close()
    return jsonify({"message": "Coupon deleted."}), 200

@app.route('/admin/logs', methods=['GET'])
@admin_required
def admin_get_logs():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, username, action, details, ip_address, status, created_at FROM audit_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/')
def home():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Error: index.html not found."

if __name__ == '__main__':
    app.run(debug=False, port=5000)