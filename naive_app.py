from flask import Flask, request, jsonify, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = '12345'  # Weak predictable secret key

DB_NAME = 'naive_secureshop.db'

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

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
            confirmation_code TEXT NOT NULL,
            is_confirmed INTEGER DEFAULT 1,
            store_credit REAL DEFAULT 1000.00,
            role TEXT DEFAULT 'user'
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS newsletter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            issued_coupon TEXT NOT NULL
        )
    ''')

    # Seed Admin & Normal User with weak unsalted MD5 hashes
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """INSERT INTO users (username, email, password_hash, totp_secret, confirmation_code, is_confirmed, store_credit, role)
               VALUES ('admin', 'admin@secureshop.local', ?, 'JBSWY3DPEHPK3PXP', 'CONF00', 1, 5000.00, 'admin')""",
            (hashlib.md5(b"AdminSecret2026!").hexdigest(),)
        )

    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'omar'")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """INSERT INTO users (username, email, password_hash, totp_secret, confirmation_code, is_confirmed, store_credit, role)
               VALUES ('omar', 'omar@secureshop.local', ?, 'JBSWY3DPEHPK3PXP', 'CONF01', 1, 1000.00, 'user')""",
            (hashlib.md5(b"UserSecret2026!").hexdigest(),)
        )

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

    cursor.execute("SELECT COUNT(*) FROM coupons")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO coupons (code, discount_percent, active) VALUES (?, ?, 1)",
            [('WELCOME20', 0.20), ('NEWSLETTER10', 0.10)]
        )

    conn.commit()
    conn.close()

init_db()

# VULNERABILITY 1: No CSRF protection, no Security Headers, Debug=True leaks stack traces

@app.route('/session', methods=['GET'])
def get_session_state():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute(
            "SELECT id, username, email, store_credit, role FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        conn.close()
        if user:
            return jsonify({"logged_in": True, "csrf_token": "none", "user": dict(user)}), 200
    return jsonify({"logged_in": False, "csrf_token": "none"}), 200

# VULNERABILITY 2: Weak password policy, unsalted MD5, no rate limit, user enumeration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    email = data.get('email', '')
    password = data.get('password', '')

    conn = get_db()
    hashed_pw = hashlib.md5(password.encode()).hexdigest()
    conn.execute(
        """INSERT INTO users (username, email, password_hash, totp_secret, confirmation_code, is_confirmed)
           VALUES (?, ?, ?, 'JBSWY3DPEHPK3PXP', '111111', 1)""",
        (username, email, hashed_pw)
    )
    conn.commit()
    conn.close()
    return jsonify({
        "message": "Account created!",
        "confirmation_code": "111111",
        "totp_secret": "JBSWY3DPEHPK3PXP"
    }), 201

@app.route('/confirm', methods=['POST'])
def confirm_account():
    return jsonify({"message": "Account confirmed!"}), 200

# VULNERABILITY 3: User Enumeration + Broken MFA (accepts any 6 digits) + No Brute-Force Lockout
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    conn = get_db()
    # Vulnerable to SQL Injection in login!
    query = f"SELECT * FROM users WHERE username = '{username}'"
    user = conn.execute(query).fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Username does not exist in database."}), 401

    if user['password_hash'] != hashlib.md5(password.encode()).hexdigest():
        return jsonify({"error": "Incorrect password for this username."}), 401

    # MFA code is completely ignored on the server!
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']

    return jsonify({
        "message": f"Welcome, {user['username']}!",
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
    session.clear()
    return jsonify({"message": "Logged out."}), 200

# VULNERABILITY 4: SQL Injection in Product Search
@app.route('/products', methods=['GET'])
def get_products():
    search = request.args.get('search', '')
    category = request.args.get('category', '')

    query = f"SELECT id, name, category, description, price, stock FROM products WHERE name LIKE '%{search}%'"
    if category and category.lower() != 'all':
        query += f" AND category = '{category}'"

    conn = get_db()
    rows = conn.execute(query).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/products/<int:product_id>', methods=['GET'])
def get_product_detail(product_id):
    conn = get_db()
    row = conn.execute(f"SELECT * FROM products WHERE id = {product_id}").fetchone()
    conn.close()
    return jsonify(dict(row)), 200

# VULNERABILITY 5: Client-Side Price Tampering & Negative Quantities
@app.route('/cart', methods=['GET'])
def view_cart():
    return jsonify(session.get('cart', {})), 200

@app.route('/cart/add', methods=['POST'])
def add_to_cart():
    data = request.get_json(silent=True) or {}
    product_id = int(data.get('product_id'))
    quantity = int(data.get('quantity', 1))

    conn = get_db()
    product = conn.execute("SELECT id, name, price FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()

    # Trusts client-supplied price if sent!
    price = float(data.get('price', product['price']))

    cart = session.get('cart', {})
    pid = str(product_id)
    cart[pid] = {
        "product_id": product['id'],
        "name": product['name'],
        "price": price,
        "quantity": quantity
    }
    session['cart'] = cart
    session.modified = True
    return jsonify({"message": "Added to cart.", "cart": cart}), 200

@app.route('/cart/update', methods=['POST'])
def update_cart_quantity():
    data = request.get_json(silent=True) or {}
    pid = str(data.get('product_id'))
    cart = session.get('cart', {})
    if pid in cart:
        cart[pid]['quantity'] = int(data.get('quantity'))
        session['cart'] = cart
        session.modified = True
    return jsonify({"message": "Updated.", "cart": cart}), 200

@app.route('/cart/remove', methods=['POST'])
def remove_from_cart():
    data = request.get_json(silent=True) or {}
    pid = str(data.get('product_id'))
    cart = session.get('cart', {})
    cart.pop(pid, None)
    session['cart'] = cart
    session.modified = True
    return jsonify({"message": "Removed.", "cart": cart}), 200

@app.route('/newsletter', methods=['POST'])
def newsletter_signup():
    data = request.get_json(silent=True) or {}
    email = data.get('email', '')
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO newsletter (email, issued_coupon) VALUES (?, 'NEWSLETTER10')", (email,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Subscribed! Coupon: NEWSLETTER10", "coupon_code": "NEWSLETTER10"}), 201

# VULNERABILITY 6: Trusts 'total' from client & allows negative prices to ADD store credit!
@app.route('/checkout', methods=['POST'])
def checkout():
    data = request.get_json(silent=True) or {}
    cart = session.get('cart', {})
    user_id = session.get('user_id', 1)

    calculated_total = sum(item['price'] * item['quantity'] for item in cart.values())
    # Trusts client 'total' parameter directly!
    final_total = float(data.get('total', calculated_total))

    conn = get_db()
    user = conn.execute("SELECT store_credit FROM users WHERE id = ?", (user_id,)).fetchone()
    new_credit = user['store_credit'] - final_total
    conn.execute("UPDATE users SET store_credit = ? WHERE id = ?", (new_credit, user_id))

    items_summary = ", ".join(f"{i['name']} (x{i['quantity']})" for i in cart.values())
    cursor = conn.execute(
        "INSERT INTO orders (user_id, items_summary, total_paid, coupon_used) VALUES (?, ?, ?, ?)",
        (user_id, items_summary, final_total, data.get('coupon_code'))
    )
    order_id = cursor.lastrowid
    conn.commit()
    conn.close()

    session.pop('cart', None)
    return jsonify({
        "message": "Order confirmed!",
        "order": {
            "order_id": order_id,
            "items_summary": items_summary,
            "total_paid": final_total,
            "coupon_used": data.get('coupon_code') or "None",
            "status": "Confirmed"
        },
        "remaining_credit": new_credit
    }), 200

@app.route('/orders', methods=['GET'])
def get_user_orders():
    # IDOR: Accepts ?user_id= from query string without checking session!
    target_uid = request.args.get('user_id', session.get('user_id', 1))
    conn = get_db()
    rows = conn.execute("SELECT * FROM orders WHERE user_id = ?", (target_uid,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/account', methods=['GET', 'PUT'])
def user_account():
    uid = session.get('user_id', 1)
    conn = get_db()
    if request.method == 'GET':
        user = conn.execute("SELECT id, username, email, store_credit, role FROM users WHERE id = ?", (uid,)).fetchone()
        conn.close()
        return jsonify(dict(user)), 200
    data = request.get_json(silent=True) or {}
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (data.get('email'), uid))
    conn.commit()
    user = conn.execute("SELECT id, username, email, store_credit, role FROM users WHERE id = ?", (uid,)).fetchone()
    conn.close()
    return jsonify({"message": "Updated.", "user": dict(user)}), 200

# VULNERABILITY 7: Broken Access Control (Missing Role Authorization on all /admin routes)
@app.route('/admin/users', methods=['GET'])
def admin_list_users():
    conn = get_db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route('/admin/users/<int:target_id>', methods=['PUT', 'DELETE'])
def admin_manage_user(target_id):
    conn = get_db()
    if request.method == 'DELETE':
        conn.execute("DELETE FROM users WHERE id = ?", (target_id,))
    else:
        data = request.get_json(silent=True) or {}
        if 'store_credit' in data:
            conn.execute("UPDATE users SET store_credit = ? WHERE id = ?", (data['store_credit'], target_id))
    conn.commit()
    conn.close()
    return jsonify({"message": "Done."}), 200

@app.route('/admin/products', methods=['POST'])
def admin_add_product():
    data = request.get_json(silent=True) or {}
    conn = get_db()
    conn.execute(
        "INSERT INTO products (name, category, description, price, stock) VALUES (?, ?, ?, ?, ?)",
        (data.get('name'), data.get('category'), data.get('description'), data.get('price'), 10)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Added."}), 201

@app.route('/admin/products/<int:prod_id>', methods=['DELETE'])
def admin_delete_product(prod_id):
    conn = get_db()
    conn.execute("DELETE FROM products WHERE id = ?", (prod_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted."}), 200

@app.route('/admin/coupons', methods=['GET', 'POST'])
def admin_coupons():
    conn = get_db()
    if request.method == 'GET':
        rows = conn.execute("SELECT * FROM coupons").fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows]), 200
    data = request.get_json(silent=True) or {}
    conn.execute("INSERT INTO coupons (code, discount_percent, active) VALUES (?, ?, 1)", (data.get('code'), data.get('discount_percent')))
    conn.commit()
    conn.close()
    return jsonify({"message": "Created."}), 201

@app.route('/admin/coupons/<int:coupon_id>', methods=['DELETE'])
def admin_delete_coupon(coupon_id):
    conn = get_db()
    conn.execute("DELETE FROM coupons WHERE id = ?", (coupon_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Deleted."}), 200

@app.route('/admin/logs', methods=['GET'])
def admin_get_logs():
    return jsonify([]), 200  # No audit logging at all in naive version!

@app.route('/')
def home():
    with open('index.html', 'r', encoding='utf-8') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True, port=5001)