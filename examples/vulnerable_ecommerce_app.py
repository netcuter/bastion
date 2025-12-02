"""
Realistic Vulnerable E-Commerce Application
For testing AdvancedSecurity-inspired features on real-world scenarios
"""
from flask import Flask, request, render_template_string, redirect, session, make_response
import sqlite3
import os
import subprocess
import hashlib
import pickle
import jwt
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'hardcoded_secret_key_12345'  # VULNERABILITY: Hardcoded secret

# Database configuration
DATABASE = 'ecommerce.db'
UPLOAD_FOLDER = '/var/www/uploads'

# AWS Credentials (VULNERABILITY: Exposed credentials)
AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'

# Payment gateway API key (VULNERABILITY: Hardcoded API key)
# NOTE: This is intentionally a FAKE key for vulnerability demonstration
STRIPE_SECRET_KEY = 'sk_test_FAKE_EXAMPLE_NOT_REAL_TESTING_ONLY_xyz'


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login endpoint
    VULNERABILITY: SQL Injection
    """
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # VULNERABLE: Direct SQL concatenation
        conn = get_db_connection()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return "Login failed", 401

    return render_template_string('''
        <form method="POST">
            <input name="username" placeholder="Username">
            <input name="password" type="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    ''')


@app.route('/search')
def search():
    """
    Product search endpoint
    VULNERABILITY: XSS (Cross-Site Scripting)
    """
    query = request.args.get('q', '')

    # VULNERABLE: Unescaped user input in template
    results_html = f'''
        <h1>Search Results for: {query}</h1>
        <p>You searched for: {query}</p>
    '''

    return render_template_string(results_html)


@app.route('/product/<product_id>')
def product_detail(product_id):
    """
    Product detail page
    VULNERABILITY: SQL Injection (Second-Order)
    """
    conn = get_db_connection()
    # VULNERABLE: User-controlled parameter in SQL
    product = conn.execute(f"SELECT * FROM products WHERE id = {product_id}").fetchone()
    conn.close()

    if product:
        return f"Product: {product['name']} - ${product['price']}"
    return "Product not found", 404


@app.route('/admin/execute')
def admin_execute():
    """
    Admin command execution
    VULNERABILITY: Command Injection
    """
    command = request.args.get('cmd', 'ls')

    # VULNERABLE: Direct command execution
    result = subprocess.check_output(command, shell=True, text=True)

    return f"<pre>{result}</pre>"


@app.route('/download')
def download_file():
    """
    File download endpoint
    VULNERABILITY: Path Traversal
    """
    filename = request.args.get('file', 'invoice.pdf')

    # VULNERABLE: No path validation
    filepath = os.path.join(UPLOAD_FOLDER, filename)

    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return content
    except:
        return "File not found", 404


@app.route('/api/user/<user_id>')
def get_user_api(user_id):
    """
    API endpoint for user data
    VULNERABILITY: IDOR (Insecure Direct Object Reference)
    """
    # VULNERABLE: No authorization check
    conn = get_db_connection()
    user = conn.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()
    conn.close()

    if user:
        return {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'credit_card': user['credit_card']  # VULNERABILITY: Exposing sensitive data
        }
    return {"error": "User not found"}, 404


@app.route('/api/token', methods=['POST'])
def create_token():
    """
    JWT token creation
    VULNERABILITY: Weak JWT implementation
    """
    data = request.get_json()

    # VULNERABLE: Using 'none' algorithm
    token = jwt.encode(
        {'user_id': data.get('user_id'), 'exp': datetime.now()},
        key='',
        algorithm='none'
    )

    return {'token': token}


@app.route('/upload', methods=['POST'])
def upload_file():
    """
    File upload endpoint
    VULNERABILITY: Unrestricted File Upload
    """
    file = request.files['file']

    # VULNERABLE: No file type validation
    filename = file.filename
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    return f"File uploaded: {filename}"


@app.route('/deserialize')
def deserialize_data():
    """
    Data deserialization endpoint
    VULNERABILITY: Insecure Deserialization
    """
    data = request.args.get('data', '')

    # VULNERABLE: Unpickling untrusted data
    try:
        obj = pickle.loads(bytes.fromhex(data))
        return f"Deserialized: {obj}"
    except:
        return "Invalid data", 400


@app.route('/redirect')
def open_redirect():
    """
    Redirect endpoint
    VULNERABILITY: Open Redirect
    """
    url = request.args.get('url', '/')

    # VULNERABLE: Unvalidated redirect
    return redirect(url)


@app.route('/xml/parse', methods=['POST'])
def parse_xml():
    """
    XML parsing endpoint
    VULNERABILITY: XXE (XML External Entity)
    """
    import xml.etree.ElementTree as ET

    xml_data = request.data

    # VULNERABLE: No XXE protection
    try:
        root = ET.fromstring(xml_data)
        return f"Parsed: {root.tag}"
    except:
        return "Invalid XML", 400


@app.route('/admin/logs')
def view_logs():
    """
    Log viewer
    VULNERABILITY: Information Disclosure
    """
    # VULNERABLE: Exposing sensitive logs
    log_content = """
    [2025-12-02 10:15:23] User admin logged in from 192.168.1.100
    [2025-12-02 10:15:24] Database password: MySecretPass123!
    [2025-12-02 10:15:25] AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    [2025-12-02 10:15:26] Credit card processed: 4532-1234-5678-9010
    """

    return f"<pre>{log_content}</pre>"


@app.route('/cart/update', methods=['POST'])
def update_cart():
    """
    Cart update endpoint
    VULNERABILITY: Mass Assignment
    """
    data = request.get_json()

    # VULNERABLE: No filtering of input fields
    conn = get_db_connection()
    conn.execute("""
        UPDATE carts SET
            product_id = ?,
            quantity = ?,
            price = ?,
            is_admin = ?
        WHERE user_id = ?
    """, (
        data.get('product_id'),
        data.get('quantity'),
        data.get('price'),
        data.get('is_admin', False),  # VULNERABLE: User can set admin flag
        session.get('user_id')
    ))
    conn.commit()
    conn.close()

    return {"status": "updated"}


@app.route('/payment/process', methods=['POST'])
def process_payment():
    """
    Payment processing
    VULNERABILITY: Missing input validation
    """
    amount = request.form.get('amount')
    card_number = request.form.get('card')

    # VULNERABLE: No amount validation - user can set negative amount
    # VULNERABLE: Storing credit card in plain text
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO transactions (amount, card_number) VALUES (?, ?)",
        (amount, card_number)
    )
    conn.commit()
    conn.close()

    return f"Payment of ${amount} processed"


# Database initialization
def init_db():
    """Initialize database with sample data"""
    conn = sqlite3.connect(DATABASE)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            credit_card TEXT,
            is_admin BOOLEAN
        )
    ''')

    conn.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL,
            description TEXT
        )
    ''')

    # Insert sample data with weak passwords
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com', '4532123456789010', 1)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'user', 'password', 'user@example.com', '4532987654321098', 0)"
    )

    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()
    # VULNERABILITY: Debug mode in production
    app.run(debug=True, host='0.0.0.0', port=5000)
