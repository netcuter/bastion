"""
Example vulnerable code for testing the security audit system
This file contains intentional security vulnerabilities for demonstration purposes
DO NOT USE IN PRODUCTION!
"""

import os
import pickle
import hashlib
from flask import Flask, request

app = Flask(__name__)

# VULNERABILITY: Hardcoded credentials (CRITICAL)
# NOTE: These are FAKE example credentials for testing - they do not work
DATABASE_PASSWORD = "example_fake_password_123"
API_KEY = "sk_test_FAKE_EXAMPLE_KEY_NOT_REAL"
AWS_ACCESS_KEY = "AKIAEXAMPLEFAKEKEY123"


# VULNERABILITY: SQL Injection (CRITICAL)
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    # Direct string concatenation in SQL query
    query = "SELECT * FROM users WHERE id = " + user_id
    # Also vulnerable with f-strings
    query2 = f"SELECT * FROM users WHERE name = '{request.args.get('name')}'"
    return "User data"


# VULNERABILITY: XSS (HIGH)
@app.route('/search')
def search():
    search_term = request.args.get('q')
    # Direct output without escaping
    return f"<html><body>Results for: {search_term}</body></html>"


# VULNERABILITY: Command Injection (CRITICAL)
@app.route('/ping')
def ping():
    host = request.args.get('host')
    # Executing shell command with user input
    os.system(f"ping -c 1 {host}")
    return "Ping completed"


# VULNERABILITY: Path Traversal (HIGH)
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # Reading file with user-controlled path
    with open(f"/var/data/{filename}", 'r') as f:
        content = f.read()
    return content


# VULNERABILITY: Insecure Deserialization (HIGH)
@app.route('/deserialize')
def deserialize():
    data = request.args.get('data')
    # Using pickle with untrusted data
    obj = pickle.loads(data)
    return str(obj)


# VULNERABILITY: Weak Cryptography (MEDIUM)
def hash_password(password):
    # Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: SSRF (HIGH)
@app.route('/fetch')
def fetch_url():
    import requests
    url = request.args.get('url')
    # Making request to user-controlled URL
    response = requests.get(url)
    return response.text


# VULNERABILITY: Missing CSRF Protection (MEDIUM)
@app.route('/transfer', methods=['POST'])
def transfer_money():
    amount = request.form.get('amount')
    recipient = request.form.get('recipient')
    # State-changing operation without CSRF protection
    return f"Transferred {amount} to {recipient}"


# More hardcoded secrets - FAKE EXAMPLES FOR TESTING
POSTGRES_CONN = "postgresql://testuser:examplepass@localhost/testdb"
SLACK_WEBHOOK = "https://hooks.example.com/services/EXAMPLE/FAKE/webhook"
GITHUB_TOKEN = "ghp_ExampleFakeTokenNotRealForTesting"


if __name__ == '__main__':
    app.run(debug=True)  # VULNERABILITY: Debug mode in production
