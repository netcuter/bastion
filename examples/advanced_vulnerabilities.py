"""
Test file for advanced SAST patterns (2025)
Contains examples of vulnerabilities from professional tools
"""

import requests
import tarfile
import zipfile
import pickle
import yaml
import re
import subprocess
import os
from jinja2 import Environment

# === HTTP Request Without Timeout (Bandit B113) ===
def test_timeout():
    # VULN: No timeout - can hang indefinitely
    response = requests.get("https://api.example.com/data")

    # VULN: Explicit None timeout
    response2 = requests.post("https://api.example.com/upload", timeout=None)

    # SAFE: With timeout
    response3 = requests.get("https://api.example.com/safe", timeout=30)


# === Archive Extraction (Bandit B202) ===
def test_archive():
    # VULN: Tarfile without validation
    with tarfile.open("archive.tar.gz") as tar:
        tar.extractall()  # Path traversal risk!

    # VULN: ZIP without validation
    with zipfile.ZipFile("file.zip") as zip:
        zip.extractall()  # Dangerous!

    # SAFE: With filter
    with tarfile.open("safe.tar") as tar:
        tar.extractall(filter="data")


# === Jinja2 Security (Bandit B701) ===
def test_jinja2():
    # VULN: autoescape disabled
    env = Environment(autoescape=False)

    # VULN: No autoescape specified (defaults to False)
    env2 = Environment()

    # SAFE: autoescape enabled
    env3 = Environment(autoescape=True)


# === Shell Injection Advanced ===
def test_shell():
    user_input = "malicious; rm -rf /"

    # VULN: shell=True with user input
    subprocess.Popen(user_input, shell=True)

    # VULN: os.system with formatted string
    os.system(f"ls {user_input}")

    # VULN: Relative path
    subprocess.Popen("mycommand")


# === TOCTOU Race Conditions (CVE-2025) ===
def test_race_condition(filename):
    # VULN: Check-then-use pattern
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            data = f.read()

    # VULN: access() before open()
    if os.access(filename, os.R_OK):
        f = open(filename, 'r')


# === Advanced Deserialization ===
def test_deserialization():
    import sys

    # VULN: Pickle from untrusted source
    data = pickle.loads(sys.stdin.read())

    # VULN: YAML without SafeLoader
    config = yaml.load(open('config.yml'))

    # VULN: Marshal
    import marshal
    obj = marshal.loads(b"data")


# === ReDoS (Regex DoS) ===
def test_redos():
    # VULN: Nested quantifiers - catastrophic backtracking
    pattern = re.compile(r'(a+)+(b+)+')

    # VULN: Multiple nested quantifiers
    result = re.match(r'(x+)+(y+)+(z+)+', user_input)


# === Integer Overflow ===
def test_integer_overflow():
    from flask import request

    # VULN: Unchecked int conversion
    size = int(request.args.get('size'))

    # VULN: Range with user input
    for i in range(int(request.args.get('count'))):
        process()

    # VULN: Multiplication
    buffer = [0] * int(request.args.get('multiplier'))


# === File Upload ===
def test_file_upload():
    from flask import request

    # VULN: No validation
    file = request.files['upload']
    file.save('uploads/' + file.filename)

    # VULN: No extension check
    uploaded = request.FILES['document']
    uploaded.save('/var/www/files/')


# === Advanced Crypto ===
def test_crypto():
    from Crypto.Cipher import DES, ARC4
    import random

    # VULN: DES encryption
    cipher = DES.new(b'key12345', DES.MODE_ECB)

    # VULN: RC4
    cipher2 = ARC4.new(b'weakkey')

    # VULN: Weak random for password
    password = str(random.random())

    # VULN: Low entropy
    token = os.urandom(8)  # Less than 16 bytes


# === Advanced SQL Injection ===
def test_sql_advanced():
    from django.db import connection
    from flask import request

    # VULN: Django raw() with % formatting
    cursor.execute(raw("SELECT * FROM users WHERE id=%s" % user_id))

    # VULN: f-string in SQL
    query = f"SELECT * FROM products WHERE name='{request.args.get('name')}'"

    # VULN: .format()
    cursor.execute("DELETE FROM logs WHERE id={}".format(log_id))


# === LDAP Injection ===
def test_ldap():
    import ldap

    # VULN: User input in LDAP search
    filter_str = f"(uid={request.args.get('username')})"
    ldap.search(filter_str)


# === NoSQL Injection ===
def test_nosql():
    from flask import request

    # VULN: User input in MongoDB query
    db.collection.find({"user": request.args.get('user')})

    # VULN: String concatenation in where
    result = collection.where("name = '" + user_input + "'")


# === Prototype Pollution (JavaScript-like in comments) ===
"""
JavaScript example:

// VULN: Object.assign with user input
const merged = Object.assign({}, req.body);

// VULN: Spread operator
const data = {...req.query};

// VULN: Direct __proto__
obj.__proto__ = malicious;
"""
