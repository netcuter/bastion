"""
Test file for v2.3.0 enhanced patterns
Demonstrates new and improved vulnerability detection
"""

# === Server-Side Template Injection (SSTI) - NEW ===

from flask import Flask, request, render_template_string
import jinja2

def ssti_flask():
    # VULN: SSTI in Flask
    template = request.args.get('template')
    return render_template_string(template)  # CRITICAL

def ssti_jinja2():
    # VULN: SSTI in Jinja2
    user_input = input()
    template = jinja2.Template(user_input)  # CRITICAL
    return template.render()

def ssti_from_string():
    # VULN: SSTI from_string
    template_str = request.form['template']
    env = jinja2.Environment()
    template = env.from_string(template_str)  # CRITICAL

# === Insecure Direct Object Reference (IDOR) - NEW ===

from django.shortcuts import get_object_or_404

def idor_django(request):
    # VULN: IDOR - direct object access
    user_id = request.GET['id']
    user = User.objects.get(id=user_id)  # HIGH - no authorization check
    return user.sensitive_data

def idor_file_access(request):
    # VULN: IDOR in file access
    filename = request.args.get('file')
    with open(filename, 'r') as f:  # HIGH
        return f.read()

def idor_sql():
    # VULN: IDOR in SQL
    user_id = request.form['userId']
    query = f"DELETE FROM users WHERE id = {user_id}"  # HIGH

# === XXE (Enhanced Multi-Language) - IMPROVED ===

import xml.etree.ElementTree as ET
from lxml import etree
import xml.dom.minidom

def xxe_etree():
    # VULN: Python xml.etree
    data = request.data
    root = ET.fromstring(data)  # XXE risk

def xxe_lxml_parse():
    # VULN: lxml without parser
    data = request.files['xml'].read()
    doc = etree.parse(data)  # XXE risk

def xxe_lxml_fromstring():
    # VULN: lxml fromstring
    xml_data = request.form['xml']
    root = etree.fromstring(xml_data)  # XXE risk

def xxe_import_check():
    # VULN: Using xml module without defusedxml
    import xml.sax  # Should use defusedxml

# === TOCTOU Race Conditions (Enhanced) - IMPROVED ===

import os
from pathlib import Path

def toctou_exists():
    # VULN: TOCTOU - exists check
    filename = request.args['file']
    if os.path.exists(filename):  # TOCTOU risk
        pass

def toctou_isfile():
    # VULN: TOCTOU - isfile check
    if os.path.isfile('/tmp/data'):  # TOCTOU risk
        pass

def toctou_isdir():
    # VULN: TOCTOU - isdir check
    if os.path.isdir('/var/log'):  # TOCTOU risk
        pass

def toctou_stat():
    # VULN: TOCTOU - stat check
    if os.stat('/etc/passwd'):  # TOCTOU risk
        pass

def toctou_pathlib():
    # VULN: TOCTOU with pathlib
    p = Path('/tmp/file')
    if p.exists():  # TOCTOU risk
        pass

# === Advanced SQL Injection (Framework-Specific) - IMPROVED ===

from django.db import connection
from sqlalchemy import text

def sqli_django_raw():
    # VULN: Django .raw() with formatting
    user = request.GET['user']
    User.objects.raw(f"SELECT * FROM users WHERE name = '{user}'")  # CRITICAL

def sqli_django_extra():
    # VULN: Django .extra() with unsafe where
    search = request.args.get('q')
    User.objects.extra(where=[f"name LIKE '%{search}%'"])  # CRITICAL

def sqli_sqlalchemy():
    # VULN: SQLAlchemy execute with format
    user_id = request.form['id']
    session.execute(f"SELECT * FROM users WHERE id = {user_id}")  # CRITICAL

def sqli_sqlalchemy_text():
    # VULN: SQLAlchemy text with f-string
    query = text(f"SELECT * FROM products WHERE category = '{request.args.get('cat')}'")  # CRITICAL

# === Advanced XSS (Framework-Specific) - IMPROVED ===

from django.http import HttpResponse

def xss_outerhtml():
    # VULN: outerHTML assignment
    # JavaScript: element.outerHTML = userInput;
    pass

def xss_insertadjacenthtml():
    # VULN: insertAdjacentHTML
    # JavaScript: div.insertAdjacentHTML('beforeend', userInput);
    pass

def xss_django_response():
    # VULN: Django HttpResponse with user input
    data = request.GET['data']
    return HttpResponse(data)  # XSS risk

def xss_flask_render():
    # VULN: Already covered in SSTI but also XSS
    template = request.args.get('tpl')
    return render_template_string(template)

# === ReDoS (Enhanced) - IMPROVED ===

import re

def redos_nested_quantifiers():
    # VULN: Nested quantifiers
    pattern = r'(a+)+'
    regex = re.compile(pattern)  # ReDoS risk

def redos_alternation():
    # VULN: Alternation with quantifier
    pattern = r'(a|ab)+'
    result = re.match(pattern, user_input)  # ReDoS risk

def redos_critical():
    # VULN: Critical ReDoS pattern
    pattern = r'(.*)*'  # Very dangerous
    regex = re.compile(pattern)

# === Archive Extraction (Enhanced) - IMPROVED ===

import tarfile
import zipfile
import shutil

def archive_tarfile_extractall():
    # VULN: tarfile.extractall
    tar = tarfile.open('archive.tar.gz')
    tar.extractall()  # Path traversal risk

def archive_tarfile_extract():
    # VULN: tarfile.extract
    tar = tarfile.open('data.tar')
    tar.extract('member.txt')  # Path traversal risk

def archive_zipfile_extractall():
    # VULN: zipfile.extractall
    with zipfile.ZipFile('data.zip') as zf:
        zf.extractall('/tmp')  # Path traversal risk

def archive_shutil():
    # VULN: shutil.unpack_archive
    shutil.unpack_archive('data.zip', '/var/www')  # Path traversal risk

# === API Security Issues - NEW ===

@app.route('/api/update', methods=['POST'])
def api_no_rate_limit():
    # VULN: No rate limiting
    pass

def api_mass_assignment():
    # VULN: Mass assignment
    user = User.objects.create(**request.POST)  # Dangerous

# === Hardcoded Secrets (Enhanced) - IMPROVED ===

# VULN: AWS Access Key
aws_key = "AKIAIOSFODNN7EXAMPLE"

# VULN: Hardcoded API key (32+ chars) - EXAMPLE ONLY
api_key = "fake_key_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

# VULN: Private key
private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""

# VULN: Hardcoded password
database_password = "MySecretPassword123!"

print("v2.3.0 test completed")
