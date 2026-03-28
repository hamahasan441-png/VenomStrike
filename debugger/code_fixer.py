"""Code fix generator — provides language-specific remediation code."""
# For authorized security testing only.
from typing import Dict


FIX_CODE = {
    "SQL Injection": {
        "summary": "Use parameterized queries / prepared statements",
        "python": """
# VULNERABLE:
query = f"SELECT * FROM users WHERE id = {user_id}"

# FIXED (Python + SQLAlchemy):
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})

# FIXED (Python + sqlite3):
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# FIXED (Python + psycopg2):
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
""",
        "php": """
// VULNERABLE:
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// FIXED (PHP PDO):
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$user = $stmt->fetch();

// FIXED (MySQLi):
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
""",
        "java": """
// VULNERABLE:
String query = "SELECT * FROM users WHERE id = " + userId;

// FIXED (Java PreparedStatement):
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();
""",
        "node": """
// VULNERABLE:
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// FIXED (Node.js + mysql2):
db.query('SELECT * FROM users WHERE id = ?', [userId]);

// FIXED (Node.js + Sequelize):
User.findOne({ where: { id: userId } });
""",
    },
    "XSS": {
        "summary": "Encode output; use Content-Security-Policy",
        "python": """
# VULNERABLE:
return f"<div>{user_input}</div>"

# FIXED (Python + markupsafe):
from markupsafe import escape
return f"<div>{escape(user_input)}</div>"

# FIXED (Django auto-escape):
# In templates, use {{ user_input }} — Django auto-escapes
# For raw HTML, use: from django.utils.html import escape

# Add CSP header:
response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'"
""",
        "php": """
// VULNERABLE:
echo $_GET['name'];

// FIXED:
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// Add CSP header:
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
""",
        "java": """
// VULNERABLE:
response.getWriter().write(userInput);

// FIXED (OWASP Java Encoder):
import org.owasp.encoder.Encode;
response.getWriter().write(Encode.forHtml(userInput));

// Spring Security CSP:
http.headers().contentSecurityPolicy("default-src 'self'");
""",
        "node": """
// VULNERABLE:
res.send(`<div>${userInput}</div>`);

// FIXED (helmet + express-validator):
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy());

const { escape } = require('he');
res.send(`<div>${escape(userInput)}</div>`);
""",
    },
    "CSRF": {
        "summary": "Implement CSRF tokens; set SameSite cookie attribute",
        "python": """
# Django (built-in CSRF):
from django.views.decorators.csrf import csrf_protect

@csrf_protect
def my_view(request):
    pass

# Flask-WTF:
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Set SameSite on session cookie:
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
""",
        "php": """
// Generate token:
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate:
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die('CSRF token mismatch');
}
""",
    },
    "SSRF": {
        "summary": "Validate and whitelist URLs; block internal IP ranges",
        "python": """
# VULNERABLE:
import requests
resp = requests.get(user_supplied_url)

# FIXED:
import ipaddress
from urllib.parse import urlparse

ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

def is_safe_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    hostname = parsed.hostname
    if hostname in ALLOWED_DOMAINS:
        return True
    # Block internal IPs
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # Not an IP
    return False

if not is_safe_url(user_supplied_url):
    raise ValueError("URL not allowed")
resp = requests.get(user_supplied_url)
""",
    },
    "LFI": {
        "summary": "Avoid user-controlled file paths; use allowlists",
        "python": """
# VULNERABLE:
with open(request.args.get('file')) as f:
    content = f.read()

# FIXED:
import os
ALLOWED_FILES = {'report.pdf', 'guide.txt', 'manual.pdf'}

def safe_file_read(filename: str, base_dir: str) -> str:
    if filename not in ALLOWED_FILES:
        raise ValueError("File not allowed")
    # Resolve and validate path stays within base_dir
    full_path = os.path.realpath(os.path.join(base_dir, filename))
    if not full_path.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path traversal detected")
    with open(full_path) as f:
        return f.read()
""",
    },
    "Command Injection": {
        "summary": "Never pass user input to shell; use subprocess with list args",
        "python": """
# VULNERABLE:
import os
os.system(f"ping {host}")

# ALSO VULNERABLE:
import subprocess
subprocess.run(f"ping {host}", shell=True)

# FIXED:
import subprocess
import shlex

# Validate input first
if not host.replace('.', '').isdigit() and not all(c.isalnum() or c in '-.' for c in host):
    raise ValueError("Invalid host")

# Use list, never shell=True
result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True, timeout=10)
""",
    },
    "SSTI": {
        "summary": "Never render user input as templates; use sandboxed environments",
        "python": """
# VULNERABLE (Jinja2):
from jinja2 import Template
template = Template(user_input)
output = template.render()

# FIXED - use SandboxedEnvironment:
from jinja2.sandbox import SandboxedEnvironment
env = SandboxedEnvironment()
template = env.from_string(user_input)
output = template.render(safe_variables_only=data)

# BETTER - never use user input as template:
# Instead, let users fill in predefined template variables:
template = env.get_template('user_template.html')
output = template.render(name=user_name, date=today)
""",
    },
    "Clickjacking": {
        "summary": "Set X-Frame-Options and Content-Security-Policy headers",
        "python": """
# Django:
# settings.py
X_FRAME_OPTIONS = 'DENY'
MIDDLEWARE = [
    ...
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Flask:
@app.after_request
def set_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "frame-ancestors 'none'"
    return response
""",
    },
    "CORS": {
        "summary": "Validate Origin against allowlist; never use wildcard with credentials",
        "python": """
# VULNERABLE:
response.headers['Access-Control-Allow-Origin'] = '*'
response.headers['Access-Control-Allow-Credentials'] = 'true'

# FIXED:
ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']

@app.after_request
def handle_cors(response):
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Vary'] = 'Origin'
    return response
""",
    },
    "JWT": {
        "summary": "Validate algorithm explicitly; use strong secrets; verify all claims",
        "python": """
# VULNERABLE:
import jwt
payload = jwt.decode(token, options={"verify_signature": False})

# FIXED:
import jwt
from jwt.exceptions import InvalidTokenError

SECRET = os.environ['JWT_SECRET']  # Strong 256-bit secret

try:
    payload = jwt.decode(
        token,
        SECRET,
        algorithms=['HS256'],  # Explicit algorithm list — never ['*'] or ['none']
        options={"require": ["exp", "iat", "sub"]}
    )
except InvalidTokenError as e:
    raise AuthError(f"Invalid token: {e}")
""",
    },
    "XXE": {
        "summary": "Disable external entities in XML parsers",
        "python": """
# VULNERABLE:
from lxml import etree
tree = etree.parse(user_xml)

# FIXED (defusedxml):
import defusedxml.ElementTree as ET
tree = ET.parse(user_xml)  # Automatically disables XXE

# FIXED (lxml with explicit hardening):
from lxml import etree
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
)
tree = etree.parse(user_xml, parser)
""",
    },
    "IDOR": {
        "summary": "Enforce object-level authorization for every resource access",
        "python": """
# VULNERABLE:
@app.route('/document/<int:doc_id>')
def get_document(doc_id):
    doc = Document.query.get(doc_id)
    return doc.content

# FIXED:
from flask_login import login_required, current_user

@app.route('/document/<int:doc_id>')
@login_required
def get_document(doc_id):
    doc = Document.query.filter_by(
        id=doc_id,
        owner_id=current_user.id  # Enforce ownership
    ).first_or_404()
    return doc.content
""",
    },
    "Open Redirect": {
        "summary": "Validate redirect URLs against an allowlist",
        "python": """
# VULNERABLE:
return redirect(request.args.get('next'))

# FIXED:
from urllib.parse import urlparse, urljoin

ALLOWED_HOSTS = {'example.com', 'app.example.com'}

def is_safe_redirect(url: str, base_url: str) -> bool:
    if not url:
        return False
    # Allow relative URLs
    if url.startswith('/') and not url.startswith('//'):
        return True
    parsed = urlparse(url)
    return parsed.netloc in ALLOWED_HOSTS

next_url = request.args.get('next', '/')
if not is_safe_redirect(next_url, request.host_url):
    next_url = '/'
return redirect(next_url)
""",
    },
    "File Upload": {
        "summary": "Validate file type via magic bytes; store outside webroot; rename files",
        "python": """
import os
import uuid
import magic  # python-magic

ALLOWED_MIME_TYPES = {'image/jpeg', 'image/png', 'image/gif', 'application/pdf'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_DIR = '/var/uploads'  # Outside webroot

def secure_upload(file):
    if len(file.read()) > MAX_FILE_SIZE:
        raise ValueError("File too large")
    file.seek(0)
    
    # Check MIME via magic bytes, not extension
    mime = magic.from_buffer(file.read(2048), mime=True)
    file.seek(0)
    if mime not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File type not allowed: {mime}")
    
    # Generate random filename — never trust original name
    safe_name = str(uuid.uuid4())
    full_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(full_path)
    return safe_name
""",
    },
    "Session Fixation": {
        "summary": "Regenerate session ID after login; use secure session flags",
        "python": """
# FIXED (Flask):
from flask import session
import secrets

@app.route('/login', methods=['POST'])
def login():
    # ... validate credentials ...
    # Regenerate session after successful login
    session.clear()  # Clear old session
    session['user_id'] = user.id
    session['_fresh'] = True
    
    return redirect('/dashboard')

# Configure secure session cookies:
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=1800,
)
""",
    },
}


class CodeFixer:
    def get_fix(self, finding: Dict) -> Dict:
        """Get fix code for a finding."""
        vuln_type = finding.get("vuln_type", "")
        
        # Normalize vuln type for lookup
        normalized = self._normalize_vuln_type(vuln_type)
        fix = FIX_CODE.get(normalized, {})
        
        if not fix:
            fix = {
                "summary": "Follow OWASP guidelines for secure coding practices",
                "python": "# See OWASP documentation for remediation guidance",
            }
        
        return fix
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        mappings = {
            "sql injection": "SQL Injection",
            "sqli": "SQL Injection",
            "xss": "XSS",
            "cross-site scripting": "XSS",
            "csrf": "CSRF",
            "ssrf": "SSRF",
            "lfi": "LFI",
            "path traversal": "LFI",
            "command injection": "Command Injection",
            "cmd injection": "Command Injection",
            "ssti": "SSTI",
            "template injection": "SSTI",
            "clickjacking": "Clickjacking",
            "cors": "CORS",
            "jwt": "JWT",
            "xxe": "XXE",
            "idor": "IDOR",
            "open redirect": "Open Redirect",
            "file upload": "File Upload",
            "session fixation": "Session Fixation",
        }
        lower = vuln_type.lower()
        for k, v in mappings.items():
            if k in lower:
                return v
        return vuln_type
    
    def get_all_fix_types(self) -> list:
        return list(FIX_CODE.keys())
