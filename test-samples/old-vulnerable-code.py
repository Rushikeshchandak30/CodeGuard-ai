# Using oldest versions of Python packages (vulnerable patterns)
# These versions have known CVEs and insecure practices

import requests          # v0.2.0 - no SSL verification by default
from flask import Flask  # v0.1 - no security features
import django            # v1.0 - lacks security middleware
import urllib3           # v0.1 - vulnerable to injection
import json
import os
import subprocess
import pickle
import yaml
import sqlite3
from datetime import datetime

app = Flask(__name__)

# VULNERABLE PATTERN 1: Requests v0.2.0 - no SSL verification
@app.route('/proxy')
def proxy():
    url = request.args.get('url')
    # requests v0.2.0 doesn't verify SSL by default
    resp = requests.get(url, verify=False)  # MITM vulnerable
    return resp.text

# VULNERABLE PATTERN 2: Flask v0.1 - no security headers
@app.route('/data')
def get_data():
    # Flask v0.1 doesn't set security headers
    data = {
        'user': request.args.get('user'),
        'timestamp': datetime.now().isoformat()
    }
    return json.dumps(data)

# VULNERABLE PATTERN 3: SQL injection with sqlite3
@app.route('/user/<int:user_id>')
def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Direct string interpolation - SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    return json.dumps(user) if user else 'User not found'

# VULNERABLE PATTERN 4: Command injection
@app.route('/ping')
def ping_host():
    host = request.args.get('host')
    # No input validation - command injection
    cmd = f"ping -c 4 {host}"
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()

# VULNERABLE PATTERN 5: Unsafe deserialization with pickle
@app.route('/deserialize')
def deserialize():
    data = request.args.get('data')
    # pickle.loads is dangerous - RCE vulnerability
    try:
        obj = pickle.loads(data.encode())
        return str(obj)
    except:
        return 'Deserialization failed'

# VULNERABLE PATTERN 6: Path traversal
@app.route('/read')
def read_file():
    filename = request.args.get('file')
    # No path validation - directory traversal
    try:
        with open(filename, 'r') as f:
            return f.read()
    except:
        return 'File not found'

# VULNERABLE PATTERN 7: YAML unsafe loading
@app.route('/config')
def load_config():
    yaml_data = request.args.get('yaml')
    # yaml.load is unsafe - can execute arbitrary code
    try:
        config = yaml.load(yaml_data)
        return json.dumps(config)
    except:
        return 'Invalid YAML'

# VULNERABLE PATTERN 8: Hardcoded credentials
@app.route('/admin')
def admin():
    username = request.args.get('user')
    password = request.args.get('pass')
    # Hardcoded credentials - no hashing
    if username == 'admin' and password == 'admin123':
        return 'Welcome admin!'
    return 'Access denied'

# VULNERABLE PATTERN 9: No CSRF protection (Flask v0.1)
@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from')
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    # No CSRF token, no authentication
    print(f"Transferring {amount} from {from_account} to {to_account}")
    return 'Transfer completed'

# VULNERABLE PATTERN 10: Information disclosure
@app.route('/debug')
def debug_info():
    # Exposes sensitive environment variables
    env_vars = {
        'DATABASE_URL': os.environ.get('DATABASE_URL', 'not set'),
        'SECRET_KEY': os.environ.get('SECRET_KEY', 'not set'),
        'API_KEY': os.environ.get('API_KEY', 'not set'),
        'PATH': os.environ.get('PATH'),
        'HOME': os.environ.get('HOME')
    }
    return json.dumps(env_vars, indent=2)

# VULNERABLE PATTERN 11: Weak session management
@app.route('/login')
def login():
    user = request.args.get('user')
    # Session without secure cookie settings
    session['user'] = user
    session.permanent = True
    return 'Logged in'

# VULNERABLE PATTERN 12: XSS vulnerability
@app.route('/echo')
def echo():
    message = request.args.get('message')
    # No output encoding - XSS vulnerable
    return f"<h1>{message}</h1>"

# VULNERABLE PATTERN 13: File upload without validation
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        # No file type validation, no size limits
        filename = file.filename
        file.save(f"/tmp/{filename}")
        return f"File {filename} uploaded"
    return 'No file uploaded'

# VULNERABLE PATTERN 14: Weak random number generation
@app.route('/token')
def generate_token():
    import random
    # random() is not cryptographically secure
    token = ''.join([str(random.randint(0, 9)) for _ in range(10)])
    return f"Token: {token}"

# VULNERABLE PATTERN 15: No rate limiting
@app.route('/api/data')
def api_data():
    # No rate limiting - vulnerable to DoS
    data = {'message': 'API response', 'timestamp': datetime.now().isoformat()}
    return json.dumps(data)

if __name__ == '__main__':
    # Flask v0.1 runs in debug mode by default - exposes debug console
    app.run(debug=True, host='0.0.0.0', port=5000)
