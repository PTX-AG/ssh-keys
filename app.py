from flask import Flask, request, render_template, redirect, url_for
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization
import sqlite3

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ssh_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_type TEXT NOT NULL,
            private_key TEXT NOT NULL,
            public_key TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Initialize the database
init_db()

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    return private_bytes, public_bytes

def generate_ed25519_keypair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    return private_bytes, public_bytes

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        key_type = request.form['key_type']
        
        if key_type == 'RSA':
            private_key, public_key = generate_rsa_keypair()
        elif key_type == 'ED25519':
            private_key, public_key = generate_ed25519_keypair()
        else:
            return "Invalid key type", 400
        
        # Store keys in database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO ssh_keys (key_type, private_key, public_key)
            VALUES (?, ?, ?)
        ''', (key_type, private_key.decode(), public_key.decode()))
        conn.commit()
        conn.close()
        
        return redirect(url_for('index'))
    
    return render_template('index.html')

@app.route('/keys')
def keys():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, key_type, public_key FROM ssh_keys')
    keys = cursor.fetchall()
    conn.close()
    
    return render_template('keys.html', keys=keys)

if __name__ == '__main__':
    app.run(debug=True)
