from flask import Flask, render_template, request, redirect, url_for, flash
from cryptography.fernet import Fernet
import hashlib
import base64
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secret key for sessions

# Paths to the key and password storage files
KEYS_FILE = 'keys.txt'
PASSWORDS_FILE = 'passwords.txt'

def generate_key():
    try:
        random_bytes = os.urandom(32)
        plain_key = base64.urlsafe_b64encode(random_bytes).decode()
        
        hash_object = hashlib.sha256()
        hash_object.update(plain_key.encode())
        hashed_key = hash_object.hexdigest()
        
        return plain_key, hashed_key
    except Exception:
        return False, False

def store_key(username, plain_key, hashed_key):
    try:
        with open(KEYS_FILE, 'a') as file:
            file.write(f'{username}:{hashed_key}:{plain_key}\n')
        return True
    except Exception:
        return False

def check_key(username, user_input_key):
    try:
        hash_object = hashlib.sha256()
        hash_object.update(user_input_key.encode())
        hashed_key = hash_object.hexdigest()
        
        if not os.path.exists(KEYS_FILE):
            return False

        with open(KEYS_FILE, 'r') as file:
            lines = file.read().splitlines()
            for line in lines:
                stored_username, stored_hashed_key, plain_key = line.split(':')
                if username == stored_username and hashed_key == stored_hashed_key:
                    return plain_key
            return False
    except Exception:
        return False

def store_password(username, key, password):
    try:
        cipher_suite = Fernet(key.encode())
        cipher_text = cipher_suite.encrypt(password.encode())
        
        with open(PASSWORDS_FILE, 'a') as file:
            file.write(f'{username}:{cipher_text.decode()}\n')
        return True
    except Exception:
        return False

def view_passwords(username, key):
    try:
        cipher_suite = Fernet(key.encode())
        passwords = []
        if os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, 'r') as file:
                lines = file.read().splitlines()
                for line in lines:
                    stored_username, cipher_text = line.split(':', 1)
                    if stored_username == username:
                        plain_text = cipher_suite.decrypt(cipher_text.encode()).decode()
                        passwords.append(plain_text)
        return passwords
    except Exception:
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_key', methods=['POST'])
def generate_key_route():
    username = request.form['username']
    plain_key, hashed_key = generate_key()
    if plain_key and hashed_key:
        if store_key(username, plain_key, hashed_key):
            flash(f'Key generated successfully! Your key is: {plain_key} . Remember to store it safely.')
        else:
            flash('Error storing key. Try again later.')
    else:
        flash('Error generating key. Try again later.')
    return redirect(url_for('index'))

@app.route('/store_password', methods=['POST'])
def store_password_route():
    username = request.form['username']
    key = request.form['key']
    password = request.form['password']
    plain_key = check_key(username, key)
    if plain_key:
        if store_password(username, plain_key, password):
            flash('Password stored successfully!')
        else:
            flash('Error storing password. Try again later.')
    else:
        flash('Invalid key. Please try again.')
    return redirect(url_for('index'))

@app.route('/view_passwords', methods=['POST'])
def view_passwords_route():
    username = request.form['username']
    key = request.form['key']
    plain_key = check_key(username, key)
    if plain_key:
        passwords = view_passwords(username, plain_key)
        if passwords:
            return render_template('view_passwords.html', passwords=passwords)
        else:
            flash('No passwords found or error retrieving them.')
    else:
        flash('Invalid key. Please try again.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
