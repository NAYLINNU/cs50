from flask import Flask, render_template, request, redirect, url_for, flash
import hashlib
import sqlite3
from werkzeug.exceptions import BadRequestKeyError
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Using a context manager to handle the database connection
with sqlite3.connect('users.db') as conn:
    cursor = conn.cursor()

    # Creating the users table if it does not exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_md5 TEXT NOT NULL
        )
    ''')

    # Committing the changes and automatically closing the connection
    conn.commit()




def base64_encode(input_text):
    return base64.b64encode(input_text.encode()).decode()

def base64_decode(input_text):
    try:
        return base64.b64decode(input_text).decode()
    except Exception as e:
        return f"Error decoding: {str(e)}"

@app.route('/base64_page', methods=['POST'])
def base64_page():
    if request.method == 'POST':
        try:
            input_text = request.form.get('inputText')
            action = request.form.get('base64Action')

            result = ''

            if action == 'encode':
                result = base64_encode(input_text)
            elif action == 'decode':
                result = base64_decode(input_text)

        except BadRequestKeyError:
            return "Bad Request: Missing inputText or action field"

        return render_template('base64.html', base64Result=result)

    return render_template('base64.html', base64Result='')



def sha256_encrypt(plaintext):
    # Use SHA-256 for encryption
    sha256_result = hashlib.sha256(plaintext.encode()).hexdigest()
    return sha256_result


def sha512_encrypt(plaintext):
    # Use SHA-512 for encryption
    sha512_result = hashlib.sha512(plaintext.encode()).hexdigest()
    return sha512_result




@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    # Hash the password using MD5
    password_md5 = hashlib.md5(password.encode()).hexdigest()

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Check if the username is already registered
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        if cursor.fetchone():
            flash('Username already exists. Please choose another username.', 'error')
            return redirect(url_for('index'))

        # Insert the new user into the database
        cursor.execute('INSERT INTO users (username, password_md5) VALUES (?, ?)',
                       (username, password_md5))
        conn.commit()

    flash('Registration successful. You can now log in.', 'success')
    return redirect(url_for('index'))


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    with sqlite3.connect('users.db') as conn:
        cursor = conn.cursor()

        # Check if the username and password match
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        user = cursor.fetchone()

        if user:
            # Check if the query result has the expected number of values
            if len(user) == 3:
                stored_username, _, stored_password_hash = user
                if hashlib.md5(password.encode()).hexdigest() == stored_password_hash:
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password. Please try again.', 'error')
            else:
                flash('Unexpected database format. Please check your database.', 'error')
        else:
            flash('Username not found. Please register.', 'error')

    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
def logout():
    flash('Logout successful!', 'success')
    return redirect(url_for('index'))


@app.route('/md5', methods=['POST'])
def md5_page():
    md5_result = ''

    if request.method == 'POST':
        plaintext = request.form.get('plaintext')
        action = request.form.get('action')

        if action == 'encrypt':
            md5_result = hashlib.md5(plaintext.encode()).hexdigest()
        elif action == 'decrypt':
            md5_result = "Decryption is not supported for MD5."

    return render_template('md5.html', md5Result=md5_result)


@app.route('/sha256', methods=['POST'])
def sha256_page():
    sha256_result = ''

    if request.method == 'POST':
        plaintext = request.form.get('sha256Text')
        action = request.form.get('sha256Action')

        if action == 'encrypt':
            sha256_result = hashlib.sha256(plaintext.encode()).hexdigest()
        elif action == 'decrypt':
            sha256_result = "Decryption is not supported for SHA-256."

    return render_template('sha256.html', sha256Result=sha256_result)


@app.route('/sha512', methods=['POST'])
def sha512_page():
    sha512_result = ''

    if request.method == 'POST':
        plaintext = request.form.get('sha512Text')
        action = request.form.get('sha512Action')

        if action == 'encrypt':
            sha512_result = hashlib.sha512(plaintext.encode()).hexdigest()
        elif action == 'decrypt':
            sha512_result = "Decryption is not supported for SHA-512."

    return render_template('sha512.html', sha512Result=sha512_result)




if __name__ == '__main__':
    app.run(debug=True)
