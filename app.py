
from flask import Flask, request, jsonify
import sqlite3
import secrets
import string

app = Flask(__name__)

def generate_username():
    return "user" + ''.join(secrets.choice(string.digits) for _ in range(5))

def generate_password():
    return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))

@app.route('/')
def index():
    return "WiFi Portal Backend Actif"

@app.route('/payment-callback', methods=['POST'])
def payment_callback():
    data = request.get_json()

    if data.get("status") != "SUCCESS":
        return jsonify({"error": "Paiement échoué"}), 400

    offer = data["data"]["offer"]
    phone = data["data"]["userData"]["phone"]
    transaction_id = data["transactionId"]
    amount = data["amount"]

    username = generate_username()
    password = generate_password()

    # Enregistrer dans SQLite
    conn = sqlite3.connect('wifi_users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            phone TEXT,
            offer TEXT,
            amount INTEGER,
            transaction_id TEXT
        )
    ''')
    cursor.execute('''
        INSERT INTO users (username, password, phone, offer, amount, transaction_id)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, password, phone, offer, amount, transaction_id))
    conn.commit()
    conn.close()

    return jsonify({
        "message": "Utilisateur créé",
        "username": username,
        "password": password
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
