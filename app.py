# app.py - Application Flask principale
# Configuration pour le déploiement
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_cors import CORS
import sqlite3
import hashlib
import secrets
import string
import datetime
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
import logging
from typing import Dict, Any, Optional, Tuple
import json
# Ajout des imports pour Flask-Limiter
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Pour le déploiement sur Render
PORT = int(os.environ.get('PORT', 5000))

# Configuration
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_urlsafe(32))
CORS(app)

# Configuration de la base de données (utiliser un chemin absolu pour Render)
DATABASE = os.path.join(os.path.dirname(__file__), 'wifi_portal.db')


# Initialisation de Flask-Limiter
# Limite par adresse IP par défaut pour toutes les routes
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"], # Limites globales par défaut
    storage_uri="memory://", # Utilise la mémoire pour le stockage (pour un déploiement simple)
    strategy="fixed-window" # Stratégie de fenêtre fixe
)

# Configuration de la base de données
DATABASE = 'wifi_portal.db'

# 🔐 Configuration KKiAPay
KKIAPAY_CONFIG = {
    # CLÉ PUBLIQUE: Retrait du préfixe 'pk_test_' pour le widget JS
    'public_key': '09c316c05cbd11f0896d8721332d7c3c', 
    'private_key': 'tpk_09c364e05cbd11f0896d8721332d7c3c',
    'secret_key': 'tsk_09c364e15cbd11f0896d8721332d7c3c',
    'sandbox': True,
    'api_url': 'https://api.kkiapay.me/api/v1'
}

# 📲 Configuration SMS (à personnaliser selon ton fournisseur)
SMS_CONFIG = {
    'api_url': 'https://sms-api.example.com/send',
    'api_key': os.environ.get('SMS_API_KEY', 'your_real_sms_api_key_here') # Utilisation de variables d'environnement
}

# 📧 Configuration e-mail (exemple avec Gmail)
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'email': os.environ.get('EMAIL_USER', 'your-email@gmail.com'),           # Utilisation de variables d'environnement
    'password': os.environ.get('EMAIL_PASS', 'your-email-password')          # Utilisation de variables d'environnement
}

# Configuration des offres
OFFERS = {
    'basic': {
        'name': 'Forfait Basic',
        'duration': '1 heure',
        'speed': '512 Kbps',
        'price': 1000,
        'duration_hours': 1,
        'max_devices': 1
    },
    'standard': {
        'name': 'Forfait Standard',
        'duration': '3 heures',
        'speed': '1 Mbps',
        'price': 2500,
        'duration_hours': 3,
        'max_devices': 2
    },
    'premium': {
        'name': 'Forfait Premium',
        'duration': '24 heures',
        'speed': '2 Mbps',
        'price': 5000,
        'duration_hours': 24,
        'max_devices': 5
    }
}

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wifi_portal.log'),
        logging.StreamHandler()
    ]
)

# === GESTION DE LA BASE DE DONNÉES ===

def init_db():
    """Initialise la base de données avec les tables nécessaires et un admin par défaut."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Table des utilisateurs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            subscription_type TEXT,
            subscription_expires TIMESTAMP,
            max_devices INTEGER DEFAULT 1
        )
    ''')
    
    # Table des transactions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            transaction_id TEXT UNIQUE NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'XOF',
            payment_method TEXT NOT NULL,
            phone_number TEXT,
            status TEXT DEFAULT 'pending',
            offer_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            kkiapay_transaction_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Table des sessions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            device_mac TEXT,
            ip_address TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Table des tokens temporaires
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temp_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            token_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Table des logs d'activité
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Table des administrateurs
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # Insérer un utilisateur admin par défaut si la table est vide
    cursor.execute("SELECT COUNT(*) FROM admins WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        admin_password = "admin123" # Mot de passe par défaut, à changer en production!
        admin_password_hash = hash_password(admin_password)
        cursor.execute('''
            INSERT INTO admins (username, password_hash, email, role, is_active)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', admin_password_hash, 'admin@example.com', 'admin', 1))
        logging.info("Admin par défaut créé: username='admin', password='admin123'")
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Retourne une connexion à la base de données"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# === UTILITAIRES ===

def generate_password(length: int = 8) -> str:
    """Génère un mot de passe aléatoire"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def hash_password(password: str) -> str:
    """Hash un mot de passe avec SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe"""
    return hash_password(password) == hashed

def generate_username() -> str:
    """Génère un nom d'utilisateur unique"""
    prefix = "user"
    suffix = ''.join(secrets.choice(string.digits) for _ in range(6))
    return f"{prefix}{suffix}"

def generate_token(length: int = 32) -> str:
    """Génère un token sécurisé"""
    return secrets.token_urlsafe(length)

def log_activity(user_id: Optional[int], action: str, details: str = None, ip_address: str = None):
    """Enregistre une activité dans les logs"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO activity_logs (user_id, action, details, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (user_id, action, details, ip_address))
    
    conn.commit()
    conn.close()

# === GESTION DES UTILISATEURS ===

def create_user(email: str, phone: str, offer_type: str) -> Dict[str, Any]:
    """Crée un nouvel utilisateur"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Générer les identifiants
        username = generate_username()
        password = generate_password()
        password_hash = hash_password(password)
        
        # Calculer la date d'expiration
        offer = OFFERS[offer_type]
        expires_at = datetime.datetime.now() + datetime.timedelta(hours=offer['duration_hours'])
        
        # Insérer l'utilisateur (utilisation de requêtes paramétrées)
        cursor.execute('''
            INSERT INTO users (username, password_hash, email, phone, subscription_type, 
                             subscription_expires, max_devices)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, email, phone, offer_type, expires_at, offer['max_devices']))
        
        user_id = cursor.lastrowid
        
        conn.commit()
        
        return {
            'success': True,
            'user_id': user_id,
            'username': username,
            'password': password, # Le mot de passe en clair est retourné pour l'envoi par email/SMS
            'expires_at': expires_at.isoformat()
        }
        
    except sqlite3.IntegrityError as e:
        conn.rollback()
        logging.error(f"Erreur d'intégrité lors de la création utilisateur: {e}")
        return {'success': False, 'error': 'Nom d\'utilisateur ou email/téléphone déjà existant'}
    except Exception as e:
        conn.rollback()
        logging.error(f"Erreur inattendue lors de la création utilisateur: {e}")
        return {'success': False, 'error': str(e)}
    finally:
        conn.close()

def authenticate_user(username: str, password: str) -> Dict[str, Any]:
    """Authentifie un utilisateur"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées pour prévenir l'injection SQL
    cursor.execute('''
        SELECT id, username, password_hash, subscription_expires, subscription_type, is_active
        FROM users WHERE username = ?
    ''', (username,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return {'success': False, 'error': 'Utilisateur non trouvé'}
    
    if not user['is_active']:
        return {'success': False, 'error': 'Compte désactivé'}
    
    if not verify_password(password, user['password_hash']):
        return {'success': False, 'error': 'Mot de passe incorrect'}
    
    # Vérifier si l'abonnement est encore valide
    if user['subscription_expires']:
        # Convertir la chaîne ISO au format datetime
        expires_at_str = user['subscription_expires']
        try:
            expires_at = datetime.datetime.fromisoformat(expires_at_str)
        except ValueError:
            # Gérer le cas où le format n'est pas ISO (ex: si c'est déjà un objet datetime ou autre)
            # Pour SQLite, TIMESTAMP est généralement une chaîne, donc fromisoformat est approprié.
            # Si le format est différent, ajustez ici.
            expires_at = datetime.datetime.strptime(expires_at_str, '%Y-%m-%d %H:%M:%S.%f') # Exemple si pas ISO
            
        if datetime.datetime.now() > expires_at:
            return {'success': False, 'error': 'Abonnement expiré'}
    
    return {
        'success': True,
        'user_id': user['id'],
        'username': user['username'],
        'subscription_type': user['subscription_type'],
        'expires_at': user['subscription_expires']
    }

# === GESTION DES PAIEMENTS ===

def create_transaction(user_id: int, amount: float, payment_method: str, phone_number: str, offer_type: str) -> str:
    """Crée une nouvelle transaction"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    transaction_id = generate_token(16)
    
    # Utilisation de requêtes paramétrées
    cursor.execute('''
        INSERT INTO transactions (user_id, transaction_id, amount, payment_method, 
                                phone_number, offer_type)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, transaction_id, amount, payment_method, phone_number, offer_type))
    
    conn.commit()
    conn.close()
    
    return transaction_id

def update_transaction_status(transaction_id: str, status: str, kkiapay_transaction_id: str = None) -> bool:
    """Met à jour le statut d'une transaction"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées
    cursor.execute('''
        UPDATE transactions 
        SET status = ?, kkiapay_transaction_id = ?, updated_at = CURRENT_TIMESTAMP
        WHERE transaction_id = ?
    ''', (status, kkiapay_transaction_id, transaction_id))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    return success

def verify_kkiapay_transaction(transaction_id: str) -> Dict[str, Any]:
    """Vérifie une transaction KKiAPay"""
    try:
        url = f"{KKIAPAY_CONFIG['api_url']}/transactions/{transaction_id}"
        headers = {
            'Authorization': f"Bearer {KKIAPAY_CONFIG['private_key']}",
            'Content-Type': 'application/json'
        }
        
        response = requests.get(url, headers=headers)
        response.raise_for_status() # Lève une exception pour les codes d'erreur HTTP
        
        return response.json()
            
    except requests.exceptions.RequestException as e:
        logging.error(f"Erreur de requête KKiAPay: {e}")
        return {'success': False, 'error': f'Erreur de communication avec KKiAPay: {e}'}
    except json.JSONDecodeError:
        logging.error(f"Erreur de décodage JSON de la réponse KKiAPay: {response.text}")
        return {'success': False, 'error': 'Réponse invalide de KKiAPay'}
    except Exception as e:
        logging.error(f"Erreur inattendue lors de la vérification KKiAPay: {e}")
        return {'success': False, 'error': str(e)}

# === GESTION DES NOTIFICATIONS ===

def send_sms(phone_number: str, message: str) -> bool:
    """Envoie un SMS"""
    if not SMS_CONFIG['api_key'] or SMS_CONFIG['api_key'] == 'your_real_sms_api_key_here':
        logging.warning("Clé API SMS non configurée. L'envoi de SMS est désactivé.")
        return False

    try:
        data = {
            'phone': phone_number,
            'message': message,
            'api_key': SMS_CONFIG['api_key']
        }
        
        response = requests.post(SMS_CONFIG['api_url'], json=data)
        response.raise_for_status() # Lève une exception pour les codes d'erreur HTTP
        return response.status_code == 200
        
    except requests.exceptions.RequestException as e:
        logging.error(f"Erreur envoi SMS: {e}")
        return False
    except Exception as e:
        logging.error(f"Erreur inattendue envoi SMS: {e}")
        return False

def send_email(to_email: str, subject: str, body: str) -> bool:
    """Envoie un email"""
    if not EMAIL_CONFIG['email'] or EMAIL_CONFIG['email'] == 'your-email@gmail.com' or \
       not EMAIL_CONFIG['password'] or EMAIL_CONFIG['password'] == 'your-email-password':
        logging.warning("Configuration email incomplète. L'envoi d'emails est désactivé.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_CONFIG['email']
        msg['To'] = to_email
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
        server.starttls() # Mettre en place le chiffrement TLS
        server.login(EMAIL_CONFIG['email'], EMAIL_CONFIG['password'])
        
        text = msg.as_string()
        server.sendmail(EMAIL_CONFIG['email'], to_email, text)
        server.quit()
        
        return True
        
    except smtplib.SMTPAuthenticationError:
        logging.error("Erreur d'authentification SMTP. Vérifiez l'email et le mot de passe.")
        return False
    except Exception as e:
        logging.error(f"Erreur envoi email: {e}")
        return False


def send_credentials(user_data: Dict[str, Any], email: str, phone: str) -> bool:
    """Envoie les identifiants par SMS et email"""
    message = f"""
Bienvenue sur notre portail WiFi !

Vos identifiants de connexion :
Nom d'utilisateur: {user_data.get('username', 'N/A')}
Mot de passe: {user_data.get('password', 'N/A')}

Valide jusqu'au: {user_data.get('expires_at', 'N/A')}

Merci de votre confiance !
"""
    
    sms_sent = send_sms(phone, message)
    email_sent = send_email(email, "Vos identifiants WiFi", message)
    
    return sms_sent or email_sent

# === GESTION DES SESSIONS ===

def create_session(user_id: int, device_mac: str = None, ip_address: str = None) -> str:
    """Crée une session utilisateur"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    session_token = generate_token()
    expires_at = datetime.datetime.now() + datetime.timedelta(hours=24) # Session valide 24h
    
    # Utilisation de requêtes paramétrées
    cursor.execute('''
        INSERT INTO sessions (user_id, session_token, device_mac, ip_address, expires_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, session_token, device_mac, ip_address, expires_at))
    
    conn.commit()
    conn.close()
    
    return session_token

def validate_session(session_token: str) -> Dict[str, Any]:
    """Valide une session"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées
    cursor.execute('''
        SELECT s.*, u.username, u.subscription_expires
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.session_token = ? AND s.is_active = 1
    ''', (session_token,))
    
    session_data = cursor.fetchone() # Renommé pour éviter le conflit avec `session` de Flask
    conn.close()
    
    if not session_data:
        return {'success': False, 'error': 'Session invalide ou inactive'}
    
    # Vérifier expiration
    expires_at = datetime.datetime.fromisoformat(session_data['expires_at'])
    if datetime.datetime.now() > expires_at:
        return {'success': False, 'error': 'Session expirée'}
    
    return {
        'success': True,
        'user_id': session_data['user_id'],
        'username': session_data['username'],
        'subscription_expires': session_data['subscription_expires']
    }

# === DÉCORATEURS ===

def login_required(f):
    """Décorateur pour les routes nécessitant une authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter pour accéder à cette page.', 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Décorateur pour les routes administrateur"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Accès administrateur requis.', 'error')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# === ROUTES PRINCIPALES ===

@app.route('/')
def index():
    """Page d'accueil - Portail captif"""
    # La page d'accueil affiche les offres et le formulaire de connexion/inscription
    return render_template('index.html', offers=OFFERS)

@app.route('/login', methods=['GET', 'POST'])
# Suppression de override_on_success=True
@limiter.limit("5 per minute") 
def login():
    """Page de connexion utilisateur"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis.', 'error')
            return render_template('index.html', offers=OFFERS) # Retourne à la page principale
        
        auth_result = authenticate_user(username, password)
        
        if auth_result['success']:
            session['user_id'] = auth_result['user_id']
            session['username'] = auth_result['username']
            
            # Créer une session de navigation pour l'application Flask
            session_token = create_session(
                auth_result['user_id'],
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string # Ajout de l'user agent
            )
            
            log_activity(
                auth_result['user_id'],
                'login',
                f"Connexion réussie pour {username}",
                request.remote_addr
            )
            
            # Redirection vers MikroTik pour l'autorisation finale
            # Ceci est un exemple, l'URL exacte dépend de votre configuration MikroTik
            # Vous devrez peut-être passer le `session_token` ou d'autres paramètres
            # pour que MikroTik reconnaisse l'utilisateur comme authentifié.
            # Pour un portail entièrement géré par Flask, vous redirigeriez vers un tableau de bord interne.
            return redirect(url_for('user_dashboard')) # Exemple de redirection interne
        else:
            flash(auth_result['error'], 'error')
            log_activity(
                None, # Pas d'ID utilisateur connu pour l'échec
                'login_failed',
                f"Échec de connexion pour {username}: {auth_result['error']}",
                request.remote_addr
            )
    
    # Pour les requêtes GET ou en cas d'échec de POST, affiche la page d'accueil avec les offres
    return render_template('index.html', offers=OFFERS)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Déconnecte un utilisateur et invalide sa session."""
    user_id = session.pop('user_id', None)
    username = session.pop('username', None)
    if user_id:
        # Optionnel: invalider la session_token spécifique dans la BDD si vous la suivez
        # Par exemple: update_session_status(user_id, 'inactive')
        log_activity(user_id, 'logout', f"Déconnexion de l'utilisateur {username}", request.remote_addr)
    flash('Vous avez été déconnecté avec succès.', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['POST'])
@limiter.limit("2 per minute") # Limite les tentatives d'inscription
def register():
    """Inscription d'un nouvel utilisateur (API)"""
    try:
        data = request.get_json()
        
        email = data.get('email')
        phone = data.get('phone')
        offer_type = data.get('offer_type')
        
        if not all([email, phone, offer_type]):
            return jsonify({'success': False, 'error': 'Données manquantes (email, phone, offer_type)'}), 400
        
        if offer_type not in OFFERS:
            return jsonify({'success': False, 'error': 'Offre invalide.'}), 400
        
        # Créer l'utilisateur
        user_result = create_user(email, phone, offer_type)
        
        if user_result['success']:
            # Envoyer les identifiants
            credentials_sent = send_credentials(user_result, email, phone)
            
            log_activity(
                user_result['user_id'],
                'register',
                f"Inscription réussie pour {email}",
                request.remote_addr
            )
            
            return jsonify({
                'success': True,
                'user_id': user_result['user_id'],
                'username': user_result['username'],
                'password': user_result['password'], # À gérer côté client, ne pas stocker en clair
                'credentials_sent': credentials_sent
            }), 201 # Code 201 pour création réussie
        else:
            return jsonify(user_result), 400 # Retourne l'erreur spécifique de create_user
            
    except Exception as e:
        logging.error(f"Erreur lors de l'inscription: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Erreur serveur interne lors de l\'inscription.'}), 500

# Route de tableau de bord utilisateur (exemple)
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    """Tableau de bord de l'utilisateur connecté."""
    # Vous pouvez récupérer les informations de l'utilisateur depuis la session
    user_id = session.get('user_id')
    username = session.get('username')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user_info = cursor.fetchone()
    conn.close()

    if user_info:
        return render_template('user_dashboard.html', user=user_info, offers=OFFERS)
    else:
        flash('Impossible de récupérer les informations utilisateur.', 'error')
        return redirect(url_for('login'))


# === ROUTES PAIEMENT ===

@app.route('/payment')
def payment():
    """Page de paiement (affichée après sélection d'offre)"""
    offer_type = request.args.get('offer')
    
    if not offer_type or offer_type not in OFFERS:
        flash('Offre invalide sélectionnée.', 'error')
        return redirect(url_for('index')) # Retourne à la page d'accueil si l'offre est invalide
    
    selected_offer = OFFERS[offer_type]
    
    return render_template(
        'payment.html', 
        offer_type=offer_type, 
        offer_name=selected_offer['name'],
        price=selected_offer['price'],
        kkiapay_public_key=KKIAPAY_CONFIG['public_key'],
        offers=OFFERS # Passer le dictionnaire OFFERS au template
    )

@app.route('/api/payment/initiate', methods=['POST'])
def initiate_payment():
    """Initie un paiement KKiAPay (API)"""
    try:
        data = request.get_json()
        
        email = data.get('email')
        phone = data.get('phone')
        offer_type = data.get('offer_type')
        payment_method = data.get('payment_method') # Ex: 'mobile_money', 'card'
        
        if not all([email, phone, offer_type, payment_method]):
            return jsonify({'success': False, 'error': 'Données manquantes pour l\'initiation du paiement.'}), 400
        
        if offer_type not in OFFERS:
            return jsonify({'success': False, 'error': 'Offre invalide.'}), 400
        
        offer = OFFERS[offer_type]
        
        # Créer l'utilisateur (ou récupérer s'il existe déjà)
        # Pour KKiAPay, on crée l'utilisateur avant le paiement pour lier la transaction
        user_result = create_user(email, phone, offer_type) # Cette fonction gère déjà la création/vérification
        
        if not user_result['success']:
            # Si la création échoue (ex: utilisateur déjà existant avec cet email/téléphone)
            # On pourrait ici tenter de récupérer l'utilisateur existant et mettre à jour son offre
            # Pour l'instant, on retourne l'erreur.
            return jsonify(user_result), 400
        
        user_id = user_result['user_id']

        # Créer la transaction dans notre base de données
        transaction_id_local = create_transaction(
            user_id,
            offer['price'],
            payment_method,
            phone,
            offer_type
        )
        
        # Préparer les données pour l'API KKiAPay (côté client)
        # Ces données sont envoyées au front-end, qui appellera ensuite le widget KKiAPay
        kkiapay_data_for_frontend = {
            'amount': offer['price'],
            'currency': 'XOF',
            'reason': f"Achat {offer['name']} - Portail WiFi",
            'public_key': KKIAPAY_CONFIG['public_key'], # Clé publique pour le frontend
            'phone': phone,
            'callback_url': url_for('payment_callback', _external=True),
            'return_url': url_for('payment_success', _external=True),
            'cancel_url': url_for('payment_cancel', _external=True),
            'merchant_transaction_id': transaction_id_local # Notre ID de transaction local
        }
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id_local, # Notre ID de transaction local
            'kkiapay_data': kkiapay_data_for_frontend,
            'user_id': user_id
        }), 200
        
    except Exception as e:
        logging.error(f"Erreur lors de l'initiation du paiement: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Erreur serveur interne lors de l\'initiation du paiement.'}), 500

@app.route('/payment/callback', methods=['POST'])
def payment_callback():
    """Endpoint de callback de KKiAPay (appelé par KKiAPay après un paiement)"""
    try:
        data = request.get_json()
        
        # Récupérer nos IDs de transaction et le statut de KKiAPay
        merchant_transaction_id = data.get('merchant_transaction_id') # Notre ID local
        kkiapay_transaction_id = data.get('transactionId') # ID de KKiAPay
        status = data.get('status') # Statut KKiAPay (SUCCESS, FAILED, PENDING)
        
        if not merchant_transaction_id or not kkiapay_transaction_id or not status:
            logging.error(f"Callback KKiAPay: Données manquantes. Data: {data}")
            return jsonify({'success': False, 'error': 'Données de callback manquantes.'}), 400
        
        # Vérifier la transaction côté KKiAPay pour s'assurer de son authenticité et de son statut final
        verification = verify_kkiapay_transaction(kkiapay_transaction_id)
        
        if verification.get('success') and verification.get('status') == 'SUCCESS':
            # Le paiement est vérifié et réussi
            update_transaction_status(merchant_transaction_id, 'completed', kkiapay_transaction_id)
            
            # Récupérer les données utilisateur liées à cette transaction
            conn = get_db_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT t.user_id, u.email, u.phone, u.username, u.password_hash, t.offer_type
                FROM transactions t
                JOIN users u ON t.user_id = u.id
                WHERE t.transaction_id = ?
            ''', (merchant_transaction_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                # Mettre à jour l'abonnement de l'utilisateur
                offer = OFFERS.get(result['offer_type'])
                if offer:
                    expires_at = datetime.datetime.now() + datetime.timedelta(hours=offer['duration_hours'])
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE users 
                        SET subscription_type = ?, subscription_expires = ?, is_active = 1, max_devices = ?
                        WHERE id = ?
                    ''', (result['offer_type'], expires_at.isoformat(), offer['max_devices'], result['user_id']))
                    conn.commit()
                    conn.close()

                    # Envoyer les identifiants (si l'utilisateur est nouveau ou si l'abonnement a été mis à jour)
                    # Le mot de passe en clair n'est pas stocké, donc on ne peut pas le renvoyer directement.
                    # L'utilisateur devra utiliser celui reçu lors de l'inscription initiale.
                    # Ou implémenter une fonction de réinitialisation de mot de passe.
                    user_data_for_credentials = {
                        'username': result['username'],
                        'expires_at': expires_at.isoformat()
                    }
                    send_credentials(user_data_for_credentials, result['email'], result['phone'])
                else:
                    logging.error(f"Offre '{result['offer_type']}' non trouvée dans OFFERS pour user_id {result['user_id']}.")
                
                log_activity(
                    result['user_id'],
                    'payment_success',
                    f"Paiement réussi et abonnement activé pour la transaction {merchant_transaction_id}",
                    request.remote_addr
                )
            else:
                logging.error(f"Utilisateur non trouvé pour la transaction {merchant_transaction_id} après paiement réussi.")
        else:
            # Le paiement a échoué ou n'a pas pu être vérifié
            update_transaction_status(merchant_transaction_id, 'failed', kkiapay_transaction_id)
            
            log_activity(
                None, # Pas d'ID utilisateur certain à ce stade
                'payment_failed',
                f"Paiement échoué ou non vérifié pour la transaction {merchant_transaction_id}. KKiAPay Status: {status}",
                request.remote_addr
            )
        
        return jsonify({'success': True}), 200 # KKiAPay attend une réponse 200 OK

    except Exception as e:
        logging.error(f"Erreur lors du callback de paiement: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Erreur serveur interne lors du callback de paiement.'}), 500

@app.route('/payment/success')
def payment_success():
    """Page de succès de paiement (affichée après redirection par KKiAPay)"""
    flash('Votre paiement a été effectué avec succès ! Vos identifiants vous ont été envoyés.', 'success')
    return render_template('payment_success.html')

@app.route('/payment/cancel')
def payment_cancel():
    """Page d'annulation de paiement (affichée après annulation par l'utilisateur sur KKiAPay)"""
    flash('Le paiement a été annulé.', 'info')
    return render_template('payment_cancel.html')

# === ROUTES ADMINISTRATION ===

@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Limite les tentatives de connexion admin
def admin_login():
    """Connexion administrateur"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password_hash, is_active FROM admins WHERE username = ?', (username,))
        admin_user = cursor.fetchone()
        conn.close()

        if admin_user and admin_user['is_active'] and verify_password(password, admin_user['password_hash']):
            session['admin_id'] = admin_user['id']
            session['admin_username'] = admin_user['username']
            log_activity(admin_user['id'], 'admin_login', 'Connexion admin réussie', request.remote_addr)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Identifiants administrateur incorrects ou compte inactif.', 'error')
            log_activity(None, 'admin_login_failed', f"Échec connexion admin pour {username}", request.remote_addr)
    
    return render_template('admin_login.html')

@app.route('/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    """Déconnecte un administrateur et invalide sa session."""
    admin_id = session.pop('admin_id', None)
    admin_username = session.pop('admin_username', None)
    if admin_id:
        log_activity(admin_id, 'admin_logout', f"Déconnexion de l'administrateur {admin_username}", request.remote_addr)
    flash('Vous avez été déconnecté de l\'interface administrateur.', 'success')
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Dashboard administrateur"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Statistiques
    cursor.execute('SELECT COUNT(*) as total FROM users')
    total_users = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM transactions WHERE status = "completed"')
    total_transactions = cursor.fetchone()['total']
    
    cursor.execute('SELECT SUM(amount) as total FROM transactions WHERE status = "completed"')
    total_revenue = cursor.fetchone()['total'] or 0
    
    cursor.execute('SELECT COUNT(*) as total FROM sessions WHERE is_active = 1')
    active_sessions = cursor.fetchone()['total']
    
    conn.close()
    
    stats = {
        'total_users': total_users,
        'total_transactions': total_transactions,
        'total_revenue': total_revenue,
        'active_sessions': active_sessions
    }
    
    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Gestion des utilisateurs"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, username, email, phone, subscription_type, 
               subscription_expires, created_at, is_active
        FROM users
        ORDER BY created_at DESC
    ''')
    
    users = cursor.fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/transactions')
@admin_required
def admin_transactions():
    """Gestion des transactions"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT t.*, u.username
        FROM transactions t
        LEFT JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC
    ''')
    
    transactions = cursor.fetchall()
    conn.close()
    
    return render_template('admin_transactions.html', transactions=transactions)

# === ROUTES API ===

@app.route('/api/users/<int:user_id>/deactivate', methods=['POST'])
@admin_required
def deactivate_user(user_id):
    """Désactiver un utilisateur"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées
    cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    if success:
        log_activity(user_id, 'deactivated', 'Compte utilisateur désactivé par admin', request.remote_addr)
        flash(f'Utilisateur {user_id} désactivé avec succès.', 'success')
    else:
        flash(f'Échec de la désactivation de l\'utilisateur {user_id}.', 'error')
    
    return jsonify({'success': success})

@app.route('/api/users/<int:user_id>/activate', methods=['POST'])
@admin_required
def activate_user(user_id):
    """Activer un utilisateur"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées
    cursor.execute('UPDATE users SET is_active = 1 WHERE id = ?', (user_id,))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    if success:
        log_activity(user_id, 'activated', 'Compte utilisateur activé par admin', request.remote_addr)
        flash(f'Utilisateur {user_id} activé avec succès.', 'success')
    else:
        flash(f'Échec de l\'activation de l\'utilisateur {user_id}.', 'error')
    
    return jsonify({'success': success})


@app.route('/api/sessions/<int:session_id>/terminate', methods=['POST'])
@admin_required
def terminate_session(session_id):
    """Terminer une session"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées
    cursor.execute('UPDATE sessions SET is_active = 0 WHERE id = ?', (session_id,))
    
    success = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    if success:
        log_activity(None, 'session_terminated', f'Session {session_id} terminée par admin', request.remote_addr)
        flash(f'Session {session_id} terminée avec succès.', 'success')
    else:
        flash(f'Échec de la terminaison de la session {session_id}.', 'error')
    
    return jsonify({'success': success})

@app.route('/api/stats/revenue')
@admin_required
def revenue_stats():
    """Statistiques de revenus"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Utilisation de requêtes paramétrées (bien que pas d'entrées directes ici, bonne pratique)
    cursor.execute('''
        SELECT 
            DATE(created_at) as date,
            SUM(amount) as daily_revenue,
            COUNT(*) as daily_transactions
        FROM transactions 
        WHERE status = "completed"
        GROUP BY DATE(created_at)
        ORDER BY date DESC
        LIMIT 30
    ''')

    revenue_data = cursor.fetchall()
    conn.close()
    
    # Convertir les Row objets en dictionnaires pour jsonify
    data_list = []
    for row in revenue_data:
        data_list.append(dict(row))

    return jsonify({'success': True, 'data': data_list})

# === POINT D'ENTRÉE ===

if __name__ == '__main__':
    init_db()  # Initialiser la base de données
    app.run(debug=False, host='0.0.0.0', port=PORT)

