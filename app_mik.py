# app.py - Application Flask avec intégration MikroTik

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from mikrotik_config import mikrotik_manager, MIKROTIK_CONFIG
import sqlite3
import logging
import datetime
from typing import Dict, List, Optional, Any

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète_ici'

# Configuration des offres avec profils MikroTik
OFFERS = {
    'basic': {
        'name': 'Forfait Basic',
        'duration': '1 heure',
        'speed': '512 Kbps',
        'price': 1000,
        'duration_hours': 1,
        'max_devices': 1,
        'mikrotik_profile': 'basic_profile',
        'rate_limit': '512k/512k'
    },
    'standard': {
        'name': 'Forfait Standard',
        'duration': '3 heures',
        'speed': '1 Mbps',
        'price': 2500,
        'duration_hours': 3,
        'max_devices': 2,
        'mikrotik_profile': 'standard_profile',
        'rate_limit': '1M/1M'
    },
    'premium': {
        'name': 'Forfait Premium',
        'duration': '24 heures',
        'speed': '2 Mbps',
        'price': 5000,
        'duration_hours': 24,
        'max_devices': 5,
        'mikrotik_profile': 'premium_profile',
        'rate_limit': '2M/2M'
    }
}

def init_mikrotik_profiles():
    """Initialise les profils MikroTik au démarrage"""
    try:
        if not mikrotik_manager.connect():
            logging.error("Impossible de se connecter à MikroTik pour initialiser les profils")
            return False
        
        # Créer les profils pour chaque offre
        for offer_key, offer_data in OFFERS.items():
            profile_name = offer_data['mikrotik_profile']
            rate_limit = offer_data['rate_limit']
            session_timeout = f"{offer_data['duration_hours']}h"
            
            result = mikrotik_manager.create_user_profile(
                profile_name=profile_name,
                rate_limit=rate_limit,
                session_timeout=session_timeout
            )
            
            if result['success']:
                logging.info(f"Profil MikroTik créé: {profile_name}")
            else:
                logging.error(f"Erreur création profil {profile_name}: {result['error']}")
        
        mikrotik_manager.disconnect()
        return True
        
    except Exception as e:
        logging.error(f"Erreur initialisation profils MikroTik: {e}")
        return False

def create_user_in_mikrotik(username: str, password: str, profile: str) -> Dict[str, Any]:
    """Crée un utilisateur dans MikroTik"""
    return mikrotik_manager.create_user(
        username=username,
        password=password,
        profile=profile
    )

def update_user_subscription(user_id: int, offer_type: str) -> Dict[str, Any]:
    """Met à jour l'abonnement utilisateur après paiement"""
    try:
        # Récupérer les données utilisateur depuis la base de données
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT username, password_hash FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            return {'success': False, 'error': 'Utilisateur non trouvé'}
        
        username, password_hash = user
        offer = OFFERS[offer_type]
        expires_at = datetime.datetime.now() + datetime.timedelta(hours=offer['duration_hours'])
        
        # Mettre à jour la base de données
        cursor.execute('''
            UPDATE users 
            SET subscription_type = ?, subscription_expires = ?, is_active = 1
            WHERE id = ?
        ''', (offer_type, expires_at.isoformat(), user_id))
        
        conn.commit()
        conn.close()
        
        # Créer/mettre à jour l'utilisateur dans MikroTik
        mikrotik_result = create_user_in_mikrotik(
            username=username,
            password=password_hash,  # Vous devrez peut-être stocker le mot de passe en clair
            profile=offer['mikrotik_profile']
        )
        
        if not mikrotik_result['success']:
            logging.error(f"Erreur création utilisateur MikroTik: {mikrotik_result['error']}")
            return {'success': False, 'error': f'Erreur MikroTik: {mikrotik_result["error"]}'}
        
        return {
            'success': True,
            'username': username,
            'expires_at': expires_at.isoformat()
        }
        
    except Exception as e:
        logging.error(f"Erreur mise à jour abonnement: {e}")
        return {'success': False, 'error': str(e)}

@app.route('/')
def home():
    """Page d'accueil"""
    return render_template('home.html', offers=OFFERS)

@app.route('/api/purchase', methods=['POST'])
def purchase():
    """Traite l'achat d'un forfait"""
    data = request.get_json()
    
    email = data.get('email')
    phone = data.get('phone')
    offer_type = data.get('offer_type')
    
    if not all([email, phone, offer_type]) or offer_type not in OFFERS:
        return jsonify({'success': False, 'error': 'Données manquantes ou invalides'}), 400
    
    # Créer l'utilisateur dans la base de données
    # ... votre logique de création d'utilisateur existante ...
    
    # Après paiement réussi, mettre à jour l'abonnement
    user_id = 1  # Remplacer par l'ID réel de l'utilisateur
    result = update_user_subscription(user_id, offer_type)
    
    return jsonify(result)

@app.route('/admin/active_sessions')
def admin_active_sessions():
    """Affiche les sessions actives MikroTik"""
    active_sessions = mikrotik_manager.get_active_sessions()
    
    # Enrichir avec les données de la base de données
    enriched_sessions = []
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    for session in active_sessions:
        username = session.get('user', '')
        cursor.execute('''
            SELECT id, email, phone, subscription_type, subscription_expires
            FROM users WHERE username = ?
        ''', (username,))
        
        user_data = cursor.fetchone()
        
        session_info = {
            'mikrotik_id': session.get('.id'),
            'username': username,
            'ip': session.get('address'),
            'mac': session.get('mac-address'),
            'uptime': session.get('uptime'),
            'bytes_in': session.get('bytes-in'),
            'bytes_out': session.get('bytes-out')
        }
        
        if user_data:
            session_info.update({
                'user_id': user_data[0],
                'email': user_data[1],
                'phone': user_data[2],
                'subscription_type': user_data[3],
                'subscription_expires': user_data[4]
            })
        
        enriched_sessions.append(session_info)
    
    conn.close()
    
    return render_template('admin_active_sessions.html', sessions=enriched_sessions)

@app.route('/api/disconnect/<username>', methods=['POST'])
def disconnect_user(username):
    """Déconnecte un utilisateur de MikroTik"""
    result = mikrotik_manager.disconnect_user(username)
    return jsonify(result)

if __name__ == '__main__':
    # Initialiser les profils MikroTik au démarrage
    init_mikrotik_profiles()
    app.run(debug=True, host='0.0.0.0', port=5000)