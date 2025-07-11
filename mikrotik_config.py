# mikrotik_config.py - Configuration MikroTik pour votre application Flask

import routeros_api
import logging
import datetime
from typing import Dict, List, Optional, Any

class MikroTikManager:
    """Gestionnaire pour l'API MikroTik"""
    
    def __init__(self, host: str, username: str, password: str, port: int = 8728):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.connection = None
        self.api = None
        
    def connect(self) -> bool:
        """Établit la connexion avec MikroTik"""
        try:
            self.connection = routeros_api.RouterOsApiPool(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True
            )
            self.api = self.connection.get_api()
            logging.info(f"Connexion MikroTik établie avec {self.host}")
            return True
        except Exception as e:
            logging.error(f"Erreur connexion MikroTik: {e}")
            return False
    
    def disconnect(self):
        """Ferme la connexion MikroTik"""
        if self.connection:
            self.connection.disconnect()
            logging.info("Connexion MikroTik fermée")
    
    def create_user(self, username: str, password: str, profile: str = "default") -> Dict[str, Any]:
        """Crée un utilisateur hotspot dans MikroTik"""
        try:
            if not self.api:
                if not self.connect():
                    return {"success": False, "error": "Impossible de se connecter à MikroTik"}
            
            # Vérifier si l'utilisateur existe déjà
            existing_users = self.api.get_resource('/ip/hotspot/user').get()
            for user in existing_users:
                if user.get('name') == username:
                    return {"success": False, "error": "Utilisateur déjà existant"}
            
            # Créer l'utilisateur
            user_data = {
                'name': username,
                'password': password,
                'profile': profile,
                'disabled': 'false'
            }
            
            self.api.get_resource('/ip/hotspot/user').add(**user_data)
            logging.info(f"Utilisateur MikroTik créé: {username}")
            
            return {"success": True, "message": "Utilisateur créé avec succès"}
            
        except Exception as e:
            logging.error(f"Erreur création utilisateur MikroTik: {e}")
            return {"success": False, "error": str(e)}
    
    def create_user_profile(self, profile_name: str, rate_limit: str = "1M/1M", 
                           session_timeout: str = "1h") -> Dict[str, Any]:
        """Crée un profil utilisateur"""
        try:
            if not self.api:
                if not self.connect():
                    return {"success": False, "error": "Impossible de se connecter à MikroTik"}
            
            profile_data = {
                'name': profile_name,
                'rate-limit': rate_limit,
                'session-timeout': session_timeout,
                'shared-users': '1'
            }
            
            self.api.get_resource('/ip/hotspot/user/profile').add(**profile_data)
            logging.info(f"Profil MikroTik créé: {profile_name}")
            
            return {"success": True, "message": "Profil créé avec succès"}
            
        except Exception as e:
            logging.error(f"Erreur création profil MikroTik: {e}")
            return {"success": False, "error": str(e)}
    
    def get_active_sessions(self) -> List[Dict]:
        """Récupère les sessions actives"""
        try:
            if not self.api:
                if not self.connect():
                    return []
            
            sessions = self.api.get_resource('/ip/hotspot/active').get()
            return sessions
            
        except Exception as e:
            logging.error(f"Erreur récupération sessions actives: {e}")
            return []
    
    def disconnect_user(self, username: str) -> Dict[str, Any]:
        """Déconnecte un utilisateur actif"""
        try:
            if not self.api:
                if not self.connect():
                    return {"success": False, "error": "Impossible de se connecter à MikroTik"}
            
            # Trouver la session active
            active_sessions = self.get_active_sessions()
            session_id = None
            
            for session in active_sessions:
                if session.get('user') == username:
                    session_id = session.get('.id')
                    break
            
            if not session_id:
                return {"success": False, "error": "Session active non trouvée"}
            
            # Déconnecter l'utilisateur
            self.api.get_resource('/ip/hotspot/active').remove(session_id)
            logging.info(f"Utilisateur MikroTik déconnecté: {username}")
            
            return {"success": True, "message": "Utilisateur déconnecté avec succès"}
            
        except Exception as e:
            logging.error(f"Erreur déconnexion utilisateur MikroTik: {e}")
            return {"success": False, "error": str(e)}

# Configuration MikroTik - À modifier selon vos paramètres
MIKROTIK_CONFIG = {
    'host': '192.168.1.1',  # Adresse IP de votre routeur MikroTik
    'username': 'api_user',  # Nom d'utilisateur API
    'password': 'api_password',  # Mot de passe API
    'port': 8728  # Port API
}

# Instance globale du gestionnaire MikroTik
mikrotik_manager = MikroTikManager(
    host=MIKROTIK_CONFIG['host'],
    username=MIKROTIK_CONFIG['username'],
    password=MIKROTIK_CONFIG['password'],
    port=MIKROTIK_CONFIG['port']
)