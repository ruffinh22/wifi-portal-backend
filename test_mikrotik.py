# test_mikrotik.py - Script pour tester la connexion MikroTik

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from mikrotik_config import mikrotik_manager, MIKROTIK_CONFIG

def test_mikrotik_connection():
    """Teste la connexion et les opérations de base avec MikroTik"""
    print("=== Test de connexion MikroTik ===")
    
    # Test de connexion
    print(f"Tentative de connexion à {MIKROTIK_CONFIG['host']}...")
    if mikrotik_manager.connect():
        print("✓ Connexion réussie")
    else:
        print("✗ Échec de la connexion")
        return False
    
    # Test de création de profil
    print("\nTest de création de profil...")
    result = mikrotik_manager.create_user_profile(
        profile_name="test_profile",
        rate_limit="1M/1M",
        session_timeout="1h"
    )
    
    if result['success']:
        print("✓ Profil créé avec succès")
    else:
        print(f"✗ Erreur création profil: {result['error']}")
    
    # Test de création d'utilisateur
    print("\nTest de création d'utilisateur...")
    result = mikrotik_manager.create_user(
        username="test_user",
        password="test_pass",
        profile="test_profile"
    )
    
    if result['success']:
        print("✓ Utilisateur créé avec succès")
    else:
        print(f"✗ Erreur création utilisateur: {result['error']}")
    
    # Test de récupération des sessions actives
    print("\nTest de récupération des sessions actives...")
    sessions = mikrotik_manager.get_active_sessions()
    print(f"✓ {len(sessions)} session(s) active(s) trouvée(s)")
    
    for session in sessions:
        print(f"  - Utilisateur: {session.get('user', 'N/A')}")
        print(f"    IP: {session.get('address', 'N/A')}")
        print(f"    Durée: {session.get('uptime', 'N/A')}")
    
    # Fermer la connexion
    mikrotik_manager.disconnect()
    print("\n✓ Connexion fermée")
    
    return True

if __name__ == "__main__":
    test_mikrotik_connection()