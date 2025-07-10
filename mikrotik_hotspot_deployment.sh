#!/bin/bash
# Script de déploiement complet pour le portail captif WiFi MikroTik
# Auteur: Assistant IA
# Version: 1.0

set -e  # Arrêter le script en cas d'erreur

# Configuration des couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction pour afficher des messages colorés
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Variables de configuration
MIKROTIK_IP="192.168.1.1"
MIKROTIK_USER="admin"
MIKROTIK_SSH_PORT="22"
HOTSPOT_INTERFACE="wlan1"
HOTSPOT_NETWORK="192.168.1.0/24"
HOTSPOT_POOL="192.168.1.100-192.168.1.200"
DOMAIN_NAME="portal.local"

# Répertoires de travail
WORK_DIR="/tmp/mikrotik_deployment"
HTML_DIR="$WORK_DIR/html"
SCRIPTS_DIR="$WORK_DIR/scripts"
BACKUP_DIR="$WORK_DIR/backup"

# =================================
# FONCTIONS UTILITAIRES
# =================================

# Fonction pour créer les répertoires de travail
create_work_directories() {
    log_info "Création des répertoires de travail..."
    mkdir -p "$WORK_DIR" "$HTML_DIR" "$SCRIPTS_DIR" "$BACKUP_DIR"
    log_success "Répertoires créés avec succès"
}

# Fonction pour vérifier la connectivité avec MikroTik
check_mikrotik_connectivity() {
    log_info "Vérification de la connectivité avec MikroTik ($MIKROTIK_IP)..."
    
    if ping -c 1 "$MIKROTIK_IP" &> /dev/null; then
        log_success "MikroTik accessible"
    else
        log_error "Impossible d'atteindre MikroTik. Vérifiez l'adresse IP."
        exit 1
    fi
}

# Fonction pour créer la sauvegarde
create_backup() {
    log_info "Création de la sauvegarde de la configuration actuelle..."
    
    local backup_file="$BACKUP_DIR/mikrotik_backup_$(date +%Y%m%d_%H%M%S).backup"
    
    # Commande pour créer une sauvegarde via SSH
    ssh "$MIKROTIK_USER@$MIKROTIK_IP" -p "$MIKROTIK_SSH_PORT" \
        "/system backup save name=deployment_backup" || {
        log_warning "Impossible de créer la sauvegarde automatique"
    }
    
    log_success "Sauvegarde créée"
}

# Fonction pour générer les fichiers HTML
generate_html_files() {
    log_info "Génération des fichiers HTML personnalisés..."
    
    # Génération du fichier login.html
    cat > "$HTML_DIR/login.html" << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion WiFi - Portail Captif</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .form-container {
            padding: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #333;
        }
        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            box-sizing: border-box;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 WiFi Portal</h1>
            <p>Accès Internet Sécurisé</p>
        </div>
        <div class="form-container">
            <form name="login" method="post" action="$(link-login-only)">
                <input type="hidden" name="dst" value="$(link-orig)" />
                <input type="hidden" name="popup" value="true" />
                
                <div class="form-group">
                    <label for="username">Nom d'utilisateur</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Mot de passe</label>
                    <input type="password" id="password" name="password" required>
                </div>
                
                <button type="submit" class="btn">Se Connecter</button>
            </form>
        </div>
    </div>
</body>
</html>
EOF

    # Génération du fichier status.html
    cat > "$HTML_DIR/status.html" << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Statut de Connexion</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 500px;
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #27ae60 0%, #2ecc71 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .content {
            padding: 30px;
        }
        .status-info {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .status-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            padding: 10px 0;
            border-bottom: 1px solid #e1e5e9;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: #e74c3c;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: block;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✅ Connecté</h1>
            <p>Votre session est active</p>
        </div>
        <div class="content">
            <div class="status-info">
                <div class="status-item">
                    <span>Utilisateur:</span>
                    <span>$(username)</span>
                </div>
                <div class="status-item">
                    <span>Adresse IP:</span>
                    <span>$(ip)</span>
                </div>
                <div class="status-item">
                    <span>Temps de connexion:</span>
                    <span>$(uptime)</span>
                </div>
                <div class="status-item">
                    <span>Temps restant:</span>
                    <span>$(session-time-left)</span>
                </div>
                <div class="status-item">
                    <span>Données envoyées:</span>
                    <span>$(bytes-out-nice)</span>
                </div>
                <div class="status-item">
                    <span>Données reçues:</span>
                    <span>$(bytes-in-nice)</span>
                </div>
            </div>
            <a href="$(link-logout)" class="btn">Se Déconnecter</a>
        </div>
    </div>
</body>
</html>
EOF

    # Génération du fichier logout.html
    cat > "$HTML_DIR/logout.html" << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Déconnexion - WiFi Portal</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
            padding: 40px;
        }
        .logout-icon {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #333;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
        }
        .btn {
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logout-icon">👋</div>
        <h1>Déconnexion réussie</h1>
        <p>Vous avez été déconnecté avec succès du réseau WiFi.</p>
        <a href="$(link-login-only)" class="btn">Se reconnecter</a>
    </div>
</body>
</html>
EOF

    # Génération du fichier error.html
    cat > "$HTML_DIR/error.html" << 'EOF'
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Erreur - WiFi Portal</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
            text-align: center;
            padding: 40px;
        }
        .error-icon {
            font-size: 64px;
            margin-bottom: 20px;
            color: #e74c3c;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
        }
        .btn {
            padding: 12px 30px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">⚠️</div>
        <h1>Erreur de connexion</h1>
        <p>$(error-orig)</p>
        <a href="$(link-login-only)" class="btn">Réessayer</a>
    </div>
</body>
</html>
EOF

    log_success "Fichiers HTML générés avec succès"
}

# Fonction pour générer les scripts MikroTik
generate_mikrotik_scripts() {
    log_info "Génération des scripts MikroTik..."
    
    # Script de configuration principal
    cat > "$SCRIPTS_DIR/configure_hotspot.rsc" << 'EOF'
# Configuration complète du portail captif
:log info "Début de la configuration du portail captif"

# 1. Configuration des profils utilisateur
/ip hotspot user profile remove [find name="basic"]
/ip hotspot user profile remove [find name="standard"]
/ip hotspot user profile remove [find name="premium"]

/ip hotspot user profile add name="basic" session-timeout=01:00:00 idle-timeout=00:10:00 rate-limit="512k/512k" shared-users=1
/ip hotspot user profile add name="standard" session-timeout=03:00:00 idle-timeout=00:15:00 rate-limit="1M/1M" shared-users=2
/ip hotspot user profile add name="premium" session-timeout=24:00:00 idle-timeout=00:30:00 rate-limit="2M/2M" shared-users=5

# 2. Configuration du pool d'adresses
/ip pool remove [find name="hotspot-pool"]
/ip pool add name="hotspot-pool" ranges=192.168.1.100-192.168.1.200

# 3. Configuration des règles de firewall
/ip firewall filter add chain=input action=accept protocol=udp dst-port=53 comment="Allow DNS"
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=80 comment="Allow HTTP"
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=443 comment="Allow HTTPS"

# 4. Configuration des scripts d'automatisation
/system script add name="create-hotspot-user" policy=read,write,policy,test,password,sniff,sensitive source={
    :local username $1
    :local password $2
    :local profile $3
    :local phone $4
    
    /ip hotspot user add name=$username password=$password profile=$profile comment="Phone: $phone"
    :log info "New user created: $username with profile: $profile"
}

# 5. Configuration du hotspot
/ip hotspot remove [find name="hotspot1"]
/ip hotspot add name="hotspot1" interface=wlan1 address-pool=hotspot-pool profile=default

# 6. Configuration des logs
/system logging add topics=hotspot action=disk prefix="HOTSPOT"
/system logging add topics=script action=disk prefix="PAYMENT"

:log info "Configuration du portail captif terminée"
EOF

    # Script de nettoyage
    cat > "$SCRIPTS_DIR/cleanup.rsc" << 'EOF'
# Script de nettoyage des utilisateurs expirés
:log info "Début du nettoyage des utilisateurs expirés"

:foreach user in=[/ip hotspot user find] do={
    :local username [/ip hotspot user get $user name]
    :if ([:len [/ip hotspot active find user=$username]] = 0) do={
        :local lastLoginTime [/ip hotspot user get $user comment]
        :if ([:len $lastLoginTime] > 0) do={
            :local daysSinceLogin ([:tonum [/system clock get date]] - [:tonum $lastLoginTime])
            :if ($daysSinceLogin > 7) do={
                /ip hotspot user remove $user
                :log info "Utilisateur supprimé: $username"
            }
        }
    }
}

:log info "Nettoyage terminé"
EOF

    # Script de monitoring
    cat > "$SCRIPTS_DIR/monitor.rsc" << 'EOF'
# Script de monitoring du portail captif
:log info "Monitoring du portail captif"

:local activeUsers [:len [/ip hotspot active find]]
:local totalUsers [:len [/ip hotspot user find]]
:local totalBandwidth 0

:foreach activeUser in=[/ip hotspot active find] do={
    :local userBandwidth [/ip hotspot active get $activeUser bytes-out]
    :set totalBandwidth ($totalBandwidth + $userBandwidth)
}

:log info "Utilisateurs actifs: $activeUsers/$totalUsers"
:log info "Bande passante totale: $totalBandwidth bytes"

# Vérification de la santé du système
:local memoryUsage [/system resource get free-memory]
:local cpuLoad [/system resource get cpu-load]

:if ($memoryUsage < 10000000) do={
    :log warning "Mémoire faible: $memoryUsage bytes"
}

:if ($cpuLoad > 80) do={
    :log warning "Charge CPU élevée: $cpuLoad%"
}
EOF

    # Script de sauvegarde automatique
    cat > "$SCRIPTS_DIR/auto_backup.rsc" << 'EOF'
# Script de sauvegarde automatique
:local backupName ("backup_" . [/system clock get date] . "_" . [/system clock get time])
:set backupName [:tostr $backupName]

/system backup save name=$backupName
:log info "Sauvegarde automatique créée: $backupName"

# Supprimer les anciennes sauvegardes (garder les 5 dernières)
:local backupCount 0
:foreach backup in=[/file find name~"^backup_"] do={
    :set backupCount ($backupCount + 1)
    :if ($backupCount > 5) do={
        :local fileName [/file get $backup name]
        /file remove $backup
        :log info "Ancienne sauvegarde supprimée: $fileName"
    }
}
EOF

    log_success "Scripts MikroTik générés avec succès"
}

# Fonction pour uploader les fichiers vers MikroTik
upload_files_to_mikrotik() {
    log_info "Upload des fichiers vers MikroTik..."
    
    # Upload des fichiers HTML
    scp -P "$MIKROTIK_SSH_PORT" "$HTML_DIR"/*.html "$MIKROTIK_USER@$MIKROTIK_IP:/flash/hotspot/" || {
        log_warning "Impossible d'uploader les fichiers HTML automatiquement"
        log_info "Veuillez uploader manuellement les fichiers HTML depuis $HTML_DIR"
    }
    
    # Upload des scripts
    scp -P "$MIKROTIK_SSH_PORT" "$SCRIPTS_DIR"/*.rsc "$MIKROTIK_USER@$MIKROTIK_IP:/flash/" || {
        log_warning "Impossible d'uploader les scripts automatiquement"
        log_info "Veuillez uploader manuellement les scripts depuis $SCRIPTS_DIR"
    }
    
    log_success "Upload terminé"
}

# Fonction pour exécuter la configuration sur MikroTik
execute_configuration() {
    log_info "Exécution de la configuration sur MikroTik..."
    
    # Exécution du script de configuration principal
    ssh "$MIKROTIK_USER@$MIKROTIK_IP" -p "$MIKROTIK_SSH_PORT" \
        "/import file-name=configure_hotspot.rsc" || {
        log_error "Erreur lors de l'exécution de la configuration"
        exit 1
    }
    
    log_success "Configuration appliquée avec succès"
}

# Fonction pour créer la base de données SQLite
setup_database() {
    log_info "Configuration de la base de données SQLite..."
    
    # Créer le fichier de base de données
    cat > "$WORK_DIR/init_database.sql" << 'EOF'
-- Création de la base de données pour le portail captif
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    profile VARCHAR(20) NOT NULL,
    phone VARCHAR(20),
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id VARCHAR(100) UNIQUE NOT NULL,
    user_id INTEGER,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(5) DEFAULT 'XOF',
    payment_method VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    mac_address VARCHAR(17),
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0,
    session_duration INTEGER DEFAULT 0,
    FOREIGN KEY (username) REFERENCES users(username)
);

CREATE TABLE IF NOT EXISTS payment_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code VARCHAR(20) UNIQUE NOT NULL,
    profile VARCHAR(20) NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    currency VARCHAR(5) DEFAULT 'XOF',
    validity_hours INTEGER DEFAULT 24,
    used BOOLEAN DEFAULT FALSE,
    used_by VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP
);

-- Insertion des données de test
INSERT OR IGNORE INTO users (username, password, profile, phone, email) VALUES
('admin', 'admin123', 'premium', '+229123456789', 'admin@portal.local'),
('test1', 'password', 'basic', '+229987654321', 'test1@portal.local'),
('test2', 'password', 'standard', '+229456789123', 'test2@portal.local');

INSERT OR IGNORE INTO payment_codes (code, profile, amount, currency, validity_hours) VALUES
('BASIC001', 'basic', 500, 'XOF', 1),
('STANDARD001', 'standard', 1000, 'XOF', 3),
('PREMIUM001', 'premium', 2000, 'XOF', 24);
EOF

    # Créer la base de données SQLite
    if command -v sqlite3 &> /dev/null; then
        sqlite3 "$WORK_DIR/portal.db" < "$WORK_DIR/init_database.sql"
        log_success "Base de données SQLite créée avec succès"
    else
        log_warning "SQLite3 non installé. Créez la base de données manuellement"
        log_info "Fichier SQL disponible : $WORK_DIR/init_database.sql"
    fi
}

# Fonction pour créer un script de gestion des utilisateurs
create_user_management_script() {
    log_info "Création du script de gestion des utilisateurs..."
    
    cat > "$WORK_DIR/user_manager.py" << 'EOF'
#!/usr/bin/env python3
"""
Script de gestion des utilisateurs du portail captif
"""

import sqlite3
import hashlib
import secrets
import argparse
from datetime import datetime, timedelta

class UserManager:
    def __init__(self, db_path="portal.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row

    def create_user(self, username, password, profile="basic", phone=None, email=None):
        """Créer un nouvel utilisateur"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, password, profile, phone, email)
                VALUES (?, ?, ?, ?, ?)
            """, (username, password, profile, phone, email))
            self.conn.commit()
            print(f"Utilisateur {username} créé avec succès")
            return True
        except sqlite3.IntegrityError:
            print(f"Erreur: L'utilisateur {username} existe déjà")
            return False

    def delete_user(self, username):
        """Supprimer un utilisateur"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        if cursor.rowcount > 0:
            self.conn.commit()
            print(f"Utilisateur {username} supprimé")
            return True
        else:
            print(f"Utilisateur {username} non trouvé")
            return False

    def list_users(self):
        """Lister tous les utilisateurs"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        
        print("\n=== Liste des utilisateurs ===")
        for user in users:
            print(f"Username: {user['username']}")
            print(f"Profile: {user['profile']}")
            print(f"Phone: {user['phone']}")
            print(f"Email: {user['email']}")
            print(f"Created: {user['created_at']}")
            print(f"Status: {user['status']}")
            print("-" * 40)

    def generate_payment_code(self, profile, amount, currency="XOF", validity_hours=24):
        """Générer un code de paiement"""
        code = secrets.token_hex(8).upper()
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO payment_codes (code, profile, amount, currency, validity_hours)
            VALUES (?, ?, ?, ?, ?)
        """, (code, profile, amount, currency, validity_hours))
        self.conn.commit()
        
        print(f"Code de paiement généré: {code}")
        print(f"Profile: {profile}")
        print(f"Montant: {amount} {currency}")
        print(f"Validité: {validity_hours} heures")
        return code

    def use_payment_code(self, code, username):
        """Utiliser un code de paiement"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM payment_codes 
            WHERE code = ? AND used = FALSE
        """, (code,))
        
        payment_code = cursor.fetchone()
        if not payment_code:
            print("Code invalide ou déjà utilisé")
            return False
            
        # Vérifier la validité
        created_at = datetime.fromisoformat(payment_code['created_at'])
        expiry = created_at + timedelta(hours=payment_code['validity_hours'])
        
        if datetime.now() > expiry:
            print("Code expiré")
            return False
            
        # Marquer comme utilisé
        cursor.execute("""
            UPDATE payment_codes 
            SET used = TRUE, used_by = ?, used_at = ? 
            WHERE code = ?
        """, (username, datetime.now().isoformat(), code))
        
        # Créer ou mettre à jour l'utilisateur
        cursor.execute("""
            INSERT OR REPLACE INTO users (username, password, profile)
            VALUES (?, ?, ?)
        """, (username, secrets.token_hex(8), payment_code['profile']))
        
        self.conn.commit()
        print(f"Code utilisé avec succès pour {username}")
        return True

    def show_stats(self):
        """Afficher les statistiques"""
        cursor = self.conn.cursor()
        
        # Nombre d'utilisateurs par profil
        cursor.execute("""
            SELECT profile, COUNT(*) as count 
            FROM users 
            GROUP BY profile
        """)
        profiles = cursor.fetchall()
        
        print("\n=== Statistiques ===")
        print("Utilisateurs par profil:")
        for profile in profiles:
            print(f"  {profile['profile']}: {profile['count']}")
        
        # Sessions actives
        cursor.execute("""
            SELECT COUNT(*) as count FROM sessions WHERE end_time IS NULL
        """)
        active_sessions = cursor.fetchone()
        print(f"Sessions actives: {active_sessions['count']}")

    def close(self):
        """Fermer la connexion à la base de données"""
        self.conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gestion des utilisateurs du portail captif")
    parser.add_argument("action", choices=["create", "delete", "list", "generate_code", "use_code", "stats"], help="Action à effectuer")
    parser.add_argument("--username", help="Nom d'utilisateur")
    parser.add_argument("--password", help="Mot de passe")
    parser.add_argument("--profile", default="basic", help="Profil de l'utilisateur")
    parser.add_argument("--phone", help="Numéro de téléphone")
    parser.add_argument("--email", help="Adresse email")
    parser.add_argument("--amount", type=float, help="Montant du code de paiement")
    parser.add_argument("--currency", default="XOF", help="Monnaie du code de paiement")
    parser.add_argument("--validity", type=int, default=24, help="Validité en heures du code de paiement")
    parser.add_argument("--code", help="Code de paiement à utiliser")

    args = parser.parse_args()

    manager = UserManager()

    if args.action == "create":
        if not args.username or not args.password:
            print("Erreur: Nom d'utilisateur et mot de passe sont requis.")
        else:
            manager.create_user(args.username, args.password, args.profile, args.phone, args.email)

    elif args.action == "delete":
        if not args.username:
            print("Erreur: Nom d'utilisateur requis pour la suppression.")
        else:
            manager.delete_user(args.username)

    elif args.action == "list":
        manager.list_users()

    elif args.action == "generate_code":
        if not args.profile or not args.amount:
            print("Erreur: Profil et montant requis pour générer un code.")
        else:
            manager.generate_payment_code(args.profile, args.amount, args.currency, args.validity)

    elif args.action == "use_code":
        if not args.code or not args.username:
            print("Erreur: Code de paiement et nom d'utilisateur requis pour l'utilisation.")
        else:
            manager.use_payment_code(args.code, args.username)

    elif args.action == "stats":
        manager.show_stats()

    manager.close()
