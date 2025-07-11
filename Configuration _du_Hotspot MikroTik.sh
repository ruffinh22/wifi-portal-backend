# Configuration MikroTik Hotspot - Commands à exécuter dans le terminal MikroTik

# 1. Créer un utilisateur API
/user add name=api_user password=api_password group=full

# 2. Activer l'API
/ip service set api disabled=no

# 3. Créer une interface bridge pour le hotspot
/interface bridge add name=bridge-hotspot

# 4. Ajouter les interfaces au bridge
/interface bridge port add bridge=bridge-hotspot interface=wlan1
/interface bridge port add bridge=bridge-hotspot interface=ether2

# 5. Configurer l'IP du bridge
/ip address add address=192.168.10.1/24 interface=bridge-hotspot

# 6. Configurer le pool d'adresses IP
/ip pool add name=hotspot-pool ranges=192.168.10.2-192.168.10.100

# 7. Créer le serveur DHCP
/ip dhcp-server add name=dhcp-hotspot interface=bridge-hotspot lease-time=1h address-pool=hotspot-pool disabled=no
/ip dhcp-server network add address=192.168.10.0/24 gateway=192.168.10.1 dns-server=8.8.8.8,8.8.4.4

# 8. Créer le serveur hotspot
/ip hotspot add name=hotspot1 interface=bridge-hotspot address-pool=hotspot-pool profile=default disabled=no

# 9. Créer les profils utilisateur
/ip hotspot user profile add name=basic_profile rate-limit=512k/512k session-timeout=1h shared-users=1
/ip hotspot user profile add name=standard_profile rate-limit=1M/1M session-timeout=3h shared-users=2
/ip hotspot user profile add name=premium_profile rate-limit=2M/2M session-timeout=24h shared-users=5

# 10. Configurer la page de connexion personnalisée (optionnel)
/ip hotspot walled-garden add dst-host=your-flask-app.com
/ip hotspot walled-garden add dst-host=api.kkiapay.me

# 11. Configurer le firewall pour autoriser l'API
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=8728 src-address=IP_DE_VOTRE_SERVEUR_FLASK

# 12. Configurer NAT pour l'accès internet
/ip firewall nat add chain=srcnat out-interface=ether1 action=masquerade