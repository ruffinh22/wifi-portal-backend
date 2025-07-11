#!/bin/bash
# start.sh - Script de démarrage pour Portail WiFi

set -e

echo "🚀 Démarrage du Portail WiFi..."

# Vérifier si le fichier .env existe
if [ ! -f .env ]; then
    echo "⚠️  Fichier .env non trouvé. Copie du fichier exemple..."
    cp .env.example .env
    echo "✅ Fichier .env créé. Veuillez le modifier avec vos vraies valeurs."
    echo "📝 Éditez le fichier .env avant de continuer."
    exit 1
fi

# Charger les variables d'environnement
source .env

# Vérifier Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker n'est pas installé. Veuillez installer Docker d'abord."
    exit 1
fi

# Vérifier Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose n'est pas installé. Veuillez installer Docker Compose d'abord."
    exit 1
fi

# Construire l'image Docker
echo "🔨 Construction de l'image Docker..."
docker-compose build

# Démarrer les services
echo "🚀 Démarrage des services..."
docker-compose up -d

# Vérifier le statut
echo "⏳ Attente du démarrage des services..."
sleep 10

# Vérifier si l'application est accessible
if curl -f http://localhost:5000/ > /dev/null 2>&1; then
    echo "✅ Portail WiFi démarré avec succès!"
    echo "🌐 Accès: http://localhost:5000"
    echo "🔧 Admin: http://localhost:5000/admin/login"
    echo "📊 Logs: docker-compose logs -f"
else
    echo "❌ Échec du démarrage. Vérifiez les logs:"
    docker-compose logs
    exit 1
fi

# Afficher les informations utiles
echo ""
echo "📋 Commandes utiles:"
echo "   - Voir les logs: docker-compose logs -f"
echo "   - Arrêter: docker-compose down"
echo "   - Redémarrer: docker-compose restart"
echo "   - Mise à jour: docker-compose pull && docker-compose up -d"
echo ""

# Optionnel: Ouvrir le navigateur
if command -v xdg-open &> /dev/null; then
    echo "🌐 Ouverture du navigateur..."
    xdg-open http://localhost:5000
elif command -v open &> /dev/null; then
    echo "🌐 Ouverture du navigateur..."
    open http://localhost:5000
fi