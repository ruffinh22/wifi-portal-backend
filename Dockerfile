# Dockerfile pour Portail WiFi Flask
# Utilise Python 3.11 slim pour une image légère et sécurisée
FROM python:3.11-slim

# Variables d'environnement pour optimiser Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Créer un utilisateur non-root pour la sécurité
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Définir le répertoire de travail
WORKDIR /app

# Installer les dépendances système nécessaires
RUN apt-get update && apt-get install -y \
    gcc \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de requirements en premier (pour optimiser le cache Docker)
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code de l'application
COPY . .

# Créer les répertoires nécessaires et définir les permissions
RUN mkdir -p /app/logs \
    && mkdir -p /app/templates \
    && mkdir -p /app/static \
    && touch /app/wifi_portal.db \
    && touch /app/wifi_portal.log \
    && chown -R appuser:appuser /app

# Basculer vers l'utilisateur non-root
USER appuser

# Exposer le port de l'application
EXPOSE 5000

# Commande de santé pour vérifier que l'application fonctionne
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Commande par défaut pour lancer l'application
CMD ["python", "app.py"]