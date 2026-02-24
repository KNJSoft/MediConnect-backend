import re
import time
import logging
from datetime import timedelta, datetime
from django.utils import timezone
from django.http import HttpRequest, HttpResponse, JsonResponse, HttpResponseForbidden
from django.conf import settings
from django.core.cache import cache
from django.urls import resolve
from user_agents import parse
from .models import User, Device, IP, UserRole
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

class SecurityHeadersMiddleware:
    """
    Middleware pour ajouter des en-têtes de sécurité HTTP
    et bloquer les requêtes suspectes
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Vérifier les en-têtes de requête suspects
        if self.is_suspicious_request(request):
            logger.warning(f"Requête suspecte bloquée : {request.path}")
            return HttpResponseForbidden("Accès non autorisé")
            
        # Traiter la requête normalement
        response = self.get_response(request)
        
        # Ajouter des en-têtes de sécurité
        self.add_security_headers(response)
        
        # Bloquer les robots sur les pages sensibles
        if self.is_sensitive_path(request.path):
            response['X-Robots-Tag'] = 'noindex, nofollow, noarchive, nosnippet, notranslate, noimageindex'
            
        return response
    
    def is_suspicious_request(self, request):
        """Détecte les requêtes potentiellement malveillantes"""
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        # Liste des user-agents de robots connus à bloquer
        bad_bots = [
            'ahrefsbot', 'semrush', 'mj12bot', 'dotbot', 'mj12bot', 'rogerbot',
            'exabot', 'grapeshot', 'ccbot', 'yandexbot', 'baiduspider', 'spbot'
        ]
        
        # Vérifier si le user-agent est dans la liste des robots indésirables
        if any(bot in user_agent for bot in bad_bots):
            return True
            
        # Vérifier les chemins d'accès suspects
        suspicious_paths = [
            '/wp-admin', '/wp-login.php', '/xmlrpc.php', '/.env',
            '/.git/config', '/adminer.php', '/phpmyadmin', '/.git/'
        ]
        
        if any(path in request.path.lower() for path in suspicious_paths):
            return True
            
        return False
    
    def add_security_headers(self, response):
        """Ajoute des en-têtes de sécurité HTTP"""
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': "geolocation=(), microphone=(), camera=()"
            # La configuration CSP est gérée par django-csp dans settings.py
        }
        
        for header, value in headers.items():
            if header not in response:
                response[header] = value
    
    def is_sensitive_path(self, path):
        """Détermine si le chemin est considéré comme sensible"""
        sensitive_paths = [
            '/profil/', '/mon-historique/', '/mes-favoris/',
            '/admin/', '/accounts/', '/favoris/ajouter/'
        ]
        return any(sensitive in path for sensitive in sensitive_paths)

class UserTrackingMiddleware:
    """
    Middleware pour la sécurité et le suivi des utilisateurs.
    - Protection contre les attaques DoS
    - Suivi des adresses IP et des appareils
    - Limitation du débit des requêtes
    """
    def __init__(self, get_response):
        self.get_response = get_response
        # Configuration de la sécurité
        self.RATE_LIMIT = getattr(settings, 'RATE_LIMIT', {
            'anon': 60,    # 60 requêtes par minute pour les utilisateurs non authentifiés
            'user': 300,   # 300 requêtes par minute pour les utilisateurs authentifiés
            'search': 30,  # 30 requêtes par minute pour les recherches
            'api': 100,    # 100 requêtes par minute pour les API
            'window': 60,  # 60 secondes
        })
        self.REQUEST_TIMEOUT = getattr(settings, 'REQUEST_TIMEOUT', 30)  # secondes
        self.MAX_UPLOAD_SIZE = getattr(settings, 'MAX_UPLOAD_SIZE', 10 * 1024 * 1024)  # 10MB
        
        # Liste noire d'agents utilisateurs suspects (robots, scrapers, etc.)
        self.BLOCKED_USER_AGENTS = [
            'scrapy', 'splash', 'selenium', 'phantomjs', 'puppeteer', 'headless',
            'python-requests', 'curl', 'wget', 'httrack', 'grab', 'go-http-client',
            'java', 'okhttp', 'apache-httpclient', 'python-urllib', 'php', 'ruby',
            'nutch', 'baiduspider', 'yandexbot', 'ahrefs', 'semrush', 'mj12bot',
            'dotbot', 'rogerbot', 'exabot', 'semrushbot', 'ahrefsbot', 'mj12bot',
            'dotbot', 'rogerbot', 'exabot', 'semrushbot', 'ahrefsbot', 'mj12bot'
        ]
        
        # Chemins à protéger contre le scraping
        self.PROTECTED_PATHS = [
            '/api/', '/admin/', '/connexion/', '/inscription/', '/compte/',
            '/recherche/', '/contact/', '/newsletter/'
        ]
        
        # Vérifier et créer l'utilisateur 'anonymous' s'il n'existe pas
        self.anonymous_user = self.get_or_create_anonymous_user()

    def __call__(self, request: HttpRequest):
        # Vérification de l'agent utilisateur
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        
        # Bloquer les robots et scrapers connus
        if any(bot in user_agent for bot in self.BLOCKED_USER_AGENTS):
            return HttpResponse('Accès refusé', status=403)
            
        # Vérification de la taille de la requête
        if request.method in ('POST', 'PUT', 'PATCH'):
            content_length = int(request.META.get('CONTENT_LENGTH', 0))
            if content_length > self.MAX_UPLOAD_SIZE:
                return HttpResponse('Requête trop volumineuse', status=413)
        
        # Vérification du timeout de la requête
        request.start_time = time.time()
        
        # Vérification du rate limiting
        if not self.check_rate_limit(request):
            # Ajouter un délai pour ralentir les requêtes excessives
            time.sleep(2)
            return JsonResponse(
                {
                    'error': 'Trop de requêtes. Veuillez ralentir et réessayer dans quelques instants.',
                    'status': 'rate_limit_exceeded'
                }, 
                status=429
            )
            
        # Vérifier les chemins protégés pour les robots
        if any(path in request.path for path in self.PROTECTED_PATHS) and \
           any(bot in user_agent for bot in ['bot', 'spider', 'crawler']):
            return HttpResponse('Accès non autorisé', status=403)
        
        # Vérification du timeout de la requête
        if hasattr(request, 'start_time') and (time.time() - request.start_time) > self.REQUEST_TIMEOUT:
            return HttpResponse('Request timeout', status=408)
        
        # Traiter la requête
        response = self.get_response(request)
        
        # Si l'utilisateur est authentifié, utiliser son compte, sinon utiliser 'anonymous'
        user = request.user if hasattr(request, 'user') and request.user.is_authenticated else self.anonymous_user
        
        # Récupérer l'adresse IP du client
        ip_address = self.get_client_ip(request)
        
        # Récupérer les informations du navigateur
        user_agent = request.META.get('HTTP_USER_AGENT', 'Inconnu')
        
        # Enregistrer l'IP et l'appareil si ce n'est pas déjà fait pour cette session
        if not request.session.get('ip_logged', False):
            self.log_ip(user, ip_address, user_agent)
            request.session['ip_logged'] = True
            
        if not request.session.get('device_logged', False):
            self.log_device(user, user_agent, ip_address)
            request.session['device_logged'] = True
        
        # Ajouter des en-têtes de sécurité avancés
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Content Security Policy (CSP)
        csp = [
            "default-src 'self';",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://code.jquery.com;",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;",
            "img-src 'self' data: https:;",
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;",
            "connect-src 'self';",
            "frame-ancestors 'none';",
            "form-action 'self';",
            "upgrade-insecure-requests;"
        ]
        response['Content-Security-Policy'] = ' '.join(csp)
        
        # Autres en-têtes de sécurité
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()"
        response['Cross-Origin-Opener-Policy'] = 'same-origin'
        response['Cross-Origin-Resource-Policy'] = 'same-origin'
        
        # Enregistrer l'IP (avec l'appareil) et l'appareil (si ce n'est pas déjà fait pour cette session)
        if not request.session.get('ip_logged', False):
            self.log_ip(user, ip_address, user_agent)
            request.session['ip_logged'] = True
            
        if not request.session.get('device_logged', False):
            self.log_device(user, user_agent)
            request.session['device_logged'] = True
        
        return response
    
    def get_or_create_anonymous_user(self):
        """Crée ou récupère l'utilisateur 'anonymous'."""
        from django.utils.crypto import get_random_string
        
        try:
            return User.objects.get(username='anonymous')
        except User.DoesNotExist:
            # Créer un mot de passe aléatoire sécurisé
            password = get_random_string(50)
            
            return User.objects.create_user(
                username='anonymous',
                email='anonymous@example.com',
                password=password,
                is_active=False,
                first_name='Anonymous',
                last_name='User',
                role=UserRole.PATIENT
            )
    
    def get_client_ip(self, request: HttpRequest) -> str:
        """
        Récupère l'adresse IP du client de manière sécurisée.
        Prend en compte les en-têtes HTTP_X_FORWARDED_FOR et REMOTE_ADDR.
        """
        # Liste des en-têtes à vérifier (par ordre de priorité)
        ip_headers = [
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR',
        ]
        
        for header in ip_headers:
            if header in request.META:
                ip = request.META[header]
                if header == 'HTTP_X_FORWARDED_FOR':
                    # Prendre la première IP de la liste (celle du client d'origine)
                    ip = ip.split(',')[0].strip()
                if ip:
                    # Validation basique de l'adresse IP
                    if self.is_valid_ip(ip):
                        return ip
        
        return '0.0.0.0'  # Adresse IP par défaut sécurisée
    
    def is_valid_ip(self, ip: str) -> bool:
        """Vérifie si une adresse IP est valide."""
        try:
            # Vérification IPv4
            parts = ip.split('.')
            if len(parts) == 4 and all(0 <= int(part) < 256 for part in parts):
                return True
                
            # Vérification IPv6 (simplifiée)
            if ':' in ip:
                return True
                
            return False
        except (ValueError, AttributeError):
            return False
    
    def log_ip(self, user: User, ip_address: str, user_agent: str = None):
        """
        Enregistre l'adresse IP de l'utilisateur avec l'appareil associé.
        
        Args:
            user: L'utilisateur associé à l'IP
            ip_address: L'adresse IP à enregistrer
            user_agent: Les informations du navigateur (optionnel)
        """
        # Vérifier si cette IP a déjà été enregistrée pour cet utilisateur
        if not IP.objects.filter(user=user, ip=ip_address).exists():
            # Créer l'entrée IP
            ip_entry = IP.objects.create(
                user=user,
                ip=ip_address
            )
            
            # Si un user_agent est fourni, enregistrer ou mettre à jour l'appareil
            if user_agent:
                self.log_device(user, user_agent, ip_address)
                
            return ip_entry
    
    def log_device(self, user: User, user_agent: str, ip_address: str = None):
        """Enregistre ou met à jour l'appareil de l'utilisateur."""
        from user_agents import parse
        
        # Parser l'user agent
        ua = parse(user_agent)
        
        # Créer un nom d'appareil lisible
        device_name = f"{ua.device.brand or 'Inconnu'} {ua.device.model or ''} ({ua.os.family} {ua.os.version_string or ''})"
        device_name = device_name.strip()
        
        # Créer ou mettre à jour l'appareil
        device, created = Device.objects.get_or_create(
            user=user,
            user_agent=user_agent[:255],  # Tronquer si nécessaire
            defaults={
                'name': device_name[:255],
                'device_type': ua.device.family,
                'os': f"{ua.os.family} {ua.os.version_string or ''}".strip(),
                'browser': f"{ua.browser.family} {ua.browser.version_string or ''}".strip(),
                'ip_address': ip_address,
                'last_login': timezone.now(),
                'active': True
            }
        )
        
        # Si l'appareil existe déjà, mettre à jour les informations
        if not created:
            device.last_login = timezone.now()
            device.active = True
            
            # Mettre à jour l'IP si elle a changé
            if ip_address and device.ip_address != ip_address:
                device.ip_address = ip_address
                
            device.save(update_fields=['last_login', 'active', 'ip_address'])
            
            # S'il n'y a pas d'appareil principal, définir celui-ci comme principal
            if not Device.objects.filter(user=user, is_primary=True).exists():
                device.is_primary = True
                device.save(update_fields=['is_primary'])
        elif not Device.objects.filter(user=user, is_primary=True).exists():
            # Pour un nouvel appareil, le définir comme principal s'il n'y en a pas
            device.is_primary = True
            device.save(update_fields=['is_primary'])
    
    def clean_user_agent(self, user_agent: str) -> str:
        """Nettoie l'user agent pour une meilleure détection des appareils."""
        # Supprimer les versions logicielles pour regrouper les appareils similaires
        cleaned = re.sub(r'\b(?:\d+\.?)+\b', '', user_agent)
        # Supprimer les espaces multiples
        cleaned = ' '.join(cleaned.split())
        return cleaned or 'Inconnu'
    def check_rate_limit(self, request):
        """
        Vérifie et applique les limites de taux pour l'utilisateur ou l'IP.
        Retourne True si la requête est autorisée, False sinon.
        """
        # Utiliser l'ID utilisateur pour les utilisateurs authentifiés, sinon l'adresse IP
        if hasattr(request, 'user') and request.user.is_authenticated:
            key = f'user:{request.user.id}'
            limit = self.RATE_LIMIT['user']
        else:
            key = f'ip:{self.get_client_ip(request)}'
            limit = self.RATE_LIMIT['anon']
        
        # Vérifier le nombre de requêtes dans la fenêtre actuelle
        current = cache.get(key, 0)
        
        if current >= limit:
            return False
        
        # Incrémenter le compteur
        cache.set(
            key, 
            current + 1, 
            timeout=self.RATE_LIMIT['window']
        )
        
        # Ajouter des en-têtes de quota
        request.META['X-RateLimit-Limit'] = str(limit)
        request.META['X-RateLimit-Remaining'] = str(limit - (current + 1))
        request.META['X-RateLimit-Reset'] = str(int(time.time()) + self.RATE_LIMIT['window'])
        
        return True


class DeviceTrackingMiddleware(MiddlewareMixin):
    """
    Middleware pour suivre les appareils connectés des utilisateurs
    """
    def process_request(self, request):
        # Ne rien faire pour les utilisateurs non authentifiés
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return

        # Ne pas traiter les requêtes AJAX ou les requêtes API
        if request.path.startswith('/api/') or request.path.startswith('/admin/'):
            return

        # Créer ou mettre à jour l'appareil pour cet utilisateur
        try:
            Device.create_from_request(request, request.user)
        except Exception as e:
            # En production, vous pourriez vouloir logger cette erreur
            pass

    def process_response(self, request, response):
        return response
