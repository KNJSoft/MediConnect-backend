import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils import timezone

# Create your models here.

# --- Helper function for UUID generation ---
# Define a named function to generate UUIDs, which Django can serialize.
def generate_uuid_pk():
    return str(uuid.uuid4())

# --- Rôles d'Utilisateur ---
# Nous allons utiliser une énumération pour les rôles afin de garantir la cohérence.
class UserRole(models.TextChoices):
    PATIENT = 'PATIENT', 'Patient'
    ADMIN = 'ADMIN', 'Admin'
    DOCTOR = 'DOCTOR', 'Doctor'
    SUPER_ADMIN = 'SUPER_ADMIN', 'Super Admin'


# --- Custom User Manager (Optionnel mais recommandé pour AbstractUser) ---
# Ceci permet de gérer la création d'utilisateurs avec nos champs personnalisés.
class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        extra_fields.setdefault('username', email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', UserRole.SUPER_ADMIN)  # SuperAdmin par défaut
        extra_fields.setdefault('username', email)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


# --- 1. User (Utilisateur) ---
class User(AbstractUser):
    groups = models.ForeignKey(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        null=True,
        help_text='The groups this user belongs to.',
        related_name='mediconnect_user_set',
        related_query_name='mediconnect_user',
        on_delete=models.CASCADE
    )
    user_permissions = models.ForeignKey(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        null=True,
        help_text='Specific permissions for this user.',
        related_name='mediconnect_user_set',
        related_query_name='mediconnect_user',
        on_delete=models.CASCADE
    )
    # Utilise un UUID comme clé primaire
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    email = models.EmailField(unique=True, blank=False, null=False)
    role = models.CharField(
        max_length=20,
        choices=UserRole.choices,
        default=UserRole.PATIENT  # Rôle par défaut
    )
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    phone_number = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)  # Pour activer/désactiver le compte
    is_staff = models.BooleanField(default=False)  # Si l'utilisateur peut accéder à l'interface d'administration
    bio = models.TextField(blank=True, null=True)
    is_verified = models.BooleanField(default=False, verbose_name='Email vérifié')
    verification_code = models.CharField(max_length=6, null=True, blank=True, verbose_name='Code de vérification')
    verification_code_created_at = models.DateTimeField(null=True, blank=True, verbose_name='Date de création du code')
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    
    
    
    
    def generate_verification_code(self):
        """Génère un code de vérification à 6 chiffres et met à jour le modèle"""
        import random
        from django.utils import timezone
        
        self.verification_code = str(random.randint(100000, 999999))
        self.verification_code_created_at = timezone.now()
        self.save(update_fields=['verification_code', 'verification_code_created_at'])
        return self.verification_code
        
    def is_verification_code_valid(self, code):
        """Vérifie si le code fourni est valide et n'a pas expiré (15 minutes)"""
        from django.utils import timezone
        from datetime import timedelta
        
        if not self.verification_code or self.verification_code != code:
            return False
            
        # Vérifier si le code a expiré (15 minutes)
        expiration_time = self.verification_code_created_at + timedelta(minutes=15)
        return timezone.now() <= expiration_time
    # Nouveau champ pour le jeton FCM (pour les notifications push)
    # Indique que 'email' est utilisé comme champ d'identification unique
    USERNAME_FIELD = 'email'
    # 'username' et 'email' sont requis par défaut, mais nous utilisons 'email' pour la connexion.
    # Les champs listés ici seront demandés lors de la création d'un superutilisateur via createsuperuser.
    REQUIRED_FIELDS = []

    objects = CustomUserManager()  # Utilise notre gestionnaire d'utilisateurs personnalisé

    class Meta:
        verbose_name = "Utilisateur"
        verbose_name_plural = "Utilisateurs"
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['role']),
        ]

    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"

# --- 2. Profils Spécifiques ---

class DoctorProfile(models.Model):
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='doctor_profile')
    specialty = models.CharField(max_length=100)
    is_available = models.BooleanField(default=True)
    license_number = models.CharField(max_length=50)

    def __str__(self):
        return f"Dr. {self.user.last_name}"

# --- 3. Cœur du Système : Consultations & IA ---

class Case(models.Model):
    """Représente un problème posé par un malade"""
    STATUS_CHOICES = [
        ('PENDING', 'Pending (IA Analysis)'),
        ('TREATED', 'Treated by Doctor'),
        ('URGENT', 'Urgent Escalation'),
    ]
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='cases')
    doctor = models.ForeignKey(DoctorProfile, on_delete=models.SET_NULL, null=True, blank=True)
    
    symptoms_description = models.TextField(help_text="User's raw description")
    ai_clarification = models.TextField(blank=True, help_text="AI's summarized/clarified version")
    
    suggested_medication = models.CharField(max_length=200, blank=True, help_text="OTC medication suggested by IA or Doctor")
    
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    is_emergency = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

# --- 4. Apprentissage & Base de Connaissances ---
class KnowledgeBase(models.Model):
    """Stocke les conseils validés par les médecins pour l'entraînement de l'IA"""
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    symptom_cluster = models.CharField(max_length=255)
    doctor_advice = models.TextField()
    recommended_otc = models.CharField(max_length=200, help_text="Safe medications like anti-inflammatories")
    frequency = models.IntegerField(default=1, help_text="How many times this advice was given")

# --- 5. Surveillance Épidémiologique ---

class PandemicSignal(models.Model):
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    symptom_type = models.CharField(max_length=100)
    region = models.CharField(max_length=100)
    occurrence_count = models.PositiveIntegerField()
    alert_level = models.CharField(max_length=20, default="Low")
    last_detected = models.DateTimeField(auto_now=True)


class DeviceManager(models.Manager):
    """Gestionnaire personnalisé pour le modèle Device"""
    
    def get_user_devices(self, user):
        """Récupère tous les appareils d'un utilisateur"""
        return self.filter(user=user, active=True)
    
    def get_primary_device(self, user):
        """Récupère l'appareil principal d'un utilisateur"""
        return self.filter(user=user, is_primary=True, active=True).first()
        
    def get_or_create_for_request(self, request, user=None):
        """Obtient ou crée un appareil à partir de la requête"""
        return Device.create_from_request(request, user)
        
    def get_anonymous_devices(self, session_key):
        """Récupère les appareils anonymes pour une clé de session"""
        return self.filter(session_key=session_key, user__isnull=True, active=True)
        
    def transfer_to_user(self, devices, user):
        """Transfère des appareils anonymes à un utilisateur"""
        if not devices:
            return
            
        # Mettre à jour les appareils pour les associer à l'utilisateur
        updated = devices.update(
            user=user,
            session_key=None,  # Nettoyer la clé de session
            is_primary=not self.filter(user=user, is_primary=True).exists()  # Définir comme principal si premier appareil
        )
        
        # Si aucun appareil n'était principal, définir le premier comme principal
        if updated > 0 and not self.filter(user=user, is_primary=True).exists():
            first_device = self.filter(user=user).first()
            if first_device:
                first_device.is_primary = True
                first_device.save(update_fields=['is_primary'])
                
        return updated


class Device(models.Model):
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices', null=True, blank=True)
    session_key = models.CharField(max_length=40, blank=True, null=True, db_index=True,
                                 help_text="Session key for anonymous users")
    name = models.CharField(max_length=255, verbose_name="Nom de l'appareil")
    device_type = models.CharField(max_length=100, blank=True, null=True, verbose_name="Type d'appareil")
    os = models.CharField(max_length=100, blank=True, null=True, verbose_name="Système d'exploitation")
    browser = models.CharField(max_length=100, blank=True, null=True, verbose_name="Navigateur")
    ip_address = models.GenericIPAddressField(blank=True, null=True, verbose_name="Adresse IP")
    user_agent = models.TextField(blank=True, null=True, verbose_name="User-Agent")
    is_primary = models.BooleanField(default=False, verbose_name="Appareil principal")
    active = models.BooleanField(default=True, verbose_name="Appareil actif")
    last_login = models.DateTimeField(auto_now=True, verbose_name="Dernière connexion")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Date de création")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Dernière mise à jour")

    objects = DeviceManager()

    class Meta:
        verbose_name = "Appareil"
        verbose_name_plural = "Appareils"
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'is_primary'],
                condition=models.Q(is_primary=True, user__isnull=False),
                name='unique_primary_device_per_user'
            ),
            models.CheckConstraint(
                check=(
                    models.Q(user__isnull=False) | 
                    (models.Q(user__isnull=True) & ~models.Q(session_key__isnull=True))
                ),
                name='device_has_user_or_session'
            )
        ]
    
    def __str__(self):
        if self.user:
            return f"{self.name} ({self.device_type or 'Inconnu'}) - {self.user.email}"
        return f"{self.name} ({self.device_type or 'Inconnu'}) - Anonyme"
    
    def save(self, *args, **kwargs):
        # S'assurer qu'un seul appareil est marqué comme principal par utilisateur
        if self.is_primary and self.user:
            # Mettre à jour tous les autres appareils de l'utilisateur pour les marquer comme non principaux
            Device.objects.filter(user=self.user, is_primary=True).exclude(pk=self.pk).update(is_primary=False)
        
        # Si l'utilisateur est défini, s'assurer que la session_key est effacée
        if self.user_id and self.session_key:
            self.session_key = None
            
        super().save(*args, **kwargs)
        
        # Si c'est le seul appareil de l'utilisateur, le marquer comme principal
        if self.user and not self.is_primary and not Device.objects.filter(
            user=self.user, is_primary=True
        ).exclude(pk=self.pk).exists():
            self.is_primary = True
            self.save(update_fields=['is_primary'])
    
    def set_as_primary(self):
        """Définit cet appareil comme appareil principal"""
        if not self.user:
            return False
        self.is_primary = True
        self.save()
        return True
    
    def disconnect(self):
        """Déconnecte l'appareil (le marque comme inactif)"""
        self.active = False
        self.save(update_fields=['active'])
        return True

    # type device
    def get_device_type(self):
        if self.device_type == 'Ordinateur':
            return 'Ordinateur'
        elif self.device_type == 'Mobile':
            return 'Mobile'
        elif self.device_type == 'Tablette':
            return 'Tablette'
        else:
            return 'Inconnu'
    
    @classmethod
    def create_from_request(cls, request, user=None):
        """Crée un nouvel appareil à partir de la requête"""
        from user_agents import parse
        
        # Récupérer les informations de l'utilisateur
        user_agent_str = request.META.get('HTTP_USER_AGENT', '')
        user_agent = parse(user_agent_str)
        
        # Récupérer l'adresse IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Créer un nom d'appareil lisible
        device_name = f"{user_agent.device.brand or 'Inconnu'} {user_agent.device.model or ''} ({user_agent.os.family})"
        device_name = device_name.strip()
        
        # Déterminer si c'est un utilisateur anonyme ou authentifié
        session_key = request.session.session_key if hasattr(request, 'session') else None
        
        # Vérifier si un appareil similaire existe déjà
        lookup = {
            'user_agent': user_agent_str[:255],
        }
        
        if user and user.is_authenticated:
            lookup['user'] = user
        elif session_key:
            lookup['session_key'] = session_key
            lookup['user__isnull'] = True
        else:
            # Impossible de créer un appareil sans utilisateur ni session
            return None
            
        device, created = cls.objects.get_or_create(
            **lookup,
            defaults={
                'name': device_name[:255],
                'device_type': user_agent.device.family,
                'os': f"{user_agent.os.family} {user_agent.os.version_string or ''}".strip(),
                'browser': f"{user_agent.browser.family} {user_agent.browser.version_string or ''}".strip(),
                'ip_address': ip,
                'session_key': session_key if not user or not user.is_authenticated else None,
                'is_primary': user and not cls.objects.filter(user=user, is_primary=True).exists()
            }
        )
        
        # Mettre à jour la dernière connexion
        if not created:
            update_fields = ['last_login']
            
            # Mettre à jour l'utilisateur si nécessaire (passage d'anonyme à connecté)
            if user and user.is_authenticated and (not device.user or device.user != user):
                device.user = user
                device.session_key = None  # Nettoyer la clé de session
                update_fields.extend(['user', 'session_key'])
                
                # Si c'est le premier appareil de l'utilisateur, le marquer comme principal
                if not cls.objects.filter(user=user, is_primary=True).exists():
                    device.is_primary = True
                    update_fields.append('is_primary')
            
            device.save(update_fields=update_fields)
        
        return device

class IP(models.Model):
    id = models.CharField(max_length=36, primary_key=True, default=generate_uuid_pk, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip = models.CharField(max_length=255, null=True, blank=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True) # device
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "IP"
        verbose_name_plural = "IPs"
        indexes = [
            models.Index(fields=['user']),
            models.Index(fields=['ip']),
        ]
    
    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{self.ip} - {username}"
        # return f"{self.user} {self.ip}"