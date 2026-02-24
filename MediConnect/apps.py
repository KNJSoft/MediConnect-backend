from django.apps import AppConfig


class MediconnectConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'MediConnect'
    def ready(self):
        # Import signals here to avoid circular imports
        from django.contrib.auth.signals import user_logged_in
        from . import signals
        # Connect the signals
        user_logged_in.connect(signals.user_logged_in_handler)