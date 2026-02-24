from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver
from django.utils import timezone
from .models import Device

def ensure_user_has_device(user, request=None):
    """Ensure the user has at least one device associated with their account."""
    # Check if user already has any active devices
    if not Device.objects.filter(user=user, active=True).exists():
        # Create a new device for the user
        from user_agents import parse
        
        user_agent = request.META.get('HTTP_USER_AGENT', '') if request else ''
        ip_address = None
        
        if request:
            # Get client IP
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip_address = x_forwarded_for.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
        
        # Parse user agent
        ua = parse(user_agent)
        
        # Create device name
        device_name = f"{ua.device.brand or 'Inconnu'} {ua.device.model or ''} ({ua.os.family})"
        device_name = device_name.strip()
        
        # Create the device
        Device.objects.create(
            user=user,
            name=device_name[:255],
            device_type=ua.device.family,
            os=f"{ua.os.family} {ua.os.version_string or ''}".strip(),
            browser=f"{ua.browser.family} {ua.browser.version_string or ''}".strip(),
            ip_address=ip_address,
            user_agent=user_agent[:255],
            is_primary=True,  # This will be the primary device
            active=True,
            last_login=timezone.now()
        )

@receiver(user_logged_in)
def user_logged_in_handler(sender, request, user, **kwargs):
    """
    Handle user login to ensure they have at least one device.
    Also handles the case where an anonymous user becomes authenticated.
    """
    # Check for any anonymous session devices
    session_key = request.session.session_key
    if session_key:
        # Find any devices created during anonymous session
        anonymous_devices = Device.objects.filter(session_key=session_key, user__isnull=True)
        
        # Transfer these devices to the now-authenticated user
        if anonymous_devices.exists():
            anonymous_devices.update(user=user)
    
    # Ensure user has at least one device
    ensure_user_has_device(user, request)
