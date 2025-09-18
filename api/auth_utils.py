from datetime import datetime, timedelta
from django.conf import settings

def get_recent_failed_attempts(user, minutes=30):
    """
    Get the number of failed login attempts in the past X minutes
    """
    from .models import LoginAttempt
    
    cutoff_time = datetime.now() - timedelta(minutes=minutes)
    return LoginAttempt.objects.filter(
        user=user, 
        successful=False,
        timestamp__gt=cutoff_time
    ).count()


def is_account_locked(user):
    """
    Check if an account is locked due to too many failed login attempts
    """
    # Get settings or use defaults
    max_attempts = getattr(settings, 'MAX_LOGIN_ATTEMPTS', 5)
    lockout_period = getattr(settings, 'LOCKOUT_PERIOD_MINUTES', 30)
    
    # Count recent failed attempts
    recent_failed_attempts = get_recent_failed_attempts(user, minutes=lockout_period)
    
    return recent_failed_attempts >= max_attempts


def add_login_attempt(user, request=None, successful=False):
    """
    Add a login attempt record
    """
    from .models import LoginAttempt
    
    ip_address = None
    user_agent = None
    
    if request:
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    
    # If login was successful, clear failed attempts
    if successful:
        # Optional: Clear recent failed attempts on successful login
        from .models import LoginAttempt
        recent_failures = LoginAttempt.objects.filter(
            user=user,
            successful=False,
            timestamp__gt=datetime.now() - timedelta(hours=24)
        )
        recent_failures.delete()
    
    return LoginAttempt.objects.create(
        user=user,
        successful=successful,
        ip_address=ip_address,
        user_agent=user_agent
    )
    

def record_logout(user, request=None):
    """
    Record user logout for security auditing
    """
    from .models import LoginAttempt
    
    ip_address = None
    user_agent = None
    
    if request:
        ip_address = request.META.get('REMOTE_ADDR')
        user_agent = request.META.get('HTTP_USER_AGENT', '')[:255]
    
    # Create a special entry to record logout
    # Add a note in the user_agent to indicate this was a logout
    logout_user_agent = f"LOGOUT: {user_agent or 'Unknown'}"
    
    return LoginAttempt.objects.create(
        user=user,
        successful=True,  # Logouts are always "successful"
        ip_address=ip_address,
        user_agent=logout_user_agent
    )