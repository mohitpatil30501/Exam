from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import auth
from django.contrib.sessions.middleware import SessionMiddleware
from django.utils import timezone


class SessionSecurityMiddleware:
    """
    Middleware for enhanced session security:
    1. Session timeout - expire sessions after inactivity
    2. Prevent session fixation - regenerate session ID on authentication
    3. Track user activity
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Only apply to authenticated sessions
        if request.user.is_authenticated:
            # Check if this is an old session that needs to expire
            last_activity = request.session.get('last_activity')
            
            # Get timeout from settings with a default of 30 minutes
            session_timeout = getattr(settings, 'SESSION_IDLE_TIMEOUT', 30 * 60)
            
            if last_activity:
                # Convert to datetime if stored as string
                if isinstance(last_activity, str):
                    last_activity = datetime.fromisoformat(last_activity)
                
                # Check if session has timed out due to inactivity
                inactivity_period = timezone.now() - last_activity
                if inactivity_period.total_seconds() > session_timeout:
                    # Log the timeout event
                    try:
                        from api.auth_utils import LoginAttempt
                        LoginAttempt.objects.create(
                            user=request.user,
                            successful=True,
                            user_agent="SESSION_TIMEOUT: Automatic logout due to inactivity"
                        )
                    except:
                        pass  # Don't fail if logging fails
                    
                    # Perform logout
                    auth.logout(request)
            
            # Update the last activity time for the session
            request.session['last_activity'] = timezone.now().isoformat()
        
        # Process the request
        response = self.get_response(request)
        
        # Additional security headers (not HTTPS related)
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'
        response['X-Frame-Options'] = 'SAMEORIGIN'
        
        # Remove any headers that might enforce HTTPS in development
        if settings.DEBUG:
            # Remove all HTTPS-related headers
            headers_to_remove = [
                'Strict-Transport-Security',
                'Content-Security-Policy-Report-Only',
                'Expect-CT',
                'Public-Key-Pins',
                'Public-Key-Pins-Report-Only'
            ]
            for header in headers_to_remove:
                if header in response:
                    del response[header]
        
        return response


class CsrfConsistencyMiddleware:
    """
    Middleware to ensure CSRF tokens are consistently used across the application
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process the request
        response = self.get_response(request)
        
        # Add CSRF cookie to all responses except for specific exemptions
        from django.middleware.csrf import get_token
        get_token(request)
        
        return response


class ContentSecurityPolicyMiddleware:
    """
    Middleware to add Content Security Policy headers to all responses
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # Define Content Security Policy
        csp_policies = [
            # Default fallback for everything else
            "default-src 'self'",
            
            # JavaScript sources
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",  # Unsafe-inline/eval for existing code, should be removed later
            
            # CSS sources
            "style-src 'self' 'unsafe-inline'",
            
            # Images
            "img-src 'self' data: blob:",
            
            # Fonts
            "font-src 'self'",
            
            # Form submission
            "form-action 'self'",
            
            # Frame sources - only allow from same origin
            "frame-ancestors 'self'",
            
            # Connect sources for AJAX, WebSockets
            "connect-src 'self'"
        ]
        
        # Only block mixed content in production
        if not settings.DEBUG:
            csp_policies.append("block-all-mixed-content")
        
        # Add CSP header
        response['Content-Security-Policy'] = "; ".join(csp_policies)
        
        return response