import logging
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)

def send_email_safely(subject, message, recipient_list, html_message=None):
    """
    Sends an email with proper error handling and logging.
    
    Args:
        subject: Email subject
        message: Plain text message
        recipient_list: List of recipient email addresses
        html_message: Optional HTML message
    
    Returns:
        tuple: (success, error_message)
    """
    if not settings.EMAIL_HOST_USER or not settings.EMAIL_HOST_PASSWORD:
        error_msg = "Email settings not configured. Please configure EMAIL_HOST_USER and EMAIL_HOST_PASSWORD."
        logger.error(error_msg)
        return False, error_msg
    
    try:
        from_email = settings.EMAIL_FROM or settings.EMAIL_HOST_USER
        
        send_mail(
            subject=subject,
            message=message,
            from_email=from_email,
            recipient_list=recipient_list,
            fail_silently=False,
            html_message=html_message
        )
        logger.info(f"Email sent successfully to {', '.join(recipient_list)}")
        return True, None
    except Exception as e:
        error_msg = f"Failed to send email: {str(e)}"
        logger.error(error_msg)
        return False, error_msg