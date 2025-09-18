import os
from pathlib import Path
import configparser
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file
load_dotenv(os.path.join(BASE_DIR, '.env'))

# Reading Properties (fallback for backward compatibility)
config = configparser.RawConfigParser()
config.read('Database/server.properties')


def configure_website(request):
    config_website = configparser.RawConfigParser()
    config_website.read('Database/server.properties')
    return {
        'Server_Title': config_website.get('Server', 'server.title'),
        'Server_Description': config_website.get('Server', 'server.description'),
        'Version': config_website.get('Server', 'server.version'),
    }


# SECURITY WARNING: keep the secret key used in production secret!
# Get SECRET_KEY from environment variable, fall back to config file if not found
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', config.get('SecretSection', 'secret.key'))

# SECURITY WARNING: don't run with debug turned on in production!
# Get DEBUG setting from environment variable, default to False for security
DEBUG = os.environ.get('DEBUG', 'False').lower() in ('true', 'yes', '1', 'on')

# Set allowed hosts from environment variable or use a restrictive default
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Project apps
    'Exam',
    'website',
    'api',
]

# Conditionally add django_extensions if available
try:
    import django_extensions
    INSTALLED_APPS.append('django_extensions')
except ImportError:
    pass

# Define middleware based on environment
MIDDLEWARE = [
    # Always needed middleware
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

# In production, add security middleware
if not DEBUG:
    MIDDLEWARE = [
        'django.middleware.security.SecurityMiddleware',  # Add security middleware first
    ] + MIDDLEWARE + [
        'api.middleware.SessionSecurityMiddleware',  # Custom session security
        'api.middleware.CsrfConsistencyMiddleware',  # Custom CSRF consistency
        'api.middleware.ContentSecurityPolicyMiddleware',  # Content Security Policy
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ]

ROOT_URLCONF = 'Exam.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, "templates")],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'Exam.settings.configure_website',
            ],
        },
    },
]

WSGI_APPLICATION = 'Exam.wsgi.application'

import os

# Get database configuration from environment variables
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'Database/db.sqlite3',
    }
    # 'default': {
    #     'ENGINE': 'django.db.backends.postgresql',
    #     'NAME': os.environ.get('DB_NAME', ''),
    #     'USER': os.environ.get('DB_USER', ''),
    #     'PASSWORD': os.environ.get('DB_PASSWORD', ''),
    #     'HOST': os.environ.get('DB_HOST', ''),
    #     'PORT': int(os.environ.get('DB_PORT', 5432)),
    # }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = config.get('Server', 'server.language_code')
TIME_ZONE = config.get('Server', 'server.time_zone')
USE_I18N = True
USE_L10N = True
USE_TZ = False

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Email configuration from environment variables with fallback to config file
EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', config.get('Email', 'email.backend'))
EMAIL_HOST = os.environ.get('EMAIL_HOST', config.get('Email', 'email.host'))
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', config.getint('Email', 'email.port')))
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', config.get('Email', 'email.host_user'))
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', config.get('Email', 'email.host_password'))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', '').lower() in ('true', 'yes', '1', 'on') or config.getboolean('Email', 'email.use_tls')
EMAIL_USE_SSL = os.environ.get('EMAIL_USE_SSL', '').lower() in ('true', 'yes', '1', 'on')
EMAIL_TIMEOUT = int(os.environ.get('EMAIL_TIMEOUT', 60))

# Default sender email address
EMAIL_FROM = os.environ.get('EMAIL_FROM', config.get('Email', 'email.from'))
DEFAULT_FROM_EMAIL = EMAIL_FROM

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
#
# Authentication URLs
LOGIN_URL = '/accounts/login'
LOGOUT_URL = '/accounts/logout'
LOGIN_REDIRECT_URL = '/dashboard'

# Improved authentication security settings
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]

# Update AUTH_PASSWORD_VALIDATORS with stronger settings
AUTH_PASSWORD_VALIDATORS[1]['OPTIONS'] = {
    'min_length': 10,
}

# Account lockout settings
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_PERIOD_MINUTES = int(os.environ.get('LOCKOUT_PERIOD_MINUTES', 30))

# Encryption settings
ENCRYPTION_SALT = os.environ.get('ENCRYPTION_SALT', SECRET_KEY[:16])  # Default: use part of SECRET_KEY
ENCRYPTION_ITERATIONS = int(os.environ.get('ENCRYPTION_ITERATIONS', 480000))  # OWASP recommended

# Session security settings
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = int(os.environ.get('SESSION_COOKIE_AGE', 30 * 60))  # 30 minutes
SESSION_IDLE_TIMEOUT = int(os.environ.get('SESSION_IDLE_TIMEOUT', 15 * 60))  # 15 minutes of inactivity

# Authentication security settings
MAX_LOGIN_ATTEMPTS = 5  # Max failed login attempts before account lockout
LOCKOUT_PERIOD_MINUTES = 30  # Account lockout period in minutes
PASSWORD_RESET_TIMEOUT = 900  # 15 minutes in seconds
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_SAVE_EVERY_REQUEST = True

# =============================================
# HTTPS AND SECURITY SETTINGS
# =============================================

# For development (DEBUG=True), completely disable all HTTPS/SSL features
if DEBUG:
    # Explicitly disable all HTTPS-related settings
    SECURE_SSL_REDIRECT = False
    SECURE_PROXY_SSL_HEADER = None
    SECURE_HSTS_SECONDS = 0
    SECURE_HSTS_INCLUDE_SUBDOMAINS = False
    SECURE_HSTS_PRELOAD = False
    SECURE_CONTENT_TYPE_NOSNIFF = False
    SECURE_BROWSER_XSS_FILTER = False
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    SECURE_REFERRER_POLICY = None
    SECURE_REDIRECT_EXEMPT = ['*']  # Exempt all URLs from redirects
    
    # Ensure no middleware accidentally forces HTTPS
    USE_X_FORWARDED_HOST = False
    USE_X_FORWARDED_PORT = False
    
    # Don't prepend www or enforce a specific URL scheme
    PREPEND_WWW = False
    APPEND_SLASH = True
    
    # Additional measures to prevent HTTPS issues with development server
    os.environ['PYTHONHTTPSVERIFY'] = '0'
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# For production (DEBUG=False), enable all security features
else:
    # Enable all HTTPS-related settings
    SECURE_SSL_REDIRECT = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    SECURE_BROWSER_XSS_FILTER = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_REFERRER_POLICY = 'same-origin'

DATA_UPLOAD_MAX_MEMORY_SIZE = 50242880

# Configure logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs/django.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'api': {
            'handlers': ['file', 'console', 'mail_admins'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}
