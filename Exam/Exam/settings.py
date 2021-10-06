import os
from pathlib import Path
import configparser

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Reading Properties
config = configparser.RawConfigParser()
config.read('Database/server.properties')


def configure_website(request):
    config_website = configparser.RawConfigParser()
    config_website.read('Database/server.properties')
    return {
        'Server_Title': config_website.get('Server', 'server.title'),
        'Server_Description': config_website.get('Server', 'server.description'),
    }


# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config.get('SecretSection', 'secret.key')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config.getboolean('SecretSection', 'secret.debug')


ALLOWED_HOSTS = ['127.0.0.1', config.get('SecretSection', 'secret.host')]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'Exam',
    'website',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
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


DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'Database/db.sqlite3',
    }
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
USE_TZ = True


STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

EMAIL_BACKEND = config.get('Email', 'email.backend')
EMAIL_HOST = config.get('Email', 'email.host')
EMAIL_PORT = config.getint('Email', 'email.port')
EMAIL_HOST_USER = config.get('Email', 'email.host_user')
EMAIL_HOST_PASSWORD = config.get('Email', 'email.host_password')
EMAIL_USE_TLS = config.getboolean('Email', 'email.use_tls')

EMAIL_FROM = str(config.get('Email', 'email.from'))

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
#
# LOGIN_URL = '/accounts/login'
# LOGOUT_URL = '/accounts/logout'

DATA_UPLOAD_MAX_MEMORY_SIZE = 50242880
