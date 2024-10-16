from pathlib import Path
from decouple import config
from datetime import timedelta

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG',cast=bool)

# settings.py

ALLOWED_HOSTS = ['noteapp-api-1r.onrender.com', 'localhost', '127.0.0.1']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'authentication.apps.AuthenticationConfig',
    'user.apps.UserConfig',
    'notes.apps.NotesConfig',
    #third party
    'rest_framework',
    'djoser',
    'drf_yasg',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    #'django.middleware.WhiteNoiseMiddleware', #1-deploy
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Correct the spelling here
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'noteApp.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'noteApp.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT=BASE_DIR/'assets'#2-deploy
#STATICFILES_STORAGE="whitenoise.storage.CompressedManifestStaticFilesStorage" #3-deploy

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'authentication.User'

REST_FRAMEWORK={
    'NON_FIELDS_ERRORS_KEY':'error',
     'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ],
    # 'DEFAULT_AUTHENTICATION_CLASSES': (
    #     'rest_framework.authentication.SessionAuthentication',
    #     'rest_framework.authentication.BasicAuthentication',
    #     'rest_framework.authentication.TokenAuthentication',
        
    # ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

SIMPLE_JWT = {
   'AUTH_HEADER_TYPES': ('Bearer',),
   "ACCESS_TOKEN_LIFETIME": timedelta(minutes=10),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,                  # Rotates refresh token when it's used
    'BLACKLIST_AFTER_ROTATION': True,               # Blacklists old refresh tokens after rotation
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USE_SSL = False
EMAIL_HOST_USER = 'awadwehbe22@gmail.com'
EMAIL_HOST_PASSWORD = '************'
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

MAX_OTP_TRY=3

SWAGGER_SETTINGS = {
   'SECURITY_DEFINITIONS': {
      'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header'
      }
   }
}

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
# Security settings
# SECURE_SSL_REDIRECT = True  # Redirect all HTTP requests to HTTPS
# SESSION_COOKIE_SECURE = True  # Ensure cookies are only sent over HTTPS
# CSRF_COOKIE_SECURE = True  # Ensure CSRF cookies are only sent over HTTPS
# SECURE_BROWSER_XSS_FILTER = True  # Protect against XSS attacks
# SECURE_CONTENT_TYPE_NOSNIFF = True  # Prevent browsers from guessing content types
# SECURE_HSTS_SECONDS = 31536000  # Enable HTTP Strict Transport Security (HSTS)
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True
# SECURE_HSTS_PRELOAD = True
