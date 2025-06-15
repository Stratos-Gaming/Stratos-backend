#!/usr/bin/env python
"""
Debug script to test CORS configuration on the server
Run this on your EC2 instance to check for issues
"""
import os
import sys
import django

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backendStratos.settings')
django.setup()

from django.conf import settings

print("=== Django CORS Debug Information ===\n")

# Check if corsheaders is installed
try:
    import corsheaders
    print("✅ django-cors-headers is installed")
    print(f"   Version: {corsheaders.__version__}")
except ImportError:
    print("❌ django-cors-headers is NOT installed!")
    print("   Run: pip install django-cors-headers")

# Check middleware configuration
print("\n=== Middleware Configuration ===")
if 'corsheaders.middleware.CorsMiddleware' in settings.MIDDLEWARE:
    cors_index = settings.MIDDLEWARE.index('corsheaders.middleware.CorsMiddleware')
    print(f"✅ CORS middleware is configured at position {cors_index}")
    if cors_index > 2:
        print("⚠️  WARNING: CORS middleware should be as early as possible in the middleware stack")
else:
    print("❌ CORS middleware is NOT in MIDDLEWARE list!")

# Check CORS settings
print("\n=== CORS Settings ===")
cors_settings = [
    'CORS_ALLOW_ALL_ORIGINS',
    'CORS_ALLOW_CREDENTIALS', 
    'CORS_ALLOWED_ORIGINS',
    'CORS_ALLOWED_ORIGIN_REGEXES',
    'CORS_ALLOW_METHODS',
    'CORS_ALLOW_HEADERS',
]

for setting in cors_settings:
    value = getattr(settings, setting, 'NOT SET')
    print(f"{setting}: {value}")

# Check CSRF settings
print("\n=== CSRF Cookie Settings ===")
csrf_settings = [
    'CSRF_COOKIE_NAME',
    'CSRF_COOKIE_AGE',
    'CSRF_COOKIE_DOMAIN',
    'CSRF_COOKIE_PATH',
    'CSRF_COOKIE_SECURE',
    'CSRF_COOKIE_HTTPONLY',
    'CSRF_COOKIE_SAMESITE',
]

for setting in csrf_settings:
    value = getattr(settings, setting, 'NOT SET')
    print(f"{setting}: {value}")

# Check if custom middleware exists
print("\n=== Custom Middleware Check ===")
if 'backendStratos.middleware.CORSMiddleware' in settings.MIDDLEWARE:
    print("⚠️  WARNING: Custom CORSMiddleware is still in MIDDLEWARE list!")
    print("   This may conflict with django-cors-headers")
else:
    print("✅ Custom CORSMiddleware is not in use")

# Test imports
print("\n=== Testing Imports ===")
try:
    from userAuth.views import GetCSRFToken, CORSTestView
    print("✅ Views import successfully")
except ImportError as e:
    print(f"❌ Error importing views: {e}")

# Check database connection
print("\n=== Database Connection ===")
try:
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        print("✅ Database connection successful")
except Exception as e:
    print(f"❌ Database error: {e}")

print("\n=== Recommendations ===")
print("1. Make sure to restart your Django server after any configuration changes")
print("2. Check your server logs: sudo journalctl -u <your-service-name> -f")
print("3. Try accessing https://api.stratosgaming.com/auth/cors-test from your browser")
print("4. Ensure your EC2 security group allows HTTPS traffic on port 443") 