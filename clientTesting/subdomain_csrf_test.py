#!/usr/bin/env python3
"""
Subdomain CSRF Cookie Test Script for Stratos Backend
This script tests the CSRF cookie functionality between subdomains of stratosgaming.com
"""

import requests
import json
import re

def test_subdomain_csrf():
    """Test CSRF cookie functionality between subdomains"""
    print("🚀 Subdomain CSRF Cookie Test")
    print("=" * 50)
    
    # Test subdomains
    subdomains = [
        "api.stratosgaming.com",
        "development.stratosgaming.com",
        "3.74.166.136"
    ]
    
    backend_url = f"https://{subdomains[0]}"
    
    print(f"🧪 Testing CSRF cookie between subdomains of stratosgaming.com")
    print(f"Backend: {backend_url}")
    print(f"Testing with subdomains: {', '.join(subdomains)}")
    print("-" * 50)
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    # Test each subdomain as origin
    for subdomain in subdomains:
        origin = f"https://{subdomain}"
        print(f"\n🌐 Testing with origin: {origin}")
        
        try:
            # Make request to CSRF cookie endpoint
            headers = {
                'Origin': origin,
                'Referer': f"{origin}/",
                'User-Agent': 'Subdomain-CSRF-Test/1.0',
                'Accept': 'application/json'
            }
            
            response = session.get(f"{backend_url}/auth/csrf_cookie", headers=headers)
            
            print(f"✅ Status Code: {response.status_code}")
            
            # Check CORS headers
            cors_origin = response.headers.get('Access-Control-Allow-Origin')
            cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
            
            print(f"CORS Headers:")
            print(f"  Access-Control-Allow-Origin: {cors_origin}")
            print(f"  Access-Control-Allow-Credentials: {cors_credentials}")
            
            # Check Set-Cookie header
            set_cookie_headers = response.headers.get('Set-Cookie', '')
            if set_cookie_headers:
                print(f"Set-Cookie: {set_cookie_headers}")
                
                # Check cookie attributes
                if 'Domain=.stratosgaming.com' in set_cookie_headers:
                    print("✅ Domain=.stratosgaming.com found (correct for subdomains)")
                else:
                    print("❌ Domain=.stratosgaming.com missing")
                    
                if 'SameSite=Lax' in set_cookie_headers:
                    print("✅ SameSite=Lax found (correct for subdomains)")
                else:
                    print("❌ SameSite=Lax missing")
                    
                if 'Secure' in set_cookie_headers:
                    print("✅ Secure flag found")
                else:
                    print("❌ Secure flag missing")
            else:
                print("❌ No Set-Cookie header found!")
            
            # Check cookies in session
            print("\n🍪 Cookies received:")
            csrf_token = None
            for cookie in session.cookies:
                print(f"  {cookie.name}: {cookie.value[:20]}...")
                print(f"    Domain: {cookie.domain}")
                print(f"    Path: {cookie.path}")
                print(f"    Secure: {cookie.secure}")
                print(f"    SameSite: {getattr(cookie, 'samesite', 'Not specified')}")
                
                if cookie.name == 'csrftoken':
                    csrf_token = cookie.value
            
            # Test login with CSRF token
            if csrf_token:
                print(f"\n🔐 Testing login with CSRF token from {origin}...")
                login_headers = {
                    'Origin': origin,
                    'Referer': f"{origin}/",
                    'X-CSRFToken': csrf_token,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Subdomain-CSRF-Test/1.0'
                }
                
                login_data = {
                    'username': 'test_user',
                    'password': 'test_password'
                }
                
                login_response = session.post(f"{backend_url}/auth/", 
                                            json=login_data, 
                                            headers=login_headers)
                
                print(f"Login test status: {login_response.status_code}")
                
                if login_response.status_code == 403:
                    error_text = login_response.text
                    if "CSRF cookie not set" in error_text:
                        print("❌ CSRF cookie not set error - subdomain cookies not working")
                    elif "CSRF verification failed" in error_text:
                        print("❌ CSRF verification failed - token not matching")
                    else:
                        print("❌ Other CSRF-related 403 error")
                elif login_response.status_code == 401:
                    print("✅ CSRF working - got authentication error (expected for invalid credentials)")
                elif login_response.status_code == 200:
                    print("✅ CSRF working - login successful")
                else:
                    print(f"❓ Unexpected response: {login_response.status_code}")
            else:
                print("❌ No CSRF token available for testing")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
        except Exception as e:
            print(f"❌ Test failed: {e}")
        
        print("-" * 50)
    
    print("\n" + "=" * 50)
    print("✅ Subdomain test completed!")

if __name__ == "__main__":
    test_subdomain_csrf() 