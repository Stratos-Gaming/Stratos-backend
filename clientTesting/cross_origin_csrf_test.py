#!/usr/bin/env python3
"""
Cross-Origin CSRF Cookie Test Script for Stratos Backend
This script tests the cross-origin CSRF cookie scenario between 
dev.d2lv8dn21inij8.amplifyapp.com (frontend) and api.stratosgaming.com (backend)
"""

import requests
import json

def test_cross_origin_csrf():
    """Test cross-origin CSRF cookie functionality"""
    print("🚀 Cross-Origin CSRF Cookie Test")
    print("=" * 50)
    
    backend_url = "https://api.stratosgaming.com"
    frontend_origin = "https://dev.d2lv8dn21inij8.amplifyapp.com"
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    print(f"🧪 Testing cross-origin CSRF cookie")
    print(f"Backend: {backend_url}")
    print(f"Frontend Origin: {frontend_origin}")
    print("-" * 50)
    
    try:
        # Make cross-origin request to CSRF cookie endpoint
        headers = {
            'Origin': frontend_origin,
            'Referer': f"{frontend_origin}/",
            'User-Agent': 'Cross-Origin-CSRF-Test/1.0',
            'Accept': 'application/json'
        }
        
        response = session.get(f"{backend_url}/auth/csrf_cookie", headers=headers)
        
        print(f"✅ Status Code: {response.status_code}")
        
        # Check response headers
        print("\n📋 Response Headers:")
        for header, value in response.headers.items():
            if any(keyword in header.lower() for keyword in ['cookie', 'csrf', 'cors', 'access-control']):
                print(f"  {header}: {value}")
        
        # Check Set-Cookie header specifically
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        if set_cookie_headers:
            print(f"\n🍪 Set-Cookie Header: {set_cookie_headers}")
            
            # Parse cookie attributes
            if 'SameSite=None' in set_cookie_headers:
                print("✅ SameSite=None found (required for cross-origin)")
            else:
                print("❌ SameSite=None missing (required for cross-origin)")
                
            if 'Secure' in set_cookie_headers:
                print("✅ Secure flag found (required for SameSite=None)")
            else:
                print("❌ Secure flag missing (required for SameSite=None)")
        else:
            print("❌ No Set-Cookie header found!")
        
        # Check CORS headers
        print("\n🌐 CORS Headers:")
        cors_origin = response.headers.get('Access-Control-Allow-Origin')
        cors_credentials = response.headers.get('Access-Control-Allow-Credentials')
        
        if cors_origin:
            print(f"✅ Access-Control-Allow-Origin: {cors_origin}")
        else:
            print("❌ Access-Control-Allow-Origin header missing")
            
        if cors_credentials:
            print(f"✅ Access-Control-Allow-Credentials: {cors_credentials}")
        else:
            print("❌ Access-Control-Allow-Credentials header missing")
        
        # Check response body
        try:
            response_data = response.json()
            print(f"\n📄 Response Body:")
            print(json.dumps(response_data, indent=2))
        except json.JSONDecodeError:
            print(f"\n📄 Response Body (raw): {response.text}")
        
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
        
        # Test cross-origin login with CSRF token
        if csrf_token:
            print(f"\n🔐 Testing cross-origin login with CSRF token...")
            login_headers = {
                'Origin': frontend_origin,
                'Referer': f"{frontend_origin}/",
                'X-CSRFToken': csrf_token,
                'Content-Type': 'application/json',
                'User-Agent': 'Cross-Origin-CSRF-Test/1.0'
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
                    print("❌ CSRF cookie not set error - cross-origin cookies not working")
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
    
    print("\n" + "=" * 50)
    print("✅ Cross-origin test completed!")

if __name__ == "__main__":
    test_cross_origin_csrf() 