#!/usr/bin/env python3
"""
CSRF Cookie Test Script for Stratos Backend
This script tests the CSRF cookie endpoint in both development and production environments.
"""

import requests
import json
from urllib.parse import urlparse

def test_csrf_cookie(base_url):
    """Test CSRF cookie endpoint"""
    print(f"\n🧪 Testing CSRF cookie endpoint: {base_url}")
    
    # Create a session to maintain cookies
    session = requests.Session()
    
    try:
        # Make request to CSRF cookie endpoint
        response = session.get(f"{base_url}/auth/csrf_cookie", 
                             headers={
                                 'User-Agent': 'CSRF-Test-Script/1.0',
                                 'Accept': 'application/json'
                             })
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers:")
        for header, value in response.headers.items():
            if 'cookie' in header.lower() or 'csrf' in header.lower():
                print(f"  {header}: {value}")
        
        # Check for Set-Cookie header
        set_cookie_headers = response.headers.get('Set-Cookie', '')
        if set_cookie_headers:
            print(f"Set-Cookie: {set_cookie_headers}")
        else:
            print("❌ No Set-Cookie header found!")
        
        # Check response body
        try:
            response_data = response.json()
            print(f"Response Body: {json.dumps(response_data, indent=2)}")
        except json.JSONDecodeError:
            print(f"Response Body (raw): {response.text}")
        
        # Check cookies in session
        print("\n🍪 Cookies in session:")
        for cookie in session.cookies:
            print(f"  {cookie.name}: {cookie.value}")
            print(f"    Domain: {cookie.domain}")
            print(f"    Path: {cookie.path}")
            print(f"    Secure: {cookie.secure}")
            print(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
        
        # Test if CSRF token is accessible
        csrf_token = None
        for cookie in session.cookies:
            if cookie.name == 'csrftoken':
                csrf_token = cookie.value
                break
        
        if csrf_token:
            print(f"✅ CSRF token found: {csrf_token[:10]}...")
            
            # Test a CSRF-protected endpoint
            print(f"\n🔐 Testing CSRF-protected login endpoint...")
            login_data = {
                'username': 'test_user',
                'password': 'test_password'
            }
            headers = {
                'X-CSRFToken': csrf_token,
                'Content-Type': 'application/json',
                'Referer': base_url
            }
            
            login_response = session.post(f"{base_url}/auth/", 
                                        json=login_data, 
                                        headers=headers)
            
            print(f"Login test status: {login_response.status_code}")
            if login_response.status_code != 403:
                print("✅ CSRF protection working - no 403 Forbidden due to missing token")
            else:
                print("❌ CSRF token might not be working properly")
        else:
            print("❌ No CSRF token found in cookies!")
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
    except Exception as e:
        print(f"❌ Test failed: {e}")

def main():
    """Main test function"""
    print("🚀 Stratos CSRF Cookie Test")
    print("=" * 50)
    
    # Test environments
    environments = [
        ("Development", "http://localhost:5371"),
        ("Production", "https://api.stratosgaming.com")
    ]
    
    for env_name, base_url in environments:
        print(f"\n🌍 Testing {env_name} Environment")
        print("-" * 30)
        test_csrf_cookie(base_url)
    
    print("\n" + "=" * 50)
    print("✅ Test completed!")

if __name__ == "__main__":
    main() 