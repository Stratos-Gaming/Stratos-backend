import requests
import json

def CreateUser(session):
    url = 'http://localhost:5371/login/register/'
    data = {'username': 'stratostest8', 'password': 'Stratos123', 're_password': 'Stratos123', 'email': 'j.piccinelli@stratosgaming.it'}
    # Get CSRF cookie
    session.get('http://localhost:5371/login/csrf_cookie/')
    csrftoken = session.cookies.get('csrftoken')
    headers = {'Content-Type': 'application/json', 'X-CSRFToken': csrftoken}
    response = session.post(url, data=json.dumps(data), headers=headers)
    print(response.text)
    return response

def authenticateUser(session):
    url = 'http://localhost:5371/login/'
    data = {'username': 'stratostest7', 'password': 'Stratos123'}
    
    # Get CSRF cookie
    session.get('http://localhost:5371/login/csrf_cookie/')
    csrftoken = session.cookies.get('csrftoken')
    
    headers = {'Content-Type': 'application/json', 'X-CSRFToken': csrftoken}
    response = session.post(url, data=json.dumps(data), headers=headers)
    print(response.text)
    print("Cookies after auth:", session.cookies.get_dict())  # Debug cookies
    return response

def getSelfUserInfo(session):
    url = 'http://localhost:5371/user/'
    
    # No need to manually set cookies - session already has them if authentication worked
    headers = {'Content-Type': 'application/json'}
    
    # Add CSRF token if it exists
    if 'csrftoken' in session.cookies:
        headers['X-CSRFToken'] = session.cookies.get('csrftoken')
    
    response = session.get(url, headers=headers)
    print(response.text)
    return response
    
def GetSpecificUserInfo(session, username):
    url = 'http://localhost:5371/user/get-user-info/'
    
    # No need to manually set cookies - session already has them if authentication worked
    headers = {'Content-Type': 'application/json'}
    
    # Add CSRF token if it exists
    if 'csrftoken' in session.cookies:
        headers['X-CSRFToken'] = session.cookies.get('csrftoken')
    
    data = {'username': username}
    response = session.post(url, data=json.dumps(data), headers=headers)
    print(response.text)
    return response


def update_user_info(session):
    url = 'http://localhost:5371/user/update/'
    
    # Data to update - customize these fields as needed
    data = {
        'first_name': 'Pierluigi',
        'last_name': 'Pedrazzi',
        'email': 'pigiped@gmail.com',
        'phone': '123-456-7890',
        'address': 'Via Roma 123',
        'city': 'Milano',
        'state': 'MI',
        'country': 'Italy',
        'zip': '20100'
    }
    
    # Get CSRF token if it exists
    if 'csrftoken' not in session.cookies:
        session.get('http://localhost:5371/login/csrf_cookie/')
    
    headers = {
        'Content-Type': 'application/json',
        'X-CSRFToken': session.cookies.get('csrftoken')
    }
    
    response = session.post(url, data=json.dumps(data), headers=headers)
    print("Update User Response:", response.status_code)
    print(response.text)
    return response

# Usage in main script:
# session = requests.Session()
# authenticateUser(session)
# update_user_info(session)

# Main script
session = requests.Session()

# Uncomment to create a user if needed
authenticateUser(session)
update_user_info(session)
# # Authenticate
# autenticatedResponse = authenticateUser(session)

# # Check if authentication was successful
# auth_data = autenticatedResponse.json()
# if autenticatedResponse.status_code == 200 and auth_data.get('success'):
#     # Get user info using the same session (cookies are automatically managed)
#     #getSelfUserInfo(session)
#     GetSpecificUserInfo(session, 'stratostest2')
# else:
#     print("Authentication failed:", auth_data)
