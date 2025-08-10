import os, requests

DOMAIN = os.getenv("AUTH0_DOMAIN")            # e.g. your-tenant.eu.auth0.com or login.stratosgaming.it
M2M_CLIENT_ID = os.getenv("AUTH0_M2M_CLIENT_ID")
M2M_CLIENT_SECRET = os.getenv("AUTH0_M2M_CLIENT_SECRET")

def mgmt_token():
    resp = requests.post(f"https://{DOMAIN}/oauth/token", json={
        "client_id": M2M_CLIENT_ID,
        "client_secret": M2M_CLIENT_SECRET,
        "audience": f"https://{DOMAIN}/api/v2/",
        "grant_type": "client_credentials"
    }, timeout=10)
    resp.raise_for_status()
    return resp.json()["access_token"]

def auth0_get_by_email(email):
    token = mgmt_token()
    r = requests.get(
        f"https://{DOMAIN}/api/v2/users-by-email",
        params={"email": email},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10
    )
    r.raise_for_status()
    return r.json()

print(auth0_get_by_email("alice@example.com"))
