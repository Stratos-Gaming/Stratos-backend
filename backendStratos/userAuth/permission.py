
# auth/permissions.py
from rest_framework import permissions

def token_scopes(request):
    scopes_str = (request.auth or {}).get("scope", "")
    return set(scopes_str.split())

class RequireScopes(permissions.BasePermission):
    required_scopes = set()

    def has_permission(self, request, view):
        return self.required_scopes.issubset(token_scopes(request))
