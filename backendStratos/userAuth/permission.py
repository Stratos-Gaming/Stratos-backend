
# auth/permissions.py
from rest_framework import permissions

def token_scopes(request):
    scopes_str = (request.auth or {}).get("scope", "")
    return set(scopes_str.split())

def token_permissions(request):
    perms = (request.auth or {}).get("permissions", [])
    if isinstance(perms, (list, tuple)):
        return set(str(p) for p in perms)
    # Sometimes providers put permissions as space-delimited string too
    if isinstance(perms, str):
        return set(perms.split())
    return set()

class RequireScopes(permissions.BasePermission):
    required_scopes = set()

    def has_permission(self, request, view):
        # Accept either OAuth scopes or RBAC permissions in the Access Token
        available = token_scopes(request) | token_permissions(request)
        return self.required_scopes.issubset(available)
