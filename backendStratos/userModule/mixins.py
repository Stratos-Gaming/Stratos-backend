from .permissions import IsStratosUserVerified, IsAdminStratosUser
from rest_framework.permissions import IsAuthenticated
from userAuth.permission import RequireScopes

class IsUserVerifiedStratosPermissionMixin:
    """
    Mixin to enforce permissions for StratosUser resources.
    """
    permission_classes = [IsStratosUserVerified, RequireScopes]
    RequireScopes.required_scopes = {"read:self"}


class IsUserAuthenticatedPermissionMixin:
    """
    Mixin to enforce permissions for authenticated users.
    """
    permission_classes = [RequireScopes]
    RequireScopes.required_scopes = {"read:self"}
