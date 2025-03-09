from .permissions import IsStratosUserVerified, IsAdminStratosUser
from rest_framework.permissions import IsAuthenticated

class IsUserVerifiedStratosPermissionMixin:
    """
    Mixin to enforce permissions for StratosUser resources.
    """
    permission_classes = [IsStratosUserVerified, IsAuthenticated]

class IsUserAuthenticatedPermissionMixin:
    """
    Mixin to enforce permissions for authenticated users.
    """
    permission_classes = [IsAuthenticated]