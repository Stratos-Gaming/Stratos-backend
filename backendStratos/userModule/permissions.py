from rest_framework import permissions

class BasePermission_Stratos(permissions.BasePermission):
        perms_map = {
        'GET': ['%(app_label)s.add_%(model_name)s'],
        'OPTIONS': [],
        'HEAD': [],
        'POST': ['%(app_label)s.add_%(model_name)s'],
        'PUT': ['%(app_label)s.change_%(model_name)s'],
        'PATCH': ['%(app_label)s.change_%(model_name)s'],
        'DELETE': ['%(app_label)s.delete_%(model_name)s'],
    }
class IsStratosUserVerified(BasePermission_Stratos):
    """
    Custom permission to only allow StratosUsers to access their own resources.
    """

    def has_permission(self, request, view):
        """
        Check if the user is authenticated and is a email verified StratosUser.
        """
        return request.user.is_authenticated and request.user.stratos_user.isEmailVerified

    def has_object_permission(self, request, view, obj):
        """
        Check if the user has permission to access the specific object.
        
        Implement your specific object permission logic here.
        For example, check if the requesting user owns the object.
        """
        # Example implementation - adjust according to your models
        # This assumes your objects have a 'user' field that links to the StratosUser
        return False

class IsAdminStratosUser(BasePermission_Stratos):
    """
    Custom permission to only allow admin-level StratosUsers.
    """
    
    def has_permission(self, request, view):
        """
        Check if the user is authenticated and has admin privileges.
        """
        return request.user.is_authenticated and request.user.is_staff

