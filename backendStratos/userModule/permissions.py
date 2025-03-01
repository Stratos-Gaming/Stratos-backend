from rest_framework import permissions

class IsStratosUserVerified(permissions.BasePermission):
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

class IsAdminStratosUser(permissions.BasePermission):
    """
    Custom permission to only allow admin-level StratosUsers.
    """
    
    def has_permission(self, request, view):
        """
        Check if the user is authenticated and has admin privileges.
        """
        return request.user.is_authenticated and request.user.is_staff


# You can add more custom permissions as needed