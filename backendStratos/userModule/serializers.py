from rest_framework import serializers
from django.contrib.auth.models import User
from .models import StratosUser, UserSubscriptionPreferences, UserSocialConnection

class UserSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    email = serializers.EmailField(source='user.email')
    user_types = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()
    
    class Meta:
        model = StratosUser
        fields = ['id', 'username', 'email', 'isEmailVerified', 'phone', 'address', 'city', 'state', 'country', 'zip', 'user_types', 'profile_picture_url']
    
    def get_user_types(self, obj):
        return obj.get_user_types()
    
    def get_profile_picture_url(self, obj):
        return obj.get_profile_picture_url()

    def get_username(self, obj):
        # Prefer email local-part if email exists
        email = getattr(obj.user, 'email', None)
        if email:
            try:
                return email.split('@')[0]
            except Exception:
                pass
        # Then prefer display name from Discord / other
        display = obj.get_display_name()
        if display and not str(display).startswith('auth0|'):
            return display
        # Fallback to stored username (may be Auth0 sub)
        return obj.user.username


class UserSubscriptionPreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscriptionPreferences
        fields = ['newsletter', 'indie_projects_updates']


class UserSocialConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSocialConnection
        fields = ['platform', 'connected', 'username', 'email', 'connected_at']
        read_only_fields = ['connected_at']
