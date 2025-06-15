from rest_framework import serializers
from django.contrib.auth.models import User
from .models import StratosUser, UserSubscriptionPreferences, UserSocialConnection

class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    email = serializers.EmailField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    user_types = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()
    
    class Meta:
        model = StratosUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'isEmailVerified', 'phone', 'address', 'city', 'state', 'country', 'zip', 'user_types', 'profile_picture_url']
    
    def get_user_types(self, obj):
        return obj.get_user_types()
    
    def get_profile_picture_url(self, obj):
        return obj.get_profile_picture_url()


class UserSubscriptionPreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscriptionPreferences
        fields = ['newsletter', 'indie_projects_updates']


class UserSocialConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSocialConnection
        fields = ['platform', 'connected', 'username', 'email', 'connected_at']
        read_only_fields = ['connected_at']
