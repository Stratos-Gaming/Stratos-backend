from rest_framework import serializers
from django.contrib.auth.models import User
from .models import StratosUser, UserSubscriptionPreferences, UserSocialConnection

class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    email = serializers.EmailField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    
    class Meta:
        model = StratosUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'phone', 'address', 'city', 'state', 'country', 'zip', 'userType']


class UserSubscriptionPreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscriptionPreferences
        fields = ['newsletter', 'indie_projects_updates']


class UserSocialConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSocialConnection
        fields = ['platform', 'connected', 'username', 'email', 'connected_at']
        read_only_fields = ['connected_at']
