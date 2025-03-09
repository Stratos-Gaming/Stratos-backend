from rest_framework import serializers
from django.contrib.auth.models import User
from .models import StratosUser

class UserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username')
    email = serializers.EmailField(source='user.email')
    first_name = serializers.CharField(source='user.first_name')
    last_name = serializers.CharField(source='user.last_name')
    
    class Meta:
        model = StratosUser
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'phone', 'address', 'city', 'state', 'country', 'zip']
