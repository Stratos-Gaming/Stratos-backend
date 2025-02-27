from rest_framework import serializers
from .models import StratosUser


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = StratosUser
        fields = '__all__'