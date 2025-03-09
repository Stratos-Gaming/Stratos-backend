from rest_framework import serializers
from .models import ProjectSubmission, Project, UserContact

class ProjectSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectSubmission
        fields = '__all__'

    def validate(self, attrs):
        # Ensure user_contact is provided
        if not attrs.get('user_contact'):
            raise serializers.ValidationError("UserContact reference is required.")
        return attrs


class UserContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserContact
        fields = ['id', 'email', 'name']

class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = '__all__'
