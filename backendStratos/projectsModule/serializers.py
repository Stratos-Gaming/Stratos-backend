from rest_framework import serializers
from .models import ProjectSubmission

class ProjectSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProjectSubmission
        fields = '__all__'

