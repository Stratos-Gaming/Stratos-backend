from django.shortcuts import render

# Create your views here.
from rest_framework import generics, permissions
from .models import ProjectSubmission
from .serializers import ProjectSubmissionSerializer
from django.http import JsonResponse

class ProjectSubmissionCreateView(generics.CreateAPIView):
    queryset = ProjectSubmission.objects.all()
    serializer_class = ProjectSubmissionSerializer
    permission_classes = [permissions.AllowAny]

