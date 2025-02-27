# Create your views here.
from django.http import JsonResponse
from rest_framework import viewsets
from rest_framework import generics, permissions
from .models import Project
from .models import ProjectSubmission
from .serializers import ProjectSubmissionSerializer, ProjectSerializer

class ProjectSubmissionCreateView(generics.CreateAPIView):
    queryset = ProjectSubmission.objects.all()
    serializer_class = ProjectSubmissionSerializer
    permission_classes = [permissions.AllowAny]


# Create your views here.
class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer
    permission_classes = [permissions.AllowAny]