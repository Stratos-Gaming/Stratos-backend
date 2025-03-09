# Create your views here.
from django.http import JsonResponse
from rest_framework import viewsets
from rest_framework import generics, permissions
from rest_framework.response import Response
from .models import Project, ProjectSubmission, UserContact
from .serializers import ProjectSubmissionSerializer, ProjectSerializer, UserContactSerializer
from userModule.mixins import IsUserVerifiedStratosPermissionMixin, IsUserAuthenticatedPermissionMixin
from rest_framework import status
from backendStratos.mailServer import send_contact_email
class ProjectSubmissionCreateView(generics.CreateAPIView):
    queryset = ProjectSubmission.objects.all()
    serializer_class = ProjectSubmissionSerializer


class AddUserContact(generics.CreateAPIView):
    serializer_class = UserContactSerializer
    queryset = UserContact.objects.all()

    def post(self, request, *args, **kwargs):
        # Check if there's a user contact with the given email
        email = request.data.get('email')
        asked_for_contact = request.data.get('asked_for_contact', False)
        
        if email:
            try:
                user_contact = UserContact.objects.get(email=email)
                # Optionally update the name if provided
                if 'name' in request.data:
                    user_contact.name = request.data['name']
                    user_contact.save()
                if asked_for_contact: 
                    print("Sending contact email")
                    send_contact_email(user_contact.name, user_contact.email, request)
                serializer = self.get_serializer(user_contact)
                return Response(serializer.data, status=status.HTTP_200_OK)
            except UserContact.DoesNotExist:
                # Create a new user contact
                return self.create(request, *args, **kwargs)
        else:
            # No email provided
            return Response(
                {"detail": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )



# Create your views here.
class ProjectViewSet(viewsets.ModelViewSet, IsUserAuthenticatedPermissionMixin):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer


