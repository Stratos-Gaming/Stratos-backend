#File used for user authentication
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework.response import Response
from django.contrib.auth.models import User
from userModule.models import StratosUser
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from rest_framework import authentication
from django.contrib import auth  # Add this import for login/logout functionality
from django.utils.decorators import method_decorator
from datetime import datetime
from backendStratos.utilities import checkForPasswordRequirements
from backendStratos.mailServer import send_verification_email
from django.contrib.auth.tokens import default_token_generator

@method_decorator(csrf_protect, name='dispatch')
class CheckAuthenticatedView(APIView):
    def get(self, request, format=None):
        try:
            isAuthenticated = User.is_authenticated

            if(isAuthenticated):
                return Response({'isAuthenticated': 'success'})
            else:
                return Response({'isAuthenticated': 'error'})
        except:
            return Response({'error': 'something went wrong checking authentication status'})

@method_decorator(csrf_protect, name='dispatch')
class SingupView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        data = self.request.data

        username = data['username']
        password = data['password']
        re_password = data['re_password']
        email = data.get('email', '')  # Get email with empty default if not provided

        if password == re_password:
            if User.objects.filter(username=username).exists():
                return Response({'error': 'Username already exists'})
            else:
                if checkForPasswordRequirements(password) == False:
                    return Response({'error': 'Password does not have all the requirements'})
                else:
                    user = User.objects.create_user(
                        username=username, 
                        email=email,
                        password=password, 
                        last_login=datetime.now()
                    )
                    user.save()
                    user = User.objects.get(id=user.id)
                    user_profile = StratosUser(user=user, phone='', address='', city='', state='', country='', zip='')
                    user_profile.save()
                    if (email != ''):  # Send verification email if email provided
                        send_verification_email(user, request, email)
                    return Response({'success': 'User created successfully'})
        else:
            return Response({'error': 'Passwords do not match'})
        
@method_decorator(csrf_protect, name='dispatch')
class LoginView(APIView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        data = self.request.data

        username = data['username']
        password = data['password']

        try:
            user = auth.authenticate(username=username, password=password)

            if user is not None:
                auth.login(request, user)
                return Response({'success': 'User authenticated', 'username': username})
            else:
                return Response({'error': 'Error authenticating'})
        except Exception as e:
            # Log the exception but don't expose details to client
            print(f"Error retrieving user info: {str(e)}")
            return Response({'error': 'Something went wrong authenticating'})
        
class LogoutView(APIView):
    def post(self, request, format=None):
        try:
            auth.logout(request)
            return Response({'success': 'Logged out'})
        except:
            return Response({'error': 'Error logging out'})

@method_decorator(ensure_csrf_cookie, name='dispatch')     
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, format=None):
        return Response({'success': 'CSRF cookie set'})

class VerifyEmailView(APIView):
    def get(self, request, uid, token):
        try:
            user = User.objects.get(pk=uid)
        except User.DoesNotExist:
            return Response({'error': 'Invalid user'}, status=400)
        
        if default_token_generator.check_token(user, token):
            stratos_user = StratosUser.objects.get(user=user)
            stratos_user.verifyEmail()
            return Response({'message': 'Email verified successfully'}, status=200)
        else:
            return Response({'error': 'Invalid or expired token'}, status=400)
