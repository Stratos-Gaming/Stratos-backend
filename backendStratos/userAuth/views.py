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
from django.utils import timezone  # Add this import for timezone-aware datetime
from datetime import datetime
from backendStratos.utilities import checkForPasswordRequirements
from backendStratos.mailServer import send_verification_email
from django.contrib.auth.tokens import default_token_generator
from google.oauth2 import id_token
from google.auth.transport import requests

@method_decorator(csrf_protect, name='dispatch')
class CheckAuthenticatedView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def get(self, request, format=None):
        try:
            # Check if user is authenticated and not anonymous
            if request.user and request.user.is_authenticated and not request.user.is_anonymous:
                # Get user details
                user_data = {
                    'isAuthenticated': True,
                    'username': request.user.username,
                    'email': request.user.email,
                    'id': request.user.id
                }
                
                # Check if user has StratosUser profile and if email is verified
                try:
                    stratos_user = StratosUser.objects.get(user=request.user)
                    user_data['isEmailVerified'] = stratos_user.isEmailVerified
                except StratosUser.DoesNotExist:
                    user_data['isEmailVerified'] = False
                
                return Response(user_data, status=200)
            else:
                return Response({
                    'isAuthenticated': False,
                    'username': None,
                    'email': None,
                    'id': None,
                    'isEmailVerified': False
                }, status=200)
        except Exception as e:
            print(f"Error checking authentication status: {str(e)}")
            return Response({
                'isAuthenticated': False,
                'error': 'Failed to check authentication status'
            }, status=500)


def verify_google_token(credential):
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            credential, 
            requests.Request(), 
            "881910389932-0978path34mbhkngiu2msis6ghlqoovt.apps.googleusercontent.com"
        )
        
        # Get user info
        email = idinfo['email']
        name = idinfo['name']
        google_id = idinfo['sub']
        
        return {
            'email': email,
            'name': name,
            'google_id': google_id
        }
    except ValueError:
        # Invalid token
        return None

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
                        last_login=timezone.now()
                    )
                    user.save()
                    user = User.objects.get(id=user.id)
                    user_profile = StratosUser(user=user, phone='', address='', city='', state='', country='', zip='')
                    user_profile.save()
                    if (email != ''):  # Send verification email if email provided
                        send_verification_email(user, request)
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
        
@method_decorator(csrf_protect, name='dispatch')
class LogoutView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, format=None):
        try:
            auth.logout(request)
            response = Response({'success': 'Logged out'})
            # Clear the session cookie
            response.delete_cookie('sessionid')
            # Clear the CSRF cookie
            response.delete_cookie('csrftoken')
            return response
        except Exception as e:
            print(f"Error during logout: {str(e)}")
            return Response({'error': 'Error logging out'})

@method_decorator(ensure_csrf_cookie, name='dispatch')     
class GetCSRFToken(APIView):
    permission_classes = (permissions.AllowAny,)

    def get(self, request, format=None):
        return Response({'success': 'CSRF cookie set'})

class VerifyEmailView(APIView):
    permission_classes = (permissions.AllowAny,)
    
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

@method_decorator(csrf_protect, name='dispatch')
class GoogleLoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request, format=None):
        data = self.request.data
        credential = data.get('credential')
        
        if not credential:
            return Response({'error': 'Google credential required'}, status=400)
        
        # Verify the Google token
        google_user_info = verify_google_token(credential)
        
        if not google_user_info:
            return Response({'error': 'Invalid Google token'}, status=400)
        
        email = google_user_info['email']
        
        try:
            # Check if user exists with this email
            user = User.objects.get(email=email)
            
            # Log the user in
            auth.login(request, user)
            
            return Response({
                'success': 'User authenticated with Google',
                'username': user.username,
                'email': user.email
            })
            
        except User.DoesNotExist:
            return Response({
                'error': 'No account found with this email. Please sign up first.'
            }, status=404)
        
        except Exception as e:
            print(f"Error during Google login: {str(e)}")
            return Response({'error': 'Something went wrong during Google authentication'}, status=500)

@method_decorator(csrf_protect, name='dispatch')
class GoogleSignupView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request, format=None):
        data = self.request.data
        credential = data.get('credential')
        provided_username = data.get('username')  # Get username from frontend
        
        if not credential:
            return Response({'error': 'Google credential required'}, status=400)
        
        # Verify the Google token
        google_user_info = verify_google_token(credential)
        
        if not google_user_info:
            return Response({'error': 'Invalid Google token'}, status=400)
        
        email = google_user_info['email']
        name = google_user_info['name']
        google_id = google_user_info['google_id']
        
        try:
            # Check if user already exists
            if User.objects.filter(email=email).exists():
                return Response({'error': 'User with this email already exists'}, status=400)
            
            # Use provided username or generate one from email
            if provided_username and not User.objects.filter(username=provided_username).exists():
                username = provided_username
            else:
                # Create username from email (before @ symbol) and make it unique
                base_username = email.split('@')[0]
                username = base_username
                counter = 1
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{counter}"
                    counter += 1
            
            # Create the user
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=name.split()[0] if name.split() else '',
                last_name=' '.join(name.split()[1:]) if len(name.split()) > 1 else '',
                last_login=timezone.now()
            )
            user.save()
            
            # Create the StratosUser profile
            user_profile = StratosUser(
                user=user, 
                phone='', 
                address='', 
                city='', 
                state='', 
                country='', 
                zip='',
                google_id=google_id if hasattr(StratosUser, 'google_id') else None,
                isEmailVerified=True  # Set email as verified for Google users
            )
            user_profile.save()
            
            # Log the user in
            auth.login(request, user)
            
            return Response({
                'success': 'User created and authenticated with Google',
                'username': username,
                'email': email
            })
            
        except Exception as e:
            print(f"Error during Google signup: {str(e)}")
            return Response({'error': 'Something went wrong during Google signup'}, status=500)
