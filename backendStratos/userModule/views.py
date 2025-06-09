from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from .models import StratosUser
from django.contrib.auth.models import User
from .permissions import IsStratosUserVerified
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from .mixins import IsUserVerifiedStratosPermissionMixin, IsUserAuthenticatedPermissionMixin
from django.conf import settings
from django.views.decorators.http import require_http_methods
from django.middleware.csrf import get_token
from django.contrib.auth import logout
class GetSelfInfo(APIView, IsUserAuthenticatedPermissionMixin): 

    def get(self, request):
        print(f"User authenticated: {request.user.is_authenticated}")
        print(f"User: {request.user}")
        
        try:
            # Get the StratosUser instance associated with this User
            stratos_user = StratosUser.objects.get(user=request.user)
            user_info = UserSerializer(stratos_user).data
            return Response(user_info, status=status.HTTP_200_OK)
        except StratosUser.DoesNotExist:
            return Response(
                {'error': 'User profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            # Log the exception but don't expose details to client
            print(f"Error retrieving user self info: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve user information'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
@method_decorator(csrf_protect, name='dispatch')
class UpdateSelfInfo(APIView, IsUserVerifiedStratosPermissionMixin):

    def post(self, request):
        user = request.user
        data = request.data

        try:
            # Get the StratosUser instance associated with this User
            stratos_user = StratosUser.objects.get(user=user)
            # Validate username if provided
            if 'username' in data:
                if not data['username']:
                    return Response({'error': 'Username cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
                if len(data['username']) < 3:
                    return Response({'error': 'Username must be at least 3 characters long'}, status=status.HTTP_400_BAD_REQUEST)
                if User.objects.filter(username=data['username']).exclude(pk=user.pk).exists():
                    return Response({'error': 'Username is already taken'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate email if provided
            if 'email' in data:
                if not data['email']:
                    return Response({'error': 'Email cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
                if User.objects.filter(email=data['email']).exclude(pk=user.pk).exists():
                    return Response({'error': 'Email is already in use'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate name if provided
            if 'first_name' in data:
                first_name = data['first_name'].strip()
                if not first_name:
                    return Response({'error': 'First name cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
                if len(first_name) > 150:  # Django's default max_length for first_name
                    return Response({'error': 'First name is too long'}, status=status.HTTP_400_BAD_REQUEST)
                user.first_name = first_name
            
            # Validate surname if provided
            if 'last_name' in data:
                last_name = data['last_name'].strip()
                if not last_name:
                    return Response({'error': 'Last name cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
                if len(last_name) > 150:  # Django
                    return Response({'error': 'Last name is too long'}, status=status.HTTP_400_BAD_REQUEST)
                user.last_name = last_name
            
            # Update user fields with validation
            user.username = data.get('username', user.username)
            user.email = data.get('email', user.email)
            user.first_name = data.get('name', user.first_name)
            user.last_name = data.get('surname', user.last_name)

            # Update StratosUser fields if provided
            if 'phone' in data:
                stratos_user.phone = data.get('phone')
            if 'address' in data:
                stratos_user.address = data.get('address')
            if 'city' in data:
                stratos_user.city = data.get('city')
            if 'state' in data:
                stratos_user.state = data.get('state')
            if 'country' in data:
                stratos_user.country = data.get('country')
            if 'zip' in data:
                stratos_user.zip = data.get('zip')
            
            # Save both models
            user.save()
            stratos_user.save()
            
            # Serialize and return the StratosUser
            user_info = UserSerializer(stratos_user).data
            return Response(user_info, status=status.HTTP_200_OK)
        
        except StratosUser.DoesNotExist:
            return Response(
                {'error': 'User profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            print(f"Error updating user info: {str(e)}")
            return Response({'error': 'Failed to update user information'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateSelfPassword(APIView, IsUserAuthenticatedPermissionMixin):
    
    def post(self, request):
        user = request.user
        data = request.data

        try:
            # if required fields are present
            if not all(key in data for key in ['old_password', 'new_password', 're_new_password']):
                return Response({'error': 'Missing required fields'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            old_password = data.get('old_password')
            new_password = data.get('new_password')
            re_new_password = data.get('re_new_password')
            
            # if password fields aren't empty
            if not old_password or not new_password or not re_new_password:
                return Response({'error': 'Password fields cannot be empty'}, 
                                status=status.HTTP_400_BAD_REQUEST)
                
            # if new password has minimum requirements
            if len(new_password) < 8:
                return Response({'error': 'Password must be at least 8 characters long'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            # Check if new password is different from the old one
            if old_password == new_password:
                return Response({'error': 'New password must be different from the old password'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            # Check if new passwords match
            if new_password != re_new_password:
                return Response({'error': 'New passwords do not match'}, 
                                status=status.HTTP_400_BAD_REQUEST)
                
            # Verify old password is correct
            if not user.check_password(old_password):
                return Response({'error': 'Old password is incorrect'}, 
                                status=status.HTTP_400_BAD_REQUEST)
                
            # Update password and save user
            user.set_password(new_password)
            user.save()
            
            return Response({'success': 'Password updated successfully'}, 
                            status=status.HTTP_200_OK)
            
        except Exception as e:
            print(f"Error updating user password: {str(e)}")
            return Response({'error': 'Failed to update password'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GetSpecificUsers(APIView, IsUserVerifiedStratosPermissionMixin):
    def post(self, request):
        try:
            data = request.data
            
            # Check if username parameter exists
            if 'username' not in data:
                return Response(
                    {'error': 'Username parameter is required'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate username parameter
            username = data['username']
            if not isinstance(username, str):
                return Response(
                    {'error': 'Username must be a string'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Prevent returning too many results
            if len(username) < 2:
                return Response(
                    {'error': 'Search term must be at least 2 characters long'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Limit number of results for performance
            users = StratosUser.objects.filter(user__username__contains=username)[:50]
            
            # Only return essential user information for security
            users_info = UserSerializer(users, many=True).data
            
            return Response(users_info, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(f"Error retrieving specific user info: {str(e)}")
            return Response(
                {'error': 'Failed to retrieve users'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@method_decorator(csrf_protect, name='dispatch')
class DeleteUserAccount(APIView, IsUserAuthenticatedPermissionMixin):
    """Delete user account - hard delete the user"""
    
    def delete(self, request):
        try:
            user = request.user
            
            # Clear all user sessions
            from django.contrib.sessions.models import Session
            from django.utils import timezone
            sessions = Session.objects.filter(expire_date__gte=timezone.now())
            for session in sessions:
                session_data = session.get_decoded()
                if session_data.get('_auth_user_id') == str(user.pk):
                    session.delete()
            
            # Delete the user correctly with the associated StratosUser
            StratosUser.objects.get(user=user).delete()
            logout(request)
            response = Response({'success': 'Logged out'})
            # Clear the session cookie
            response.delete_cookie('sessionid')
            # Clear the CSRF cookie
            response.delete_cookie('csrftoken')
            user.delete()
            
            return Response({'success': 'Account deactivated successfully'}, 
                            status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error deleting user account: {str(e)}")
            return Response({'error': 'Failed to delete account'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserSubscriptionPreferencesView(APIView, IsUserAuthenticatedPermissionMixin):
    """Get and update user subscription preferences"""
    
    @method_decorator(ensure_csrf_cookie)
    def get(self, request):
        try:
            from .models import UserSubscriptionPreferences
            from .serializers import UserSubscriptionPreferencesSerializer
            
            # Get or create subscription preferences
            preferences, created = UserSubscriptionPreferences.objects.get_or_create(
                user=request.user,
                defaults={'newsletter': True, 'indie_projects_updates': True}
            )
            
            serializer = UserSubscriptionPreferencesSerializer(preferences)
            response = Response(serializer.data, status=status.HTTP_200_OK)
            response["Access-Control-Allow-Credentials"] = "true"
            return response
        except Exception as e:
            print(f"Error retrieving subscription preferences: {str(e)}")
            return Response({'error': 'Failed to retrieve subscription preferences'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @method_decorator(csrf_protect)
    def post(self, request):
        try:
            from .models import UserSubscriptionPreferences
            from .serializers import UserSubscriptionPreferencesSerializer
            
            # Get or create subscription preferences
            preferences, created = UserSubscriptionPreferences.objects.get_or_create(
                user=request.user
            )
            
            # Update only provided fields
            data = request.data
            if 'newsletter' in data:
                preferences.newsletter = data['newsletter']
            if 'indieProjectsUpdates' in data:
                preferences.indie_projects_updates = data['indieProjectsUpdates']
            
            preferences.save()
            
            serializer = UserSubscriptionPreferencesSerializer(preferences)
            response = Response(serializer.data, status=status.HTTP_200_OK)
            response["Access-Control-Allow-Credentials"] = "true"
            return response
        except Exception as e:
            print(f"Error updating subscription preferences: {str(e)}")
            return Response({'error': 'Failed to update subscription preferences'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_protect, name='dispatch')
class UnsubscribeAllView(APIView, IsUserAuthenticatedPermissionMixin):
    """Unsubscribe from all communications"""
    
    def post(self, request):
        try:
            from .models import UserSubscriptionPreferences
            
            # Get or create subscription preferences
            preferences, created = UserSubscriptionPreferences.objects.get_or_create(
                user=request.user
            )
            
            # Unsubscribe from all
            preferences.newsletter = False
            preferences.indie_projects_updates = False
            preferences.save()
            
            return Response({'success': 'Unsubscribed from all communications'}, 
                            status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error unsubscribing from all: {str(e)}")
            return Response({'error': 'Failed to unsubscribe'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SocialConnectionsView(APIView, IsUserAuthenticatedPermissionMixin):
    """Get connected social accounts"""
    
    @method_decorator(ensure_csrf_cookie)
    def get(self, request):
        try:
            from .models import UserSocialConnection
            
            # Check Discord connection (both in StratosUser and UserSocialConnection)
            stratos_user = StratosUser.objects.get(user=request.user)
            discord_connected = bool(stratos_user.discord_id) or UserSocialConnection.objects.filter(
                user=request.user, platform='discord', connected=True
            ).exists()
            
            discord_info = {
                'connected': discord_connected,
                'username': stratos_user.discord_username or ''
            }
            
            # Check Google connection
            google_connected = bool(stratos_user.google_id) or UserSocialConnection.objects.filter(
                user=request.user, platform='google', connected=True
            ).exists()
            
            google_info = {
                'connected': google_connected,
                'email': request.user.email if google_connected else ''
            }
            
            response = Response({
                'discord': discord_info,
                'google': google_info
            }, status=status.HTTP_200_OK)
            response["Access-Control-Allow-Credentials"] = "true"
            return response
        except Exception as e:
            print(f"Error retrieving social connections: {str(e)}")
            return Response({'error': 'Failed to retrieve social connections'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_protect, name='dispatch')
class ConnectDiscordView(APIView, IsUserAuthenticatedPermissionMixin):
    """Connect Discord account"""
    
    def post(self, request):
        try:
            from .models import UserSocialConnection
            import requests
            
            access_token = request.data.get('access_token')
            if not access_token:
                return Response({'error': 'Access token is required'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            # Verify token and get Discord user info
            headers = {'Authorization': f'Bearer {access_token}'}
            response = requests.get('https://discord.com/api/users/@me', headers=headers)
            
            if response.status_code != 200:
                return Response({'error': 'Invalid Discord access token'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            discord_data = response.json()
            
            # Update StratosUser with Discord info
            stratos_user = StratosUser.objects.get(user=request.user)
            stratos_user.discord_id = discord_data['id']
            stratos_user.discord_username = discord_data['username']
            stratos_user.discord_global_name = discord_data.get('global_name', '')
            stratos_user.discord_avatar = discord_data.get('avatar', '')
            stratos_user.discord_discriminator = discord_data.get('discriminator', '')
            stratos_user.save()
            
            # Create or update UserSocialConnection
            social_connection, created = UserSocialConnection.objects.update_or_create(
                user=request.user,
                platform='discord',
                defaults={
                    'connected': True,
                    'username': discord_data['username'],
                    'platform_user_id': discord_data['id'],
                    'access_token': access_token
                }
            )
            
            response = Response({'success': 'Discord account connected successfully'}, 
                            status=status.HTTP_200_OK)
            response["Access-Control-Allow-Credentials"] = "true"
            return response
        except Exception as e:
            print(f"Error connecting Discord account: {str(e)}")
            return Response({'error': 'Failed to connect Discord account'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_protect, name='dispatch')
class ConnectGoogleView(APIView, IsUserAuthenticatedPermissionMixin):
    """Connect Google account"""
    
    def post(self, request):
        try:
            from .models import UserSocialConnection
            from google.oauth2 import id_token
            from google.auth.transport import requests as google_requests
            
            credential = request.data.get('credential')
            if not credential:
                return Response({'error': 'Google credential is required'}, 
                                status=status.HTTP_400_BAD_REQUEST)
            
            # Verify the Google JWT token
            try:
                # You need to set up your Google OAuth client ID
                CLIENT_ID = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', None)
                if not CLIENT_ID:
                    return Response({'error': 'Google OAuth not configured'}, 
                                    status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
                idinfo = id_token.verify_oauth2_token(
                    credential, 
                    google_requests.Request(), 
                    CLIENT_ID
                )
                
                if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                    raise ValueError('Wrong issuer.')
                
                # Update StratosUser with Google info
                stratos_user = StratosUser.objects.get(user=request.user)
                stratos_user.google_id = idinfo['sub']
                stratos_user.save()
                
                # Create or update UserSocialConnection
                social_connection, created = UserSocialConnection.objects.update_or_create(
                    user=request.user,
                    platform='google',
                    defaults={
                        'connected': True,
                        'email': idinfo.get('email', ''),
                        'platform_user_id': idinfo['sub'],
                        'access_token': credential
                    }
                )
                
                response = Response({'success': 'Google account connected successfully'}, 
                                status=status.HTTP_200_OK)
                response["Access-Control-Allow-Credentials"] = "true"
                return response
            except ValueError as e:
                return Response({'error': 'Invalid Google credential'}, 
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"Error connecting Google account: {str(e)}")
            return Response({'error': 'Failed to connect Google account'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_protect, name='dispatch')
class DisconnectDiscordView(APIView, IsUserAuthenticatedPermissionMixin):
    """Disconnect Discord account"""
    
    def post(self, request):
        try:
            from .models import UserSocialConnection
            
            # Clear Discord info from StratosUser
            stratos_user = StratosUser.objects.get(user=request.user)
            stratos_user.discord_id = None
            stratos_user.discord_username = None
            stratos_user.discord_global_name = None
            stratos_user.discord_avatar = None
            stratos_user.discord_discriminator = None
            stratos_user.save()
            
            # Delete or mark as disconnected in UserSocialConnection
            UserSocialConnection.objects.filter(
                user=request.user, 
                platform='discord'
            ).delete()
            
            return Response({'success': 'Discord account disconnected successfully'}, 
                            status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error disconnecting Discord account: {str(e)}")
            return Response({'error': 'Failed to disconnect Discord account'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_protect, name='dispatch')
class DisconnectGoogleView(APIView, IsUserAuthenticatedPermissionMixin):
    """Disconnect Google account"""
    
    def post(self, request):
        try:
            from .models import UserSocialConnection
            
            # Clear Google info from StratosUser
            stratos_user = StratosUser.objects.get(user=request.user)
            stratos_user.google_id = None
            stratos_user.save()
            
            # Delete or mark as disconnected in UserSocialConnection
            UserSocialConnection.objects.filter(
                user=request.user, 
                platform='google'
            ).delete()
            
            return Response({'success': 'Google account disconnected successfully'}, 
                            status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error disconnecting Google account: {str(e)}")
            return Response({'error': 'Failed to disconnect Google account'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_protect, name='dispatch')
class DeleteAllUserDataView(APIView, IsUserAuthenticatedPermissionMixin):
    """Delete all user personal data (GDPR compliance)"""
    
    def delete(self, request):
        try:
            from .models import UserSubscriptionPreferences, UserSocialConnection
            from django.contrib.sessions.models import Session
            from django.utils import timezone
            
            user = request.user
            
            # Clear all sessions
            sessions = Session.objects.filter(expire_date__gte=timezone.now())
            for session in sessions:
                session_data = session.get_decoded()
                if session_data.get('_auth_user_id') == str(user.pk):
                    session.delete()
            
            # Delete social connections
            UserSocialConnection.objects.filter(user=user).delete()
            
            # Delete subscription preferences
            UserSubscriptionPreferences.objects.filter(user=user).delete()
            
            # Clear personal data from StratosUser
            stratos_user = StratosUser.objects.get(user=user)
            stratos_user.phone = ''
            stratos_user.address = ''
            stratos_user.city = ''
            stratos_user.state = ''
            stratos_user.country = ''
            stratos_user.zip = ''
            stratos_user.google_id = None
            stratos_user.discord_id = None
            stratos_user.discord_username = None
            stratos_user.discord_global_name = None
            stratos_user.discord_avatar = None
            stratos_user.discord_discriminator = None
            stratos_user.save()
            
            # Clear user personal info but keep account for audit
            user.first_name = ''
            user.last_name = ''
            user.email = f'deleted_{user.id}@stratos.local'
            user.is_active = False
            user.save()
            
            return Response({'success': 'All personal data deleted successfully'}, 
                            status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error deleting all user data: {str(e)}")
            return Response({'error': 'Failed to delete user data'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


