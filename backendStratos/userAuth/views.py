#File used for user authentication
from rest_framework.views import APIView
from rest_framework import permissions
from rest_framework.response import Response
from django.contrib.auth.models import User
from userModule.models import StratosUser, UserType, PasswordResetToken
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_protect
from rest_framework import authentication
from django.contrib import auth  # Add this import for login/logout functionality
from django.utils.decorators import method_decorator
from django.utils import timezone  # Add this import for timezone-aware datetime
from datetime import datetime, timedelta
from backendStratos.utilities import checkForPasswordRequirements, validate_password_requirements
from backendStratos.mailServer import send_verification_email, send_password_reset_email, generate_reset_token
from django.contrib.auth.tokens import default_token_generator
from google.oauth2 import id_token
from google.auth.transport import requests
import urllib.parse
import urllib.request
import json
import logging
import gzip
import io
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.core.cache import cache

# Set up logging
logger = logging.getLogger(__name__)

def validate_user_types(user_types):
    """Validate user types against available choices"""
    if not isinstance(user_types, list):
        return False, "User types must be a list"
    
    if not user_types:
        return False, "At least one user type must be selected"
    
    valid_types = [choice[0] for choice in UserType.USER_TYPE_CHOICES]
    invalid_types = [ut for ut in user_types if ut not in valid_types]
    
    if invalid_types:
        return False, f"Invalid user types: {', '.join(invalid_types)}"
    
    return True, None

@method_decorator(csrf_protect, name='dispatch')
class CheckAuthenticatedView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def get(self, request, format=None):
        try:
            isAuthenticated = request.user.is_authenticated

            if(isAuthenticated):
                # Get additional user information
                user = request.user
                stratos_user = None
                
                try:
                    stratos_user = StratosUser.objects.get(user=user)
                except StratosUser.DoesNotExist:
                    pass
                
                response_data = {
                    'isAuthenticated': True,
                    'username': user.username,
                    'email': user.email,
                    'id': user.id,
                    'isEmailVerified': stratos_user.isEmailVerified if stratos_user else False,
                    'google_id': stratos_user.google_id if stratos_user and stratos_user.google_id else None,
                    'discord_id': stratos_user.discord_id if stratos_user and stratos_user.discord_id else None
                }
                
                # Add Discord profile information if available
                if stratos_user and stratos_user.discord_id:
                    response_data['discord_profile'] = {
                        'username': stratos_user.discord_username,
                        'global_name': stratos_user.discord_global_name,
                        'avatar_url': stratos_user.get_discord_avatar_url(),
                        'display_name': stratos_user.get_display_name()
                    }
                
                return Response(response_data)
            else:
                return Response({
                    'isAuthenticated': False,
                    'username': None,
                    'email': None,
                    'id': None,
                    'isEmailVerified': False,
                    'google_id': None,
                    'discord_id': None,
                    'discord_profile': None
                })
        except Exception as e:
            logger.error(f"Error checking authentication: {str(e)}")
            return Response({'error': 'something went wrong checking authentication status'})


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
    except ValueError as e:
        logger.error(f"Google token verification failed: {str(e)}")
        return None

def verify_discord_token(access_token):
    """Verify Discord access token and get user info"""
    try:
        # Log the token length (not the actual token for security)
        logger.info(f"Attempting to verify Discord token of length: {len(access_token) if access_token else 0}")
        
        if not access_token:
            logger.error("Discord token is empty or None")
            return None
            
        # Get user info from Discord API with all required headers
        headers = {
            'Authorization': f'Bearer {access_token.strip()}',  # Ensure no whitespace
            'Content-Type': 'application/json',
            'User-Agent': 'Stratos/1.0 (https://stratosgaming.it, v1.0)',
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Origin': 'https://discord.com',
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin'
        }
        
        # Log the request details (without sensitive data)
        logger.info("Making request to Discord API with headers: %s", 
                   {k: v if k != 'Authorization' else 'Bearer [REDACTED]' for k, v in headers.items()})
        
        # Create a custom opener with a timeout
        opener = urllib.request.build_opener()
        opener.addheaders = [(k, v) for k, v in headers.items()]
        
        try:
            # Use the opener to make the request
            with opener.open('https://discord.com/api/v10/users/@me', timeout=10) as response:
                if response.status == 200:
                    # Read the response content
                    content = response.read()
                    
                    # Check if the response is gzip compressed
                    if response.headers.get('Content-Encoding') == 'gzip':
                        try:
                            # Decompress the gzip content
                            content = gzip.decompress(content)
                        except Exception as e:
                            logger.error(f"Error decompressing gzip content: {str(e)}")
                            return None
                    
                    try:
                        # Decode and parse the JSON
                        user_data = json.loads(content.decode('utf-8'))
                    except UnicodeDecodeError as e:
                        logger.error(f"Error decoding response content: {str(e)}")
                        return None
                    except json.JSONDecodeError as e:
                        logger.error(f"Error parsing JSON response: {str(e)}")
                        return None
                    
                    # Extract user information
                    discord_id = user_data['id']
                    username = user_data['username']
                    global_name = user_data.get('global_name', username)
                    discriminator = user_data.get('discriminator', '0000')
                    avatar = user_data.get('avatar', '')
                    email = user_data.get('email', None)
                    
                    logger.info(f"Discord token verified successfully for user: {username}")
                    
                    return {
                        'discord_id': discord_id,
                        'username': username,
                        'global_name': global_name,
                        'discriminator': discriminator,
                        'avatar': avatar,
                        'email': email
                    }
                else:
                    try:
                        content = response.read()
                        if response.headers.get('Content-Encoding') == 'gzip':
                            content = gzip.decompress(content)
                        response_body = content.decode('utf-8')
                    except Exception as e:
                        response_body = f"Error reading response body: {str(e)}"
                    logger.error(f"Discord API returned status {response.status}: {response_body}")
                    return None
                    
        except urllib.error.HTTPError as e:
            try:
                content = e.read()
                if e.headers.get('Content-Encoding') == 'gzip':
                    content = gzip.decompress(content)
                response_body = content.decode('utf-8')
            except Exception as read_error:
                response_body = f"Error reading error response: {str(read_error)}"
            
            logger.error(f"Discord API HTTP Error {e.code}: {response_body}")
            if e.code == 403:
                if 'error code: 1010' in response_body:
                    logger.error("Discord API returned 403 with error code 1010. This indicates a request was blocked by Discord's security measures. Please check your IP address and request headers.")
                else:
                    logger.error("Discord API returned 403 Forbidden. This usually means the token is invalid or expired.")
            return None
        except urllib.error.URLError as e:
            logger.error(f"Discord API URL Error: {str(e)}")
            return None
                
    except Exception as e:
        logger.error(f"Error verifying Discord token: {str(e)}", exc_info=True)
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
        user_types = data.get('user_types', [])  # Get user types with empty list default
        name = data.get('name', '')
        surname = data.get('surname', '')
        # Validate user types
        is_valid, error_message = validate_user_types(user_types)
        if not is_valid:
            return Response({'error': error_message}, status=400)

        if password == re_password:
            # Check username uniqueness
            if User.objects.filter(username=username).exists():
                return Response({'error': 'Username already exists'})
            
            # Check email uniqueness if email is provided
            if email and User.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'})
            
            if checkForPasswordRequirements(password) == False:
                return Response({'error': 'Password does not have all the requirements'})
            else:
                user = User.objects.create_user(
                    username=username, 
                    email=email,
                    password=password, 
                    last_login=timezone.now(),
                    first_name=name,
                    last_name=surname
                )
                user.save()
                user = User.objects.get(id=user.id)
                
                # Create user profile
                user_profile = StratosUser(
                    user=user, 
                    phone='', 
                    address='', 
                    city='', 
                    state='', 
                    country='', 
                    zip=''
                )
                user_profile.save()
                
                # Add user types
                for user_type in user_types:
                    type_obj, created = UserType.objects.get_or_create(type=user_type)
                    user_profile.user_types.add(type_obj)
                
                # Log the user in after successful registration
                auth.login(request, user)
                
                if (email != ''):  # Send verification email if email provided
                    send_verification_email(user, request)
                
                return Response({
                    'success': 'User created successfully',
                    'user': {
                        'username': user.username,
                        'email': user.email,
                        'id': user.id,
                        'isEmailVerified': user_profile.isEmailVerified,
                        'user_types': user_profile.get_user_types()
                    }
                })
        else:
            return Response({'error': 'Passwords do not match'})

@method_decorator(csrf_protect, name='dispatch')
class ResendVerificationEmailView(APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, format=None):
        try:
            user = request.user
            stratos_user = StratosUser.objects.get(user=user)
            if not stratos_user.isEmailVerified:
                if send_verification_email(user, request):
                    return Response({'success': 'Verification email sent successfully'})
                else:
                    return Response({'error': 'Failed to send verification email'}, status=400)
            else:
                return Response({'error': 'Email already verified'}, status=400)
        except Exception as e:
            logger.error(f"Error sending verification email: {str(e)}")
            return Response({'error': 'Something went wrong sending verification email'}, status=500)

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
                stratos_user = StratosUser.objects.get(user=user)
                return Response({'success': 'User authenticated', 'username': username, 'isEmailVerified': stratos_user.isEmailVerified})
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
        from django.conf import settings
        from django.middleware.csrf import get_token
        
        # Get the CSRF token
        csrf_token = get_token(request)
        
        # Log the request details for debugging
        logger.info(f"CSRF cookie request from: {request.META.get('HTTP_HOST', 'Unknown')}")
        logger.info(f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'Unknown')}")
        logger.info(f"Origin: {request.META.get('HTTP_ORIGIN', 'None')}")
        logger.info(f"Referer: {request.META.get('HTTP_REFERER', 'None')}")
        logger.info(f"Is secure: {request.is_secure()}")
        logger.info(f"DEBUG mode: {settings.DEBUG}")
        
        # Create response
        response = Response({
            'success': 'CSRF cookie set',
            'csrf_token': csrf_token,
            'debug_info': {
                'is_secure': request.is_secure(),
                'host': request.META.get('HTTP_HOST'),
                'csrf_cookie_secure': settings.CSRF_COOKIE_SECURE,
                'csrf_cookie_domain': settings.CSRF_COOKIE_DOMAIN,
                'csrf_cookie_path': getattr(settings, 'CSRF_COOKIE_PATH', '/'),
                'csrf_cookie_samesite': settings.CSRF_COOKIE_SAMESITE,
            } if settings.DEBUG else None
        })
        
        # Explicitly set CSRF cookie with proper attributes
        response.set_cookie(
            settings.CSRF_COOKIE_NAME,
            csrf_token,
            max_age=settings.CSRF_COOKIE_AGE if hasattr(settings, 'CSRF_COOKIE_AGE') else None,
            expires=None,
            path=getattr(settings, 'CSRF_COOKIE_PATH', '/'),
            domain=settings.CSRF_COOKIE_DOMAIN,
            secure=settings.CSRF_COOKIE_SECURE,
            httponly=settings.CSRF_COOKIE_HTTPONLY,
            samesite=settings.CSRF_COOKIE_SAMESITE
        )
        
        logger.info(f"CSRF cookie set with token: {csrf_token[:10]}...")
        return response

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
        google_id = google_user_info['google_id']
        
        try:
            # Check if user exists with this email
            user = User.objects.get(email=email)
            
            # Get or create StratosUser profile
            stratos_user, created = StratosUser.objects.get_or_create(user=user)
            
            # Link Google account if not already linked
            if not stratos_user.google_id:
                stratos_user.google_id = google_id
                logger.info(f"Linked Google account to existing user: {user.username}")
            
            # Mark email as verified (since Google verified it)
            if not stratos_user.isEmailVerified:
                stratos_user.isEmailVerified = True
                logger.info(f"Marked email as verified for user: {user.username}")
            
            stratos_user.save()
            
            # Log the user in
            auth.login(request, user)
            
            return Response({
                'success': 'User authenticated with Google',
                'username': user.username,
                'email': user.email,
                'user': {
                    'isEmailVerified': stratos_user.isEmailVerified
                }
            })
            
        except User.DoesNotExist:
            return Response({
                'error': 'No account found with this email. Please sign up first.'
            }, status=404)
        
        except Exception as e:
            logger.error(f"Error during Google login: {str(e)}")
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
            # Check if user already exists with this email
            if User.objects.filter(email=email).exists():
                return Response({'error': 'User with this email already exists'}, status=400)
            
            # Use provided username or generate one from email
            if provided_username:
                # Check if provided username is unique
                if User.objects.filter(username=provided_username).exists():
                    return Response({'error': 'Username already exists'}, status=400)
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

@method_decorator(csrf_protect, name='dispatch')
class DiscordLoginView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request, format=None):
        logger.info("Discord login attempt")
        data = self.request.data
        access_token = data.get('access_token')
        
        if not access_token:
            logger.warning("Discord login attempted without access token")
            return Response({'error': 'Discord access token required'}, status=400)
        
        # Verify the Discord token and get user info
        discord_user_info = verify_discord_token(access_token)
        
        if not discord_user_info:
            logger.warning("Discord login failed: Invalid token")
            return Response({'error': 'Invalid Discord token'}, status=400)
        
        discord_id = discord_user_info['discord_id']
        email = discord_user_info['email']
        
        try:
            # Try to find user by Discord ID first (if we have stored it)
            try:
                stratos_user = StratosUser.objects.get(discord_id=discord_id)
                user = stratos_user.user
                
                # Update Discord profile info if it has changed
                discord_username = discord_user_info['username']
                global_name = discord_user_info['global_name']
                avatar = discord_user_info['avatar']
                discriminator = discord_user_info['discriminator']
                
                # Update Discord profile information
                stratos_user.discord_username = discord_username
                stratos_user.discord_global_name = global_name
                stratos_user.discord_avatar = avatar
                stratos_user.discord_discriminator = discriminator
                stratos_user.save()
                
                logger.info(f"Discord login successful for user: {user.username}")
                
            except StratosUser.DoesNotExist:
                # Try to find user by email if Discord provided one
                if email:
                    try:
                        user = User.objects.get(email=email)
                        logger.info(f"Found user by email for Discord login: {user.username}")
                    except User.DoesNotExist:
                        logger.warning(f"Discord login failed: No account found with email {email}")
                        # Return Discord user info for registration pre-fill
                        return Response({
                            'error': 'No account found with this Discord account. Please sign up first.',
                            'discord_user_info': {
                                'discord_id': discord_id,
                                'username': discord_user_info['username'],
                                'global_name': discord_user_info['global_name'],
                                'email': email,
                                'avatar': discord_user_info['avatar'],
                                'suggested_username': discord_user_info['username'].lower()
                            }
                        }, status=404)
                else:
                    logger.warning("Discord login failed: No Discord ID or email found")
                    # Return Discord user info for registration pre-fill (without email)
                    return Response({
                        'error': 'No account found with this Discord account. Please sign up first.',
                        'discord_user_info': {
                            'discord_id': discord_id,
                            'username': discord_user_info['username'],
                            'global_name': discord_user_info['global_name'],
                            'email': None,
                            'avatar': discord_user_info['avatar'],
                            'suggested_username': discord_user_info['username'].lower()
                        }
                    }, status=404)
            
            # Log the user in
            auth.login(request, user)
            
            # Get updated stratos_user for response
            stratos_user = StratosUser.objects.get(user=user)
            
            return Response({
                'success': 'User authenticated with Discord',
                'username': user.username,
                'email': user.email,
                'discord_profile': {
                    'username': discord_user_info['username'],
                    'global_name': discord_user_info['global_name'],
                    'avatar_url': stratos_user.get_discord_avatar_url(),
                    'display_name': stratos_user.get_display_name()
                }
            })
            
        except Exception as e:
            logger.error(f"Error during Discord login: {str(e)}")
            return Response({'error': 'Something went wrong during Discord authentication'}, status=500)

@method_decorator(csrf_protect, name='dispatch')
class DiscordLinkView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    
    def post(self, request, format=None):
        """Link Discord account to existing authenticated user"""
        logger.info(f"Discord link attempt for user: {request.user.username}")
        data = self.request.data
        access_token = data.get('access_token')
        
        if not access_token:
            logger.warning("Discord link attempted without access token")
            return Response({'error': 'Discord access token required'}, status=400)
        
        # Verify the Discord token and get user info
        discord_user_info = verify_discord_token(access_token)
        
        if not discord_user_info:
            logger.warning("Discord link failed: Invalid token")
            return Response({'error': 'Invalid Discord token'}, status=400)
        
        discord_id = discord_user_info['discord_id']
        
        try:
            # Check if Discord account is already linked to another user
            existing_link = StratosUser.objects.filter(discord_id=discord_id).exclude(user=request.user).first()
            if existing_link:
                logger.warning(f"Discord link failed: Discord ID {discord_id} already linked to another user")
                return Response({'error': 'Discord account is already linked to another user'}, status=400)
            
            # Get or create StratosUser for current user
            stratos_user, created = StratosUser.objects.get_or_create(user=request.user)
            
            # Update Discord profile information
            stratos_user.discord_id = discord_id
            stratos_user.discord_username = discord_user_info['username']
            stratos_user.discord_global_name = discord_user_info['global_name']
            stratos_user.discord_avatar = discord_user_info['avatar']
            stratos_user.discord_discriminator = discord_user_info['discriminator']
            stratos_user.save()
            
            logger.info(f"Discord account successfully linked for user: {request.user.username}")
            
            return Response({
                'success': 'Discord account linked successfully',
                'discord_profile': {
                    'username': discord_user_info['username'],
                    'global_name': discord_user_info['global_name'],
                    'avatar_url': stratos_user.get_discord_avatar_url(),
                    'display_name': stratos_user.get_display_name()
                }
            })
            
        except Exception as e:
            logger.error(f"Error during Discord link: {str(e)}")
            return Response({'error': 'Something went wrong while linking Discord account'}, status=500)

@method_decorator(csrf_protect, name='dispatch')
class DiscordUnlinkView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    
    def post(self, request, format=None):
        """Unlink Discord account from authenticated user"""
        logger.info(f"Discord unlink attempt for user: {request.user.username}")
        
        try:
            stratos_user = StratosUser.objects.get(user=request.user)
            
            if not stratos_user.discord_id:
                return Response({'error': 'No Discord account linked'}, status=400)
            
            # Clear Discord information
            stratos_user.discord_id = None
            stratos_user.discord_username = None
            stratos_user.discord_global_name = None
            stratos_user.discord_avatar = None
            stratos_user.discord_discriminator = None
            stratos_user.save()
            
            logger.info(f"Discord account successfully unlinked for user: {request.user.username}")
            
            return Response({'success': 'Discord account unlinked successfully'})
            
        except StratosUser.DoesNotExist:
            return Response({'error': 'User profile not found'}, status=404)
        except Exception as e:
            logger.error(f"Error during Discord unlink: {str(e)}")
            return Response({'error': 'Something went wrong while unlinking Discord account'}, status=500)

@method_decorator(csrf_protect, name='dispatch')
class DiscordSignupView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request, format=None):
        logger.info("Discord signup attempt")
        data = self.request.data
        access_token = data.get('access_token')
        provided_username = data.get('username')  # Get username from frontend
        provided_email = data.get('email')  # Get email from frontend
        
        if not access_token:
            logger.warning("Discord signup attempted without access token")
            return Response({'error': 'Discord access token required'}, status=400)
        
        # Verify the Discord token and get user info
        discord_user_info = verify_discord_token(access_token)
        
        if not discord_user_info:
            logger.warning("Discord signup failed: Invalid token")
            return Response({'error': 'Invalid Discord token'}, status=400)
        
        discord_id = discord_user_info['discord_id']
        discord_username = discord_user_info['username']
        global_name = discord_user_info['global_name']
        discord_email = discord_user_info['email']
        avatar = discord_user_info['avatar']
        discriminator = discord_user_info['discriminator']
        
        try:
            # Use provided email or Discord email
            email = provided_email or discord_email
            
            if not email:
                logger.warning(f"Discord signup failed: No email for user {discord_username}")
                return Response({'error': 'Email is required for registration'}, status=400)
            
            # Check if user already exists with this email
            if User.objects.filter(email=email).exists():
                logger.warning(f"Discord signup failed: Email {email} already exists")
                return Response({'error': 'User with this email already exists'}, status=400)
            
            # Check if Discord account is already linked
            if StratosUser.objects.filter(discord_id=discord_id).exists():
                logger.warning(f"Discord signup failed: Discord ID {discord_id} already linked")
                return Response({'error': 'Discord account is already linked to another user'}, status=400)
            
            # Use provided username or generate one from Discord username
            if provided_username:
                # Check if provided username is unique
                if User.objects.filter(username=provided_username).exists():
                    logger.warning(f"Discord signup failed: Username {provided_username} already exists")
                    return Response({'error': 'Username already exists'}, status=400)
                username = provided_username
            else:
                # Create username from Discord username and make it unique
                base_username = discord_username.lower()
                username = base_username
                counter = 1
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{counter}"
                    counter += 1
            
            # Create the user
            user = User.objects.create_user(
                username=username,
                email=email,
                first_name=global_name.split()[0] if global_name and global_name.split() else discord_username,
                last_name=' '.join(global_name.split()[1:]) if global_name and len(global_name.split()) > 1 else '',
                last_login=timezone.now()
            )
            user.save()
            
            # Create the StratosUser profile with Discord info
            user_profile = StratosUser(
                user=user, 
                phone='', 
                address='', 
                city='', 
                state='', 
                country='', 
                zip='',
                discord_id=discord_id,
                discord_username=discord_username,
                discord_global_name=global_name,
                discord_avatar=avatar,
                discord_discriminator=discriminator,
                isEmailVerified=True if discord_email else False  # Set as verified if Discord provided email
            )
            user_profile.save()
            
            # Log the user in
            auth.login(request, user)
            
            logger.info(f"Discord signup successful for user: {username}")
            
            return Response({
                'success': 'User created and authenticated with Discord',
                'username': username,
                'email': email,
                'discord_profile': {
                    'username': discord_username,
                    'global_name': global_name,
                    'avatar_url': user_profile.get_discord_avatar_url(),
                    'display_name': user_profile.get_display_name()
                }
            })
            
        except Exception as e:
            logger.error(f"Error during Discord signup: {str(e)}")
            return Response({'error': 'Something went wrong during Discord signup'}, status=500)

def get_rate_limit_key(prefix, identifier):
    """Generate rate limit key for cache"""
    return f"{prefix}:{identifier}"

def check_rate_limit(key, limit, window_seconds):
    """Check if rate limit has been exceeded"""
    current_count = cache.get(key, 0)
    return current_count >= limit

def increment_rate_limit(key, window_seconds):
    """Increment rate limit counter"""
    current_count = cache.get(key, 0)
    cache.set(key, current_count + 1, window_seconds)

@method_decorator(csrf_protect, name='dispatch')
class PasswordRecoveryRequestView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request, format=None):
        """Handle password recovery requests"""
        logger.info("Password recovery request received")
        data = self.request.data
        
        email = data.get('email', '').strip().lower()
        
        if not email:
            return Response({'error': 'Email is required'}, status=400)
        
        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response({'error': 'Invalid email format'}, status=400)
        
        # Rate limiting - 3 requests per email per hour
        rate_limit_key = get_rate_limit_key('password_recovery', email)
        if check_rate_limit(rate_limit_key, 3, 3600):  # 3 requests per hour
            logger.warning(f"Rate limit exceeded for password recovery: {email}")
            return Response({
                'error': 'Too many password recovery requests. Please try again later.'
            }, status=429)
        
        # Increment rate limit counter
        increment_rate_limit(rate_limit_key, 3600)
        
        try:
            # Always return success message to prevent email enumeration
            success_response = {
                'success': True,
                'message': 'If an account with that email exists, we\'ve sent you a password reset link.'
            }
            
            # Check if user exists
            try:
                user = User.objects.get(email=email)
                logger.info(f"Password recovery requested for user: {user.username}")
                
                # Invalidate any existing unused tokens for this user
                PasswordResetToken.objects.filter(
                    user=user, 
                    is_used=False
                ).update(is_used=True)
                
                # Generate new reset token
                reset_token = generate_reset_token()
                
                # Create password reset token record
                token_record = PasswordResetToken.objects.create(
                    user=user,
                    token=reset_token,
                    expires_at=timezone.now() + timedelta(hours=1)
                )
                
                # Send password reset email
                if send_password_reset_email(user, reset_token, request):
                    logger.info(f"Password reset email sent successfully to {user.email}")
                else:
                    logger.error(f"Failed to send password reset email to {user.email}")
                
            except User.DoesNotExist:
                logger.info(f"Password recovery requested for non-existent email: {email}")
                # Still return success to prevent email enumeration
                pass
            
            return Response(success_response)
            
        except Exception as e:
            logger.error(f"Error during password recovery request: {str(e)}")
            return Response({
                'error': 'Something went wrong processing your request. Please try again.'
            }, status=500)

@method_decorator(csrf_protect, name='dispatch')
class PasswordResetView(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request, format=None):
        """Handle password reset with token"""
        logger.info("Password reset attempt")
        data = self.request.data
        
        user_id = data.get('user_id')
        user_token = data.get('user_token', '').strip()
        new_password = data.get('new_password')
        
        # Validate required parameters
        if not all([user_id, user_token, new_password]):
            return Response({
                'error': 'Missing required parameters: user_id, user_token, and new_password are required'
            }, status=400)
        
        # Rate limiting - 5 attempts per token
        rate_limit_key = get_rate_limit_key('password_reset', user_token)
        if check_rate_limit(rate_limit_key, 5, 3600):  # 5 attempts per hour
            logger.warning(f"Rate limit exceeded for password reset token: {user_token[:10]}...")
            return Response({
                'error': 'Too many password reset attempts. Please request a new reset link.'
            }, status=429)
        
        # Increment rate limit counter
        increment_rate_limit(rate_limit_key, 3600)
        
        try:
            # Validate user exists
            try:
                user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                logger.warning(f"Password reset attempted with invalid user_id: {user_id}")
                return Response({'error': 'Invalid reset link'}, status=404)
            
            # Validate token
            try:
                token_record = PasswordResetToken.objects.get(
                    user=user,
                    token=user_token,
                    is_used=False
                )
            except PasswordResetToken.DoesNotExist:
                logger.warning(f"Password reset attempted with invalid token for user: {user.username}")
                return Response({'error': 'Invalid or expired reset link'}, status=404)
            
            # Check if token has expired
            if token_record.is_expired():
                logger.warning(f"Password reset attempted with expired token for user: {user.username}")
                token_record.is_used = True
                token_record.save()
                return Response({'error': 'Reset link has expired. Please request a new one.'}, status=410)
            
            # Validate new password
            is_valid, password_errors = validate_password_requirements(new_password)
            if not is_valid:
                return Response({
                    'error': 'Password does not meet requirements',
                    'password_errors': password_errors
                }, status=400)
            
            # Update user's password
            user.set_password(new_password)
            user.save()
            
            # Mark token as used
            token_record.is_used = True
            token_record.save()
            
            # Invalidate any other unused tokens for this user
            PasswordResetToken.objects.filter(
                user=user,
                is_used=False
            ).update(is_used=True)
            
            logger.info(f"Password successfully reset for user: {user.username}")
            
            return Response({
                'success': True,
                'message': 'Password has been successfully reset. You can now log in with your new password.'
            })
            
        except Exception as e:
            logger.error(f"Error during password reset: {str(e)}")
            return Response({
                'error': 'Something went wrong processing your request. Please try again.'
            }, status=500)
