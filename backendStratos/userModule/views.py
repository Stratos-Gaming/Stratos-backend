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

class GetSelfInfo(APIView): 
    permission_classes = [IsAuthenticated]

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
class UpdateSelfInfo(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        try:
            # Validate email if provided
            if 'email' in data:
                if not data['email']:
                    return Response({'error': 'Email cannot be empty'}, status=status.HTTP_400_BAD_REQUEST)
                if User.objects.filter(email=data['email']).exclude(pk=user.pk).exists():
                    return Response({'error': 'Email is already in use'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Update user fields with validation
            user.first_name = data.get('first_name', user.first_name)
            user.last_name = data.get('last_name', user.last_name)
            user.email = data.get('email', user.email)
            
            # Save user and handle database errors
            user.save()
            
            user_info = UserSerializer(user).data
            return Response(user_info, status=status.HTTP_200_OK)
        
        except Exception as e:
            print(f"Error updating user info: {str(e)}")
            return Response({'error': 'Failed to update user information'}, 
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateSelfPassword(APIView):
    permission_classes = [IsAuthenticated]

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


class GetSpecificUsers(APIView):
    permission_classes = [IsAuthenticated, IsStratosUserVerified]
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