from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.models import User
from .serializers import UserSerializer

class GetSelfInfo(APIView): 
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        user_info = UserSerializer(user).data
        return Response(user_info, status=status.HTTP_200_OK)

class UpdateSelfInfo(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        user.first_name = data.get('first_name', user.first_name)
        user.last_name = data.get('last_name', user.last_name)
        user.email = data.get('email', user.email)
        user.save()

        user_info = UserSerializer(user).data
        return Response(user_info, status=status.HTTP_200_OK)

class UpdateSelfPassword(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        data = request.data

        old_password = data.get('old_password')
        new_password = data.get('new_password')
        re_new_password = data.get('re_new_password')

        if new_password == re_new_password:
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                return Response({'success': 'Password updated successfully'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Old password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'New passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)


class GetSpecificUsers(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        users = User.objects.filter(username__contains=data['username'])
        users_info = UserSerializer(users, many=True).data
        return Response(users_info, status=status.HTTP_200_OK)