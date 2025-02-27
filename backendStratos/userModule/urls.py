from django.urls import path
from . import views
from .views import GetSelfInfo, UpdateSelfInfo, UpdateSelfPassword, GetSpecificUsers
app_name = 'userModule'

urlpatterns = [
    path('', GetSelfInfo.as_view(), name='get-self-info'),
    path('update/', UpdateSelfInfo.as_view(), name='update-self-info'),
    path('change-password/', UpdateSelfPassword.as_view(), name='update-self-password'),
    path('get-user-info/', GetSpecificUsers.as_view(), name='get-specific-users'),
]