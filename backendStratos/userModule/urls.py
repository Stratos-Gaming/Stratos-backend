from django.urls import path
from . import views
from .views import (
    GetSelfInfo, UpdateSelfInfo, UpdateSelfPassword, GetSpecificUsers,
    DeleteUserAccount, UserSubscriptionPreferencesView, UnsubscribeAllView,
    SocialConnectionsView, ConnectDiscordView, ConnectGoogleView,
    DisconnectDiscordView, DisconnectGoogleView, DeleteAllUserDataView,
    UpdateProfilePicture
)

app_name = 'userModule'

urlpatterns = [
    # User Profile APIs
    path('', GetSelfInfo.as_view(), name='get-self-info'),
    path('update/', UpdateSelfInfo.as_view(), name='update-self-info'),
    path('change-password/', UpdateSelfPassword.as_view(), name='update-self-password'),
    path('update-profile-picture/', UpdateProfilePicture.as_view(), name='update-profile-picture'),
    path('delete/', DeleteUserAccount.as_view(), name='delete-user-account'),
    
    # Subscription APIs
    path('subscriptions/', UserSubscriptionPreferencesView.as_view(), name='user-subscriptions'),
    path('subscriptions/unsubscribe-all/', UnsubscribeAllView.as_view(), name='unsubscribe-all'),
    
    # Social Media Connection APIs
    path('social-connections/', SocialConnectionsView.as_view(), name='social-connections'),
    path('social-connect/discord/', ConnectDiscordView.as_view(), name='connect-discord'),
    path('social-connect/google/', ConnectGoogleView.as_view(), name='connect-google'),
    path('social-disconnect/discord/', DisconnectDiscordView.as_view(), name='disconnect-discord'),
    path('social-disconnect/google/', DisconnectGoogleView.as_view(), name='disconnect-google'),
    
    # Legal/Data APIs
    path('delete-all-data/', DeleteAllUserDataView.as_view(), name='delete-all-data'),
    
    # Other existing endpoints
    path('get-user-info/', GetSpecificUsers.as_view(), name='get-specific-users'),
]