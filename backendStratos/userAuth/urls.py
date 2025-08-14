from django.urls import path, include
from .views import (
    SingupView, GetCSRFToken, LoginView, LogoutView, CheckAuthenticatedView, 
    VerifyEmailView, GoogleLoginView, GoogleSignupView, DiscordLoginView, DiscordSignupView,
    DiscordLinkView, DiscordUnlinkView, ResendVerificationEmailView, PasswordRecoveryRequestView,
    PasswordResetView
)

urlpatterns = [
    path('', LoginView.as_view(), name='login'),  # POST /login/
    path('logout/', LogoutView.as_view(), name='logout'),
    path('authenticated/', CheckAuthenticatedView.as_view(), name='authenticated'),
]