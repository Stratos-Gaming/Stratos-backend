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
    path('register/', SingupView.as_view(), name='signup'),  # POST /login/register/
    path('csrf_cookie', GetCSRFToken.as_view(), name='csrf'),  # GET /login/csrf_cookie
    path('verify-email/<int:uid>/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('resend-verification-email/', ResendVerificationEmailView.as_view(), name='resend-verification-email'),
    path('google/', GoogleLoginView.as_view(), name='google_login'),  # POST /auth/google/
    path('google/signup/', GoogleSignupView.as_view(), name='google_signup'),  # POST /auth/google/signup/
    path('discord/', DiscordLoginView.as_view(), name='discord_login'),  # POST /auth/discord/
    path('discord/signup/', DiscordSignupView.as_view(), name='discord_signup'),  # POST /auth/discord/signup/
    path('discord/link/', DiscordLinkView.as_view(), name='discord_link'),  # POST /auth/discord/link/
    path('discord/unlink/', DiscordUnlinkView.as_view(), name='discord_unlink'),  # POST /auth/discord/unlink/
    path('recover-password/', PasswordRecoveryRequestView.as_view(), name='password_recovery_request'),  # POST /auth/recover-password/
    path('reset-password/', PasswordResetView.as_view(), name='password_reset'),  # POST /auth/reset-password/
]