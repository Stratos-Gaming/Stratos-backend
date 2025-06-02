from django.urls import path, include
from .views import (
    SingupView, GetCSRFToken, LoginView, LogoutView, CheckAuthenticatedView, 
    VerifyEmailView, GoogleLoginView, GoogleSignupView
)

urlpatterns = [
    path('', LoginView.as_view(), name='login'),  # POST /login/
    path('logout/', LogoutView.as_view(), name='logout'),
    path('authenticated/', CheckAuthenticatedView.as_view(), name='authenticated'),
    path('register/', SingupView.as_view(), name='signup'),  # POST /login/register/
    path('csrf_cookie', GetCSRFToken.as_view(), name='csrf'),  # GET /login/csrf_cookie
    path('verify-email/<int:uid>/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('google/', GoogleLoginView.as_view(), name='google_login'),  # POST /auth/google/
    path('google/signup/', GoogleSignupView.as_view(), name='google_signup'),  # POST /auth/google/signup/
]