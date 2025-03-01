from django.urls import path, include
from .views import SingupView, GetCSRFToken, LoginView, LogoutView, CheckAuthenticatedView, VerifyEmailView

urlpatterns = [
    path('', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('authenticated/', CheckAuthenticatedView.as_view(), name='authenticated'),
    path('register/', SingupView.as_view(), name='signup'),
    path('csrf_cookie/', GetCSRFToken.as_view(), name='csrf'),
    path('verify-email/<int:uid>/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),

]