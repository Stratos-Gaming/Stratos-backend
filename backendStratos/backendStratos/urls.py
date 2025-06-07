"""
URL configuration for backendStratos project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.views.generic import TemplateView
from django.conf.urls.static import static
from django.conf import settings
from .mailServer import send_notification
from userAuth.views import GoogleLoginView, GoogleSignupView
from Mailing.views import SendEmailHelpRequest, SendEmailEvent
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import logging

logger = logging.getLogger('django')

@csrf_exempt
@require_http_methods(["GET", "POST", "OPTIONS"])
def debug_view(request):
    logger.debug(f"Request method: {request.method}")
    logger.debug(f"Request headers: {dict(request.headers)}")
    logger.debug(f"Request GET params: {request.GET}")
    logger.debug(f"Request POST data: {request.POST}")
    logger.debug(f"Request body: {request.body}")
    
    response = JsonResponse({
        'message': 'Debug endpoint working',
        'method': request.method,
        'headers': dict(request.headers),
        'get_params': dict(request.GET),
        'post_data': dict(request.POST),
    })
    
    # Add CORS headers manually for debugging
    response["Access-Control-Allow-Origin"] = "*"
    response["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRFToken"
    response["Access-Control-Allow-Credentials"] = "true"
    
    return response

urlpatterns = [
    path('admin/', admin.site.urls),
    path('debug/', debug_view, name='debug'),
    path('api-auth/', include('rest_framework.urls')),
    path('user/', include('userModule.urls')),
    path('auth/', include('userAuth.urls')),
    path('projects/', include('projectsModule.urls')),
    path('notification/create-email/', send_notification, name='create_email'),
    # Mailing endpoints
    path('api/mail/', SendEmailHelpRequest.as_view(), name='send_email_help_request'),
    path('api/mail/event/', SendEmailEvent.as_view(), name='send_email_event'),
    # Apis endpoints
    path('api/', include('Apis.urls')),
]
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

#urlpatterns += [re_path(r'^.*', TemplateView.as_view(template_name='index.html'))]