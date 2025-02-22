from django.urls import path
from .views import ProjectSubmissionCreateView
from .mailServer import send_notification
urlpatterns = [
    path('submit-project/', ProjectSubmissionCreateView.as_view(), name='submit-project'),
    path('create-email/', send_notification, name='create_email'),

]
