from django.urls import path
from .views import ProjectSubmissionCreateView

urlpatterns = [
    path('submit-project/', ProjectSubmissionCreateView.as_view(), name='submit-project'),
]
