from rest_framework import routers
from userModule.views import ProjectViewSet
from django.urls import path, include

router = routers.DefaultRouter()
router.register('projects', ProjectViewSet)


urlpatterns = [
    path('', include(router.urls)),
]