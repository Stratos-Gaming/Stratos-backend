from django.urls import path
from .views import ProjectSubmissionCreateView
from backendStratos.mailServer import send_notification
from rest_framework import routers
from .views import ProjectViewSet
from django.urls import path, include


router = routers.DefaultRouter()
router.register('', ProjectViewSet)

urlpatterns = [
    path('submit-project/', ProjectSubmissionCreateView.as_view(), name='submit-project'),
    path('', include(router.urls)),
]

#GET /projects/
#Restituisce la lista di tutti gli oggetti.
#
#Create:
#POST /projects/
#Consente di creare un nuovo oggetto.
#
#Retrieve:
#GET /projects/<pk>/
#Restituisce i dettagli di un oggetto identificato da <pk>.
#
#Update:
#PUT /projects/<pk>/
#Aggiorna completamente un oggetto esistente.
#
#Partial Update:
#PATCH /projects/<pk>/
#Aggiorna parzialmente un oggetto esistente.
#
#Destroy:
#DELETE /projects/<pk>/
#Elimina un oggetto esistente.

