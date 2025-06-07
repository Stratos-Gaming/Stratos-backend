from django.urls import path
from . import views

urlpatterns = [
    path('instagram-posts/', views.get_instagram_posts, name='instagram-posts'),
    path('instagram-webhook/', views.instagram_webhook, name='instagram-webhook'),
] 