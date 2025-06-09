from django.contrib import admin
from .models import StratosUser, UserType, UserSubscriptionPreferences, UserSocialConnection

admin.site.register(StratosUser)
admin.site.register(UserType)
admin.site.register(UserSubscriptionPreferences)
admin.site.register(UserSocialConnection)