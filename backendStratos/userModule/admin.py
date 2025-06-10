from django.contrib import admin
from .models import StratosUser, UserType, UserSubscriptionPreferences, UserSocialConnection, PasswordResetToken

admin.site.register(StratosUser)
admin.site.register(UserType)
admin.site.register(UserSubscriptionPreferences)
admin.site.register(UserSocialConnection)

@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token_preview', 'created_at', 'expires_at', 'is_used', 'is_expired_now')
    list_filter = ('is_used', 'created_at', 'expires_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('token', 'created_at')
    ordering = ('-created_at',)
    
    def token_preview(self, obj):
        return f"{obj.token[:10]}..." if obj.token else ""
    token_preview.short_description = "Token Preview"
    
    def is_expired_now(self, obj):
        return obj.is_expired()
    is_expired_now.boolean = True
    is_expired_now.short_description = "Is Expired"
    
    actions = ['mark_as_used', 'mark_as_unused']
    
    def mark_as_used(self, request, queryset):
        updated = queryset.update(is_used=True)
        self.message_user(request, f'{updated} tokens marked as used.')
    mark_as_used.short_description = "Mark selected tokens as used"
    
    def mark_as_unused(self, request, queryset):
        updated = queryset.update(is_used=False)
        self.message_user(request, f'{updated} tokens marked as unused.')
    mark_as_unused.short_description = "Mark selected tokens as unused"