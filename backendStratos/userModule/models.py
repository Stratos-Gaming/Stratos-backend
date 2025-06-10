from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class UserType(models.Model):
    """Model to store user types"""
    USER_TYPE_CHOICES = [
        ('investor', 'Investor'),
        ('developer', 'Developer'),
        ('gamer', 'Gamer'),
    ]
    
    type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.get_type_display()

# Model for user: username, fisrtname, lastname, email, password, isStaff, isactive, issuperuser, lastlogin, datejoined, isautenthicated, isanonymous | relations: groups, user_permissions
class StratosUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='stratos_user')
    #projects = models.ManyToManyField(Project, related_name='users')
    phone = models.CharField(max_length=20)
    address = models.CharField(max_length=50)
    city = models.CharField(max_length=20)
    state = models.CharField(max_length=20)
    country = models.CharField(max_length=20)
    zip = models.CharField(max_length=10)
    
    # User types - many-to-many relationship
    user_types = models.ManyToManyField(UserType, related_name='users', blank=True)
    
    # OAuth integrations
    google_id = models.CharField(max_length=200, null=True, blank=True)
    discord_id = models.CharField(max_length=200, null=True, blank=True)
    discord_username = models.CharField(max_length=200, null=True, blank=True, help_text="Discord username")
    discord_global_name = models.CharField(max_length=200, null=True, blank=True, help_text="Discord display name")
    discord_avatar = models.CharField(max_length=200, null=True, blank=True, help_text="Discord avatar hash")
    discord_discriminator = models.CharField(max_length=10, null=True, blank=True, help_text="Discord discriminator (legacy)")

    #Verification
    isEmailVerified = models.BooleanField(default=False)
    
    def verifyEmail(self):
        self.isEmailVerified = True
        #Add permissions related to email verification
        self.save()
    
    def get_discord_avatar_url(self):
        """Get full Discord avatar URL"""
        if self.discord_avatar and self.discord_id:
            return f"https://cdn.discordapp.com/avatars/{self.discord_id}/{self.discord_avatar}.png"
        return None
    
    def get_display_name(self):
        """Get preferred display name"""
        if self.discord_global_name:
            return self.discord_global_name
        elif self.discord_username:
            return self.discord_username
        return self.user.username
    
    def get_user_types(self):
        """Get list of user types as strings"""
        return [ut.type for ut in self.user_types.all()]
    
    def __str__(self):
        return self.user.username  # Access username through the related User model


class UserSubscriptionPreferences(models.Model):
    """Model to store user subscription preferences"""
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription_preferences')
    newsletter = models.BooleanField(default=True)
    indie_projects_updates = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username} - Subscription Preferences"


class UserSocialConnection(models.Model):
    """Model to track social media connections"""
    SOCIAL_PLATFORMS = [
        ('discord', 'Discord'),
        ('google', 'Google'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='social_connections')
    platform = models.CharField(max_length=20, choices=SOCIAL_PLATFORMS)
    connected = models.BooleanField(default=True)
    username = models.CharField(max_length=200, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    platform_user_id = models.CharField(max_length=200, null=True, blank=True)
    access_token = models.TextField(null=True, blank=True)  # Should be encrypted in production
    refresh_token = models.TextField(null=True, blank=True)  # Should be encrypted in production
    connected_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('user', 'platform')
    
    def __str__(self):
        return f"{self.user.username} - {self.platform}"


class PasswordResetToken(models.Model):
    """Model to store password reset tokens"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'password_reset_tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_used']),
        ]
    
    def save(self, *args, **kwargs):
        # Set expiration time to 1 hour from creation if not set
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=4)
        super().save(*args, **kwargs)
    
    def is_expired(self):
        """Check if the token has expired"""
        return timezone.now() > self.expires_at
    
    def __str__(self):
        return f"Reset token for {self.user.username} - {self.token[:10]}..."
