from django.db import models
from django.conf import settings
from django.contrib.auth.models import User

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

    google_id = models.CharField(max_length=200, null=True, blank=True)

    #Verification
    isEmailVerified = models.BooleanField(default=False)
    def verifyEmail(self):
        self.isEmailVerified = True
        #Add permissions related to email verification

        self.save()
    def __str__(self):
        return self.user.username  # Access username through the related User model
