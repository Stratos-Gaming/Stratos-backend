from django.db import models
from django.conf import settings
from django.contrib.auth.models import User

# Model for user: username, fisrtname, lastname, email, password, isSatff, isactive, issuperuser, lastlogin, datejoined, isautenthicated, isanonymous | relations: groups, user_permissions
class StratosUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    #projects = models.ManyToManyField(Project, related_name='users')
    phone = models.CharField(max_length=20)
    address = models.CharField(max_length=50)
    city = models.CharField(max_length=20)
    state = models.CharField(max_length=20)
    country = models.CharField(max_length=20)
    zip = models.CharField(max_length=10)

    def __str__(self):
        return self.username

