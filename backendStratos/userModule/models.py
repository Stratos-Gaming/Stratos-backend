from django.db import models
from django.conf import settings
from django.contrib.auth.models import User

# Model for project= id, name, description, body, author, creationDate, startingDate, endingDate, maxFunds, minFunds, funds, productionTime, developers, status, members, 
class Project(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=1000)
    body = models.TextField(max_length=10000)
    author = models.CharField(max_length=100)
    creationDate = models.DateField()
    startingDate = models.DateField()
    endingDate = models.DateField()
    maxFunds = models.DecimalField(max_digits=10, decimal_places=2)
    minFunds = models.DecimalField(max_digits=10, decimal_places=2)
    funds = models.DecimalField(max_digits=10, decimal_places=2)
    productionTime = models.IntegerField()
    developers = models.CharField(max_length=1000)
    status = models.IntegerField()
    def __str__(self):
        return self.name


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