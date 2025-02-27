from django.db import models

class ProjectSubmission(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    file = models.FileField(upload_to='uploads/', )
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.email}"

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
