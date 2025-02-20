from django.db import models

class ProjectSubmission(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    file = models.FileField(upload_to='uploads/')
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.email}"
