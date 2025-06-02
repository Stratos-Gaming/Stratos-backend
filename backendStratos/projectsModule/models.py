from django.db import models
from django.db.models import ForeignKey
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator
from django.core.exceptions import ValidationError
from datetime import timedelta
from django.utils import timezone
from backendStratos.utilities import validate_future_date_one_month
from backendStratos.mailServer import send_contact_email

# Example choices for distribution platforms
PLATFORM_CHOICES = [
    ('xbox_series', 'XBOX SERIES'),
    ('xbox_one', 'XBOX ONE'),
    ('ps5', 'PLAY STATION 5'),
    ('ps4', 'PLAY STATION 4'),
    ('switch', 'NINTENDO SWITCH'),
    ('meta_quest', 'META QUEST'),
]
SERVICE_CHOICES = [
    ('funding only', 'Funding Only'),
    ('funding + services', 'Funding + Services'),
    ('funding + services + hr', 'Funding + Services + HR'),
]
class UserContact(models.Model):
    email = models.EmailField(unique=True)  # Make email unique if that is your desired logic
    name = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)  # for 24h check if has not submitted a project
    def save(self, *args, **kwargs):
        is_new = self.pk is None  # Check if this is a new instance
        
        # First save the model
        super().save(*args, **kwargs)
        print(f"UserContact saved: {self.email}")
        # Then perform post-save operations for new instances

    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    def __str__(self):
        return self.email


class ProjectSubmission(models.Model):
    # Contact info
    name = models.CharField(max_length=255, help_text="Name of the person submitting")
    email = models.EmailField()

    # Main project details
    project_name = models.CharField(max_length=255, null=False, blank=False, help_text="Name of the project")
    expected_production_budget = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=0,
        null=False, 
        blank=True,
        validators=[MinValueValidator(0)],
        help_text="Production budget in EUR/USD"
    )
    required_funding_size = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        null=True, 
        blank=True,
        validators=[MinValueValidator(0)],
        help_text="Required funding in EUR/USD"
    )
    distribution_platforms = ArrayField(
        models.CharField(max_length=24, choices=PLATFORM_CHOICES),
        default=list,
        blank=True,
        help_text="Select one or more distribution platforms"
    )
    is_debut_title = models.BooleanField(
        default=False, 
        help_text="Is this your first (debut) video game title?"
    )
    expected_release_date = models.DateField(
        null=False, 
        blank=False,
        default=timezone.now,
        validators=[validate_future_date_one_month],
        help_text="When do you expect to release?"
    )
    i_am_looking_for = ArrayField(
        models.CharField(max_length=23, choices=SERVICE_CHOICES),
        default=list,
        blank=True,
        help_text="Describe what you are looking for (e.g., investment, publishing, distribution)"
    )
    plan_to_choose_publisher = models.BooleanField(
        default=False, 
        help_text="Do you plan on choosing a publisher?"
    )
    notes = models.TextField(
        null=True, 
        blank=True, 
        help_text="Any additional notes or details about your project"
    )
    trailer_link = models.URLField(
        null=True, 
        blank=True, 
        help_text="Link to a trailer or gameplay video"
    )
    demo_link = models.URLField(
        null=True, 
        blank=True, 
        help_text="Link to a playable demo"
    )

    # Pitch security
    pitch_password = models.CharField(
        max_length=128, 
        null=True, 
        blank=True,
        help_text="Optional password to protect your pitch"
    )

    # File upload
    file = models.FileField(upload_to='uploads/')
    
    #One to one relationship with userContact
    ForeignKey(UserContact, on_delete=models.CASCADE)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.project_name} by {self.name} ({self.email})"



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



