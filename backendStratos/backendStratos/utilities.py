from datetime import timedelta
from django.utils import timezone
from django.core.exceptions import ValidationError

def checkForPasswordRequirements(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    # Check for special characters
    special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    if not any(char in special_chars for char in password):
        return False
    return True

def validate_password_requirements(password):
    """
    Validates password requirements and returns detailed error messages
    Returns: (is_valid: bool, errors: list)
    """
    errors = []
    
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")
    
    if not any(char.isdigit() for char in password):
        errors.append("Password must contain at least one digit")
    
    if not any(char.isupper() for char in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(char.islower() for char in password):
        errors.append("Password must contain at least one lowercase letter")
    
    special_chars = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    if not any(char in special_chars for char in password):
        errors.append("Password must contain at least one special character")
    
    return len(errors) == 0, errors

def validate_future_date_one_month(value):
    if value and value < timezone.now().date() + timedelta(days=30):
        raise ValidationError("Expected release date must be at least one month in the future.")