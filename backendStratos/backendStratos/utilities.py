def checkForPasswordRequirements(password):
    if len(password) < 8:
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    return True

def validate_future_date_one_month(value):
    if value and value < timezone.now().date() + timedelta(days=30):
        raise ValidationError("Expected release date must be at least one month in the future.")