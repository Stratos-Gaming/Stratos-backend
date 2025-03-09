from django.core.mail import send_mail
from django.http import HttpResponse
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings
from userModule.models import StratosUser
from django.contrib.auth.models import User
def send_notification(request, request_type = "nothing_asked"):
    #repeat 100 times
    subject = "Stratos: il tuo investimento è andato a buon fine!"
    message = f"""The user has done something!! 
    {request_type}
     """
    recipient_list = ['info@stratosgaming.it']  # l'indirizzo email dell'admin
    
    try:
        send_mail(subject, message, None, recipient_list, fail_silently=False)
        return HttpResponse("Notifica inviata correttamente.")
    except Exception as e:
        return HttpResponse(f"Si è verificato un errore: {e}", status=500)
# utils.py


def send_verification_email(user, request):
    try:
        token = default_token_generator.make_token(user)
        uid = user.pk
        # Construct a URL for email verification
        verify_url = request.build_absolute_uri(
            reverse('verify-email', kwargs={'uid': uid, 'token': token})
        )
        
        subject = 'Verify your email'
        message = f'Please click the link to verify your email: {verify_url}'
        print(f"Verification link: {verify_url}, user: {user}, email: {user.email}")
        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
        return True
    except Exception as e:
        # Log the error (you might want to use logger instead of print in production)
        print(f"Failed to send verification email: {e}")
        return False

def send_contact_email(name, email, request):
    try:
        print(f"Sending contact email to {email}")
        subject = f'Stratos Team - You asked for contact'
        email_message = f'Ciao {name}, Hai chiesto di essere contattato dal team di stratos, rispondi a questa mail per farci sapere della tua richiesta.'
        send_mail(subject, email_message, settings.DEFAULT_FROM_EMAIL, [email])
        return True
    except Exception as e:
        print(f"Failed to send contact email: {e}")
        return False
