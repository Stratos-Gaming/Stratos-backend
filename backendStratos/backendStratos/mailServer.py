from django.core.mail import send_mail
from django.http import HttpResponse
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings

def send_notification(request):
    subject = "Notifica: Azione utente"
    message = "Un utente ha compiuto l'azione prevista. ASSURDO!"
    recipient_list = ['j.piccinelli@stratosgaming.it']  # l'indirizzo email dell'admin
    
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