from django.core.mail import send_mail
from django.http import HttpResponse
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings

def send_notification(request):
    #repeat 100 times
    subject = "Stratos: il tuo investimento è andato a buon fine!"
    message = """
    C'era una volta in una piccola città italiana, due amici di nome Giorgio e Pierluigi. 
    Giorgio era un ingegnere informatico sempre pieno di idee innovative, mentre Pierluigi 
    era un designer con un occhio attento ai dettagli. Un giorno decisero di collaborare 
    su un progetto che avrebbe rivoluzionato il modo in cui le persone interagivano con la 
    tecnologia. Passarono mesi a lavorare insieme, affrontando sfide e superando ostacoli. 
    La loro determinazione li portò infine al successo, dimostrando che la combinazione di 
    competenze diverse può portare a risultati straordinari.

    Da Stratosgaming, investi in stratos
    """
    recipient_list = ['pigi.ped@hotmail.it']  # l'indirizzo email dell'admin
    
    try:
        for i in range(5):
            send_mail(subject, message, None, recipient_list, fail_silently=False)
            print(f"Email {i+1} sent.")
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