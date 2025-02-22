from django.core.mail import send_mail
from django.http import HttpResponse

def send_notification(request):
    subject = "Notifica: Azione utente"
    message = "Un utente ha compiuto l'azione prevista. ASSURDO!"
    recipient_list = ['pigiped@gmail.com']  # l'indirizzo email dell'admin
    
    try:
        send_mail(subject, message, None, recipient_list, fail_silently=False)
        return HttpResponse("Notifica inviata correttamente.")
    except Exception as e:
        return HttpResponse(f"Si è verificato un errore: {e}", status=500)
