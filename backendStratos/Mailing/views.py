from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

class SendEmailEvent(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        #send the email html
        # Render HTML content
        html_content = render_to_string('email/event_mail.html')
        
        # Create plain text version
        text_content = strip_tags(html_content)
        
        from_email = 'info@stratosgaming.it'
        recipient_list = [email]
        
        try:
            # Create the email message
            email_message = EmailMultiAlternatives(
                'Stratos Investors Meetup',
                text_content,
                from_email,
                recipient_list
            )
            
            # Attach the HTML version
            email_message.attach_alternative(html_content, "text/html")
            
            # Send the email
            mail_sent = email_message.send()
            
            return Response({
                'success': True,
                'message': 'Notifica inviata correttamente',
                'mail_sent': mail_sent
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SendEmailHelpRequest(APIView):
    authentication_classes = []  # If you don't need authentication
    permission_classes = []      # Or define your own permissions

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        user_name = request.data.get('name', 'utente')  # Default to 'utente' if no name provided
        
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        subject = "Stratos: Richiesta di chiarimento"
        
        # Context for the template
        context = {
            'user_name': user_name,
            'documentation_link': '[LINK_DOCUMENTAZIONE]',
            'faq_link': '[LINK_FAQ]',
            'social_link': '[LINK_SOCIAL]'
        }
        
        # Render HTML content
        html_content = render_to_string('email/help_request.html', context)
        
        # Create plain text version
        text_content = strip_tags(html_content)
        
        from_email = 'info@stratosgaming.it'
        recipient_list = [email]
        
        try:
            # Create the email message
            email_message = EmailMultiAlternatives(
                subject,
                text_content,
                from_email,
                recipient_list
            )
            
            # Attach the HTML version
            email_message.attach_alternative(html_content, "text/html")
            
            # Send the email
            mail_sent = email_message.send()
            
            return Response({
                'success': True,
                'message': 'Notifica inviata correttamente',
                'mail_sent': mail_sent
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
