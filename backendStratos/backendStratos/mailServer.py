from django.core.mail import send_mail
from django.http import HttpResponse
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse
from django.conf import settings
from userModule.models import StratosUser
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import secrets
import string
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
        verify_url = f"https://development.stratosgaming.com/auth/verify-email/{uid}/{token}/"
        subject = 'Stratos - Verify your email'
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

def generate_reset_token():
    """Generate a secure random token for password reset"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(64))

def send_password_reset_email(user, reset_token, request):
    """Send password reset email to user"""
    try:
        # Determine frontend URL based on environment
        if settings.DEBUG:
            frontend_base_url = "http://localhost:5173"
        else:
            frontend_base_url = "https://development.stratosgaming.com"
        
        # Construct reset URL
        reset_url = f"{frontend_base_url}/recover-password/{user.pk}/{reset_token}"
        
        # Email content
        subject = 'Stratos - Reset Your Password'
        
        # Create HTML email content
        html_message = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                .content {{ background-color: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                .button {{ 
                    display: inline-block; 
                    background-color: #e74c3c; 
                    color: white; 
                    padding: 15px 30px; 
                    text-decoration: none; 
                    border-radius: 5px; 
                    margin: 20px 0;
                    font-weight: bold;
                }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }}
                .warning {{ background-color: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #ffc107; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🎮 STRATOS</h1>
                    <h2>Password Reset Request</h2>
                </div>
                <div class="content">
                    <p>Hello <strong>{user.username}</strong>,</p>
                    
                    <p>We received a request to reset the password for your Stratos account. If you made this request, please click the button below to reset your password:</p>
                    
                    <div style="text-align: center;">
                        <a href="{reset_url}" class="button">Reset My Password</a>
                    </div>
                    
                    <p>Alternatively, you can copy and paste this link into your browser:</p>
                    <p style="word-break: break-all; background-color: #f1f1f1; padding: 10px; border-radius: 5px;">
                        {reset_url}
                    </p>
                    
                    <div class="warning">
                        <strong>⚠️ Important Security Information:</strong>
                        <ul>
                            <li>This reset link will expire in <strong>1 hour</strong></li>
                            <li>If you didn't request this password reset, please ignore this email</li>
                            <li>Your password will remain unchanged until you create a new one</li>
                            <li>For security reasons, this link can only be used once</li>
                        </ul>
                    </div>
                    
                    <p>If you have any questions or need assistance, please contact our support team.</p>
                    
                    <p>Best regards,<br>The Stratos Gaming Team</p>
                </div>
                <div class="footer">
                    <p>This email was sent from an automated system. Please do not reply to this email.</p>
                    <p>© 2024 Stratos Gaming. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Create plain text version
        plain_message = f"""
        Hello {user.username},

        We received a request to reset the password for your Stratos account.

        To reset your password, please visit the following link:
        {reset_url}

        IMPORTANT SECURITY INFORMATION:
        - This reset link will expire in 1 hour
        - If you didn't request this password reset, please ignore this email
        - Your password will remain unchanged until you create a new one
        - For security reasons, this link can only be used once

        If you have any questions or need assistance, please contact our support team.

        Best regards,
        The Stratos Gaming Team
        
        ---
        This email was sent from an automated system. Please do not reply to this email.
        © 2024 Stratos Gaming. All rights reserved.
        """
        
        # Send email
        from django.core.mail import EmailMultiAlternatives
        
        msg = EmailMultiAlternatives(
            subject=subject,
            body=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        msg.attach_alternative(html_message, "text/html")
        msg.send()
        
        print(f"Password reset email sent to {user.email} for user {user.username}")
        return True
        
    except Exception as e:
        print(f"Failed to send password reset email: {e}")
        return False
