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
        
        # Determine frontend URL based on environment
        if settings.DEBUG:
            frontend_base_url = "http://localhost:5173"
        else:
            frontend_base_url = "https://development.stratosgaming.com"
        
        # Construct a URL for email verification
        verify_url = f"{frontend_base_url}/auth/verify-email/{uid}/{token}/"
        
        # Email subject
        subject = 'Stratos Gaming - Verify Your Email'
        
        # Render HTML email
        html_message = render_to_string('email/verification_email.html', {
            'username': user.username,
            'verify_url': verify_url,
        })
        
        # Create plain text version
        plain_message = strip_tags(html_message)
        
        # Send email with both HTML and plain text versions
        from django.core.mail import EmailMultiAlternatives
        
        msg = EmailMultiAlternatives(
            subject=subject,
            body=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        msg.attach_alternative(html_message, "text/html")
        msg.send()
        
        print(f"Verification email sent to {user.email} for user {user.username}")
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
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Stratos - Password Reset</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                /* FONT DECLARATION */
                @font-face {{
                    font-family: 'Mazzard Soft';
                    src: url('https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/mazzard-soft-h-medium.otf') format('opentype');
                    font-weight: 500;
                    font-style: normal;
                }}

                @font-face {{
                    font-family: 'Mazzard Soft';
                    src: url('https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/mazzard-soft-h-light.otf') format('opentype');
                    font-weight: 300;
                    font-style: normal;
                }}

                /* CLIENT-SPECIFIC STYLES */
                body, table, td, a {{
                    -webkit-text-size-adjust: 100%;
                    -ms-text-size-adjust: 100%;
                    font-family: 'Mazzard Soft', 'Helvetica Neue', Helvetica, Arial, sans-serif;
                    font-weight: 300;
                }}

                table, td {{
                    mso-table-lspace: 0pt;
                    mso-table-rspace: 0pt;
                }}

                img {{
                    -ms-interpolation-mode: bicubic;
                    border: 0;
                    height: auto;
                    line-height: 100%;
                    outline: none;
                    text-decoration: none;
                }}

                body {{
                    margin: 0;
                    padding: 0;
                    width: 100% !important;
                    background: #ffffff !important;
                    color: #333333;
                }}

                /* MOBILE STYLES */
                @media screen and (max-width:600px) {{
                    .container {{
                        width: 100% !important;
                    }}
                    .padding {{
                        padding: 20px !important;
                    }}
                    .button {{
                        padding: 20px 40px !important;
                        font-size: 24px !important;
                    }}
                }}

                .navbar-bg {{
                    background-color: #ffffff;
                }}
                @media screen and (max-width: 600px) {{
                    .navbar-bg {{
                        background-color: #1A1C2A;
                    }}
                }}
            </style>
        </head>
        <body style="background:#ffffff !important; margin:0; padding:0; font-family:'Mazzard Soft', 'Helvetica Neue', Helvetica, Arial, sans-serif; font-weight: 300;">
            <!-- CENTERING TABLE -->
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                    <td align="center">
                        <!-- MAIN CONTAINER -->
                        <table border="0" cellpadding="0" cellspacing="0" class="container" style="max-width:800px; min-width: 400px;">
                            
                            <!-- HEADER -->
                            <tr>
                                <td class="navbar-bg" style="padding:20px;">
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tr>
                                            <td align="left" valign="middle">
                                                <a href="https://stratosgaming.com" target="_blank" style="text-decoration:none;">
                                                    <img src="https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/logo.png" alt="Stratos Logo" width="240" style="display:block; border:0;" />
                                                </a>
                                            </td>
                                            <td align="right" valign="middle" style="font-family:'Mazzard Soft', 'Helvetica Neue', Helvetica, Arial, sans-serif; color:#333333; font-size:32px; font-weight:500;">
                                                Password Reset
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>

                            <!-- MAIN CONTENT -->
                            <tr>
                                <td bgcolor="#ffffff" class="padding" style="padding:60px 40px; font-family:'Mazzard Soft', 'Helvetica Neue', Helvetica, Arial, sans-serif; color:#333333; text-align: center;">
                                    
                                    <p style="font-size:28px; font-weight:300; margin:20px 0; text-align:center;">
                                        Hello <strong style="color:#1B74E4;">{user.username}</strong>,
                                    </p>
                                    
                                    <p style="font-size:24px; font-weight:300; line-height:1.5; margin:30px 0; text-align:center;">
                                        We received a request to reset the password for your Stratos account. If you made this request, please click the button below to reset your password:
                                    </p>
                                    
                                    <!-- CTA BUTTON -->
                                    <div style="text-align: center; margin:40px 0;">
                                        <a href="{reset_url}" class="button" style="
                                            display: inline-block;
                                            background: linear-gradient(90deg, #D20B76 0%, #A20075 100%);
                                            color: #ffffff;
                                            text-decoration: none;
                                            font-family: 'Mazzard Soft', 'Helvetica Neue', Helvetica, Arial, sans-serif;
                                            font-size: 28px;
                                            font-weight: 500;
                                            text-transform: uppercase;
                                            padding: 24px 64px;
                                            border-radius: 999px;
                                            letter-spacing: 2px;
                                            box-shadow: 0 2px 8px rgba(162,0,117,0.08);
                                        ">
                                            RESET MY PASSWORD
                                        </a>
                                    </div>
                                    
                                    <p style="font-size:20px; font-weight:300; margin:30px 0 10px 0; text-align:center; color:#666;">
                                        Alternatively, you can copy and paste this link into your browser:
                                    </p>
                                    <p style="word-break: break-all; background-color: #f8f9fa; padding: 15px; border-radius: 8px; font-size:16px; margin:10px 0 30px 0; border-left: 4px solid #1B74E4;">
                                        {reset_url}
                                    </p>
                                    
                                    <!-- WARNING SECTION -->
                                    <div style="background-color: #fff3cd; padding: 25px; border-radius: 8px; margin: 40px 0; border-left: 4px solid #ffc107; text-align:left;">
                                        <p style="color:#856404; font-size:24px; font-weight:500; margin:0 0 15px 0;">
                                            ⚠️ Important Security Information:
                                        </p>
                                        <ul style="color:#856404; font-size:20px; font-weight:300; margin:0; padding-left:20px;">
                                            <li style="margin-bottom:8px;">This reset link will expire in <strong>1 hour</strong></li>
                                            <li style="margin-bottom:8px;">If you didn't request this password reset, please ignore this email</li>
                                            <li style="margin-bottom:8px;">Your password will remain unchanged until you create a new one</li>
                                            <li>For security reasons, this link can only be used once</li>
                                        </ul>
                                    </div>
                                    
                                    <p style="font-size:22px; font-weight:300; margin:40px 0 20px 0; text-align:center;">
                                        If you have any questions or need assistance, please contact our support team.
                                    </p>
                                    
                                    <p style="font-size:24px; font-weight:300; margin:30px 0 0 0; text-align:center;">
                                        Best regards,<br>
                                        <strong style="color:#1B74E4;">The Stratos Gaming Team</strong>
                                    </p>
                                </td>
                            </tr>

                            <!-- FOOTER -->
                            <tr>
                                <td bgcolor="#1A1C2A" class="padding" style="padding:40px 40px 40px 40px; font-family:'Mazzard Soft', 'Helvetica Neue', Helvetica, Arial, sans-serif; color:#aaaaaa; font-size:18px; text-align:center;">
                                    
                                    <!-- Social links -->
                                    <table align="center" border="0" cellpadding="0" cellspacing="0" style="margin:0 auto 30px auto;">
                                        <tr>
                                            <td style="padding:0 16px;">
                                                <a href="https://discord.gg/stratos" target="_blank" style="text-decoration:none;">
                                                    <img src="https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/Social_Discord.png" width="32" alt="Discord" style="display:inline-block;" />
                                                </a>
                                            </td>
                                            <td style="padding:0 16px;">
                                                <a href="https://instagram.com/stratos_official" target="_blank" style="text-decoration:none;">
                                                    <img src="https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/Social_Insta.png" width="32" alt="Instagram" style="display:inline-block;" />
                                                </a>
                                            </td>
                                            <td style="padding:0 16px;">
                                                <a href="https://linkedin.com/company/stratos-gaming" target="_blank" style="text-decoration:none;">
                                                    <img src="https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/Social_LinkedIn.png" width="32" alt="LinkedIn" style="display:inline-block;" />
                                                </a>
                                            </td>
                                            <td style="padding:0 16px;">
                                                <a href="https://reddit.com/r/stratos_gaming" target="_blank" style="text-decoration:none;">
                                                    <img src="https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/Social_reddit.png" width="32" alt="Reddit" style="display:inline-block;" />
                                                </a>
                                            </td>
                                        </tr>
                                    </table>
                                    
                                    <!-- Bottom row -->
                                    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%">
                                        <tr>
                                            <td align="left" style="color:#fff; font-size:20px; font-family:'Mazzard Soft', Arial, sans-serif;">
                                                <a href="https://www.iubenda.com/privacy-policy/37001222" style="color:#fff; text-decoration:none;">Privacy Policy</a>
                                            </td>
                                            <td align="center">
                                                <img src="https://stratos-email-assets.s3.eu-central-1.amazonaws.com/event-mail-assets/Logo_Small_White.png" width="48" alt="Stratos Logo" style="display:inline-block; vertical-align:middle;" />
                                            </td>
                                            <td align="right" style="color:#fff; font-size:20px; font-family:'Mazzard Soft', Arial, sans-serif;">
                                                Copyright © 2025 Stratos
                                            </td>
                                        </tr>
                                    </table>
                                    
                                    <p style="margin:30px 0 0 0; color:#888; font-size:16px; text-align:center;">
                                        This email was sent from an automated system. Please do not reply to this email.
                                    </p>
                                </td>
                            </tr>
                        </table>
                        <!-- END MAIN CONTAINER -->
                    </td>
                </tr>
            </table>
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
