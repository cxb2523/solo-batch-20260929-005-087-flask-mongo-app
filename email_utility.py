"""Outgoing email helpers.

The confirmation link base address comes from configuration.ini
(CONFIRM_BASE_URL in [DEFAULT]); only when it is missing do we fall back to
the incoming request Host. Reading the configured address first prevents a
spoofed Host header behind a reverse proxy from poisoning the link.
"""
from flask import url_for, render_template, request, has_request_context
import smtplib
import ssl
import configparser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'configuration.ini')


def _configured_base_url():
    """CONFIRM_BASE_URL from configuration.ini, or None when unset."""
    parser = configparser.ConfigParser()
    parser.read(_CONFIG_PATH)
    base = (parser['DEFAULT'].get('CONFIRM_BASE_URL', fallback='') or '').strip()
    if not base or base.lower().startswith('<'):
        return None
    return base.rstrip('/')


def confirmation_url(token):
    """Build the external confirmation link.

    Prefer the pinned BASE_URL from configuration.ini so a spoofed Host header
    behind a reverse proxy cannot poison the link; fall back to the request
    Host only when the configuration does not provide one.
    """
    base = _configured_base_url()
    if base:
        return base + url_for('confirm_email', token=token)
    if has_request_context():
        return request.host_url.rstrip('/') + url_for('confirm_email',
                                                      token=token)
    # No configured base and no request context - relative link as last resort
    return url_for('confirm_email', token=token)


# Common email sending function
def send_email(receiver_email, subject, plaintext, html):
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    PORT = os.environ.get('EMAIL_PORT')
    SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
    PASSWORD = os.environ.get('EMAIL_PASSWORD')

    # SMTP not configured (e.g. local/dev): never raise into the caller
    if not SMTP_SERVER or not SENDER_EMAIL or not PORT:
        print("[email] SMTP not configured; skipping email to", receiver_email)
        return False

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = SENDER_EMAIL
    message["To"] = receiver_email

    message.attach(MIMEText(plaintext, "plain"))
    message.attach(MIMEText(html, "html"))

    context = ssl.create_default_context()
    server = None
    try:
        server = smtplib.SMTP(SMTP_SERVER, int(PORT))
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        server.login(SENDER_EMAIL, PASSWORD)
        server.send_message(message)
    except Exception as exc:
        print(exc)
        return False
    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass
    return True


# Convenience function - registration / verification email
def send_registration_email(user, token=None):
    if token is None:
        # Resend path: mint a fresh single-use token via the User model
        token = user.issue_activation_token()
    confirm_url = confirmation_url(token)
    subject = "Registration successful - Please verify your email address."
    plaintext = (f"Welcome {user.display_name()}.\n"
                 f"Please verify your email address by following this link:\n\n"
                 f"{confirm_url}")
    html = render_template('verification_email.html',
                           confirm_url=confirm_url, user=user)
    send_email(user.email, subject, plaintext, html)
    return token


# Convenience function - message received notification
def send_message_email(from_user, to_user, message):
    subject = f"{from_user.display_name()} sent you a message"
    plaintext = f"{to_user.display_name()} sent you this message:\n\n{message.title}\n\n{message.body}"
    html = render_template(
        'message_email.html', from_user=from_user, to_user=to_user, message=message)
    send_email(to_user.email, subject, plaintext, html)
