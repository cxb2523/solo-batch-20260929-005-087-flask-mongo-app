"""Confirmation token generation and adjudication.

This module owns nothing but the token itself: signing, TTL checks and the
stored-token hash. Account-level verdicts live in ``activation_state``.
"""
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
import configparser
import hashlib
import os

from itsdangerous import (
    URLSafeTimedSerializer,
    BadSignature,
    BadData,
    SignatureExpired,
)

# Default link lifetime
TOKEN_TTL_SECONDS = 3600

# Token verdicts returned by inspect_token
TOKEN_VALID = "valid"
TOKEN_EXPIRED = "expired"
TOKEN_INVALID = "invalid"


def _load_config():
    config = configparser.ConfigParser()
    config.read(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'configuration.ini'))
    default = config['DEFAULT']
    secret_key = os.environ.get('SECRET_KEY', default.get('SECRET_KEY', ''))
    salt = os.environ.get(
        'SECURITY_PASSWORD_SALT', default.get('SECURITY_PASSWORD_SALT', ''))
    return secret_key, salt


SECRET_KEY, SECURITY_PASSWORD_SALT = _load_config()


def _serializer():
    return URLSafeTimedSerializer(SECRET_KEY)


def generate_confirmation_token(email):
    """Sign a fresh single-use confirmation token for an email address."""
    return _serializer().dumps(email, salt=SECURITY_PASSWORD_SALT)


def inspect_token(token, max_age=TOKEN_TTL_SECONDS):
    """Adjudicate a raw token.

    Returns a ``(verdict, email)`` tuple. ``verdict`` is one of
    ``TOKEN_VALID``, ``TOKEN_EXPIRED`` or ``TOKEN_INVALID``; for an expired
    token the embedded email is still returned so account state can be
    inspected, while a forged/malformed token yields ``(TOKEN_INVALID, None)``.
    """
    if not token or not isinstance(token, str):
        return TOKEN_INVALID, None
    serializer = _serializer()
    try:
        email = serializer.loads(token, salt=SECURITY_PASSWORD_SALT,
                                 max_age=max_age)
        return TOKEN_VALID, email
    except SignatureExpired:
        try:
            _valid, email = serializer.loads_unsafe(
                token, salt=SECURITY_PASSWORD_SALT)
            if isinstance(email, str) and email:
                return TOKEN_EXPIRED, email
        except BadData:
            pass
        return TOKEN_EXPIRED, None
    except (BadSignature, BadData):
        return TOKEN_INVALID, None


def confirm_token(token, expiration=TOKEN_TTL_SECONDS):
    """Backward-compatible helper: email on success, False otherwise."""
    verdict, email = inspect_token(token, max_age=expiration)
    return email if verdict == TOKEN_VALID else False


def hash_token(token):
    """Deterministic hash stored instead of the raw single-use token."""
    if not token:
        return None
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def token_expiry(ttl_seconds=TOKEN_TTL_SECONDS):
    """Aware-UTC expiry timestamp for a freshly issued token."""
    return datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)


def configured_base_url():
    """Base URL for confirmation links read from configuration.ini.

    Returns an http(s) origin without a trailing slash, or None when the
    setting is missing/blank/placeholder so callers can fall back to the
    request Host. A forwarded Host is never trusted when the ini value is set.
    """
    config = configparser.ConfigParser()
    config.read(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'configuration.ini'))
    value = config['DEFAULT'].get('CONFIRM_BASE_URL', '').strip()
    if not value or value.startswith('<'):
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return None
    return value.rstrip('/')
