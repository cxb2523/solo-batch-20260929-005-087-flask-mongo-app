from datetime import datetime
import uuid

from verification import generate_confirmation_token, hash_token, token_expiry, TOKEN_TTL_SECONDS


# User class
class User():
    def __init__(self, title, first_name, last_name, email, id="", verified=False,
                 activation_token=None, token_expires_at=None, token_consumed=False):
        # Main initialiser
        self.title = title if title != "none" else ""
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.id = uuid.uuid4().hex if not id else id
        # Activation state: verified flag plus the single-use token bookkeeping
        self.verified = verified
        self.activation_token = activation_token
        self.token_expires_at = token_expires_at
        self.token_consumed = token_consumed

    @classmethod
    def make_from_dict(cls, d):
        # Initialise User object from a dictionary (tolerates legacy records)
        return cls(
            d.get('title', ''),
            d.get('first_name', ''),
            d.get('last_name', ''),
            d.get('email'),
            d.get('id', ''),
            d.get('verified', False),
            d.get('activation_token'),
            d.get('token_expires_at'),
            d.get('token_consumed', False)
        )

    def dict(self):
        # Return dictionary representation of the object
        return {
            "id": self.id,
            "title": self.title,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "verified": self.verified,
            "activation_token": self.activation_token,
            "token_expires_at": self.token_expires_at,
            "token_consumed": self.token_consumed
        }

    def issue_activation_token(self, ttl_seconds=TOKEN_TTL_SECONDS):
        """Generate a single-use, time-limited token and stage it.

        The raw token is returned for the confirmation email; only its hash
        and the expiry are kept on the record, so it is safe to persist with
        the new account in the same insert.
        """
        raw_token = generate_confirmation_token(self.email)
        self.activation_token = hash_token(raw_token)
        self.token_expires_at = token_expiry(ttl_seconds)
        self.token_consumed = False
        self.verified = False
        return raw_token

    def display_name(self):
        # Return concatenation of name components
        if self.title:
            return self.title + " " + self.first_name + " " + self.last_name
        else:
            return self.first_name + " " + self.last_name

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


# Anonymous user class
class Anonymous():

    @property
    def is_authenticated(self):
        return False

    @property
    def is_active(self):
        return False

    @property
    def is_anonymous(self):
        return True

    def get_id(self):
        return None
