"""Registration activation state machine.

All verdicts for the /confirm/<token> link are decided here. The web layer only
assembles parameters and renders whatever this module returns; every path
returns a well-defined state, so the request can never fall through to a 500.

States
------
ACTIVATED          first successful confirmation: verified flag set and the
                   token invalidated together in one find_one_and_update
ALREADY_ACTIVATED  idempotent branch - the account was already verified;
                   nothing is written
TOKEN_USED         the token signature is still valid, but this exact token has
                   already been consumed (or superseded by a newer one)
TOKEN_EXPIRED      the token signature is valid but past its TTL
TOKEN_INVALID      malformed / forged token, or no account matches it
DB_ERROR           storage failure - still a rendered message, never a 500
"""
from datetime import datetime, timezone

from verification import (
    inspect_token,
    hash_token,
    token_expiry,
    TOKEN_VALID,
    TOKEN_EXPIRED,
    TOKEN_INVALID,
)

# Activation state constants
ACTIVATED = "activated"
ALREADY_ACTIVATED = "already_activated"
TOKEN_USED = "token_used"
TOKEN_EXPIRED_STATE = "token_expired"
TOKEN_INVALID_STATE = "token_invalid"
DB_ERROR = "db_error"

# Rendering copy keyed by state - the confirm page only renders this text
STATE_MESSAGES = {
    ACTIVATED: {
        "ok": True,
        "heading": "Thank you!",
        "title": "Email address verified successfully",
        "detail": "Your account is now active.",
    },
    ALREADY_ACTIVATED: {
        "ok": True,
        "heading": "Already activated",
        "title": "Your email address was already verified",
        "detail": "This link has already been used to activate your account; "
                  "no changes were made.",
    },
    TOKEN_USED: {
        "ok": False,
        "heading": "Link already used",
        "title": "This confirmation link has already been used",
        "detail": "Each confirmation link can only be used once and was "
                  "consumed by an earlier request.",
    },
    TOKEN_EXPIRED_STATE: {
        "ok": False,
        "heading": "Link expired",
        "title": "Your confirmation link has expired",
        "detail": "The link was valid for one hour. Please request a new "
                  "verification email.",
    },
    TOKEN_INVALID_STATE: {
        "ok": False,
        "heading": "Invalid link",
        "title": "Your email address could not be verified",
        "detail": "The verification link is invalid or unknown.",
    },
    DB_ERROR: {
        "ok": False,
        "heading": "Temporary problem",
        "title": "Verification could not be completed",
        "detail": "A temporary error occurred. Please try the link again.",
    },
}


def _aware_utc(value):
    """Normalise a stored timestamp to an aware UTC datetime (PyMongo safe)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None


def issue_activation(users, email, token, ttl_seconds=None):
    """Persist a freshly issued token for an existing account.

    Used at registration and on resend. Issuing a new token supersedes any
    outstanding one and resets the consumed flag. Returns True on success.
    """
    try:
        expiry = token_expiry(ttl_seconds=ttl_seconds) if ttl_seconds else token_expiry()
        result = users.update_one(
            {"email": email},
            {"$set": {
                "verified": False,
                "activation_token": hash_token(token),
                "token_expires_at": expiry,
                "token_consumed": False,
            }},
        )
        return bool(result and result.matched_count)
    except Exception:
        return False


def _refetch(users, email):
    try:
        return users.find_one({"email": email})
    except Exception:
        return None


def transition(users, raw_token):
    """Run one confirmation submission through the activation state machine.

    `users` is the PyMongo users collection; `raw_token` is the link token.
    Returns one of the state constants above. The only state transition that
    performs a write is ACTIVATED, and in that single find_one_and_update the
    verified flag is set and the token is invalidated atomically, so concurrent
    submissions of the same token produce exactly one success.
    """
    try:
        verdict, email = inspect_token(raw_token)

        # Malformed / unsigned token - no account lookup is meaningful
        if verdict == TOKEN_INVALID or not email:
            return TOKEN_INVALID_STATE

        try:
            record = users.find_one({"email": email})
        except Exception:
            return DB_ERROR

        # Unknown account - treat as invalid rather than crashing
        if record is None:
            return TOKEN_INVALID_STATE

        # Idempotent first: an already verified account never gets written again
        if record.get("verified"):
            return ALREADY_ACTIVATED

        stored_hash = record.get("activation_token")
        consumed = bool(record.get("token_consumed"))
        submitted_hash = hash_token(raw_token)
        matches_current = bool(stored_hash) and stored_hash == submitted_hash

        # Expiry beats consumption: the same old token re-submitted after its
        # TTL is reported as "expired", not merely "used"
        if verdict == TOKEN_EXPIRED:
            return TOKEN_EXPIRED_STATE

        # Within TTL: if this exact token was already spent, or it does not
        # match the outstanding token (superseded), the one-time use is gone
        if consumed or not matches_current:
            return TOKEN_USED

        # Atomic activation: flip the flag and invalidate the token together.
        # The filter re-checks every precondition so racing requests cannot
        # both succeed; only one find_one_and_update returns the old document.
        now = datetime.now(timezone.utc)
        try:
            updated = users.find_one_and_update(
                {
                    "email": email,
                    "verified": False,
                    "token_consumed": False,
                    "activation_token": submitted_hash,
                    "$or": [
                        {"token_expires_at": None},
                        {"token_expires_at": {"$exists": False}},
                        {"token_expires_at": {"$gt": now}},
                    ],
                },
                {
                    "$set": {
                        "verified": True,
                        "token_consumed": True,
                        "activated_at": now,
                    },
                    "$unset": {"activation_token": "", "token_expires_at": ""},
                },
            )
        except Exception:
            return DB_ERROR

        if updated is not None:
            return ACTIVATED

        # Lost the race (or expired between read and write). Re-read once and
        # report the now-current state without performing any further write.
        current = _refetch(users, email)
        if current is None:
            return TOKEN_INVALID_STATE
        if current.get("verified"):
            return ALREADY_ACTIVATED
        expires = _aware_utc(current.get("token_expires_at"))
        if expires is not None and expires <= now:
            return TOKEN_EXPIRED_STATE
        return TOKEN_USED

    except Exception:
        # Absolute safety net - every path renders a message, never a 500
        return DB_ERROR


def render_context(state):
    """Map a state constant to the copy rendered by the confirmation page."""
    return STATE_MESSAGES.get(state, STATE_MESSAGES[TOKEN_INVALID_STATE])
