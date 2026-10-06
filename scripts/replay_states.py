"""Replay the registration-activation states end to end.

Drives the real ``/confirm/<token>``) Flask route with an in-memory users
collection (same ``find_one`` / ``find_one_and_update`` semantics the state
machine relies on), so no live MongoDB is required.

Replayed in order:

1. fresh unverified account      -> activated, resubmission -> already
                                    activated (idempotent, zero extra writes)
2. expired token                 -> token_expired, no writes
3. superseded / consumed token   -> token_used, no writes
4. concurrent confirmations      -> exactly one activation, every other
                                    submission lands on the idempotent branch

A forged-link and a Host-spoof check are included as guards.
"""
import os
import re
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from itsdangerous import URLSafeTimedSerializer  # noqa: E402

import activation_state  # noqa: E402
import run  # noqa: E402
from email_utility import confirmation_url  # noqa: E402
from verification import (  # noqa: E402
    SECRET_KEY,
    SECURITY_PASSWORD_SALT,
    TOKEN_TTL_SECONDS,
    generate_confirmation_token,
    hash_token,
    token_expiry,
)

MISSING = object()
CONCURRENCY = 8


class UpdateResult:
    def __init__(self, matched_count):
        self.matched_count = matched_count


class MemoryUsers:
    """Minimal thread-safe PyMongo-compatible users collection."""

    def __init__(self):
        self._docs = []
        self._lock = threading.RLock()
        self.write_count = 0

    def insert_one(self, doc):
        with self._lock:
            self._docs.append(dict(doc))
            self.write_count += 1
        return UpdateResult(1)

    def update_one(self, query, update):
        with self._lock:
            for doc in self._docs:
                if _matches(doc, query):
                    _apply_update(doc, update)
                    self.write_count += 1
                    return UpdateResult(1)
            return UpdateResult(0)

    def find_one(self, query=None):
        with self._lock:
            for doc in self._docs:
                if query is None or _matches(doc, query):
                    return dict(doc)
        return None

    def find_one_and_update(self, query, update):
        # Returns the pre-update document (PyMongo default) or None.
        with self._lock:
            for doc in self._docs:
                if _matches(doc, query):
                    before = dict(doc)
                    _apply_update(doc, update)
                    self.write_count += 1
                    return before
        return None


def _match_condition(doc, key, cond):
    if key == "$or":
        return any(_matches(doc, sub) for sub in cond)
    if isinstance(cond, dict) and any(op in cond for op in ("$gt", "$exists")):
        present = key in doc
        for op, arg in cond.items():
            if op == "$exists" and present != arg:
                return False
            if op == "$gt" and not (present and doc[key] is not None
                                   and doc[key] > arg):
                return False
        return True
    if cond is None:
        return doc.get(key) is None
    return doc.get(key, MISSING) == cond


def _matches(doc, query):
    return all(_match_condition(doc, key, cond) for key, cond in query.items())


def _apply_update(doc, update):
    for key, value in update.get("$set", {}).items():
        doc[key] = value
    for key in update.get("$unset", {}):
        doc.pop(key, None)


class BackdatedSerializer(URLSafeTimedSerializer):
    """URLSafeTimedSerializer whose signature carries a fixed timestamp."""

    def __init__(self, secret_key, timestamp):
        super().__init__(secret_key)
        self._timestamp = timestamp

    def make_signer(self, salt=None):
        signer = super().make_signer(salt)
        signer.get_timestamp = lambda: self._timestamp
        return signer


def expired_token(email, age_seconds=TOKEN_TTL_SECONDS + 60):
    past = int(time.time()) - age_seconds
    return BackdatedSerializer(SECRET_KEY, past).dumps(
        email, salt=SECURITY_PASSWORD_SALT)


def seed_account(users, email, token, *, verified=False, consumed=False,
                 expires_at=None):
    users.insert_one({
        "id": email.split("@")[0],
        "email": email,
        "verified": verified,
        "activation_token": hash_token(token),
        "token_expires_at": expires_at or token_expiry(),
        "token_consumed": consumed,
    })


def title_to_state(title_text):
    for state, copy in activation_state.STATE_MESSAGES.items():
        if copy["title"] == title_text:
            return state
    return "???"


def confirm_via_http(token):
    client = run.app.test_client()
    response = client.get("/confirm/" + token, base_url="https://localhost:8080")
    match = re.search(r"<h2>(.*?)</h2>", response.get_data(as_text=True))
    return response.status_code, match.group(1) if match else "(no copy)"


def print_verdict(label, status_code, title_text):
    state = title_to_state(title_text)
    copy = activation_state.render_context(
        state if state in activation_state.STATE_MESSAGES
        else activation_state.TOKEN_INVALID_STATE)
    print("[{0}] HTTP {1} -> state={2}".format(label, status_code, state))
    print("    heading: {0}".format(copy["heading"]))
    print("    title  : {0}".format(copy["title"]))
    print("    detail : {0}".format(copy["detail"]))
    return state


def main():
    users = MemoryUsers()

    class _Db:
        pass

    db = _Db()
    db.users = users

    class MongoShim:
        pass

    run.mongo = MongoShim()
    run.mongo.db = db

    print("=" * 72)
    print("Activation state replay")
    print("=" * 72)

    # ---- 1. fresh unverified -> activated, then idempotent resubmission ---
    token_one = generate_confirmation_token("fresh@example.com")
    seed_account(users, "fresh@example.com", token_one)

    code, title = confirm_via_http(token_one)
    state_one = print_verdict("1a fresh unverified", code, title)

    record = users.find_one({"email": "fresh@example.com"})
    assert code == 200 and state_one == activation_state.ACTIVATED
    assert record["verified"] is True
    assert record["token_consumed"] is True
    assert "activation_token" not in record
    assert "token_expires_at" not in record
    assert isinstance(record.get("activated_at"), datetime)

    writes_after_activation = users.write_count
    code, title = confirm_via_http(token_one)
    state_one_repeat = print_verdict("1b same token resubmitted", code, title)
    assert code == 200 and state_one_repeat == activation_state.ALREADY_ACTIVATED
    assert users.write_count == writes_after_activation, "idempotent branch wrote!"

    # ---- 2. expired token --------------------------------------------------
    token_old = expired_token("expired@example.com")
    seed_account(
        users, "expired@example.com", token_old,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=60))
    before = users.find_one({"email": "expired@example.com"})
    code, title = confirm_via_http(token_old)
    state_two = print_verdict("2  expired token", code, title)
    after = users.find_one({"email": "expired@example.com"})
    assert code == 200 and state_two == activation_state.TOKEN_EXPIRED_STATE
    assert before == after, "expired branch mutated the record!"

    # ---- 3. consumed / superseded token -----------------------------------
    # Issue a link, wait for the timestamp to tick over, then issue a
    # replacement link: the older in-window token is now superseded.
    superseded_token = generate_confirmation_token("used@example.com")
    time.sleep(1.1)
    current_token = generate_confirmation_token("used@example.com")
    seed_account(users, "used@example.com", current_token)
    code, title = confirm_via_http(superseded_token)
    state_three = print_verdict("3  token superseded/used", code, title)
    assert code == 200 and state_three == activation_state.TOKEN_USED
    assert users.find_one({"email": "used@example.com"})["verified"] is False

    # ---- 3b. same token twice on one account: first used-up, then "used" --
    victim_token = generate_confirmation_token("twice@example.com")
    seed_account(users, "twice@example.com", victim_token, consumed=True)
    code, title = confirm_via_http(victim_token)
    state_three_b = print_verdict("3b token already consumed", code, title)
    assert code == 200 and state_three_b == activation_state.TOKEN_USED

    # ---- 4. concurrent confirmations of one fresh token -------------------
    race_token = generate_confirmation_token("race@example.com")
    seed_account(users, "race@example.com", race_token)
    barrier = threading.Barrier(CONCURRENCY)
    results = []
    results_lock = threading.Lock()

    def race():
        barrier.wait()
        seen = confirm_via_http(race_token)
        with results_lock:
            results.append(seen)

    threads = [threading.Thread(target=race) for _ in range(CONCURRENCY)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    states = [title_to_state(title) for _, title in results]
    success = [s for s in states if s == activation_state.ACTIVATED]
    idempotent = [s for s in states if s == activation_state.ALREADY_ACTIVATED]
    print("[4  concurrent confirmations x{0}]".format(CONCURRENCY))
    for status_code, title_text in results:
        print("    HTTP {0} -> {1} | {2}".format(
            status_code, title_to_state(title_text), title_text))
    print("    SUCCESS count      : {0}".format(len(success)))
    print("    idempotent fallback: {0}".format(len(idempotent)))
    assert len(results) == CONCURRENCY
    assert all(code == 200 for code, _ in results), "a path fell out of 200!"
    assert len(success) == 1, "exactly one activation required"
    assert len(idempotent) == CONCURRENCY - 1
    assert users.find_one({"email": "race@example.com"})["verified"] is True

    # ---- guards: forged link never 500s, ini base URL beats Host ----------
    code, title = confirm_via_http("forged.garbage.value")
    state_forged = print_verdict("g1 forged link", code, title)
    assert code == 200 and state_forged == activation_state.TOKEN_INVALID_STATE

    with run.app.test_request_context(
            "/confirm/x", base_url="https://hosted-by-attacker.test"):
        url = confirmation_url(race_token)
    print("[g2 spoofed reverse-proxy Host]")
    print("    link actually sent: {0}".format(url))
    assert url.startswith("http://localhost:8080/confirm/"), url
    assert "hosted-by-attacker" not in url

    print("=" * 72)
    print("OK - 1 activation across {0} races; all other paths idempotent; "
          "no 500.".format(CONCURRENCY))
    print("Open the running app and visit a /confirm/<token> link to compare "
          "the page.")
    print("=" * 72)


if __name__ == "__main__":
    main()
