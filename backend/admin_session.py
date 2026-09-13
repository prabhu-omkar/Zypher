"""
Admin sessions.

The previous implementation was a module-level `set()` of token strings: a token
never expired, there was no way to sign out, and a failed password cost the
attacker nothing. That was tolerable while the admin view showed four counts.
It stops being tolerable now that the same token unlocks every asset in the
estate, so the session has a lifetime and the login has a cost.

State is per-process and in memory by design. These tokens are not credentials
to be persisted — restarting the application ends every session, which for an
offline desktop tool is the behaviour you want.
"""
import secrets
import time
from typing import Dict, Optional, Tuple

# A session lasts a working day and is not extended by use. An absolute
# lifetime is easier to reason about than a sliding one, and there is no
# scenario here where an admin needs a session to outlive the day it began.
SESSION_TTL_SECONDS = 8 * 60 * 60

# Failed logins are throttled after this many attempts, with the lockout
# doubling each time so that guessing becomes impractical quickly without ever
# locking a legitimate operator out permanently.
FAILURES_BEFORE_LOCKOUT = 5
BASE_LOCKOUT_SECONDS = 30
MAX_LOCKOUT_SECONDS = 15 * 60


class AdminSessions:
    def __init__(self, ttl_seconds: int = SESSION_TTL_SECONDS):
        self.ttl = ttl_seconds
        self._tokens: Dict[str, float] = {}      # token -> expiry timestamp
        self._failures = 0
        self._locked_until = 0.0

    # ------------------------------------------------------------- throttle

    def lockout_remaining(self, now: Optional[float] = None) -> int:
        """Seconds before another login attempt is accepted. Zero when open."""
        now = now if now is not None else time.time()
        return max(0, int(self._locked_until - now))

    def record_failure(self, now: Optional[float] = None) -> int:
        """Count a failed login and return the seconds now locked out."""
        now = now if now is not None else time.time()
        self._failures += 1
        if self._failures >= FAILURES_BEFORE_LOCKOUT:
            over = self._failures - FAILURES_BEFORE_LOCKOUT
            delay = min(MAX_LOCKOUT_SECONDS, BASE_LOCKOUT_SECONDS * (2 ** over))
            self._locked_until = now + delay
            return delay
        return 0

    def record_success(self) -> None:
        self._failures = 0
        self._locked_until = 0.0

    # -------------------------------------------------------------- tokens

    def issue(self, now: Optional[float] = None) -> Tuple[str, int]:
        """A new session token and how many seconds it is good for."""
        now = now if now is not None else time.time()
        self._purge(now)
        token = secrets.token_urlsafe(32)
        self._tokens[token] = now + self.ttl
        return token, self.ttl

    def is_valid(self, token: Optional[str], now: Optional[float] = None) -> bool:
        if not token:
            return False
        now = now if now is not None else time.time()
        expiry = self._tokens.get(token)
        if expiry is None:
            return False
        if expiry <= now:
            # Expiring on read keeps a stale token from being accepted even if
            # nothing has triggered a purge since it lapsed.
            self._tokens.pop(token, None)
            return False
        return True

    def revoke(self, token: Optional[str]) -> bool:
        return self._tokens.pop(token, None) is not None if token else False

    def revoke_all(self) -> int:
        count = len(self._tokens)
        self._tokens.clear()
        return count

    def _purge(self, now: float) -> None:
        for token in [t for t, exp in self._tokens.items() if exp <= now]:
            self._tokens.pop(token, None)

    @property
    def active_count(self) -> int:
        self._purge(time.time())
        return len(self._tokens)


def bearer_token(authorization: Optional[str]) -> Optional[str]:
    """Pull the token out of an Authorization header, if it is a bearer one."""
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None
