"""Bounded recovery of local research triage; never fetches or activates rules."""
import logging
import math
import time

LOG = logging.getLogger(__name__)


class TriageRecovery:
    # Respect Obsession's persisted five-minute failure cooldown.
    RETRY_DELAYS = (300, 600)

    def __init__(self, callback, clock=None):
        self.callback = callback
        self.clock = clock or time.monotonic
        self.due = None
        self.status = {"state": "not_run", "attempts": 0,
                       "last_error": None, "last_success": None,
                       "retry_after_seconds": None}

    def schedule(self):
        """A successful collection starts a new bounded triage attempt group."""
        if self.due is not None:
            return
        self.due = self.clock()
        self.status = {**self.status, "state": "pending", "attempts": 0,
                       "retry_after_seconds": None}

    def run_due(self):
        if self.due is None or self.clock() < self.due:
            return
        attempts = self.status["attempts"] + 1
        self.status = {**self.status, "state": "running", "attempts": attempts,
                       "retry_after_seconds": None}
        try:
            result = self.callback()
            if isinstance(result, dict) and result.get("status") == "not_due_or_locked":
                next_due = result.get("next_due")
                if type(next_due) not in (int, float) or not math.isfinite(next_due):
                    raise ValueError("Invalid research triage due time")
                # Honor the durable policy timer independently of source collection.
                # A held lease is revisited at most once every 30 seconds.
                delay = min(86400, max(30, next_due - time.time()))
                self.due = self.clock() + delay
                self.status = {**self.status, "state": "deferred", "attempts": attempts - 1,
                               "last_error": None, "retry_after_seconds": delay}
                return
        except Exception as error:
            delay = self.RETRY_DELAYS[attempts - 1] if attempts <= len(self.RETRY_DELAYS) else None
            self.due = self.clock() + delay if delay is not None else None
            self.status = {**self.status,
                           "state": "retry_wait" if delay is not None else "exhausted",
                           "last_error": type(error).__name__, "retry_after_seconds": delay}
            # Exception messages can contain source text; report the type only.
            LOG.error("Research triage attempt %s failed (%s); retry in %s seconds",
                      attempts, type(error).__name__, delay)
        else:
            self.due = None
            self.status = {**self.status, "state": "current", "last_error": None,
                           "last_success": time.time(), "retry_after_seconds": None}

    def wait_seconds(self):
        return max(0, self.due - self.clock()) if self.due is not None else 30


def health_status(worker_alive, collection_error, recovery, persisted_triage_error):
    """A live thread alone is insufficient proof of a healthy research pipeline."""
    if not worker_alive:
        return "worker_stopped"
    if collection_error:
        return "collection_failed"
    if recovery.get("last_error") or persisted_triage_error:
        return "triage_failed"
    return "ok"
