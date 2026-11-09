"""Bounded process-local scan receipts, allowing short HTTP polling requests."""
import threading
import time
import uuid


class ScanJobs:
    def __init__(self, *, ttl=600, retained=2, clock=time.monotonic):
        self.ttl, self.retained, self.clock = ttl, retained, clock
        self.lock = threading.Lock()
        self.jobs = {}
        self.sequence = 0

    def _prune(self):
        finished = sorted((job["finished"], job["sequence"], key) for key, job in self.jobs.items()
                          if job.get("finished") is not None)
        now = self.clock()
        for index, (at, sequence, key) in enumerate(finished):
            if now - at >= self.ttl or index < len(finished) - self.retained:
                del self.jobs[key]

    def submit(self, work, release):
        key = uuid.uuid4().hex
        with self.lock:
            self._prune()
            self.jobs[key] = {"status": "running"}

        def run():
            try:
                status, content = work()
                outcome = ({"status": "completed", "result": content} if status == 200 else
                           {"status": "failed", "http_status": status,
                            "detail": content.get("detail", {"message": "Scan failed."})})
            except Exception:
                outcome = {"status": "failed", "http_status": 500,
                           "detail": {"message": "Scan failed unexpectedly.", "stage": "analysis"}}
            finally:
                release()
            with self.lock:
                self.sequence += 1
                self.jobs[key] = dict(outcome, finished=self.clock(), sequence=self.sequence)
                self._prune()

        try:
            threading.Thread(target=run, name="skill-scan", daemon=True).start()
        except Exception:
            with self.lock:
                self.jobs.pop(key, None)
            raise
        return key

    def get(self, key):
        with self.lock:
            self._prune()
            job = self.jobs.get(key)
            return None if job is None else {k: v for k, v in job.items() if k not in {"finished", "sequence"}}
