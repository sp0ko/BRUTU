"""
BruteForceTracker — sliding-window counter for failed login attempts.
Thread-safe; designed to be shared across multiple log-monitor threads.

Detects two attack patterns:
  • Brute force   — many attempts from one IP (same or few accounts)
  • Password spray — one IP tries many distinct accounts (few attempts each)
"""

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Dict, List


@dataclass
class AlertEvent:
    ip: str
    count: int
    time_window: int
    attack_type: str
    usernames: List[str]
    log_sources: List[str]
    first_seen: float
    last_seen: float
    successful_login: bool = False
    geo_info: Optional[dict] = None
    threat_intel: Optional[str] = None   # set to source label when IP is in threat intel DB

    def is_critical(self) -> bool:
        """Returns True when a successful login follows the brute-force storm."""
        return self.successful_login


class BruteForceTracker:
    """
    Tracks failed (and successful) login attempts per IP in a configurable time
    window.  Emits an AlertEvent when *threshold* failures occur within
    *time_window* seconds.  Repeated alerts for the same IP are suppressed for
    *alert_cooldown* seconds to avoid notification spam.

    Additionally emits a PASSWORD_SPRAY alert when the number of distinct
    usernames tried from a single IP reaches *spray_username_threshold* within
    the time window, even if the total attempt count is below *threshold*.
    """

    def __init__(
        self,
        threshold: int = 5,
        time_window: int = 60,
        alert_cooldown: int = 300,
        success_failure_threshold: int = 3,
        spray_username_threshold: int = 8,
    ) -> None:
        self.threshold = threshold
        self.time_window = time_window
        self.alert_cooldown = alert_cooldown
        self.success_failure_threshold = success_failure_threshold
        self.spray_username_threshold = spray_username_threshold

        # ip -> deque of (timestamp, username, attack_type, log_source)
        self._failed: Dict[str, deque] = defaultdict(deque)
        self._last_alert: Dict[str, float] = {}
        self._total_triggered: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_failed(
        self,
        ip: str,
        username: str = "",
        attack_type: str = "SSH",
        log_source: str = "",
        timestamp: Optional[float] = None,
    ) -> Optional[AlertEvent]:
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            bucket = self._failed[ip]
            bucket.append((timestamp, username, attack_type, log_source))
            self._evict_old(bucket, time.time())

            count = len(bucket)
            unique_users = len({e[1] for e in bucket if e[1]})

            # Password spray: many distinct accounts, few attempts each
            if (
                unique_users >= self.spray_username_threshold
                and self._cooldown_elapsed(ip, timestamp)
            ):
                self._last_alert[ip] = timestamp
                self._total_triggered[ip] += 1
                event = self._build_event(ip, bucket, count, successful_login=False)
                event.attack_type = "PASSWORD_SPRAY"
                return event

            # Classic brute force: many attempts (threshold) in time window
            if count >= self.threshold and self._cooldown_elapsed(ip, timestamp):
                self._last_alert[ip] = timestamp
                self._total_triggered[ip] += 1
                return self._build_event(ip, bucket, count, successful_login=False)

        return None

    def record_success(
        self,
        ip: str,
        username: str = "",
        attack_type: str = "SSH",
        log_source: str = "",
        timestamp: Optional[float] = None,
    ) -> Optional[AlertEvent]:
        if timestamp is None:
            timestamp = time.time()

        with self._lock:
            bucket = self._failed.get(ip)
            if not bucket:
                return None

            relevant_cutoff = timestamp - self.time_window * 2
            recent = [e for e in bucket if e[0] >= relevant_cutoff]

            if len(recent) >= self.success_failure_threshold:
                augmented = list(recent)
                augmented.append((timestamp, f"{username} ✓ (UDANE LOGOWANIE)", attack_type, log_source))
                return self._build_event(ip, augmented, len(recent), successful_login=True)

        return None

    def get_stats(self) -> Dict[str, dict]:
        now = time.time()
        with self._lock:
            stats: Dict[str, dict] = {}
            for ip, bucket in self._failed.items():
                recent = [e for e in bucket if e[0] >= now - self.time_window]
                if recent:
                    stats[ip] = {
                        "count": len(recent),
                        "attack_types": list({e[2] for e in recent}),
                        "usernames": list({e[1] for e in recent if e[1]}),
                        "total_alerts_triggered": self._total_triggered[ip],
                        "last_seen": recent[-1][0],
                    }
        return stats

    def reset_ip(self, ip: str) -> None:
        with self._lock:
            self._failed.pop(ip, None)
            self._last_alert.pop(ip, None)

    # ------------------------------------------------------------------

    def _evict_old(self, bucket: deque, now: float) -> None:
        cutoff = now - self.time_window
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

    def _cooldown_elapsed(self, ip: str, now: float) -> bool:
        last = self._last_alert.get(ip, 0.0)
        return (now - last) >= self.alert_cooldown

    def _build_event(self, ip, entries, count, successful_login) -> AlertEvent:
        usernames = list({e[1] for e in entries if e[1]})
        attack_types = list({e[2] for e in entries})
        log_sources = list({e[3] for e in entries})
        return AlertEvent(
            ip=ip,
            count=count,
            time_window=self.time_window,
            attack_type=", ".join(attack_types),
            usernames=usernames,
            log_sources=log_sources,
            first_seen=entries[0][0],
            last_seen=entries[-1][0],
            successful_login=successful_login,
        )
