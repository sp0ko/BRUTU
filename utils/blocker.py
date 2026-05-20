"""
IPBlocker — active defense via iptables / ip6tables.

Automatically blocks attacker IPs using DROP rules and optionally
auto-unblocks them after a configurable timeout.  Requires the process
to run as root (or have CAP_NET_ADMIN) to modify iptables.

All subprocess calls use argument lists (no shell=True) to prevent
command injection.  IPs are validated before use.
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("brute-force-detector.blocker")

# Strict validation patterns — no shell metacharacters can pass
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}$")


def _validate_ip(ip: str) -> bool:
    """Return True only for syntactically valid IPv4 or IPv6 addresses."""
    if _IPV4_RE.match(ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    return bool(_IPV6_RE.match(ip))


def _is_ipv6(ip: str) -> bool:
    return ":" in ip


class IPBlocker:
    """
    Manages a set of blocked IPs via iptables/ip6tables INSERT rules.

    Parameters
    ----------
    enabled : bool
        Master switch.  When False no iptables calls are made.
    auto_unblock_after : int
        Seconds until automatic unblock.  0 = permanent until program exit
        or explicit unblock.
    state_file : str
        JSON file to persist block state across restarts.
    dry_run : bool
        Log what would happen but do not execute iptables commands.
    """

    def __init__(
        self,
        enabled: bool = True,
        auto_unblock_after: int = 3600,
        state_file: str = "reports/blocked_ips.json",
        dry_run: bool = False,
    ) -> None:
        self.enabled = enabled
        self.auto_unblock_after = auto_unblock_after
        self.state_file = state_file
        self.dry_run = dry_run

        # ip -> {"blocked_at": float, "attempts": int, "attack_type": str,
        #         "usernames": list, "geo": dict|None, "unblock_at": float|None}
        self._blocked: Dict[str, dict] = {}
        self._lock = threading.Lock()

        self._check_privileges()
        self._load_state()

        if self.enabled and self.auto_unblock_after > 0:
            self._start_unblock_scheduler()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def block(
        self,
        ip: str,
        attempts: int = 0,
        attack_type: str = "",
        usernames: Optional[List[str]] = None,
        geo: Optional[dict] = None,
    ) -> bool:
        """Add a DROP rule for *ip*.  Returns True if the rule was added."""
        if not self.enabled:
            return False
        if not _validate_ip(ip):
            log.warning("IPBlocker: invalid IP address ignored: %r", ip)
            return False

        with self._lock:
            if ip in self._blocked:
                return False  # already blocked

            unblock_at = (
                time.time() + self.auto_unblock_after
                if self.auto_unblock_after > 0
                else None
            )
            self._blocked[ip] = {
                "blocked_at": time.time(),
                "attempts":   attempts,
                "attack_type": attack_type,
                "usernames":  usernames or [],
                "geo":        geo,
                "unblock_at": unblock_at,
            }

        if self._iptables_insert(ip):
            log.warning(
                "BLOCKED %s | type=%s attempts=%d users=%s unblock_in=%s",
                ip, attack_type, attempts,
                ",".join((usernames or [])[:5]) or "—",
                f"{self.auto_unblock_after}s" if self.auto_unblock_after else "permanent",
            )
            self._save_state()
            return True

        with self._lock:
            self._blocked.pop(ip, None)
        return False

    def unblock(self, ip: str) -> bool:
        """Remove the DROP rule for *ip*.  Returns True on success."""
        if not _validate_ip(ip):
            return False
        with self._lock:
            if ip not in self._blocked:
                return False
            self._blocked.pop(ip)

        result = self._iptables_delete(ip)
        self._save_state()
        if result:
            log.info("UNBLOCKED %s", ip)
        return result

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked

    def get_blocked(self) -> List[dict]:
        """Return a snapshot list of all currently blocked IPs with metadata."""
        now = time.time()
        with self._lock:
            rows = []
            for ip, meta in self._blocked.items():
                remaining = None
                if meta["unblock_at"]:
                    remaining = max(0, int(meta["unblock_at"] - now))
                rows.append({
                    "ip":          ip,
                    "blocked_at":  meta["blocked_at"],
                    "attempts":    meta["attempts"],
                    "attack_type": meta["attack_type"],
                    "usernames":   meta["usernames"],
                    "geo":         meta["geo"],
                    "remaining_s": remaining,
                })
            return sorted(rows, key=lambda r: r["blocked_at"], reverse=True)

    def unblock_all(self) -> int:
        """Unblock all IPs (called on clean shutdown).  Returns count."""
        ips = list(self._blocked.keys())
        count = 0
        for ip in ips:
            if self.unblock(ip):
                count += 1
        return count

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------

    def _iptables_insert(self, ip: str) -> bool:
        cmd = self._cmd(ip, action="I")  # INSERT at position 1
        return self._run(cmd)

    def _iptables_delete(self, ip: str) -> bool:
        cmd = self._cmd(ip, action="D")  # DELETE matching rule
        return self._run(cmd)

    def _cmd(self, ip: str, action: str) -> List[str]:
        binary = "ip6tables" if _is_ipv6(ip) else "iptables"
        # INSERT: ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        # DELETE: ["iptables", "-D", "INPUT",       "-s", ip, "-j", "DROP"]
        if action == "I":
            return [binary, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        return [binary, "-D", "INPUT", "-s", ip, "-j", "DROP"]

    def _run(self, cmd: List[str]) -> bool:
        if self.dry_run:
            log.info("[DRY-RUN] Would run: %s", " ".join(cmd))
            return True
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                log.error("iptables error: %s", result.stderr.strip())
                return False
            return True
        except FileNotFoundError:
            log.error("iptables not found — is it installed and in PATH?")
            return False
        except subprocess.TimeoutExpired:
            log.error("iptables command timed out")
            return False
        except OSError as exc:
            log.error("iptables OS error: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Auto-unblock scheduler
    # ------------------------------------------------------------------

    def _start_unblock_scheduler(self) -> None:
        def _loop() -> None:
            while True:
                time.sleep(10)
                now = time.time()
                to_unblock = []
                with self._lock:
                    for ip, meta in list(self._blocked.items()):
                        if meta["unblock_at"] and now >= meta["unblock_at"]:
                            to_unblock.append(ip)
                for ip in to_unblock:
                    self.unblock(ip)

        threading.Thread(target=_loop, daemon=True, name="ip-unblock-scheduler").start()

    # ------------------------------------------------------------------
    # Privilege check
    # ------------------------------------------------------------------

    def _check_privileges(self) -> None:
        if not self.enabled or self.dry_run:
            return
        if os.geteuid() != 0:
            log.warning(
                "IPBlocker enabled but not running as root — "
                "iptables calls will fail. Re-run with sudo or disable blocker."
            )

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.state_file)), exist_ok=True)
            with self._lock:
                data = dict(self._blocked)
            with open(self.state_file, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
        except OSError as exc:
            log.debug("Could not save blocker state: %s", exc)

    def _load_state(self) -> None:
        if not os.path.isfile(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            now = time.time()
            restored = 0
            for ip, meta in data.items():
                if not _validate_ip(ip):
                    continue
                # Skip entries whose auto-unblock time has already passed
                if meta.get("unblock_at") and now >= meta["unblock_at"]:
                    continue
                with self._lock:
                    self._blocked[ip] = meta
                # Re-insert iptables rule
                self._iptables_insert(ip)
                restored += 1
            if restored:
                log.info("IPBlocker: restored %d block rule(s) from %s", restored, self.state_file)
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            log.warning("Could not load blocker state: %s", exc)
