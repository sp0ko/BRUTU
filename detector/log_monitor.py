"""
Real-time log file monitor.

One LogFileWatcher thread per log file.  Tails the file,
parses new lines, feeds events to the BruteForceTracker.
"""

import os
import time
import threading
import logging
from typing import List, Callable, Optional

import utils.i18n as i18n
from .tracker import BruteForceTracker, AlertEvent
from .parsers import get_parser, PARSER_REGISTRY

log = logging.getLogger("brute-force-detector.monitor")


class LogFileWatcher(threading.Thread):

    def __init__(
        self,
        path: str,
        parser_type: str,
        tracker: BruteForceTracker,
        on_alert: Callable[[AlertEvent], None],
        whitelist_nets: Optional[list] = None,
        poll_interval: float = 0.25,
    ) -> None:
        super().__init__(daemon=True, name=f"watcher:{os.path.basename(path)}")
        self.path = path
        self.parser = get_parser(parser_type)
        self.tracker = tracker
        self.on_alert = on_alert
        self.whitelist_nets = whitelist_nets or []
        self.poll_interval = poll_interval
        self._stop = threading.Event()

    def run(self) -> None:
        log.info(i18n.get_T()["lm_monitoring"], self.path, self.parser.name)
        self._tail()

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------

    def _tail(self) -> None:
        while not self._stop.is_set():
            if not os.path.exists(self.path):
                log.warning(i18n.get_T()["lm_no_file"], self.path)
                time.sleep(2)
                continue
            try:
                with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(0, 2)
                    log.info(i18n.get_T()["lm_ready"], self.path)
                    while not self._stop.is_set():
                        line = fh.readline()
                        if not line:
                            try:
                                if os.stat(self.path).st_ino != os.fstat(fh.fileno()).st_ino:
                                    log.info(i18n.get_T()["lm_rotated"], self.path)
                                    break
                                if os.stat(self.path).st_size < fh.tell():
                                    log.info(i18n.get_T()["lm_truncated"], self.path)
                                    break
                            except OSError:
                                break
                            time.sleep(self.poll_interval)
                            continue
                        self._process_line(line)
            except OSError as exc:
                log.error(i18n.get_T()["lm_read_err"], self.path, exc)
                time.sleep(2)

    def _process_line(self, line: str) -> None:
        from utils.ip_utils import ip_in_list
        try:
            event = self.parser.parse_line(line)
        except Exception as exc:
            log.debug(i18n.get_T()["lm_parse_err"], exc)
            return

        if event is None:
            return

        if self.whitelist_nets and ip_in_list(event.ip, self.whitelist_nets):
            return

        if event.event_type == "FAILED":
            alert = self.tracker.record_failed(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source=self.path,
                timestamp=event.timestamp or None,
            )
        elif event.event_type == "SUCCESS":
            alert = self.tracker.record_success(
                ip=event.ip, username=event.username,
                attack_type=event.attack_type, log_source=self.path,
                timestamp=event.timestamp or None,
            )
        else:
            return

        if alert:
            try:
                self.on_alert(alert)
            except Exception as exc:
                log.error(i18n.get_T()["lm_alert_err"], exc)


class LogMonitor:

    def __init__(self, tracker: BruteForceTracker, whitelist_nets: Optional[list] = None) -> None:
        self.tracker = tracker
        self.whitelist_nets = whitelist_nets or []
        self._watchers: List[LogFileWatcher] = []
        self._handlers: List[Callable] = []

    def add_alert_handler(self, handler: Callable[[AlertEvent], None]) -> None:
        self._handlers.append(handler)

    def add_log_file(self, path: str, parser_type: str) -> None:
        if parser_type not in PARSER_REGISTRY:
            raise ValueError(i18n.get_T()["lm_unknown_parser"] % parser_type)
        self._watchers.append(LogFileWatcher(
            path=path, parser_type=parser_type,
            tracker=self.tracker, on_alert=self._dispatch,
            whitelist_nets=self.whitelist_nets,
        ))

    def start(self) -> None:
        if not self._watchers:
            raise RuntimeError(i18n.get_T()["lm_no_files"])
        for w in self._watchers:
            w.start()
        log.info(i18n.get_T()["lm_started"], len(self._watchers))

    def stop(self) -> None:
        for w in self._watchers:
            w.stop()
        for w in self._watchers:
            w.join(timeout=3)

    def _dispatch(self, event: AlertEvent) -> None:
        for h in self._handlers:
            try:
                h(event)
            except Exception as exc:
                log.error(i18n.get_T()["lm_dispatch_err"], exc)
