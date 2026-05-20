"""
Discord webhook alert handler — rich embeds.
"""

from datetime import datetime
from typing import Optional

import requests

import utils.i18n as i18n
from ..tracker import AlertEvent


class DiscordAlert:
    _COLOR_WARNING  = 0xFFA500
    _COLOR_CRITICAL = 0xFF0000

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        if not webhook_url:
            raise ValueError("Discord webhook URL cannot be empty.")
        self._url = webhook_url
        self._timeout = timeout

    def send(self, event: AlertEvent, geo: Optional[dict] = None) -> bool:
        try:
            resp = requests.post(self._url, json=self._build_payload(event, geo), timeout=self._timeout)
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            print(f"[Discord] Send error: {exc}")
            return False

    def _build_payload(self, event: AlertEvent, geo: Optional[dict]) -> dict:
        T      = i18n.get_T()
        ts_iso = datetime.utcfromtimestamp(event.last_seen).isoformat() + "Z"
        color  = self._COLOR_CRITICAL if event.successful_login else self._COLOR_WARNING

        if event.successful_login:
            title       = T["dc_title_crit"]
            description = T["dc_desc_crit"].format(ip=event.ip, count=event.count)
        else:
            title       = T["dc_title_warn"]
            description = T["dc_desc_warn"].format(ip=event.ip, count=event.count, window=event.time_window)

        fields = [
            {"name": T["dc_f_ip"],       "value": f"`{event.ip}`",                                         "inline": True},
            {"name": T["dc_f_attempts"], "value": str(event.count),                                        "inline": True},
            {"name": T["dc_f_window"],   "value": f"{event.time_window}s",                                 "inline": True},
            {"name": T["dc_f_type"],     "value": event.attack_type or "—",                               "inline": True},
            {"name": T["dc_f_users"],    "value": _trunc(", ".join(event.usernames) or "—", 1024),        "inline": False},
            {"name": T["dc_f_source"],   "value": _trunc(", ".join(event.log_sources) or "—", 512),       "inline": False},
        ]

        if geo:
            loc = ", ".join(str(geo[k]) for k in ("country", "regionName", "city") if geo.get(k) and geo[k] != "unknown")
            if loc:
                fields.append({"name": T["dc_f_geo"], "value": loc, "inline": False})
            if geo.get("isp") and geo["isp"] != "unknown":
                fields.append({"name": T["dc_f_isp"], "value": geo["isp"], "inline": False})

        return {
            "username": "BRUTU$",
            "embeds": [{
                "title": title,
                "description": description,
                "color": color,
                "fields": fields,
                "timestamp": ts_iso,
                "footer": {"text": "BRUTU$ • SSH/RDP Brute-Force Detector"},
            }],
        }


def _trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."
