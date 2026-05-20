"""
Slack webhook alert handler — Block Kit formatting.
"""

from datetime import datetime
from typing import Optional

import requests

import utils.i18n as i18n
from ..tracker import AlertEvent


class SlackAlert:

    def __init__(self, webhook_url: str, timeout: int = 10) -> None:
        if not webhook_url:
            raise ValueError("Slack webhook URL cannot be empty.")
        self._url = webhook_url
        self._timeout = timeout

    def send(self, event: AlertEvent, geo: Optional[dict] = None) -> bool:
        try:
            resp = requests.post(self._url, json=self._build_payload(event, geo), timeout=self._timeout)
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            print(f"[Slack] Send error: {exc}")
            return False

    def _build_payload(self, event: AlertEvent, geo: Optional[dict]) -> dict:
        T      = i18n.get_T()
        ts_str = datetime.fromtimestamp(event.last_seen).strftime("%Y-%m-%d %H:%M:%S")

        if event.successful_login:
            header  = T["sl_title_crit"]
            color   = "#FF0000"
            summary = T["sl_summ_crit"].format(ip=event.ip, count=event.count)
        else:
            header  = T["sl_title_warn"]
            color   = "#FFA500"
            summary = T["sl_summ_warn"].format(ip=event.ip, count=event.count, window=event.time_window)

        fields_md = "\n".join([
            f"{T['sl_f_ip']}\t`{event.ip}`",
            f"{T['sl_f_attempts']}\t{event.count} / {event.time_window}s",
            f"{T['sl_f_type']}\t{event.attack_type or '—'}",
            f"{T['sl_f_users']}\t{_trunc(', '.join(event.usernames) or '—', 300)}",
            f"{T['sl_f_source']}\t{_trunc(', '.join(event.log_sources) or '—', 200)}",
            f"{T['sl_f_time']}\t{ts_str}",
        ])

        if geo:
            loc = ", ".join(str(geo[k]) for k in ("country", "regionName", "city") if geo.get(k) and geo[k] != "unknown")
            if loc:
                fields_md += f"\n{T['sl_f_geo']}\t{loc}"
            if geo.get("isp") and geo["isp"] != "unknown":
                fields_md += f"\n{T['sl_f_isp']}\t{geo['isp']}"

        blocks = [
            {"type": "header",  "text": {"type": "plain_text", "text": header.replace("*", ""), "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": summary}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": fields_md}},
        ]

        return {
            "attachments": [{
                "color": color,
                "blocks": blocks,
                "fallback": T["sl_fallback"].format(ip=event.ip, count=event.count, window=event.time_window),
            }]
        }


def _trunc(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit - 3] + "..."
