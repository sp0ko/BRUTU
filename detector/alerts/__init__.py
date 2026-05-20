import time
from datetime import datetime
from typing import Optional

import utils.i18n as i18n
from ..tracker import AlertEvent


def format_alert(event: AlertEvent, geo: Optional[dict] = None) -> str:
    T  = i18n.get_T()
    ts = datetime.fromtimestamp(event.last_seen).strftime("%Y-%m-%d %H:%M:%S")
    tag = "BRUTE-FORCE+PWNED" if event.successful_login else "BRUTE-FORCE"
    return (
        f"[{ts}] [{tag}] IP={event.ip}  {T['fmt_attacks']}={event.count}  "
        f"{T['fmt_window']}={event.time_window}s  {T['fmt_type']}={event.attack_type}  "
        f"{T['fmt_users']}={','.join(event.usernames)}"
    )
