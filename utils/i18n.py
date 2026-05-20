"""
Centralised internationalisation (i18n) module.

Usage
-----
    import utils.i18n as i18n

    i18n.set_lang("en")      # called once at startup
    T = i18n.get_T()         # retrieve current translation dict anywhere
"""

import sys
from typing import Optional

STRINGS: dict = {
    "pl": {
        # ── main.py ──────────────────────────────────────────────────────────
        "description":   "BRUTU$ — detekcja ataków SSH/RDP w czasie rzeczywistym",
        "help_config":   "Ścieżka do pliku config.yaml",
        "help_log":      "Dodatkowy plik logu",
        "help_type":     "Typ parsera: linux_ssh | windows_evtx",
        "help_threshold":"Próg nieudanych logowań",
        "help_window":   "Okno czasu (sekundy)",
        "help_cooldown": "Cooldown alertów (sekundy)",
        "help_discord":  "Discord webhook URL",
        "help_slack":    "Slack webhook URL",
        "help_test":     "Tryb testowy — symulacja ataku",
        "help_stats":    "Pokaż statystyki i zakończ",
        "help_lang":     "Język interfejsu: pl | en (pomija interaktywny wybór)",
        "err_config":    "[BŁĄD] Plik konfiguracyjny nie istnieje: %s",
        "tracker_info":  "Tracker: próg=%d  okno=%ds  cooldown=%ds",
        "discord_on":    "Discord webhook: aktywny ✓",
        "discord_off":   "Discord: wyłączony",
        "slack_on":      "Slack webhook: aktywny ✓",
        "slack_off":     "Slack: wyłączony",
        "reports_info":  "Raporty: %s",
        "no_log_files":  "Brak aktywnych plików logów! Dodaj wpisy w 'log_files' w config.yaml.",
        "adding_file":   "Dodaję plik: %s  (parser: %s)",
        "signal_stop":   "Sygnał %s — zatrzymuję…",
        "started":       "BRUTU$ uruchomiony — Ctrl+C aby zatrzymać.",
        "lang_hint":     '[WSKAZÓWKA] Wpisz "lang" + Enter, aby zmienić język podczas działania.',
        "active_ips":    "Aktywne IP: %d  |  Najbardziej aktywne: %s (%d prób)",
        "stopped":       "BRUTU$ zatrzymany.",
        "test_start":    "\n[TEST] Uruchamiam symulację ataku brute-force…\n",
        "test_end":      "\n[TEST] Symulacja zakończona. Sprawdź Discord/Slack jeśli webhooks są skonfigurowane.",
        "no_activity":   "Brak aktywności w bieżącym oknie czasu.",
        "col_ip":        "IP",
        "col_attempts":  "Próby",
        "col_type":      "Typ ataku",
        "col_users":     "Użytkownicy",
        "lang_changed":  "Zmieniono język na: Polski.",
        # ── console_alert.py ─────────────────────────────────────────────────
        "ca_title_crit":    " 🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE! 🚨",
        "ca_title_warn":    " ⚠️  UWAGA! POTENCJALNY BRUTE FORCE!  ⚠️",
        "ca_line_ip":       "  🌐 Adres IP       : {ip}",
        "ca_line_attempts": "  📊 Nieudane próby : {count} w ciągu {window}s",
        "ca_line_type":     "  🔌 Typ ataku      : {type}",
        "ca_line_users":    "  👤 Użytkownicy    : {users}",
        "ca_line_source":   "  📁 Źródło logów   : {source}",
        "ca_line_time":     "  🕐 Czas wykrycia  : {ts}",
        "ca_line_geo":      "  🗺  Geolokalizacja  : {geo}",
        "ca_line_isp":      "  🏢 ISP / Org       : {isp}",
        "ca_breach":        "  ‼ MOŻLIWE WŁAMANIE — sprawdź konto natychmiast!",
        # ── discord_alert.py ─────────────────────────────────────────────────
        "dc_title_crit": "🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE!",
        "dc_title_warn": "⚠️ UWAGA! POTENCJALNY BRUTE FORCE WYKRYTY!",
        "dc_desc_crit":  "Adres IP **{ip}** prawdopodobnie **pomyślnie przejął konto** po {count} nieudanych próbach.",
        "dc_desc_warn":  "Adres IP **{ip}** wykonał **{count} nieudanych prób logowania** w ciągu **{window} sekund**.",
        "dc_f_ip":       "🌐 Adres IP",
        "dc_f_attempts": "📊 Liczba prób",
        "dc_f_window":   "⏱ Okno czasu",
        "dc_f_type":     "🔌 Typ ataku",
        "dc_f_users":    "👤 Użytkownicy",
        "dc_f_source":   "📁 Źródło logów",
        "dc_f_geo":      "🗺 Geolokalizacja",
        "dc_f_isp":      "🏢 ISP / Org",
        # ── slack_alert.py ───────────────────────────────────────────────────
        "sl_title_crit": "🚨 KRYTYCZNE! UDANE LOGOWANIE PO BRUTE-FORCE!",
        "sl_title_warn": "⚠️ UWAGA! POTENCJALNY BRUTE FORCE WYKRYTY!",
        "sl_summ_crit":  "IP `{ip}` prawdopodobnie *pomyślnie przejął konto* po {count} nieudanych próbach.",
        "sl_summ_warn":  "IP `{ip}` wykonał *{count} nieudanych prób logowania* w ciągu *{window} sekund*.",
        "sl_f_ip":       "*🌐 Adres IP:*",
        "sl_f_attempts": "*📊 Próby:*",
        "sl_f_type":     "*🔌 Typ ataku:*",
        "sl_f_users":    "*👤 Użytkownicy:*",
        "sl_f_source":   "*📁 Źródło:*",
        "sl_f_time":     "*🕐 Czas:*",
        "sl_f_geo":      "*🗺 Lokalizacja:*",
        "sl_f_isp":      "*🏢 ISP:*",
        "sl_fallback":   "[BRUTE-FORCE] IP {ip} — {count} prób w {window}s",
        # ── log_monitor.py ───────────────────────────────────────────────────
        "lm_monitoring":    "Monitorowanie: %s  (parser: %s)",
        "lm_no_file":       "Plik nie istnieje: %s — czekam…",
        "lm_ready":         "Gotowy do czytania: %s",
        "lm_rotated":       "Rotacja logu: %s",
        "lm_truncated":     "Plik skrócony: %s",
        "lm_read_err":      "Błąd odczytu %s: %s",
        "lm_parse_err":     "Błąd parsowania: %s",
        "lm_alert_err":     "Błąd callbacku alertu: %s",
        "lm_unknown_parser":"Nieznany parser: %s",
        "lm_no_files":      "Brak plików logów do monitorowania.",
        "lm_started":       "Monitor uruchomiony — %d plik(ów).",
        "lm_dispatch_err":  "Błąd handlera: %s",
        # ── alerts/__init__.py ───────────────────────────────────────────────
        "fmt_attacks":  "ataki",
        "fmt_window":   "okno",
        "fmt_type":     "typ",
        "fmt_users":    "użytkownicy",
    },
    "en": {
        # ── main.py ──────────────────────────────────────────────────────────
        "description":   "BRUTU$ — real-time SSH/RDP brute-force attack detector",
        "help_config":   "Path to config.yaml file",
        "help_log":      "Additional log file path",
        "help_type":     "Parser type: linux_ssh | windows_evtx",
        "help_threshold":"Failed login threshold",
        "help_window":   "Time window (seconds)",
        "help_cooldown": "Alert cooldown (seconds)",
        "help_discord":  "Discord webhook URL",
        "help_slack":    "Slack webhook URL",
        "help_test":     "Test mode — simulate attack",
        "help_stats":    "Show statistics and exit",
        "help_lang":     "Interface language: pl | en (skips interactive prompt)",
        "err_config":    "[ERROR] Config file not found: %s",
        "tracker_info":  "Tracker: threshold=%d  window=%ds  cooldown=%ds",
        "discord_on":    "Discord webhook: active ✓",
        "discord_off":   "Discord: disabled",
        "slack_on":      "Slack webhook: active ✓",
        "slack_off":     "Slack: disabled",
        "reports_info":  "Reports: %s",
        "no_log_files":  "No active log files! Add entries under 'log_files' in config.yaml.",
        "adding_file":   "Adding file: %s  (parser: %s)",
        "signal_stop":   "Signal %s — stopping…",
        "started":       "BRUTU$ running — press Ctrl+C to stop.",
        "lang_hint":     '[HINT] Type "lang" + Enter to change language at any time.',
        "active_ips":    "Active IPs: %d  |  Most active: %s (%d attempts)",
        "stopped":       "BRUTU$ stopped.",
        "test_start":    "\n[TEST] Starting brute-force attack simulation…\n",
        "test_end":      "\n[TEST] Simulation complete. Check Discord/Slack if webhooks are configured.",
        "no_activity":   "No activity in the current time window.",
        "col_ip":        "IP",
        "col_attempts":  "Attempts",
        "col_type":      "Attack type",
        "col_users":     "Usernames",
        "lang_changed":  "Language changed to: English.",
        # ── console_alert.py ─────────────────────────────────────────────────
        "ca_title_crit":    " 🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE! 🚨",
        "ca_title_warn":    " ⚠️  WARNING! POTENTIAL BRUTE FORCE ATTACK!  ⚠️",
        "ca_line_ip":       "  🌐 IP Address      : {ip}",
        "ca_line_attempts": "  📊 Failed attempts : {count} in {window}s",
        "ca_line_type":     "  🔌 Attack type     : {type}",
        "ca_line_users":    "  👤 Usernames       : {users}",
        "ca_line_source":   "  📁 Log source      : {source}",
        "ca_line_time":     "  🕐 Detected at     : {ts}",
        "ca_line_geo":      "  🗺  Geolocation     : {geo}",
        "ca_line_isp":      "  🏢 ISP / Org       : {isp}",
        "ca_breach":        "  ‼ POSSIBLE BREACH — check account immediately!",
        # ── discord_alert.py ─────────────────────────────────────────────────
        "dc_title_crit": "🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE!",
        "dc_title_warn": "⚠️ WARNING! POTENTIAL BRUTE FORCE DETECTED!",
        "dc_desc_crit":  "IP address **{ip}** likely **successfully took over an account** after {count} failed attempts.",
        "dc_desc_warn":  "IP address **{ip}** made **{count} failed login attempts** in **{window} seconds**.",
        "dc_f_ip":       "🌐 IP Address",
        "dc_f_attempts": "📊 Attempt count",
        "dc_f_window":   "⏱ Time window",
        "dc_f_type":     "🔌 Attack type",
        "dc_f_users":    "👤 Usernames",
        "dc_f_source":   "📁 Log source",
        "dc_f_geo":      "🗺 Geolocation",
        "dc_f_isp":      "🏢 ISP / Org",
        # ── slack_alert.py ───────────────────────────────────────────────────
        "sl_title_crit": "🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE!",
        "sl_title_warn": "⚠️ WARNING! POTENTIAL BRUTE FORCE DETECTED!",
        "sl_summ_crit":  "IP `{ip}` likely *successfully took over an account* after {count} failed attempts.",
        "sl_summ_warn":  "IP `{ip}` made *{count} failed login attempts* in *{window} seconds*.",
        "sl_f_ip":       "*🌐 IP Address:*",
        "sl_f_attempts": "*📊 Attempts:*",
        "sl_f_type":     "*🔌 Attack type:*",
        "sl_f_users":    "*👤 Usernames:*",
        "sl_f_source":   "*📁 Log source:*",
        "sl_f_time":     "*🕐 Time:*",
        "sl_f_geo":      "*🗺 Location:*",
        "sl_f_isp":      "*🏢 ISP:*",
        "sl_fallback":   "[BRUTE-FORCE] IP {ip} — {count} attempts in {window}s",
        # ── log_monitor.py ───────────────────────────────────────────────────
        "lm_monitoring":    "Monitoring: %s  (parser: %s)",
        "lm_no_file":       "File not found: %s — waiting…",
        "lm_ready":         "Ready to read: %s",
        "lm_rotated":       "Log rotated: %s",
        "lm_truncated":     "File truncated: %s",
        "lm_read_err":      "Read error %s: %s",
        "lm_parse_err":     "Parse error: %s",
        "lm_alert_err":     "Alert callback error: %s",
        "lm_unknown_parser":"Unknown parser: %s",
        "lm_no_files":      "No log files to monitor.",
        "lm_started":       "Monitor started — %d file(s).",
        "lm_dispatch_err":  "Handler error: %s",
        # ── alerts/__init__.py ───────────────────────────────────────────────
        "fmt_attacks":  "attempts",
        "fmt_window":   "window",
        "fmt_type":     "type",
        "fmt_users":    "usernames",
    },
}

_state: dict = {"lang": "en"}


def get_T() -> dict:
    """Return the current active translation dictionary."""
    return STRINGS[_state["lang"]]


def set_lang(lang: str) -> None:
    """Switch the active language. All subsequent get_T() calls reflect the change."""
    if lang not in STRINGS:
        raise ValueError(f"Unsupported language: {lang!r}. Choose from: {list(STRINGS)}")
    _state["lang"] = lang


def detect_lang_flag() -> Optional[str]:
    """Scan sys.argv for --lang without running the full argparser."""
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg.startswith("--lang="):
            val = arg.split("=", 1)[1]
            if val in STRINGS:
                return val
        elif arg == "--lang" and i + 1 < len(argv):
            val = argv[i + 1]
            if val in STRINGS:
                return val
    return None


def select_language() -> str:
    """Prompt the user to choose a language interactively and return 'pl' or 'en'."""
    prompt = "  Wybierz język / Choose language:\n  [1] Polski  [2] English  (default: 2)\n  > "
    while True:
        try:
            choice = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "en"
        if choice == "1":
            return "pl"
        if choice in ("2", ""):
            return "en"
