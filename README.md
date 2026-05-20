# BRUTU$ 🛡️

> Because every random Shodan crawler thinks your SSH is their personal playground.

**BRUTU$** monitors SSH and RDP logs in real time, counts failed logins per IP, and the moment some guy crosses the threshold — you get a ping on Discord/Slack before you even finish your coffee. GeoIP included, so you know exactly which country they're coming from.

```
 ██████╗ ██████╗ ██╗   ██╗████████╗██╗   ██╗███████╗
 ██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██║   ██║██╔════╝
 ██████╔╝██████╔╝██║   ██║   ██║   ██║   ██║███████╗
 ██╔══██╗██╔══██╗██║   ██║   ██║   ██║   ██║╚════██║
 ██████╔╝██║  ██║╚██████╔╝   ██║   ╚██████╔╝███████║
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚══════╝  $  v1.2.0
```

---

## What it does

| Feature | Description |
|---|---|
| 🔍 **Real-time monitoring** | Tails log files just like `tail -f` — reacts in a fraction of a second |
| 🐧 **Linux SSH** | Parses `/var/log/auth.log` and `/var/log/secure` (regex on syslog format) |
| 🪟 **Windows RDP** | Reads `.evtx` files (Event ID 4625 / 4624) or live Windows Event Log |
| 🧠 **Sliding window** | Counts attempts in a rolling time window — no false alarms on restarts |
| 🚨 **Brute + breach** | If a successful login appears AFTER a series of failures, you get a CRITICAL alert |
| 🌍 **GeoIP — offline** | Country, city, ISP via local **GeoLite2-City.mmdb** — no internet, no API key, no data leaving your server |
| 🌐 **GeoIP — online fallback** | Falls back to [ip-api.com](http://ip-api.com) if no local database is configured |
| 💬 **Discord** | Rich embeds — orange = warning, red = breach |
| 💬 **Slack** | Block Kit — looks professional even at 3 AM |
| 📄 **JSON reports** | Every alert is saved to `.jsonl` — pipe it into a SIEM or just keep the history |
| ✅ **IP whitelist** | Your home network / VPN / CI won't trigger false alarms |
| 🔕 **Cooldown** | Same IP won't flood you with 500 notifications — one alert per X minutes |
| 🧪 **Test mode** | `--test` generates a simulated attack and fires alerts to your real webhooks |
| 🔫 **Password spray** | Detects credential-stuffing (one IP → many different usernames) |
| 🚫 **IP blocker** | Automatically adds iptables DROP rules for detected attackers (requires root) |

---

## Installation

```bash
git clone https://github.com/sp0ko/BRUTU.git
cd BRUTU
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Linux — log file permissions

```bash
# Ubuntu/Debian
sudo usermod -aG adm $USER
# RHEL/CentOS
sudo usermod -aG adm $USER

# or just run with sudo
sudo python main.py
```

---

## Quick start

### 1. Configure `config.yaml`

```yaml
detection:
  threshold: 5       # how many failures trigger an alert
  time_window: 60    # within how many seconds

log_files:
  - path: /var/log/auth.log
    type: linux_ssh
    enabled: true

discord:
  enabled: true
  webhook_url: "https://discord.com/api/webhooks/YOUR_URL"

slack:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/YOUR_URL"
```

### 2. Run it

```bash
python main.py
```

### 3. Test your webhooks before anything goes wrong

```bash
python main.py --test
```

---

## CLI reference

```
python main.py [options]

  --config PATH         Custom config file path
  --log PATH            Additional log file to monitor
  --type TYPE           Parser: linux_ssh | windows_evtx
  --threshold N         Number of attempts to trigger an alert
  --window N            Time window in seconds
  --cooldown N          Cooldown between alerts for the same IP
  --discord-url URL     Discord webhook (overrides config file)
  --slack-url URL       Slack webhook (overrides config file)
  --test                Simulate an attack — tests webhooks end-to-end
  --stats               Show active IPs and exit
  --blocked             Show blocked IPs report and exit
  --geoip-db PATH       Path to GeoLite2-City.mmdb for offline geolocation
  --version             Show version
```

### Examples

```bash
# Lower threshold, shorter window
python main.py --threshold 3 --window 30

# Pass webhook from CLI (e.g. for quick testing)
python main.py --discord-url "https://discord.com/api/webhooks/..."

# Monitor a specific file
python main.py --log /var/log/secure --type linux_ssh

# Use offline GeoLite2 database (no internet needed for geolocation)
python main.py --geoip-db /opt/GeoLite2-City.mmdb

# Show blocked IP report
python main.py --blocked
```

---

## Password spray detection

BRUTUS tracks not only the number of failed attempts per IP, but also the **number of unique usernames** tried. When one IP tries more than `spray_username_threshold` different usernames it is classified as a **PASSWORD_SPRAY** attack.

Configure in `config.yaml`:

```yaml
detection:
  spray_username_threshold: 8   # unique usernames before spray alert
```

---

## Active IP blocking (iptables)

When `blocker.enabled: true`, BRUTUS automatically adds **iptables DROP rules** for every detected attacker. Works on Linux with `CAP_NET_ADMIN` (typically run as root or via `sudo`).

> **Warning**: This modifies live iptables rules. All rules are removed on clean shutdown via `unblock_all()`. Test with `dry_run: true` first.

```yaml
blocker:
  enabled: false          # set true to activate (requires root)
  auto_unblock_after: 3600  # seconds before automatic unblock; 0 = permanent
  state_file: reports/blocked_ips.json
  dry_run: false          # set true to log without touching iptables
```

```bash
# Run with blocking enabled (requires root)
sudo python main.py

# View blocked IPs
python main.py --blocked
```

IPv6 addresses are handled via `ip6tables` automatically.

---

## Discord setup

1. Server settings → **Integrations → Webhooks → New Webhook**
2. Pick a channel, click **Copy Webhook URL**
3. Paste into `config.yaml`:
   ```yaml
   discord:
     enabled: true
     webhook_url: "https://discord.com/api/webhooks/YOUR_URL_HERE"
   ```

## Slack setup

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. **Create New App → From Scratch**
3. **Incoming Webhooks → Activate → Add New Webhook to Workspace**
4. Pick a channel, copy the URL → paste into `config.yaml`

---

## Example alerts

**Terminal — standard brute-force:**
```
══════════════════════════════════════════════════════════════════════
          ⚠️  WARNING! POTENTIAL BRUTE FORCE DETECTED!  ⚠️
══════════════════════════════════════════════════════════════════════
  🌐 IP Address      : 203.0.113.42
  📊 Failed attempts : 8 in 60s
  🔌 Attack type     : SSH
  👤 Usernames tried : root, admin, Administrator
  📁 Log source      : /var/log/auth.log
  🕐 Detected at     : 2026-05-20 12:13:21
  🗺  Geolocation     : China, Beijing
  🏢 ISP / Org       : ChinaNet
══════════════════════════════════════════════════════════════════════
```

**Terminal — successful login after brute-force:**
```
══════════════════════════════════════════════════════════════════════
       🚨 CRITICAL! SUCCESSFUL LOGIN AFTER BRUTE-FORCE! 🚨
══════════════════════════════════════════════════════════════════════
  🌐 IP Address      : 192.0.2.55
  📊 Failed attempts : 5 in 60s
  ...
  ‼ POSSIBLE BREACH — check the account immediately!
══════════════════════════════════════════════════════════════════════
```

---

## Supported log formats

### `/var/log/auth.log` (Debian/Ubuntu) / `/var/log/secure` (RHEL)

Detected patterns:
- `Failed password for [invalid user] X from IP`
- `Invalid user X from IP`
- `Disconnected from invalid user X IP [preauth]`
- `pam_unix(sshd:auth): authentication failure`
- `xrdp-sesman: Authentication failed` (Linux RDP via xRDP)
- `Accepted password/publickey for X from IP` (successful login)

### Windows Event Log (`.evtx`)

- **4625** — failed logon
- **4624** — successful logon
- **4648** — logon using explicit credentials
- LogonType **10** = RemoteInteractive (RDP), **7** = Unlock (RDP-related)

---

## Project structure

```
BRUTU/
├── main.py                    ← entry point, CLI, alert dispatcher
├── config.yaml                ← all configuration lives here
├── requirements.txt
├── tests/
│   ├── test_tracker.py        ← sliding-window unit tests
│   └── test_parsers.py        ← log parser unit tests
├── detector/
│   ├── tracker.py             ← thread-safe sliding-window counter
│   ├── log_monitor.py         ← file-tailing threads
│   ├── report_manager.py      ← JSONL report writer
│   ├── parsers/
│   │   ├── linux_ssh.py       ← regex parser for auth.log
│   │   └── windows_evtx.py    ← EVTX parser + live win32evtlog
│   └── alerts/
│       ├── console_alert.py   ← colored terminal output
│       ├── discord_alert.py   ← Discord Rich Embeds
│       └── slack_alert.py     ← Slack Block Kit
└── utils/
    ├── geo.py                 ← GeoIP with cache and rate limiting
    └── ip_utils.py            ← CIDR whitelist parsing
```

---

## Requirements

- Python **3.8+**
- `requests`, `pyyaml`, `colorama` (all in `requirements.txt`)
- Windows EVTX static files: `pip install python-evtx`
- Windows live Event Log: `pip install pywin32` (Windows only)

---

## Security notes

- Keep your webhook URLs in `config.yaml` and **do not commit it to a public repo** — add it to `.gitignore` or use environment variables
- IP whitelist prevents false alarms from your own network
- Cooldown prevents notification spam from persistent attackers

---

## License

MIT — do whatever you want, but if something breaks it's on you 🤷
