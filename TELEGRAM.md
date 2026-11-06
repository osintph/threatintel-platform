# Telegram Channel Scraping

The platform provides two complementary ways to work with Telegram channels:

1. **Channel Monitor tab** (administrators only) — interactive, on-demand scraping of any **public** channel directly from the dashboard. Fetches messages, auto-translates to English with Google Translate, downloads media, and lets you download a ZIP of the full report.
2. **Background Telegram Scraper** — automated keyword scanning of a fixed list of channels, feeding hits into the main database alongside dark web crawler results.

---

## 📡 Channel Monitor (Dashboard Tab)

### Prerequisites

Get API credentials at [https://my.telegram.org/apps](https://my.telegram.org/apps) and add them to `.env`:

```env
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=abcdef1234567890abcdef1234567890
TELEGRAM_PHONE=+639XXXXXXXXX
```

`TELEGRAM_PHONE` is your Telegram account phone number with country code. This is required for the Channel Monitor — the background scraper does not use it.

### First-time authentication

Run this once on the server to generate the session file:

```bash
cd ~/darkweb-scanner
docker compose exec dashboard python3 -c "
import asyncio
from telethon import TelegramClient
import os
from dotenv import load_dotenv
load_dotenv('/app/.env')
async def auth():
    c = TelegramClient('/app/data/channel_monitor/channel_monitor', int(os.environ['TELEGRAM_API_ID']), os.environ['TELEGRAM_API_HASH'])
    await c.start(phone=os.environ['TELEGRAM_PHONE'])
    print('Auth OK:', (await c.get_me()).username)
    await c.disconnect()
asyncio.run(auth())
"
```

Enter the OTP sent to your Telegram app when prompted. The session is saved to `/app/data/channel_monitor/channel_monitor.session` and persists across restarts — you only need to do this once.

### Using the tab

1. Click **📡 Channel Monitor** in the nav bar
2. Enter a public channel username (e.g. `irna_1931`), `@handle`, or a `t.me/name` link. Private chats, saved messages, phone numbers, numeric ids and invite links are refused
3. Configure your scan settings and click **▶ Start Scan**
4. Watch the live log — the scan runs in the background so you can navigate away
5. When the status changes to **✓ Completed**, click **⬇ Download ZIP**

### What's in the ZIP

| File | Contents |
|------|----------|
| `messages.html` | Full rendered report — original text, English translation, inline photos/videos |
| `messages.json` | Structured data for all messages: original text, translation, and the text split into `segments` (plain text, links, formatting) |
| `media/` | All downloaded photos and video files |

### Privacy, access and retention

- **Administrators only.** Other users do not see the tab, and the API refuses them. Each job records who started it.
- **Public channels only.** The name is checked before Telegram is contacted, and the resolved chat must be a public channel with a user name.
- **Google Translate.** The text of every message that is not detected as English is sent from the server to `translate.google.com` in pieces of up to 4,500 characters. No key or account is used; media, sender names, message ids and the channel name are not sent. Forcing the source language to English sends nothing. Language detection itself runs on the server.
- **Retention.** A job folder and its ZIP are deleted `CHANNEL_MONITOR_RETENTION_DAYS` days (default 90) after their last change. A running job cannot be deleted.
- **The report** shows channel content as text. It contains no scripts and loads nothing from the internet; media of a type the report does not know is saved as `.bin` and linked, not displayed.

### Scan options

| Option | Default | Description |
|--------|---------|-------------|
| Message Limit | 200 | Number of messages to fetch. 0 = all |
| Last N Days | — | Only fetch messages newer than N days ago |
| Force Source Language | Auto | Override per-message language detection |
| Max Video Size (MB) | 50 | Skip videos larger than this. 0 = skip all |
| Min Free Disk (GB) | 1.0 | Abort scan if server disk falls below this |
| Skip English translation | Off | Don't translate messages already detected as English |

### Supported languages

Auto-detection and translation supports: Farsi, Russian, Chinese (Simplified/Traditional), Korean, Arabic, Ukrainian, German, French, Spanish, and English. Any other detected language will still be passed to Google Translate.

### Notes

- Only **public** channels are supported
- Job history is held in memory and resets when the container restarts
- Output files are stored at `/app/data/channel_monitor/{job_id}/` on the server
- Use a dedicated Telegram account for scanning — not your personal account
- Telegram may rate-limit heavy usage; the scanner handles this gracefully

---

## 🔄 Background Telegram Scraper

## Recommended Channel List

The following channels are configured and monitored. Update `TELEGRAM_CHANNELS` in `.env` to add or remove:

### Breach & Data Leak Alerts
- `darkwebinformer` — Dark Web Informer breach and leak alerts
- `breachdetector` — Breach detection alerts
- `leakbase` — Leaked database announcements
- `databreaches` — Data breach news
- `exposeddb` — Exposed database announcements
- `breachalert` — General breach alerts
- `leaked_databases` — Database leak announcements
- `combo_cloud` — Combolist cloud dumps

### Credential Dumps / Combolists
- `combolistfree` — Free combolist drops
- `privatecombolists` — Private combo drops
- `cloudcombos` — Cloud credential dumps
- `freecombolists` — Free credential lists
- `accsleak` — Account leaks
- `leaked_accounts` — Leaked account dumps
- `stealerlogs_free` — Free stealer logs
- `redline_logs` — Redline stealer logs
- `raccoon_logs` — Raccoon stealer logs
- `vidar_logs` — Vidar stealer logs
- `lumma_logs` — Lumma stealer logs

### Ransomware & Malware
- `ransomwarealerts` — Ransomware attack alerts
- `ransomwatch` — Ransomware tracker updates
- `vxunderground` — Malware samples and news
- `malware_news` — Malware news aggregator
- `lockbitleaks` — LockBit victim announcements
- `alphvleaks` — ALPHV/BlackCat leaks
- `blackbastagroup` — Black Basta announcements
- `medusaransomware` — Medusa group
- `akiransomware` — Akira ransomware
- `rhysidagroup` — Rhysida ransomware
- `playransomware` — Play ransomware

### Vulnerabilities & Exploits
- `cve_new` — New CVE announcements
- `exploitalerts` — Exploit alerts
- `zerodayalerts` — Zero-day alerts
- `vulnerabilitynews` — Vulnerability news

### Dark Web News & Intel
- `darkwebdaily` — Daily dark web news
- `cyberthreatintel` — CTI aggregator
- `threatintel` — Threat intelligence feeds

### OSINT
- `osintframework` — OSINT framework updates
- `osinttechniques` — OSINT techniques

### SEA / Philippines Focused
- `phcybersecurity` — PH cybersecurity news
- `cybersecurityph` — Philippine cybersecurity
- `seacybercrime` — SEA cybercrime
- `asiacyberthreat` — Asia cyber threats
- `asiadataleaks` — Asia data leak alerts
- `sealeaks` — Southeast Asia leaks

### Threat Actor Monitoring
- `apt_news` — APT group news
- `lazarusgroup_updates` — Lazarus Group activity

The background scraper monitors a fixed list of public channels for keyword hits, feeding results into the same database as the dark web crawler.

### Prerequisites

```env
TELEGRAM_API_ID=12345678
TELEGRAM_API_HASH=abcdef1234567890abcdef1234567890
TELEGRAM_CHANNELS=channel1,channel2,channel3
```

Authenticate once (interactive — requires phone + OTP):

```bash
docker compose exec dashboard python -m darkweb_scanner.main telegram-auth
```

This saves a session file to `/app/data/telegram.session`. You only need to do this once.

### Running a Scan

```bash
# Scan all channels configured in TELEGRAM_CHANNELS
docker compose exec dashboard python -m darkweb_scanner.main telegram-scan

# Or trigger from the dashboard — Seeds tab > Telegram Channels section
```

### How It Works

- Reads the last `TELEGRAM_LIMIT_PER_CHANNEL` messages (default: 200) from each configured channel
- Runs every message through the same keyword scanner used for `.onion` crawling
- Hits are stored in the main database and appear in the Keyword Hits tab
- Source URLs are formatted as `https://t.me/channelname/message_id`

### Notes

- Only **public** channels are supported
- The session file contains your auth token — keep `/app/data/` secure and never commit it
- Telegram rate-limits heavy usage; the scraper includes polite delays
