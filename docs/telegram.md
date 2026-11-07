# Telegram Channel Scraping

The Telegram scraper monitors public channels for keyword hits using the same keyword engine as the dark web crawler.

This page covers the background scraper. The **Channel Monitor** tab (on-demand export of one public channel, with its own session, limits and job states) is described in [TELEGRAM.md](../TELEGRAM.md).

## Prerequisites

1. **Get API credentials** at [https://my.telegram.org/apps](https://my.telegram.org/apps)
   - Log in with your phone number
   - Create a new application (name/description can be anything)
   - Copy your **API ID** and **API Hash**

2. **Add credentials to `.env`**:
   ```
   TELEGRAM_API_ID=12345678
   TELEGRAM_API_HASH=abcdef1234567890abcdef1234567890
   TELEGRAM_CHANNELS=channel1,channel2,channel3
   ```

3. **Authenticate once** (interactive — requires phone + OTP):
   ```bash
   docker compose exec dashboard python -m darkweb_scanner.main telegram-auth
   ```
   This saves a session file to `/app/data/telegram.session`. You only need to do this once — the session persists across restarts.

## Running a Scan

```bash
# Scan all channels configured in TELEGRAM_CHANNELS
docker compose exec dashboard python -m darkweb_scanner.main telegram-scan

```

## How It Works

- Reads the last `TELEGRAM_LIMIT_PER_CHANNEL` messages (default: 200) from each channel
- Runs every message through the same keyword scanner used for .onion crawling
- Hits are stored in the same database and appear in the Keyword Hits tab
- Source URLs are formatted as `https://t.me/channelname/message_id` for easy lookup

## Notes

- Only **public** channels work — private channels require membership and are not supported
- Telethon uses your personal Telegram account — use a dedicated account for scanning
- Flood limits: Telegram rate-limits heavy usage; the scraper includes polite delays
- The session file contains your auth token — keep `/app/data/` secure and never commit it

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
