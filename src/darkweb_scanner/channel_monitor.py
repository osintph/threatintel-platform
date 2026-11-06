import argparse
import asyncio
import json
import os
import re
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deep_translator import GoogleTranslator
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from langdetect import LangDetectException, detect
from telethon import TelegramClient
from telethon.helpers import add_surrogate
from telethon.tl.types import (
    Channel,
    MessageEntityBold,
    MessageEntityCode,
    MessageEntityHashtag,
    MessageEntityItalic,
    MessageEntityMention,
    MessageEntityPre,
    MessageEntityTextUrl,
    MessageEntityUrl,
    MessageMediaDocument,
    MessageMediaPhoto,
    MessageMediaWebPage,
)

# ─── CONFIG ────────────────────────────────────────────────────────────────────
load_dotenv()

# Read here, converted in main(): the dashboard passes its own credentials and
# must be able to import this module when none are set.
API_ID        = os.getenv("TELEGRAM_API_ID")
API_HASH      = os.getenv("TELEGRAM_API_HASH")
PHONE         = os.getenv("TELEGRAM_PHONE")
SESSION_NAME  = "channel_monitor"
LIMIT         = 200

OUTPUT_DIR    = Path("output")
TEMPLATE_DIR  = Path(__file__).parent / "templates"
# ───────────────────────────────────────────────────────────────────────────────

# ─── LANGUAGE CONFIG ───────────────────────────────────────────────────────────
SUPPORTED_LANGUAGES = {
    "fa": {"name": "Farsi",              "flag": "🇮🇷"},
    "ru": {"name": "Russian",            "flag": "🇷🇺"},
    "zh-cn": {"name": "Chinese (Simplified)",  "flag": "🇨🇳"},
    "zh-tw": {"name": "Chinese (Traditional)", "flag": "🇹🇼"},
    "ko": {"name": "Korean",             "flag": "🇰🇵"},
    "ar": {"name": "Arabic",             "flag": "🇸🇦"},
    "uk": {"name": "Ukrainian",          "flag": "🇺🇦"},
    "de": {"name": "German",             "flag": "🇩🇪"},
    "fr": {"name": "French",             "flag": "🇫🇷"},
    "es": {"name": "Spanish",            "flag": "🇪🇸"},
    "en": {"name": "English",            "flag": "🇬🇧"},
}

LANG_DISPLAY = {
    "fa": "🇮🇷 Farsi",
    "ru": "🇷🇺 Russian",
    "zh-cn": "🇨🇳 Chinese (Simplified)",
    "zh-tw": "🇹🇼 Chinese (Traditional)",
    "ko": "🇰🇵 Korean",
    "ar": "🇸🇦 Arabic",
    "uk": "🇺🇦 Ukrainian",
    "de": "🇩🇪 German",
    "fr": "🇫🇷 French",
    "es": "🇪🇸 Spanish",
    "en": "🇬🇧 English",
}

# RTL languages
RTL_LANGUAGES = {"fa", "ar", "he", "ur"}


# ─── DISK SPACE ────────────────────────────────────────────────────────────────
def check_disk_space(min_gb: float, path: str = "/") -> None:
    total, used, free = shutil.disk_usage(path)
    free_gb  = free  / (1024 ** 3)
    total_gb = total / (1024 ** 3)
    used_pct = (used / total) * 100
    print(f"[i] Disk space — Free: {free_gb:.2f} GB / Total: {total_gb:.2f} GB ({used_pct:.1f}% used)")
    if free_gb < min_gb:
        raise RuntimeError(
            f"ABORT: Less than {min_gb} GB free ({free_gb:.2f} GB remaining)."
        )


def assert_disk_space(min_gb: float, path: str = "/") -> bool:
    free = shutil.disk_usage(path).free / (1024 ** 3)
    if free < min_gb:
        print(f"\n[✗] CRITICAL: Disk space dropped below {min_gb} GB ({free:.2f} GB free). Stopping.")
        return False
    return True


# ─── CLI ARGS ──────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Telegram Channel Monitor — multi-language auto-translation to English",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-c", "--channel",
        help="Single public channel: username, @username or https://t.me/username\nExample: --channel irna_1931"
    )
    group.add_argument(
        "-f", "--file",
        help="Path to channels file (one per line)\nFormat: channel::lang_code or just channel\nExample: --file channels.txt"
    )
    parser.add_argument(
        "-l", "--limit",
        type=int, default=LIMIT,
        help=f"Messages to fetch per channel (default: {LIMIT}, 0 = all)"
    )
    parser.add_argument(
        "-d", "--days",
        type=int, default=None,
        help="Only fetch messages from last N days\nExample: --days 7"
    )
    parser.add_argument(
        "--lang",
        type=str, default=None,
        help="Force source language code (skips auto-detect)\nExample: --lang ru\nSupported: fa, ru, zh-cn, zh-tw, ko, ar, uk\nDefault: auto-detect per message"
    )
    parser.add_argument(
        "-o", "--output",
        default="output",
        help="Output directory (default: output/)"
    )
    parser.add_argument(
        "--max-video-mb",
        type=int, default=50,
        help="Max video size in MB (default: 50, 0 = skip all)"
    )
    parser.add_argument(
        "--min-space-gb",
        type=float, default=1.0,
        help="Abort if free disk space drops below this GB (default: 1.0)"
    )
    parser.add_argument(
        "--skip-english",
        action="store_true",
        help="Skip translation if message is already detected as English"
    )
    return parser.parse_args()


# ─── CHANNEL LOADER ────────────────────────────────────────────────────────────
def load_channels(args) -> list:
    """Returns list of (channel, forced_lang_or_None) tuples."""
    if args.channel:
        return [(args.channel.strip(), args.lang)]

    path = Path(args.file)
    if not path.exists():
        print(f"[!] File not found: {args.file}")
        exit(1)

    channels = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "::" in line:
                parts = line.split("::", 1)
                channels.append((parts[0].strip(), parts[1].strip().lower()))
            else:
                channels.append((line, args.lang))  # use CLI --lang or None

    if not channels:
        print("[!] No channels found in file.")
        exit(1)

    print(f"[+] Loaded {len(channels)} channel(s) from {args.file}")
    return channels


# ─── LANGUAGE DETECTION ────────────────────────────────────────────────────────
def detect_language(text: str) -> str:
    """Detect language of text, returns language code string."""
    if not text or len(text.strip()) < 10:
        return "unknown"
    try:
        detected = detect(text)
        # Normalize Chinese variants
        if detected in ("zh-cn", "zh-tw", "zh"):
            # Simple heuristic: traditional chars tend to appear in zh-tw
            return "zh-cn"
        return detected
    except LangDetectException:
        return "unknown"


def get_lang_display(lang_code: str) -> str:
    return LANG_DISPLAY.get(lang_code, f"🌐 {lang_code.upper()}")


def is_rtl(lang_code: str) -> bool:
    return lang_code in RTL_LANGUAGES


# ─── TRANSLATION ───────────────────────────────────────────────────────────────
_translator_cache = {}

def get_translator(source_lang: str) -> GoogleTranslator:
    """Cache translator instances per language."""
    if source_lang not in _translator_cache:
        _translator_cache[source_lang] = GoogleTranslator(
            source=source_lang, target="en"
        )
    return _translator_cache[source_lang]


def translate_text(text: str, source_lang: str) -> str:
    if not text or not text.strip():
        return ""
    if source_lang in ("en", "unknown"):
        return text  # Already English or undetectable

    try:
        translator  = get_translator(source_lang)
        chunk_size  = 4500
        if len(text) <= chunk_size:
            return translator.translate(text)
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        return " ".join([translator.translate(c) for c in chunks])
    except Exception as e:
        return f"[Translation error: {e}]"


# ─── PUBLIC CHANNELS ONLY ──────────────────────────────────────────────────────
class ChannelNotAllowed(ValueError):
    """The reference, or what it resolved to, is not a public channel."""


class ChannelAccessError(RuntimeError):
    """Telegram could not resolve the channel."""


# Telegram's rule for public usernames: 5 to 32 characters, letters, digits and
# underscores, starting with a letter.
_CHANNEL_REF_RE = re.compile(
    r"(?:@|(?:https?://)?(?:www\.)?(?:t|telegram)\.me/(?:s/)?)?"
    r"(?P<name>[A-Za-z][A-Za-z0-9_]{4,31})/?"
)


def parse_public_channel(ref) -> str:
    """Return the username from ``name``, ``@name`` or ``https://t.me/name``.

    Telethon's get_entity() also resolves ``me``, phone numbers, numeric ids,
    invite links and exact chat titles, which reach the account's private
    chats. None of those match here, so none of them reach Telethon.
    """
    if isinstance(ref, str) and len(ref) <= 100:
        match = _CHANNEL_REF_RE.fullmatch(ref.strip())
        if match:
            return match.group("name")
    raise ChannelNotAllowed(
        "Only public channels can be monitored. Enter the channel as name, @name or https://t.me/name."
    )


def require_public_channel(entity, username: str) -> None:
    """Refuse whatever is not a public broadcast channel or public group."""
    if not isinstance(entity, Channel):
        raise ChannelNotAllowed(
            f"@{username} is not a channel ({type(entity).__name__}). Only public channels can be monitored."
        )
    names = [getattr(entity, "username", None)]
    names += [getattr(u, "username", None) for u in (getattr(entity, "usernames", None) or [])]
    if not any(names):
        raise ChannelNotAllowed(f"@{username} is a private channel. Only public channels can be monitored.")
    if not (entity.broadcast or entity.megagroup or getattr(entity, "gigagroup", False)):
        raise ChannelNotAllowed(f"@{username} is not a broadcast channel or public group.")


# ─── LINKS AND MEDIA FILES ─────────────────────────────────────────────────────
LINK_SCHEMES = ("http", "https", "tg")
_SCHEME_RE   = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")


def safe_link(url):
    """Return ``url`` if the report may link to it, else None (it is shown as text)."""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url or len(url) > 2048 or any(c.isspace() or not c.isprintable() for c in url):
        return None
    scheme, colon, _ = url.partition(":")
    if colon and _SCHEME_RE.fullmatch(scheme):
        return url if scheme.lower() in LINK_SCHEMES else None
    if url[0] in "/\\?#":
        return None
    return "http://" + url  # Telegram also marks bare domains as links


# The uploader chooses the MIME string, so it only ever selects one of these
# extensions; file names are built from the message id. Anything else is saved
# as .bin, which the report links to instead of displaying.
MEDIA_EXTENSIONS = {
    "image/jpeg":      "jpg",
    "image/png":       "png",
    "image/gif":       "gif",
    "image/webp":      "webp",
    "video/mp4":       "mp4",
    "video/mpeg4":     "mp4",
    "video/webm":      "webm",
    "video/quicktime": "mov",
    "audio/mpeg":      "mp3",
    "audio/ogg":       "ogg",
    "application/pdf": "pdf",
    "text/plain":      "txt",
}
EMBED_IMAGE_EXTENSIONS = {"jpg", "png", "gif", "webp"}
EMBED_VIDEO_EXTENSIONS = {"mp4", "webm"}
_MEDIA_PATH_RE = re.compile(r"media/[0-9]+\.[a-z0-9]{1,5}")


def media_extension(mime) -> str:
    return MEDIA_EXTENSIONS.get(str(mime or "").split(";")[0].strip().lower(), "bin")


def media_filename(message_id, mime) -> str:
    return f"{int(message_id)}.{media_extension(mime)}"


# ─── ENTITY FORMATTER ──────────────────────────────────────────────────────────
_ENTITY_STYLES = (
    (MessageEntityBold,    "bold"),
    (MessageEntityItalic,  "italic"),
    (MessageEntityCode,    "code"),
    (MessageEntityPre,     "pre"),
    (MessageEntityMention, "mention"),
    (MessageEntityHashtag, "hashtag"),
)
_STYLE_NAMES = {style for _, style in _ENTITY_STYLES}


def _from_utf16(units: str) -> str:
    """Undo add_surrogate(); half a surrogate pair (a bad offset) becomes U+FFFD."""
    return units.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


def build_segments(text: str, entities) -> list:
    """Split raw message text at entity boundaries, for the report template.

    Returns [{"text", "styles", "href"}]: plain values, no markup. The template
    escapes each one. Telegram counts entity offsets in UTF-16 code units.
    """
    if not text:
        return []
    units = add_surrogate(text)
    spans = []
    for ent in entities or []:
        start, length = getattr(ent, "offset", None), getattr(ent, "length", None)
        if not isinstance(start, int) or not isinstance(length, int):
            continue
        start, end = max(0, start), min(len(units), start + length)
        if start >= end:
            continue
        if isinstance(ent, MessageEntityTextUrl):
            spans.append((start, end, None, safe_link(getattr(ent, "url", None))))
        elif isinstance(ent, MessageEntityUrl):
            spans.append((start, end, None, safe_link(_from_utf16(units[start:end]))))
        else:
            for cls, style in _ENTITY_STYLES:
                if isinstance(ent, cls):
                    spans.append((start, end, style, None))
                    break

    cuts = sorted({0, len(units)} | {p for s, e, _, _ in spans for p in (s, e)})
    segments = []
    for a, b in zip(cuts, cuts[1:]):
        inside = [(style, href) for s, e, style, href in spans if s <= a and b <= e]
        segments.append({
            "text":   _from_utf16(units[a:b]),
            "styles": sorted({style for style, _ in inside if style}),
            "href":   next((href for _, href in inside if href), None),
        })
    return segments


# ─── HTML GENERATOR ────────────────────────────────────────────────────────────
# Auto-escaping is on for every template and every value. Nothing from Telegram
# is ever marked safe; see templates/channel_report.html.
_report_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)


def _report_media(m: dict) -> dict:
    """How the report shows a message's media: {"kind", "src", "label"}."""
    media_type = str(m.get("media_type") or "")
    path       = str(m.get("media_path") or "")

    if media_type == "webpage":
        url = m.get("media_url")
        if not url:
            return {"kind": None}
        href = safe_link(url)
        return {"kind": "link" if href else "note", "src": href, "label": str(url)}

    if media_type in ("photo", "image_doc", "video"):
        if not path:
            label = "🎥 Video (skipped)" if media_type == "video" else ""
            return {"kind": "note" if label else None, "label": label}
        if not _MEDIA_PATH_RE.fullmatch(path):
            return {"kind": "note", "label": f"[media file: {path}]"}
        ext = path.rsplit(".", 1)[-1]
        if media_type != "video" and ext in EMBED_IMAGE_EXTENSIONS:
            return {"kind": "image", "src": path, "label": "photo" if media_type == "photo" else "image"}
        if media_type == "video" and ext in EMBED_VIDEO_EXTENSIONS:
            return {"kind": "video", "src": path}
        return {"kind": "file", "src": path, "label": f"Attachment ({path})"}

    return {"kind": None}


def _report_segments(m: dict) -> list:
    """The message's segments, re-checked: the caller's dict is not trusted either."""
    segments = m.get("segments")
    if not isinstance(segments, list):
        return build_segments(str(m.get("original") or ""), None)
    return [
        {
            "text":   str(seg.get("text") or ""),
            "styles": sorted(_STYLE_NAMES.intersection(seg.get("styles") or ())),
            "href":   safe_link(seg.get("href")),
        }
        for seg in segments if isinstance(seg, dict)
    ]


def _report_message(m: dict) -> dict:
    lang_code  = str(m.get("detected_lang") or "unknown")
    segments   = _report_segments(m)
    translated = str(m.get("translated_en") or "")
    return {
        "id":           m.get("id"),
        "date":         m.get("date"),
        "views":        m.get("views"),
        "reply_to":     m.get("reply_to"),
        "lang_display": get_lang_display(lang_code),
        "dir":          "rtl" if is_rtl(lang_code) else "ltr",
        "segments":     segments,
        "translated":   translated if lang_code != "en" else "",
        "has_media":    bool(m.get("media_type")),
        "media":        _report_media(m),
    }


def generate_html(messages, channel_title, output_path):
    html_content = _report_env.get_template("channel_report.html").render(
        channel_title=str(channel_title),
        messages=[_report_message(m) for m in reversed(messages)],
    )
    with open(output_path, "w", encoding="utf-8", errors="replace") as f:
        f.write(html_content)


# ─── CHANNEL PROCESSOR ─────────────────────────────────────────────────────────
async def _save_media(client, message, media_dir, filename):
    """Download a message's media under a name chosen here. Returns its report path or None."""
    saved = await client.download_media(message, file=str(media_dir / filename))
    if not saved or Path(saved).name != filename:
        return None
    return f"media/{filename}"


async def process_channel(client, channel_id, limit, output_dir,
                           days=None, min_space_gb=1.0, max_video_mb=50,
                           forced_lang=None, skip_english=False, translate=True):
    # Public channels only: checked on the reference before Telethon sees it,
    # and on the entity before any message is read.
    username = parse_public_channel(channel_id)
    try:
        channel = await client.get_entity(username)
    except Exception as e:
        raise ChannelAccessError(f"Could not access @{username}: {e}") from e
    require_public_channel(channel, username)

    channel_title = getattr(channel, "title", None) or username

    channel_dir = output_dir / username
    media_dir   = channel_dir / "media"
    channel_dir.mkdir(parents=True, exist_ok=True)
    media_dir.mkdir(exist_ok=True)

    cutoff_date = None
    if days:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        print(f"[i] Fetching since: {cutoff_date.strftime('%Y-%m-%d %H:%M UTC')} ({days} days back)")

    lang_mode = f"forced={forced_lang}" if forced_lang else "auto-detect"
    print(f"\n[+] Processing: {channel_title} | lang: {lang_mode}")
    if not translate:
        print("[i] Translation is off for this run: no message text is sent to Google Translate")

    results     = []
    fetch_limit = None if limit == 0 else limit
    lang_stats  = {}

    async for message in client.iter_messages(channel, limit=fetch_limit):

        if cutoff_date and message.date < cutoff_date:
            print("  [i] Reached cutoff date. Stopping.")
            break

        if not assert_disk_space(min_space_gb, str(output_dir)):
            print(f"  [i] Partial results saved up to #{message.id}")
            break

        # raw_text, not text: the entity offsets belong to it, and it carries
        # no markup added by Telethon.
        text  = message.raw_text or ""
        entry = {
            "id":             message.id,
            "date":           message.date.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "original":       text,
            "translated_en":  "",
            "segments":       [],
            "detected_lang":  "unknown",
            "forced_lang":    forced_lang,
            "media_type":     None,
            "media_path":     None,
            "media_url":      None,
            "views":          getattr(message, "views", None),
            "forwards":       getattr(message, "forwards", None),
            "reply_to":       message.reply_to_msg_id if message.reply_to else None,
        }

        if text:
            # Detect or use forced language
            if forced_lang:
                lang = forced_lang
            else:
                lang = detect_language(text)

            entry["detected_lang"] = lang
            entry["segments"]      = build_segments(text, message.entities)

            # Track language stats
            lang_stats[lang] = lang_stats.get(lang, 0) + 1

            # Translate if not already English
            if not translate:
                entry["translated_en"] = ""
            elif skip_english and lang == "en":
                entry["translated_en"] = text
            else:
                entry["translated_en"] = translate_text(text, lang)

        # ── MEDIA ──────────────────────────────────────────────────────────────
        if message.media:
            if isinstance(message.media, MessageMediaPhoto):
                entry["media_type"] = "photo"
                if assert_disk_space(min_space_gb, str(output_dir)):
                    try:
                        filename = f"{int(message.id)}.jpg"
                        entry["media_path"] = await _save_media(client, message, media_dir, filename)
                        if entry["media_path"]:
                            print(f"  [+] Photo: {filename}")
                    except Exception as e:
                        print(f"  [!] Photo error: {e}")

            elif isinstance(message.media, MessageMediaDocument):
                doc  = message.media.document
                mime = str(getattr(doc, "mime_type", "") or "")

                if mime.startswith("image/"):
                    entry["media_type"] = "image_doc"
                    if assert_disk_space(min_space_gb, str(output_dir)):
                        try:
                            filename = media_filename(message.id, mime)
                            entry["media_path"] = await _save_media(client, message, media_dir, filename)
                        except Exception as e:
                            print(f"  [!] Image error: {e}")

                elif mime.startswith("video/"):
                    entry["media_type"] = "video"
                    file_size_mb = (getattr(doc, "size", 0) or 0) / (1024 * 1024)

                    if max_video_mb == 0:
                        print("  [i] Video skipped (--max-video-mb 0)")
                    elif file_size_mb > max_video_mb:
                        print(f"  [!] Video skipped — {file_size_mb:.1f} MB > limit {max_video_mb} MB")
                    elif assert_disk_space(min_space_gb, str(output_dir)):
                        try:
                            filename = media_filename(message.id, mime)
                            print(f"  [~] Video ({file_size_mb:.1f} MB): {filename} ...")
                            entry["media_path"] = await _save_media(client, message, media_dir, filename)
                            if entry["media_path"]:
                                print(f"  [+] Video saved: {filename}")
                        except Exception as e:
                            print(f"  [!] Video error: {e}")
                else:
                    entry["media_type"] = f"document ({mime})"

            elif isinstance(message.media, MessageMediaWebPage):
                wp = message.media.webpage
                entry["media_type"] = "webpage"
                entry["media_url"]  = getattr(wp, "url", None)

        results.append(entry)
        lang_label = get_lang_display(entry["detected_lang"])
        print(f"  [MSG {message.id}] {entry['date']} | {lang_label} | {entry['media_type'] or 'text'}")

    # ── SAVE OUTPUTS ───────────────────────────────────────────────────────────
    json_path = channel_dir / "messages.json"
    html_path = channel_dir / "messages.html"

    with open(json_path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    generate_html(results, channel_title, html_path)

    # Language breakdown summary
    print(f"\n  [✓] {len(results)} messages saved → {channel_dir}/")
    if lang_stats:
        print("  [i] Language breakdown:")
        for lang, count in sorted(lang_stats.items(), key=lambda x: -x[1]):
            print(f"       {get_lang_display(lang):<30} {count} messages")
    print(f"  [✓] Open: firefox {html_path}")


# ─── MAIN ──────────────────────────────────────────────────────────────────────
async def main():
    args       = parse_args()
    channels   = load_channels(args)
    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    check_disk_space(min_gb=args.min_space_gb, path=str(output_dir))

    client = TelegramClient(SESSION_NAME, int(API_ID), API_HASH)
    await client.start(phone=PHONE)
    print(f"[+] Connected as {(await client.get_me()).username}")

    for channel_id, forced_lang in channels:
        try:
            await process_channel(
                client,
                channel_id,
                limit        = args.limit,
                output_dir   = output_dir,
                days         = args.days,
                min_space_gb = args.min_space_gb,
                max_video_mb = args.max_video_mb,
                forced_lang  = forced_lang,
                skip_english = args.skip_english,
            )
        except (ChannelNotAllowed, ChannelAccessError) as e:
            print(f"[!] Skipped '{channel_id}': {e}")

    await client.disconnect()
    print(f"\n[+] All done. Output in: {output_dir}/")


if __name__ == "__main__":
    asyncio.run(main())
