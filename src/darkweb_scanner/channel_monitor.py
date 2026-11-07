import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from deep_translator import GoogleTranslator
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from langdetect import LangDetectException, detect
from telethon import TelegramClient
from telethon import errors as tg_errors
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

logger = logging.getLogger(__name__)

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

MB = 1024 ** 2
GB = 1024 ** 3

# The dashboard never signs in by itself (that makes Telegram send a login
# code). An administrator does it once from a terminal with this command.
AUTH_COMMAND          = "docker compose exec dashboard python -m darkweb_scanner.main channel-monitor-auth"
SESSION_NOT_SIGNED_IN = f"The Telegram session is not signed in. On the server, run: {AUTH_COMMAND}"
# ───────────────────────────────────────────────────────────────────────────────


# ─── ERRORS SHOWN TO THE USER ──────────────────────────────────────────────────
def log_exception(what: str) -> str:
    """Log the exception being handled, with its traceback, under a new error id.

    Returns the id (8 hex characters). Job logs and API answers show a plain
    sentence and this id, never the exception text.
    """
    error_id = secrets.token_hex(4)
    logger.exception("%s [error_id=%s]", what, error_id)
    return error_id


def telegram_error_text(exc) -> str | None:
    """A plain sentence for the Telegram errors an administrator can act on, else None."""
    if isinstance(exc, tg_errors.FloodWaitError):
        seconds = getattr(exc, "seconds", None)
        wait = f"{seconds} seconds" if isinstance(seconds, int) else "a while"
        return f"Telegram asked this account to wait {wait} before more requests. Try again later."
    if isinstance(exc, (tg_errors.UnauthorizedError, tg_errors.AuthKeyError)):
        return f"Telegram no longer accepts the session. On the server, run: {AUTH_COMMAND}"
    return None

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
def check_disk_space(min_gb: float, path: str = "/", log=print) -> None:
    total, used, free = shutil.disk_usage(path)
    free_gb  = free  / GB
    total_gb = total / GB
    used_pct = (used / total) * 100
    log(f"[i] Disk space — Free: {free_gb:.2f} GB / Total: {total_gb:.2f} GB ({used_pct:.1f}% used)")
    if free_gb < min_gb:
        raise RuntimeError(
            f"ABORT: Less than {min_gb} GB free ({free_gb:.2f} GB remaining)."
        )


def assert_disk_space(min_gb: float, path: str = "/", log=print) -> bool:
    free = shutil.disk_usage(path).free / GB
    if free < min_gb:
        log(f"[✗] CRITICAL: Disk space dropped below {min_gb:g} GB ({free:.2f} GB free). Stopping.")
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
        help=f"Messages to fetch per channel (default: {LIMIT})"
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

# What the export shows in place of a translation that failed.
TRANSLATION_FAILED = "[Translation failed]"


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
        # The reason stays in the server log; the export only says that it failed.
        logger.warning("Channel Monitor: translation from %s failed: %s", source_lang, type(e).__name__)
        return TRANSLATION_FAILED


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
def _photo_bytes(photo) -> int:
    """Size of the largest version of a photo as Telegram states it; 0 when it does not."""
    best = 0
    for size in getattr(photo, "sizes", None) or []:
        best = max(best, getattr(size, "size", 0) or 0, *(getattr(size, "sizes", None) or []))
    return best


async def _save_media(client, message, media_dir, filename, max_bytes=None):
    """Download a message's media under a name chosen here.

    Returns (report path, bytes on disk). The path is None when nothing was
    saved, and also when the file turned out larger than ``max_bytes``: that
    file is deleted again and its size returned.
    """
    target = media_dir / filename
    saved = await client.download_media(message, file=str(target))
    if not saved:
        return None, 0
    saved = Path(saved)
    if saved.name != filename:
        # Telethon chose another name: nothing the report cannot point at stays behind.
        if saved.parent == media_dir:
            saved.unlink(missing_ok=True)
        return None, 0
    size = target.stat().st_size
    if max_bytes is not None and size > max_bytes:
        target.unlink(missing_ok=True)
        return None, size
    return f"media/{filename}", size


async def process_channel(client, channel_id, limit, output_dir,
                           days=None, min_space_gb=1.0, max_video_mb=50,
                           forced_lang=None, skip_english=False, translate=True,
                           max_file_mb=50, max_job_gb=2.0, log=print):
    """Export one public channel into ``output_dir/<username>/``.

    ``log`` gets every progress line, one string per call. ``limit`` is the
    number of messages to read (0 or less: LIMIT). Videos up to ``max_video_mb``
    and other files up to ``max_file_mb`` are downloaded until the media of
    this run reach ``max_job_gb``; from then on the text export continues
    without media. The run stops early when less than ``min_space_gb`` of disk
    space is free.

    Returns {"messages", "media_files", "media_bytes", "stopped"}; ``stopped``
    is "disk" for a run cut short by low disk space, else None.
    """
    # Public channels only: checked on the reference before Telethon sees it,
    # and on the entity before any message is read.
    username = parse_public_channel(channel_id)
    try:
        channel = await client.get_entity(username)
    except (tg_errors.UsernameNotOccupiedError, tg_errors.UsernameInvalidError, ValueError) as e:
        # ValueError is what Telethon raises for a name nobody has.
        raise ChannelAccessError(f"Telegram has no public channel or group named @{username}.") from e
    except tg_errors.ChannelPrivateError as e:
        raise ChannelAccessError(f"@{username} is private or closed to this account.") from e
    except Exception as e:
        reason = telegram_error_text(e)
        if reason is None:
            error_id = log_exception(f"Channel Monitor: could not resolve @{username}")
            reason = f"Could not open @{username}. Error id: {error_id}"
        raise ChannelAccessError(reason) from e
    require_public_channel(channel, username)

    channel_title = getattr(channel, "title", None) or username

    channel_dir = output_dir / username
    media_dir   = channel_dir / "media"
    channel_dir.mkdir(parents=True, exist_ok=True)
    media_dir.mkdir(exist_ok=True)

    cutoff_date = None
    if days:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        log(f"[i] Fetching since: {cutoff_date.strftime('%Y-%m-%d %H:%M UTC')} ({days} days back)")

    lang_mode = f"forced={forced_lang}" if forced_lang else "auto-detect"
    log(f"[+] Processing: {channel_title} | lang: {lang_mode}")
    if not translate:
        log("[i] Translation is off for this run: no message text is sent to Google Translate")

    limit          = limit if isinstance(limit, int) and limit > 0 else LIMIT
    max_file_bytes = int(max_file_mb * MB)
    max_job_bytes  = int(max_job_gb * GB)
    results        = []
    lang_stats     = {}
    untranslated   = 0
    media_bytes    = 0      # downloaded by this run
    media_files    = 0
    media_off      = False  # True once the media of this run reach max_job_gb
    stopped        = None

    async def fetch(message, label, filename, declared, cap):
        """Download one file unless a limit says no. Returns its report path or None."""
        nonlocal media_bytes, media_files, media_off, stopped
        if media_off or stopped:
            return None
        if declared > cap:
            log(f"  [!] {label} skipped: {declared / MB:.1f} MB is over the limit of {cap / MB:g} MB")
            return None
        if media_bytes >= max_job_bytes or media_bytes + declared > max_job_bytes:
            media_off = True
            log(f"  [!] Job size limit reached ({max_job_gb:g} GB of media). "
                "No more media is downloaded; the text export continues.")
            return None
        if not assert_disk_space(min_space_gb, str(output_dir), log=log):
            stopped = "disk"
            return None
        try:
            path, size = await _save_media(client, message, media_dir, filename, cap)
        except Exception:
            error_id = log_exception(f"Channel Monitor: download of {filename} failed")
            log(f"  [!] {label} {filename} could not be downloaded. Error id: {error_id}")
            return None
        if path is None:
            if size:
                log(f"  [!] {label} {filename} removed: {size / MB:.1f} MB is over the limit of {cap / MB:g} MB")
            return None
        media_bytes += size
        media_files += 1
        log(f"  [+] {label} saved: {filename} ({size / MB:.1f} MB)")
        return path

    async for message in client.iter_messages(channel, limit=limit):

        if len(results) >= limit:
            break

        if cutoff_date and message.date < cutoff_date:
            log("  [i] Reached cutoff date. Stopping.")
            break

        if not assert_disk_space(min_space_gb, str(output_dir), log=log):
            log(f"  [i] Partial results saved up to #{message.id}")
            stopped = "disk"
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
                if entry["translated_en"] == TRANSLATION_FAILED:
                    untranslated += 1

        # ── MEDIA ──────────────────────────────────────────────────────────────
        if message.media:
            if isinstance(message.media, MessageMediaPhoto):
                entry["media_type"] = "photo"
                entry["media_path"] = await fetch(
                    message, "Photo", f"{int(message.id)}.jpg",
                    _photo_bytes(getattr(message.media, "photo", None)), max_file_bytes,
                )

            elif isinstance(message.media, MessageMediaDocument):
                doc  = message.media.document
                mime = str(getattr(doc, "mime_type", "") or "")
                size = getattr(doc, "size", 0) or 0

                # The file limit holds for every document that is downloaded,
                # whatever MIME type its uploader gave it; videos have their own.
                if mime.startswith("image/"):
                    entry["media_type"] = "image_doc"
                    entry["media_path"] = await fetch(
                        message, "Image", media_filename(message.id, mime), size, max_file_bytes,
                    )

                elif mime.startswith("video/"):
                    entry["media_type"] = "video"
                    if max_video_mb == 0:
                        log("  [i] Video skipped (videos are off for this run)")
                    else:
                        entry["media_path"] = await fetch(
                            message, "Video", media_filename(message.id, mime), size, int(max_video_mb * MB),
                        )
                else:
                    entry["media_type"] = f"document ({mime})"

            elif isinstance(message.media, MessageMediaWebPage):
                wp = message.media.webpage
                entry["media_type"] = "webpage"
                entry["media_url"]  = getattr(wp, "url", None)

        results.append(entry)
        lang_label = get_lang_display(entry["detected_lang"])
        log(f"  [MSG {message.id}] {entry['date']} | {lang_label} | {entry['media_type'] or 'text'}")

        if stopped:
            log(f"  [i] Partial results saved up to #{message.id}")
            break

    # ── SAVE OUTPUTS ───────────────────────────────────────────────────────────
    json_path = channel_dir / "messages.json"
    html_path = channel_dir / "messages.html"

    with open(json_path, "w", encoding="utf-8", errors="replace") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    generate_html(results, channel_title, html_path)

    # Summary and language breakdown
    log(f"  [✓] {len(results)} messages saved, {media_files} media file(s), {media_bytes / MB:.1f} MB")
    if untranslated:
        log(f"  [!] Translation failed for {untranslated} message(s); the report marks them")
    if lang_stats:
        log("  [i] Language breakdown:")
        for lang, count in sorted(lang_stats.items(), key=lambda x: -x[1]):
            log(f"       {get_lang_display(lang):<30} {count} messages")

    return {
        "messages":    len(results),
        "media_files": media_files,
        "media_bytes": media_bytes,
        "stopped":     stopped,
    }


# ─── SIGN-IN (TERMINAL ONLY) ───────────────────────────────────────────────────
def session_file(data_dir=None) -> Path:
    """Where the dashboard keeps the Channel Monitor's Telegram session."""
    base = Path(data_dir or os.getenv("DATA_DIR", "/app/data"))
    return base / "channel_monitor" / f"{SESSION_NAME}.session"


async def interactive_auth(api_id: int, api_hash: str, phone=None, session_path=None) -> None:
    """Sign the Channel Monitor's session in from a terminal.

    Called by: python -m darkweb_scanner.main channel-monitor-auth. This is the
    only place that may make Telegram send a login code; a job started from the
    dashboard uses the session as it finds it. Signing in again when the
    session is still valid asks for nothing.
    """
    path = Path(session_path) if session_path else session_file()
    path.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 55}")
    print("  Channel Monitor: Telegram sign-in")
    print(f"{'=' * 55}")
    print(f"  Session file: {path}")
    print()

    # The session file holds the account's key: readable by its owner only.
    old_umask = os.umask(0o077)
    try:
        client = TelegramClient(str(path.with_suffix("")), api_id, api_hash)
        if phone:
            await client.start(phone=phone)
        else:
            await client.start()
        me = await client.get_me()
        await client.disconnect()
    finally:
        os.umask(old_umask)
    os.chmod(path, 0o600)

    print(f"\nSigned in as: {me.first_name} (@{me.username})")
    print(f"Session saved to: {path} (mode 600)")
    print("Channel Monitor jobs can be started from the dashboard now.")


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
