import asyncio
import json
import os
import argparse
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from telethon import TelegramClient
from telethon.tl.types import (
    MessageMediaPhoto, MessageMediaDocument, MessageMediaWebPage
)
from deep_translator import GoogleTranslator
from langdetect import detect, LangDetectException

# ─── CONFIG ────────────────────────────────────────────────────────────────────
load_dotenv()

API_ID        = int(os.getenv("TELEGRAM_API_ID"))
API_HASH      = os.getenv("TELEGRAM_API_HASH")
PHONE         = os.getenv("TELEGRAM_PHONE")
SESSION_NAME  = "channel_monitor"
LIMIT         = 200

OUTPUT_DIR    = Path("output")
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
        help="Single channel username or invite link\nExample: --channel irna_1931"
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


# ─── ENTITY FORMATTER ──────────────────────────────────────────────────────────
def format_entities(text: str, entities) -> str:
    import html
    if not text:
        return ""
    if not entities:
        return html.escape(text).replace("\n", "<br>")

    from telethon.tl.types import (
        MessageEntityBold, MessageEntityItalic, MessageEntityCode,
        MessageEntityPre, MessageEntityUrl, MessageEntityTextUrl,
        MessageEntityMention, MessageEntityHashtag
    )

    tags = []
    for ent in entities:
        s, length = ent.offset, ent.length
        seg_esc = html.escape(text[s:s+length])
        if isinstance(ent, MessageEntityBold):
            tags.append((s, s+length, "<b>", "</b>"))
        elif isinstance(ent, MessageEntityItalic):
            tags.append((s, s+length, "<i>", "</i>"))
        elif isinstance(ent, MessageEntityCode):
            tags.append((s, s+length, "<code>", "</code>"))
        elif isinstance(ent, MessageEntityPre):
            tags.append((s, s+length, "<pre>", "</pre>"))
        elif isinstance(ent, MessageEntityTextUrl):
            tags.append((s, s+length, f'<a href="{ent.url}" target="_blank">', "</a>"))
        elif isinstance(ent, MessageEntityUrl):
            tags.append((s, s+length, f'<a href="{seg_esc}" target="_blank">', "</a>"))
        elif isinstance(ent, MessageEntityMention):
            tags.append((s, s+length, '<span class="mention">', "</span>"))
        elif isinstance(ent, MessageEntityHashtag):
            tags.append((s, s+length, '<span class="hashtag">', "</span>"))

    output = html.escape(text)
    for s, e, open_t, close_t in sorted(tags, key=lambda x: x[0], reverse=True):
        seg = html.escape(text[s:e])
        output = output[:s] + open_t + seg + close_t + output[e:]

    return output.replace("\n", "<br>")


# ─── HTML GENERATOR ────────────────────────────────────────────────────────────
def generate_html(messages, channel_title, output_path):
    html_messages = []
    for m in reversed(messages):
        media_block = ""
        if m["media_type"] == "photo" and m["media_path"]:
            media_block = f'<img src="{m["media_path"]}" class="msg-photo" alt="photo">'
        elif m["media_type"] == "image_doc" and m["media_path"]:
            media_block = f'<img src="{m["media_path"]}" class="msg-photo" alt="image">'
        elif m["media_type"] == "video" and m["media_path"]:
            media_block = f'''
            <video controls class="msg-video">
                <source src="{m["media_path"]}">
                Your browser does not support video playback.
            </video>'''
        elif m["media_type"] == "video" and not m["media_path"]:
            media_block = '<div class="media-placeholder">🎥 Video (skipped)</div>'
        elif m["media_type"] == "webpage" and m.get("media_url"):
            media_block = f'<div class="webpage-preview"><a href="{m["media_url"]}" target="_blank">🔗 {m["media_url"]}</a></div>'

        text_block   = ""
        lang_code    = m.get("detected_lang", "unknown")
        lang_display = get_lang_display(lang_code)
        text_dir     = "rtl" if is_rtl(lang_code) else "ltr"

        if m["formatted_html"]:
            already_english = lang_code == "en"
            if already_english:
                text_block = f'''
                <div class="lang-badge">{lang_display}</div>
                <div class="msg-text original" dir="{text_dir}">{m["formatted_html"]}</div>
                '''
            else:
                text_block = f'''
                <div class="lang-badge">{lang_display}</div>
                <div class="msg-text original" dir="{text_dir}">{m["formatted_html"]}</div>
                <div class="msg-divider">🔽 English Translation</div>
                <div class="msg-text translated">{m["translated_en"]}</div>
                '''
        elif not m["formatted_html"] and m["media_type"]:
            text_block = '<div class="msg-text translated" style="color:#555">[No caption]</div>'

        meta_views  = f'👁 {m["views"]}' if m["views"] else ""
        reply_badge = f'<span class="reply-badge">↩ Reply to #{m["reply_to"]}</span>' if m["reply_to"] else ""

        html_messages.append(f'''
        <div class="message" id="msg-{m["id"]}">
            <div class="msg-meta">
                <span class="msg-id">#{m["id"]}</span>
                <span class="msg-date">{m["date"]}</span>
                {reply_badge}
                <span class="msg-views">{meta_views}</span>
            </div>
            {media_block}
            {text_block}
        </div>
        ''')

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{channel_title} — Translated Monitor</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0e0e0e; color: #e0e0e0;
            max-width: 780px; margin: 0 auto; padding: 20px;
        }}
        h1 {{ color: #29b6f6; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .stats {{ color: #555; font-size: 0.85em; margin-bottom: 24px; }}
        .message {{
            background: #1a1a2e; border-radius: 10px;
            padding: 14px 18px; margin-bottom: 16px;
            border-left: 3px solid #29b6f6;
        }}
        .msg-meta {{
            font-size: 0.75em; color: #888; margin-bottom: 8px;
            display: flex; gap: 12px; flex-wrap: wrap; align-items: center;
        }}
        .msg-id {{ color: #29b6f6; font-weight: bold; }}
        .reply-badge {{ background: #1e3a5f; padding: 2px 6px; border-radius: 4px; color: #90caf9; }}
        .lang-badge {{
            display: inline-block; font-size: 0.72em;
            background: #0d2137; color: #81d4fa;
            padding: 2px 8px; border-radius: 12px;
            margin-bottom: 6px; border: 1px solid #1a4a6e;
        }}
        .msg-photo {{ max-width: 100%; border-radius: 8px; margin: 8px 0; display: block; }}
        .msg-video {{ max-width: 100%; border-radius: 8px; margin: 8px 0; display: block; background: #000; }}
        .msg-text {{ padding: 6px 0; line-height: 1.8; font-size: 0.97em; }}
        .original {{
            color: #ffcc80; font-size: 1.05em;
            border-right: 3px solid #ff8f00; padding-right: 10px;
        }}
        .original[dir="ltr"] {{
            border-right: none;
            border-left: 3px solid #ff8f00;
            padding-right: 0; padding-left: 10px;
        }}
        .msg-divider {{ color: #444; font-size: 0.75em; margin: 6px 0; }}
        .translated {{ color: #a5d6a7; }}
        .media-placeholder {{ color: #777; font-style: italic; padding: 8px 0; }}
        .webpage-preview {{
            background: #111; padding: 8px 12px;
            border-radius: 6px; margin: 6px 0; border: 1px solid #2a2a2a;
        }}
        .webpage-preview a {{ color: #29b6f6; text-decoration: none; }}
        .mention {{ color: #80cbc4; }}
        .hashtag {{ color: #ce93d8; }}
        code {{ background: #2a2a2a; padding: 2px 6px; border-radius: 3px; font-family: monospace; color: #ef9a9a; }}
        pre {{ background: #2a2a2a; padding: 12px; border-radius: 6px; overflow-x: auto; }}
        b {{ color: #ffffff; }}
        a {{ color: #29b6f6; }}
    </style>
</head>
<body>
    <h1>📡 {channel_title}</h1>
    <p class="stats">Auto-translated → English &nbsp;|&nbsp; {len(messages)} messages</p>
    {"".join(html_messages)}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)


# ─── CHANNEL PROCESSOR ─────────────────────────────────────────────────────────
async def process_channel(client, channel_id, limit, output_dir,
                           days=None, min_space_gb=1.0, max_video_mb=50,
                           forced_lang=None, skip_english=False):
    try:
        channel = await client.get_entity(channel_id)
    except Exception as e:
        print(f"[!] Could not access '{channel_id}': {e}")
        return

    channel_title = getattr(channel, "title", str(channel_id))
    safe_name     = "".join(c if c.isalnum() else "_" for c in channel_title)

    channel_dir = output_dir / safe_name
    media_dir   = channel_dir / "media"
    channel_dir.mkdir(parents=True, exist_ok=True)
    media_dir.mkdir(exist_ok=True)

    cutoff_date = None
    if days:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        print(f"[i] Fetching since: {cutoff_date.strftime('%Y-%m-%d %H:%M UTC')} ({days} days back)")

    lang_mode = f"forced={forced_lang}" if forced_lang else "auto-detect"
    print(f"\n[+] Processing: {channel_title} | lang: {lang_mode}")

    results     = []
    fetch_limit = None if limit == 0 else limit
    lang_stats  = {}

    async for message in client.iter_messages(channel, limit=fetch_limit):

        if cutoff_date and message.date < cutoff_date:
            print(f"  [i] Reached cutoff date. Stopping.")
            break

        if not assert_disk_space(min_space_gb, str(output_dir)):
            print(f"  [i] Partial results saved up to #{message.id}")
            break

        entry = {
            "id":             message.id,
            "date":           message.date.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "original":       message.text or "",
            "translated_en":  "",
            "formatted_html": "",
            "detected_lang":  "unknown",
            "forced_lang":    forced_lang,
            "media_type":     None,
            "media_path":     None,
            "media_url":      None,
            "views":          getattr(message, "views", None),
            "forwards":       getattr(message, "forwards", None),
            "reply_to":       message.reply_to_msg_id if message.reply_to else None,
        }

        if message.text:
            # Detect or use forced language
            if forced_lang:
                lang = forced_lang
            else:
                lang = detect_language(message.text)

            entry["detected_lang"]  = lang
            entry["formatted_html"] = format_entities(message.text, message.entities)

            # Track language stats
            lang_stats[lang] = lang_stats.get(lang, 0) + 1

            # Translate if not already English
            if skip_english and lang == "en":
                entry["translated_en"] = message.text
            else:
                entry["translated_en"] = translate_text(message.text, lang)

        # ── MEDIA ──────────────────────────────────────────────────────────────
        if message.media:
            if isinstance(message.media, MessageMediaPhoto):
                entry["media_type"] = "photo"
                if assert_disk_space(min_space_gb, str(output_dir)):
                    try:
                        filename = media_dir / f"{message.id}.jpg"
                        await client.download_media(message, file=str(filename))
                        entry["media_path"] = f"media/{message.id}.jpg"
                        print(f"  [+] Photo: {filename.name}")
                    except Exception as e:
                        print(f"  [!] Photo error: {e}")

            elif isinstance(message.media, MessageMediaDocument):
                doc  = message.media.document
                mime = getattr(doc, "mime_type", "")

                if mime.startswith("image/"):
                    entry["media_type"] = "image_doc"
                    ext = mime.split("/")[-1]
                    if assert_disk_space(min_space_gb, str(output_dir)):
                        try:
                            filename = media_dir / f"{message.id}.{ext}"
                            await client.download_media(message, file=str(filename))
                            entry["media_path"] = f"media/{message.id}.{ext}"
                        except Exception as e:
                            print(f"  [!] Image error: {e}")

                elif mime.startswith("video/"):
                    entry["media_type"] = "video"
                    ext = mime.split("/")[-1]
                    ext = "mp4" if ext in ("mp4", "mpeg4") else ext
                    file_size_mb = getattr(doc, "size", 0) / (1024 * 1024)

                    if max_video_mb == 0:
                        print(f"  [i] Video skipped (--max-video-mb 0)")
                    elif file_size_mb > max_video_mb:
                        print(f"  [!] Video skipped — {file_size_mb:.1f} MB > limit {max_video_mb} MB")
                    elif assert_disk_space(min_space_gb, str(output_dir)):
                        try:
                            filename = media_dir / f"{message.id}.{ext}"
                            print(f"  [~] Video ({file_size_mb:.1f} MB): {filename.name} ...")
                            await client.download_media(message, file=str(filename))
                            entry["media_path"] = f"media/{message.id}.{ext}"
                            print(f"  [+] Video saved: {filename.name}")
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

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    generate_html(results, channel_title, html_path)

    # Language breakdown summary
    print(f"\n  [✓] {len(results)} messages saved → {channel_dir}/")
    if lang_stats:
        print(f"  [i] Language breakdown:")
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

    client = TelegramClient(SESSION_NAME, API_ID, API_HASH)
    await client.start(phone=PHONE)
    print(f"[+] Connected as {(await client.get_me()).username}")

    for channel_id, forced_lang in channels:
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

    await client.disconnect()
    print(f"\n[+] All done. Output in: {output_dir}/")


if __name__ == "__main__":
    asyncio.run(main())

