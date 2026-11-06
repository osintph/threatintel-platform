"""
XSS-4 / AZ-1: the Channel Monitor report and the files next to it.

Everything in messages.html comes from a Telegram channel: the title, the text,
the translation, links, MIME types and file names. None of it may reach the
report as markup, and none of it may choose a file name. The markers used here
are inert (an id attribute), never a script.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup
from telethon.tl.types import (
    Channel,
    ChannelForbidden,
    Chat,
    ChatPhotoEmpty,
    Document,
    DocumentAttributeFilename,
    MessageEntityBold,
    MessageEntityItalic,
    MessageEntityTextUrl,
    MessageEntityUrl,
    MessageMediaDocument,
    MessageMediaPhoto,
    Photo,
    User,
)

from darkweb_scanner import channel_monitor as cm


def _message(**over):
    m = {
        "id": 7,
        "date": "2026-11-06 01:02:03 UTC",
        "original": "Привет, это обычное сообщение",
        "translated_en": "Hello, this is an ordinary message",
        # Read by versions before 1.2.0 only; kept so these tests also run against them.
        "formatted_html": "Привет, это обычное сообщение",
        "detected_lang": "ru",
        "forced_lang": None,
        "media_type": None,
        "media_path": None,
        "media_url": None,
        "views": 3,
        "forwards": 0,
        "reply_to": None,
    }
    m.update(over)
    return m


def _render(tmp_path, messages, title="Channel"):
    out = tmp_path / "messages.html"
    cm.generate_html(messages, title, out)
    html = out.read_text(encoding="utf-8")
    return html, BeautifulSoup(html, "html.parser")


# ── Report: values are text, never markup ──────────────────────────────────────


def test_channel_title_cannot_close_the_title_element(tmp_path):
    title = '</title><i id="inj3">'
    html, soup = _render(tmp_path, [_message()], title=title)
    assert soup.find(id="inj3") is None
    assert '<i id="inj3">' not in html
    assert title in soup.title.get_text()
    assert title in soup.h1.get_text()


def test_translated_text_is_shown_as_text(tmp_path):
    html, soup = _render(tmp_path, [_message(translated_en='<b id="inj1">t</b>')])
    assert soup.find(id="inj1") is None
    assert '<b id="inj1">' not in html
    assert '<b id="inj1">t</b>' in soup.find(class_="translated").get_text()


def test_media_path_with_a_quote_cannot_add_an_attribute(tmp_path):
    path = 'media/1.jpg" id="inj4'
    html, soup = _render(tmp_path, [_message(media_type="photo", media_path=path)])
    assert soup.find(id="inj4") is None
    assert soup.find("img") is None, "a path this code did not generate is not used as a source"
    assert path in soup.get_text()


def test_media_path_outside_the_archive_is_not_loaded(tmp_path):
    for path in (
        "https://remote.invalid/pixel.png",
        "//remote.invalid/pixel.png",
        "../../secret.jpg",
    ):
        _, soup = _render(tmp_path, [_message(media_type="photo", media_path=path)])
        assert soup.find("img") is None, path
        assert soup.find("video") is None, path


def test_web_page_preview_with_a_script_url_is_text(tmp_path):
    url = "javascript:document.title='inj6'"
    html, soup = _render(tmp_path, [_message(media_type="webpage", media_url=url)])
    assert not [a for a in soup.find_all("a") if "javascript" in (a.get("href") or "").lower()]
    assert url in soup.get_text()


def test_text_link_with_a_script_url_is_text(tmp_path):
    text = "click here"
    segments = cm.build_segments(
        text, [MessageEntityTextUrl(0, 5, "javascript:document.title='inj7'")]
    )
    html, soup = _render(tmp_path, [_message(original=text, segments=segments)])
    assert soup.find_all("a") == []
    assert "javascript:" not in html
    assert text in soup.find(class_="original").get_text()


def test_link_with_a_quote_stays_inside_the_href(tmp_path):
    url = 'https://example.com/"id="inj5'
    segments = cm.build_segments("link", [MessageEntityTextUrl(0, 4, url)])
    _, soup = _render(tmp_path, [_message(original="link", segments=segments)])
    assert soup.find(id="inj5") is None
    (a,) = soup.find_all("a")
    assert a["href"] == url
    assert "noreferrer" in a["rel"] and "noopener" in a["rel"]


def test_segments_handed_to_the_generator_are_checked_again(tmp_path):
    segments = [
        {
            "text": "click",
            "styles": ['x" id="inj11', "bold"],
            "href": "javascript:document.title='inj12'",
        }
    ]
    html, soup = _render(tmp_path, [_message(original="click", segments=segments)])
    assert soup.find_all("a") == [] and soup.find(id="inj11") is None
    assert "javascript:" not in html
    assert soup.find(class_="original").find("span")["class"] == ["bold"]


def test_message_text_and_entities_are_text(tmp_path):
    text = '<i id="inj2">x</i> bold'
    segments = cm.build_segments(text, [MessageEntityBold(19, 4)])
    _, soup = _render(tmp_path, [_message(original=text, segments=segments)])
    assert soup.find(id="inj2") is None
    original = soup.find(class_="original")
    assert original.get_text() == text
    assert original.find(class_="bold").get_text() == "bold"


def test_report_carries_a_policy_without_script_or_remote_origins(tmp_path):
    hostile = '<script id="inj8">1</script>'
    html, soup = _render(
        tmp_path,
        [
            _message(
                original=hostile, translated_en=hostile, media_type="webpage", media_url=hostile
            )
        ],
        title=hostile,
    )
    meta = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})
    assert meta is not None
    policy = meta["content"]
    assert "default-src 'none'" in policy
    assert "script-src" not in policy and "http" not in policy and "*" not in policy
    assert soup.find("script") is None
    assert "<script" not in html.lower()
    # Nothing in the page is fetched from elsewhere.
    assert soup.find("link") is None and soup.find("iframe") is None
    assert "@import" not in html and "url(" not in html


def test_unknown_file_type_is_linked_not_displayed(tmp_path):
    _, soup = _render(tmp_path, [_message(media_type="image_doc", media_path="media/5.bin")])
    assert soup.find("img") is None
    assert [a["href"] for a in soup.find_all("a")] == ["media/5.bin"]


def test_known_image_and_video_are_displayed(tmp_path):
    _, soup = _render(
        tmp_path,
        [
            _message(id=1, media_type="photo", media_path="media/1.jpg"),
            _message(id=2, media_type="video", media_path="media/2.mp4"),
        ],
    )
    assert soup.find("img")["src"] == "media/1.jpg"
    assert soup.find("video").find("source")["src"] == "media/2.mp4"


# ── Links, MIME types and file names ───────────────────────────────────────────


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://example.com/a", "http://example.com/a"),
        ("HTTPS://Example.com/", "HTTPS://Example.com/"),
        ("tg://resolve?domain=durov", "tg://resolve?domain=durov"),
        ("example.com/path", "http://example.com/path"),
        ("javascript:alert(1)", None),
        ("JaVaScRiPt:alert(1)", None),
        ("java\tscript:alert(1)", None),
        (" javascript:alert(1)", None),
        ("data:text/html,x", None),
        ("vbscript:x", None),
        ("file:///etc/passwd", None),
        ("//remote.invalid/x", None),
        ("/local/path", None),
        ("", None),
        (None, None),
        (5, None),
    ],
)
def test_safe_link_allows_only_http_https_and_tg(url, expected):
    assert cm.safe_link(url) == expected


@pytest.mark.parametrize(
    "mime,extension",
    [
        ("image/jpeg", "jpg"),
        ("IMAGE/PNG", "png"),
        ("image/gif", "gif"),
        ("image/webp", "webp"),
        ("video/mp4", "mp4"),
        ("video/webm", "webm"),
        ("audio/mpeg", "mp3"),
        ("audio/ogg", "ogg"),
        ("application/pdf", "pdf"),
        ("text/plain; charset=utf-8", "txt"),
        ("image/svg+xml", "bin"),
        ("image/html", "bin"),
        ("text/html", "bin"),
        ("application/x-msdownload", "bin"),
        ('image/x" id="inj', "bin"),
        ("image/../../evil", "bin"),
        ("", "bin"),
        (None, "bin"),
    ],
)
def test_mime_type_selects_from_a_fixed_list_of_extensions(mime, extension):
    assert cm.media_extension(mime) == extension


def test_media_file_names_are_built_from_the_message_id():
    assert cm.media_filename(123, 'image/x" id="inj') == "123.bin"
    assert cm.media_filename(123, "image/png") == "123.png"
    with pytest.raises(ValueError):
        cm.media_filename("12/../3", "image/png")


def test_entity_offsets_count_utf16_units():
    # The emoji is two UTF-16 units, so "bold" starts at offset 3.
    segments = cm.build_segments(
        "😀 bold and plain", [MessageEntityBold(3, 4), MessageEntityItalic(3, 4)]
    )
    assert [(s["text"], s["styles"]) for s in segments] == [
        ("😀 ", []),
        ("bold", ["bold", "italic"]),
        (" and plain", []),
    ]


def test_bare_url_entity_links_only_when_the_scheme_is_allowed():
    text = "see https://example.com/x or javascript:alert(1)"
    segments = cm.build_segments(text, [MessageEntityUrl(4, 21), MessageEntityUrl(29, 19)])
    assert [(s["text"], s["href"]) for s in segments] == [
        ("see ", None),
        ("https://example.com/x", "https://example.com/x"),
        (" or ", None),
        ("javascript:alert(1)", None),
    ]


def test_entities_with_bad_offsets_are_ignored():
    segments = cm.build_segments(
        "short", [MessageEntityBold(50, 4), MessageEntityBold(-3, 0), MessageEntityBold(2, 99)]
    )
    assert "".join(s["text"] for s in segments) == "short"


# ── Public channels only (AZ-1) ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ref",
    [
        "durov",
        "@durov",
        "https://t.me/durov",
        "http://t.me/durov/",
        "t.me/s/durov",
        " durov ",
        "telegram.me/durov",
    ],
)
def test_public_channel_references_are_accepted(ref):
    assert cm.parse_public_channel(ref) == "durov"


@pytest.mark.parametrize(
    "ref",
    [
        "me",
        "self",
        "+79990000000",
        "79990000000",
        "https://t.me/+AbCdEfGhIjKl",
        "https://t.me/joinchat/AbCdEfGhIjKl",
        "t.me/c/1234567890/5",
        "-1001234567890",
        "12345",
        "a b",
        "Saved Messages",
        "dur",
        "a" * 300,
        "durov\nme",
        "https://evil.example/durov",
        "",
        None,
        12345,
    ],
)
def test_everything_else_is_refused(ref):
    with pytest.raises(cm.ChannelNotAllowed):
        cm.parse_public_channel(ref)


def _channel(**kw):
    args = dict(
        id=1, title="Title", photo=ChatPhotoEmpty(), date=None, broadcast=True, username="durov"
    )
    args.update(kw)
    return Channel(**args)


def test_public_broadcast_channel_and_public_group_pass():
    cm.require_public_channel(_channel(), "durov")
    cm.require_public_channel(_channel(broadcast=False, megagroup=True), "durov")


@pytest.mark.parametrize(
    "entity",
    [
        User(id=1, username="alice_account"),
        Chat(
            id=1,
            title="Private group",
            photo=ChatPhotoEmpty(),
            participants_count=3,
            date=None,
            version=1,
        ),
        _channel(username=None),
        _channel(username=None, broadcast=False, megagroup=True),
        ChannelForbidden(id=1, access_hash=1, title="Gone"),
    ],
    ids=["user", "basic-group", "private-channel", "private-supergroup", "forbidden-channel"],
)
def test_users_groups_and_private_channels_are_refused(entity):
    with pytest.raises(cm.ChannelNotAllowed):
        cm.require_public_channel(entity, "durov")


class _FakeClient:
    """Stands in for TelegramClient: no network, records what was asked of it."""

    def __init__(self, entity, messages=()):
        self.entity = entity
        self.messages = list(messages)
        self.resolved = []
        self.read = 0
        self.downloads = []

    async def get_entity(self, ref):
        self.resolved.append(ref)
        return self.entity

    async def iter_messages(self, channel, limit=None):
        for message in self.messages:
            self.read += 1
            yield message

    async def download_media(self, message, file=None):
        self.downloads.append(file)
        with open(file, "wb") as fh:
            fh.write(b"x")
        return file


def _telegram_message(mid, text="", media=None, entities=None):
    return SimpleNamespace(
        id=mid,
        date=datetime(2026, 11, 6, 1, 2, 3, tzinfo=timezone.utc),
        raw_text=text,
        text=text,
        entities=entities,
        media=media,
        views=1,
        forwards=0,
        reply_to=None,
        reply_to_msg_id=None,
    )


@pytest.mark.parametrize(
    "entity",
    [User(id=1, username="alice_account"), _channel(username=None)],
    ids=["user", "private-channel"],
)
async def test_nothing_is_read_from_an_entity_that_is_not_a_public_channel(tmp_path, entity):
    client = _FakeClient(entity, [_telegram_message(1, "private text")])
    with pytest.raises(cm.ChannelNotAllowed):
        await cm.process_channel(client, "alice_account", 10, tmp_path)
    assert client.read == 0 and client.downloads == []
    assert list(tmp_path.iterdir()) == [], "no output is written for a refused channel"


@pytest.mark.parametrize(
    "ref", ["me", "+79990000000", "https://t.me/+AbCdEfGhIjKl", "-1001234567890"]
)
async def test_private_references_never_reach_telegram(tmp_path, ref):
    client = _FakeClient(_channel())
    with pytest.raises(cm.ChannelNotAllowed):
        await cm.process_channel(client, ref, 10, tmp_path)
    assert client.resolved == []


async def test_downloads_get_generated_names_and_text_goes_to_the_translator_only_when_asked(
    tmp_path, monkeypatch
):
    sent = []
    monkeypatch.setattr(cm, "translate_text", lambda text, lang: sent.append(text) or "translated")
    monkeypatch.setattr(cm, "assert_disk_space", lambda *a, **k: True)

    def document(mime):
        return MessageMediaDocument(
            document=Document(
                id=1,
                access_hash=1,
                file_reference=b"",
                date=None,
                mime_type=mime,
                size=10,
                dc_id=1,
                attributes=[DocumentAttributeFilename('evil" id="inj9.html')],
            )
        )

    photo = MessageMediaPhoto(
        photo=Photo(id=1, access_hash=1, file_reference=b"", date=None, sizes=[], dc_id=1)
    )
    messages = [
        _telegram_message(1, "Это сообщение на русском языке", media=photo),
        _telegram_message(2, "", media=document("image/html")),
        _telegram_message(3, "", media=document('video/x" id="inj10')),
        _telegram_message(4, "", media=document("image/png")),
    ]
    client = _FakeClient(_channel(title='</title><i id="inj3">'), messages)

    await cm.process_channel(client, "@durov", 10, tmp_path, forced_lang="ru")

    media = sorted(p.name for p in tmp_path.rglob("media/*"))
    assert media == ["1.jpg", "2.bin", "3.bin", "4.png"]
    assert [p.name for p in tmp_path.iterdir()] == ["durov"], (
        "the folder is named after the validated username"
    )
    assert client.resolved == ["durov"]
    assert sent == ["Это сообщение на русском языке"]

    soup = BeautifulSoup(
        (tmp_path / "durov" / "messages.html").read_text(encoding="utf-8"), "html.parser"
    )
    assert (
        soup.find(id="inj3") is None
        and soup.find(id="inj9") is None
        and soup.find(id="inj10") is None
    )
    assert [img["src"] for img in soup.find_all("img")] == ["media/4.png", "media/1.jpg"]

    # Translation switched off: the text stays on the server.
    sent.clear()
    await cm.process_channel(
        client, "durov", 10, tmp_path / "second", forced_lang="ru", translate=False
    )
    assert sent == []
