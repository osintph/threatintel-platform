"""
The two config files the dashboard rewrites: the keyword YAML and the seed list.

  * One lock per file. A change is read, made and written under it, so two
    requests cannot lose each other's change.
  * Atomic. The new content goes to a temp file in the same directory and is
    renamed over the old one: a reader (a crawl, the CLI) sees the old file or
    the new one, never half of one.
  * Only what the route meant to change is changed. The keyword file keeps its
    other top-level blocks (``settings:``), their order and its leading
    comment; the seed list keeps its comments, blank lines and order.

PyYAML does not keep comments inside the document, so those are still lost
the first time the dashboard rewrites a hand-edited keyword file.

The locks are in this process. Only the dashboard writes these files, and it
runs as one process.
"""

import contextlib
import copy
import os
import stat
import threading
from pathlib import Path
from typing import Callable, Iterable

import yaml

_locks: dict = {}
_locks_guard = threading.Lock()


def lock_for(path: Path) -> threading.RLock:
    """The lock for one file, the same object for every caller."""
    key = os.path.abspath(path)
    with _locks_guard:
        lock = _locks.get(key)
        if lock is None:
            lock = _locks[key] = threading.RLock()
        return lock


def atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path`` with ``text`` in one step. The file keeps its mode."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    # 0o666 less the umask: what a plain open() would have given a new file.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o666)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        with contextlib.suppress(FileNotFoundError):
            os.chmod(tmp, stat.S_IMODE(os.stat(path).st_mode))
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _leading_comment(text: str) -> str:
    """The comment lines at the top of a file, up to the first line of content."""
    head = []
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            break
        head.append(line)
    while head and not head[-1].strip():
        head.pop()
    return "\n".join(head) + "\n\n" if head else ""


def update_keywords(path: Path, default: Path, change: Callable[[dict], object]):
    """Change the keyword categories of the keyword file. Returns what ``change`` returns.

    ``change(categories)`` edits the dict {category: [keyword, ...]} in place.
    The document is read from ``path``, or from ``default`` (the bundled
    file) when the dashboard has not written one yet, and is written to
    ``path`` only when a category changed. Every other block is written back
    as it was read.
    """
    with lock_for(path):
        text = _read(path if path.exists() else default)
        doc = yaml.safe_load(text) or {}
        if not isinstance(doc, dict):
            doc = {}
        categories = doc.get("keywords")
        if not isinstance(categories, dict):
            categories = {}
        doc["keywords"] = categories
        before = copy.deepcopy(categories)
        result = change(categories)
        if categories != before:
            body = yaml.dump(doc, default_flow_style=False, allow_unicode=True, sort_keys=False)
            atomic_write_text(path, _leading_comment(text) + body)
        return result


def update_seeds(path: Path, default: Path, add: Iterable[str] = (), remove: Iterable[str] = ()) -> int:
    """Add and remove seed URLs. Returns how many were added.

    Works on lines: a removed URL loses its line, a new one is appended, and
    comment lines, blank lines and the order of the rest stay as they are.
    """
    with lock_for(path):
        text = _read(path if path.exists() else default)
        lines = text.splitlines()
        gone = {u.strip() for u in remove}
        kept = [line for line in lines if not (line.strip() in gone and not line.strip().startswith("#"))]
        present = {line.strip() for line in kept if line.strip() and not line.strip().startswith("#")}
        added = 0
        for url in add:
            url = url.strip()
            if url and url not in present:
                kept.append(url)
                present.add(url)
                added += 1
        if kept != lines:
            atomic_write_text(path, "\n".join(kept) + "\n")
        return added
