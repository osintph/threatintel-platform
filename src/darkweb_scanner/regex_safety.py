"""
Checks for regular expressions that come from users (project keywords).

Python's ``re`` backtracks and has no timeout: one pattern such as ``(a+)+$``
freezes the process on a short line of text. A pattern is therefore checked
before it is stored and again before it is used, and it is only ever run
against a bounded piece of text (``clip``).

What ``check_pattern`` refuses:

* a pattern longer than ``MAX_PATTERN_LENGTH`` characters, or one that does
  not compile;
* back-references (``\\1``, ``(?P=name)``) and conditional groups;
* a look-ahead or look-behind that contains ``*``, ``+``, ``?`` or ``{n,m}``;
* a repeat followed by something it can also match, when another repeat comes
  later in the pattern: ``(a+)+``, ``(\\w+\\s?)+``, ``a?a?a?b``, ``\\w+\\d+x``,
  ``.*a.*b``. The character the pattern needs next has to be one the repeat
  cannot take, so there is only one place where the repeat can end;
* alternatives of which more than one can match at the same place, when a
  repeat comes later or the alternatives are themselves repeated:
  ``(a|aa)+``, ``(\\d+|\\w+)x+y``. Alternatives that differ in their plain
  start (``foo|bar``, ``bdo|bpi``) are fine anywhere.

What it lets through: everything else, which includes patterns that are
quadratic in the length of the text (``\\b[\\w.-]+\\.ph\\b`` on ``a.a.a.a...``).
On ``MAX_MATCH_TEXT`` characters the slowest accepted pattern found so far
takes about 0.15 s; the usual ones take microseconds.

The check reads the parse tree that ``re`` itself builds, so it sees the
pattern exactly as it will be run. When it cannot tell that two parts are
unable to match the same character, it treats them as overlapping.
"""

import logging
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

try:  # Python 3.11+
    from re import _constants as _c
    from re import _parser
except ImportError:  # pragma: no cover - older interpreters
    import sre_constants as _c  # type: ignore[no-redef]
    import sre_parse as _parser  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

MAX_PATTERN_LENGTH = 200
# Longest text a user pattern is run against (see clip()).
MAX_MATCH_TEXT = 1000
# A character range wider than this is not expanded; it then counts as
# overlapping with everything.
_MAX_RANGE = 512


class UnsafePattern(ValueError):
    """Raised with a reason that is safe to show to the user."""


# ── Sets of characters ─────────────────────────────────────────────────────────

_CATEGORY_TEST = {
    "digit": str.isdecimal,
    "space": str.isspace,
    "word": lambda ch: ch.isalnum() or ch == "_",
}
_CATEGORIES = {
    _c.CATEGORY_DIGIT: ("digit", False),
    _c.CATEGORY_NOT_DIGIT: ("digit", True),
    _c.CATEGORY_SPACE: ("space", False),
    _c.CATEGORY_NOT_SPACE: ("space", True),
    _c.CATEGORY_WORD: ("word", False),
    _c.CATEGORY_NOT_WORD: ("word", True),
}


@dataclass(frozen=True)
class _Chars:
    """The characters one position of a pattern can match.

    ``points`` and ``cats`` list them; with ``negated`` it is every character
    but those. ``unknown`` means the set could not be worked out.
    """

    points: frozenset = frozenset()
    cats: frozenset = frozenset()
    negated: bool = False
    unknown: bool = False

    def has(self, code: int) -> bool:
        """Whether the listed characters include ``code`` (ignores ``negated``)."""
        if code in self.points:
            return True
        ch = chr(code)
        return any(_CATEGORY_TEST[cat](ch) for cat in self.cats)


def _fold(code: int) -> set:
    """``code`` with its other case: patterns are run with IGNORECASE."""
    out = {code}
    ch = chr(code)
    for other in (ch.lower(), ch.upper()):
        if len(other) == 1:
            out.add(ord(other))
    return out


def _class_chars(items) -> _Chars:
    points: set = set()
    cats: set = set()
    negated = False
    flipped = 0
    for op, av in items:
        if op is _c.NEGATE:
            negated = True
        elif op is _c.LITERAL:
            points |= _fold(av)
        elif op is _c.RANGE:
            low, high = av
            if high - low > _MAX_RANGE:
                return _Chars(unknown=True)
            for code in range(low, high + 1):
                points |= _fold(code)
        elif op is _c.CATEGORY and av in _CATEGORIES:
            name, is_not = _CATEGORIES[av]
            cats.add(name)
            flipped += is_not
        else:
            return _Chars(unknown=True)
    if flipped:
        # [\S] is "everything but \s"; a class that mixes \S with more is not worked out.
        if len(cats) != 1 or points:
            return _Chars(unknown=True)
        negated = not negated
    return _Chars(frozenset(points), frozenset(cats), negated)


def _disjoint_pair(a: _Chars, b: _Chars) -> bool:
    """True only when no character can be in both sets."""
    if a.unknown or b.unknown or (a.negated and b.negated):
        return False
    if a.negated:
        a, b = b, a
    if b.negated:
        # a and "everything but B" share nothing when all of a is inside B.
        if any(not b.has(code) for code in a.points):
            return False
        return all(cat in b.cats or (cat == "digit" and "word" in b.cats) for cat in a.cats)
    if a.points & b.points:
        return False
    if any(b.has(code) for code in a.points) or any(a.has(code) for code in b.points):
        return False
    for x in a.cats:
        for y in b.cats:
            if x == y or {x, y} == {"digit", "word"}:
                return False
    return True


def _disjoint(first: list, second: list) -> bool:
    return all(_disjoint_pair(a, b) for a in first for b in second)


# ── The pattern as a tree ──────────────────────────────────────────────────────


@dataclass
class _Node:
    kind: str  # char | zero | look | seq | alt | repeat
    chars: Optional[_Chars] = None  # char
    items: list = field(default_factory=list)  # seq: nodes; alt: branches (seq nodes)
    body: Optional["_Node"] = None  # repeat, look
    low: int = 0  # repeat
    high: int = 0  # repeat; _c.MAXREPEAT when open-ended


_ZERO = _Node("zero")


def _build(parsed, dotall: bool) -> _Node:
    """The parse tree of ``re`` as _Node objects. Raises UnsafePattern for what is never accepted."""
    out = []
    for op, av in parsed:
        if op is _c.LITERAL:
            out.append(_Node("char", chars=_Chars(frozenset(_fold(av)))))
        elif op is _c.NOT_LITERAL:
            out.append(_Node("char", chars=_Chars(frozenset(_fold(av)), negated=True)))
        elif op is _c.ANY:
            skip = frozenset() if dotall else frozenset({10})
            out.append(_Node("char", chars=_Chars(skip, negated=True)))
        elif op is _c.IN:
            out.append(_Node("char", chars=_class_chars(av)))
        elif op in (_c.AT, _c.FAILURE):
            out.append(_ZERO)
        elif op in (_c.MAX_REPEAT, _c.MIN_REPEAT, _c.POSSESSIVE_REPEAT):
            low, high, sub = av
            out.append(_Node("repeat", body=_build(sub, dotall), low=low, high=high))
        elif op is _c.SUBPATTERN:
            _group, add_flags, _del_flags, sub = av
            out.append(_build(sub, dotall or bool(add_flags & _c.SRE_FLAG_DOTALL)))
        elif op is _c.ATOMIC_GROUP:
            out.append(_build(av, dotall))
        elif op is _c.BRANCH:
            out.append(_Node("alt", items=[_build(sub, dotall) for sub in av[1]]))
        elif op in (_c.ASSERT, _c.ASSERT_NOT):
            direction, sub = av
            body = _build(sub, dotall)
            if _has_variable_repeat(body):
                raise UnsafePattern(
                    "a look-ahead or look-behind may not contain *, +, ? or {n,m}"
                )
            # A look-behind reads text that is already matched; a look-ahead
            # reads on, so what it starts with counts as what comes next.
            out.append(_Node("look", body=body) if direction > 0 else _ZERO)
        elif op in (_c.GROUPREF, _c.GROUPREF_EXISTS):
            raise UnsafePattern("back-references and conditional groups are not accepted")
        else:
            raise UnsafePattern("it uses a construct that is not accepted")
    return _Node("seq", items=out)


def _has_variable_repeat(node: _Node) -> bool:
    if node.kind == "repeat":
        return node.low != node.high or _has_variable_repeat(node.body)
    if node.kind in ("seq", "alt"):
        return any(_has_variable_repeat(item) for item in node.items)
    if node.kind == "look":
        return _has_variable_repeat(node.body)
    return False


def _nullable(node: _Node) -> bool:
    """Whether the node can match without taking a character."""
    if node.kind == "char":
        return False
    if node.kind in ("zero", "look"):
        return True
    if node.kind == "seq":
        return all(_nullable(item) for item in node.items)
    if node.kind == "alt":
        return any(_nullable(item) for item in node.items)
    return node.low == 0 or _nullable(node.body)


def _first(node: _Node) -> list:
    """The sets of characters the node can start with (or look at first)."""
    if node.kind == "char":
        return [node.chars]
    if node.kind == "zero":
        return []
    if node.kind in ("look", "repeat"):
        return _first(node.body)
    if node.kind == "alt":
        return [chars for branch in node.items for chars in _first(branch)]
    out = []
    for item in node.items:
        out += _first(item)
        if not _nullable(item):
            break
    return out


_MAX_PREFIX = 64


def _prefix(node: _Node, out: list) -> bool:
    """Collect in ``out`` the single characters the node starts with, up to its first
    repeat, alternation or look-ahead. False when it stopped before the end of the node."""
    if len(out) >= _MAX_PREFIX:
        return False
    if node.kind == "char":
        out.append(node.chars)
        return True
    if node.kind == "zero":
        return True
    if node.kind == "seq":
        return all(_prefix(item, out) for item in node.items)
    if node.kind == "repeat" and node.low == node.high and node.body.kind == "seq":
        body = node.body.items
        if len(body) == 1 and body[0].kind == "char" and node.low <= _MAX_PREFIX:
            out.extend([body[0].chars] * node.low)
            return True
    return False


def _deterministic(alt: _Node) -> bool:
    """An alternation of which at most one branch can get past its plain start.

    Two branches exclude each other when they cannot start with the same
    character (``foo|bar``), or when their plain starts differ at some later
    character (``bdo|bpi``, ``no\\.?|number``).
    """
    firsts, prefixes = [], []
    for branch in alt.items:
        if _nullable(branch):
            return False
        firsts.append(_first(branch))
        prefix: list = []
        _prefix(branch, prefix)
        prefixes.append(prefix)
    for i in range(len(firsts)):
        for j in range(i + 1, len(firsts)):
            if _disjoint(firsts[i], firsts[j]):
                continue
            if not any(_disjoint_pair(a, b) for a, b in zip(prefixes[i], prefixes[j])):
                return False
    return True


def _is_choice(node: _Node) -> bool:
    """Whether matching the node can be tried in more than one way."""
    if node.kind == "repeat":
        return node.low != node.high or _is_choice(node.body)
    if node.kind == "alt":
        return not _deterministic(node) or any(_is_choice(branch) for branch in node.items)
    if node.kind == "seq":
        return any(_is_choice(item) for item in node.items)
    return False


@dataclass
class _Follow:
    """What comes after a piece of the pattern."""

    first: list  # sets of characters it can start with
    choice: bool  # whether it holds a repeat or alternation that can be tried in several ways
    end: bool  # whether nothing at all comes after: the pattern ends there


def _simple_last(node: _Node) -> bool:
    """A repeat or alternation at the very end of the pattern, made of plain parts.

    Once it has matched, the pattern has matched: it is never tried again
    from another place, so it does not count as "another repeat comes later".
    """
    if node.kind == "repeat":
        return not _is_choice(node.body)
    if node.kind == "alt":
        return not any(_is_choice(branch) for branch in node.items)
    return False


def _follow_of(rest: list, follow: _Follow) -> _Follow:
    first: list = []
    nullable = True
    for item in rest:
        first += _first(item)
        if not _nullable(item):
            nullable = False
            break
    if nullable:
        first += follow.first
    choice = follow.choice
    for index, item in enumerate(rest):
        if choice:
            break
        if _is_choice(item):
            last = index == len(rest) - 1 and follow.end
            choice = not (last and _simple_last(item))
    return _Follow(first, choice, follow.end and not rest)


_OVERLAP = (
    "a repeat is followed by something it can also match, and another repeat comes later "
    "(examples: (a+)+, \\w+\\d+x, .*a.*b). Put a character between them that the first "
    "repeat cannot match, or remove a leading or trailing .*"
)
_AMBIGUOUS = (
    "alternatives that can match the same text are repeated or followed by a repeat "
    "(examples: (a|ab)+, (\\d+|\\w+)x+y)"
)


def _check(node: _Node, follow: _Follow) -> None:
    if node.kind == "seq":
        for index, item in enumerate(node.items):
            _check(item, _follow_of(node.items[index + 1 :], follow))
    elif node.kind == "repeat":
        start = _first(node.body)
        if node.low != node.high and follow.choice and not _disjoint(start, follow.first):
            raise UnsafePattern(_OVERLAP)
        if node.high > 1:
            # After one round comes another round, or what follows the repeat.
            inner = _Follow(start + follow.first, _is_choice(node.body) or follow.choice, False)
        else:
            inner = follow
        _check(node.body, inner)
    elif node.kind == "alt":
        if not _deterministic(node):
            plain = [branch for branch in node.items if branch.items]
            optional = len(plain) == len(node.items) - 1 and _deterministic(
                _Node("alt", items=plain)
            )
            if follow.choice:
                # "x|" (x or nothing) is an optional x; anything else is refused here.
                if not optional or not _disjoint(_first(node), follow.first):
                    raise UnsafePattern(_AMBIGUOUS if not optional else _OVERLAP)
        for branch in node.items:
            _check(branch, follow)


# ── Public functions ───────────────────────────────────────────────────────────


def check_pattern(pattern: str) -> None:
    """Raise UnsafePattern when ``pattern`` is not accepted as a user regular expression."""
    if not isinstance(pattern, str) or not pattern:
        raise UnsafePattern("it is empty")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise UnsafePattern(f"it is longer than {MAX_PATTERN_LENGTH} characters")
    try:
        re.compile(pattern, re.IGNORECASE)
        parsed = _parser.parse(pattern, re.IGNORECASE)
    except (re.error, RecursionError, OverflowError):
        raise UnsafePattern("it is not a valid regular expression") from None
    try:
        dotall = bool(parsed.state.flags & _c.SRE_FLAG_DOTALL)
        _check(_build(parsed, dotall), _Follow([], False, True))
    except UnsafePattern:
        raise
    except Exception:  # the parse tree is not what this module expects: refuse
        logger.exception("regular expression check failed on a pattern")
        raise UnsafePattern("it could not be checked") from None


def is_safe(pattern: str) -> bool:
    try:
        check_pattern(pattern)
    except UnsafePattern:
        return False
    return True


@lru_cache(maxsize=1024)
def compile_checked(pattern: str) -> Optional["re.Pattern"]:
    """The compiled pattern (case-insensitive), or None when it is refused.

    Compiled once per pattern; a refused pattern is logged once, not at every use.
    """
    try:
        check_pattern(pattern)
    except UnsafePattern as exc:
        logger.warning("Skipping stored regular expression %r: %s", pattern[:80], exc)
        return None
    return re.compile(pattern, re.IGNORECASE)


def clip(text: str, limit: int = MAX_MATCH_TEXT) -> str:
    """At most ``limit`` characters from the middle of ``text``.

    The text a pattern sees is the context around a keyword hit, and the hit
    is in its middle.
    """
    text = text or ""
    if len(text) <= limit:
        return text
    start = (len(text) - limit) // 2
    return text[start : start + limit]


def search(pattern: str, text: str) -> bool:
    """Whether the user pattern matches in ``text``. A refused pattern never matches."""
    compiled = compile_checked(pattern)
    if compiled is None:
        return False
    return compiled.search(clip(text)) is not None
