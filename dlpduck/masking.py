"""Never store the value a rule matched. Store a masked form for humans and
a keyed digest for correlation instead.

The v1 implementation wrote raw matched text to the index, audit log, and sinks.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata


def _normalize(raw: str) -> str:
    """Reduce a matched value to what should decide whether two matches
    are the same value.

    Unicode-aware on purpose. This was `re.sub(r"[^0-9a-z]", "", s.lower())`,
    which drops every character outside ASCII — so any wholly non-Latin
    value normalised to the empty string and they *all* produced the same
    digest. A Cyrillic name, a Japanese address and a Greek identifier
    correlated as "the same value appeared in 3 documents", which is not a
    near-miss: it is a confident, wrong answer handed to an investigator,
    in most of the world's deployments.

    NFKC first, so a full-width digit run from a CJK scan correlates with
    the same digits typed normally, and composed and decomposed accents
    agree. Then casefold rather than lower, which handles the cases lower
    does not (ß and SS are the same value). Then keep alphanumerics of any
    script and drop the formatting — "4111 1111" and "4111-1111" are one
    card number.

    One casefold gap needs a manual patch: Turkish dotless "ı" (U+0131) is
    str.upper()'s target for plain "i" (Unicode's simple, locale-independent
    uppercase mapping treats them as a pair), but casefold() does not fold
    it back to "i" — that mapping is marked Turkish-locale-only ('T') in
    CaseFolding.txt, and casefold() applies only the common/full ('C'/'F')
    entries. Left alone, "ı" and its own naive uppercase "I" normalise to
    two different strings and silently fail to correlate. Folded here as a
    correlation heuristic, not a claim that ı and i are the same letter.
    """
    folded = unicodedata.normalize("NFKC", raw).casefold().replace("ı", "i")
    return "".join(c for c in folded if c.isalnum())


def mask(raw: str, keep: int = 0) -> str:
    """Mask everything except an optional trailing tail.

    keep is per-rule and defaults to 0 (fully masked). A fixed tail is
    reasonable on a 16-digit card and reckless on a 9-character NI number,
    where it would disclose nearly half the value — so rules opt into a
    tail, they never get one by default.
    """
    chars = [c for c in raw if c.isalnum()]
    if not chars:
        return ""
    # Never reveal a tail from a short match: e.g. a 5-character value with
    # keep=4 would be 80% cleartext.
    if keep <= 0 or len(chars) <= keep + 3:
        return "•" * len(chars)
    return "•" * (len(chars) - keep) + "".join(chars[-keep:])


def correlate(raw: str, key: bytes) -> str:
    """Stable keyed digest: lets an investigator see 'this same value
    appeared in N documents' without any of them storing the value itself.

    key comes from DLPDUCK_HMAC_KEY and must never be written to config,
    the archive, or the audit trail alongside the digests it produces.

    A value with no alphanumeric content at all still normalises to the
    empty string, so such matches share a digest. That is a much narrower
    class than the ASCII-only normaliser used to collapse, and a match
    made entirely of punctuation is not a value worth correlating.
    """
    return hmac.new(key, _normalize(raw).encode("utf-8"), hashlib.sha256).hexdigest()[:32]
